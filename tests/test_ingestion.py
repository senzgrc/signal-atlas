"""Offline tests for cache correctness, interrupted syncs, and upstream failures."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

from cvefetcher import OVERLAP, WINDOW, sync_nvd
from fetch_cisakev import sync_kev
from pipeline.cache import connect_db, get_meta, parse_time, set_meta, timestamp, upsert_cve, upsert_kev
from pipeline.http import CISA_FEED, FetchError, JsonClient, JsonResponse, NVD_API, retry_delay

NOW = datetime(2020, 1, 3, 12, 0, tzinfo=timezone.utc)


def cve(identifier="CVE-2020-1000", *, published="2020-01-01T01:00:00.000", modified="2020-01-02T01:00:00.000", description="Example"):
    return {"id": identifier, "published": published, "lastModified": modified, "vulnStatus": "Rejected",
            "descriptions": [{"lang": "en", "value": description}], "references": [], "metrics": {}}


def page(records=None, *, index=0, total=None):
    records = records or []
    return JsonResponse(200, {"format": "NVD_CVE", "version": "2.0", "timestamp": "2020-01-03T12:00:00.000",
                             "startIndex": index, "resultsPerPage": len(records), "totalResults": len(records) if total is None else total,
                             "vulnerabilities": [{"cve": item} for item in records]}, {})


def kev(identifier="CVE-2020-1000", description="Example"):
    return {"cveID": identifier, "vendorProject": "Every vendor", "product": "Every product", "vulnerabilityName": "Example",
            "dateAdded": "2020-01-02", "shortDescription": description, "requiredAction": "Apply updates", "dueDate": "2020-02-02"}


def catalog(items, headers=None):
    return JsonResponse(200, {"catalogVersion": "2020.01.03", "dateReleased": "2020-01-03T12:00:00Z", "count": len(items), "vulnerabilities": items}, headers or {})


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def get(self, url, headers=None):
        self.requests.append((url, headers))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.db = connect_db(":memory:")

    def tearDown(self):
        self.db.close()

    def sync(self, responses, **kwargs):
        client = FakeClient(responses)
        stats = sync_nvd(self.db, start_year=2020, end_year=2020, client=client, now=lambda: NOW, progress=lambda _: None, **kwargs)
        return stats, client

    def complete_bootstrap(self):
        return self.sync([page([cve()]), page([])])

    def test_hash_upserts_are_idempotent_and_cve_does_not_regress(self):
        with self.db:
            self.assertTrue(upsert_cve(self.db, cve()))
            self.assertFalse(upsert_cve(self.db, cve()))
            newer = cve(modified="2020-01-03T01:00:00", description="Corrected")
            self.assertTrue(upsert_cve(self.db, newer))
            self.assertFalse(upsert_cve(self.db, cve(description="Stale upstream page")))
            self.assertTrue(upsert_kev(self.db, kev()))
            self.assertFalse(upsert_kev(self.db, kev()))
        payload = json.loads(self.db.execute("SELECT payload FROM cves").fetchone()[0])
        self.assertEqual(payload, newer)

    def test_bootstrap_retains_rejected_and_catches_changes_during_backfill(self):
        updated = cve(modified="2020-01-03T11:59:00.000", description="Updated during backfill")
        stats, client = self.sync([page([cve()]), page([updated])])
        self.assertTrue(stats["complete"])
        self.assertEqual(stats["changed"], 2)
        self.assertTrue(get_meta(self.db, "nvd_bootstrap_complete"))
        self.assertEqual(get_meta(self.db, "nvd_last_sync"), timestamp(NOW))
        params = parse_qs(urlsplit(client.requests[1][0]).query)
        self.assertEqual(params["lastModStartDate"], [timestamp(NOW - OVERLAP)])
        self.assertNotIn("keywordSearch", params)
        self.assertNotIn("noRejected", params)

    def test_mid_page_bootstrap_resume_uses_committed_cursor(self):
        self.sync([page([cve()], total=2)], max_pages=1)
        state = get_meta(self.db, "nvd_sync_state")
        self.assertEqual(state["index"], 1)
        self.assertFalse(get_meta(self.db, "nvd_bootstrap_complete"))
        stats, client = self.sync([page([cve("CVE-2020-1001")], index=1, total=2), page([])])
        self.assertTrue(stats["complete"])
        self.assertEqual(parse_qs(urlsplit(client.requests[0][0]).query)["startIndex"], ["1"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM cves").fetchone()[0], 2)

    def test_failed_page_preserves_records_and_checkpoint(self):
        self.sync([page([cve()], total=2)], max_pages=1)
        state = get_meta(self.db, "nvd_sync_state")
        with self.assertRaises(FetchError):
            self.sync([FetchError("Network failed")])
        self.assertEqual(get_meta(self.db, "nvd_sync_state"), state)
        self.assertIsNone(get_meta(self.db, "nvd_last_sync"))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM cves").fetchone()[0], 1)

    def test_malformed_page_cannot_partially_write_or_advance_watermark(self):
        malformed = cve("INVALID")
        with self.assertRaises(ValueError):
            self.sync([page([cve(), malformed])])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM cves").fetchone()[0], 0)
        self.assertEqual(get_meta(self.db, "nvd_sync_state")["index"], 0)
        self.assertIsNone(get_meta(self.db, "nvd_last_sync"))

    def test_database_failure_rolls_back_entire_page_and_checkpoint(self):
        calls = 0

        def fail_second_record(db, record):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("Simulated storage failure")
            return upsert_cve(db, record)

        with patch("cvefetcher.upsert_cve", side_effect=fail_second_record):
            with self.assertRaises(RuntimeError):
                self.sync([page([cve(), cve("CVE-2020-1001")])])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM cves").fetchone()[0], 0)
        self.assertEqual(get_meta(self.db, "nvd_sync_state")["index"], 0)
        self.assertIsNone(get_meta(self.db, "nvd_last_sync"))

    def test_incremental_overlap_fetches_new_modified_and_ignores_outside_range(self):
        self.complete_bootstrap()
        later = NOW + timedelta(hours=1)
        new = cve("CVE-2020-1001", published="2020-01-03T12:30:00", modified="2020-01-03T12:30:00")
        updated = cve(modified="2020-01-03T12:40:00", description="Revised")
        outside = cve("CVE-2019-1000", published="2019-01-01T01:00:00", modified="2020-01-03T12:45:00")
        client = FakeClient([page([new, updated, outside])])
        stats = sync_nvd(self.db, start_year=2020, end_year=2020, client=client, now=lambda: later, progress=lambda _: None)
        self.assertEqual(stats["changed"], 2)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM cves").fetchone()[0], 2)
        self.assertEqual(get_meta(self.db, "nvd_last_sync"), timestamp(later))
        params = parse_qs(urlsplit(client.requests[0][0]).query)
        self.assertEqual(params["lastModStartDate"], [timestamp(NOW - OVERLAP)])
        self.assertNotIn("pubStartDate", params)

    def test_failed_incremental_does_not_advance_watermark_and_can_resume(self):
        self.complete_bootstrap()
        last_sync = get_meta(self.db, "nvd_last_sync")
        client = FakeClient([FetchError("Unavailable")])
        with self.assertRaises(FetchError):
            sync_nvd(self.db, start_year=2020, end_year=2020, client=client, now=lambda: NOW + timedelta(hours=1), progress=lambda _: None)
        self.assertEqual(get_meta(self.db, "nvd_last_sync"), last_sync)
        state = get_meta(self.db, "nvd_sync_state")
        self.sync([page([])])
        self.assertEqual(get_meta(self.db, "nvd_last_sync"), state["end"])

    def test_date_windows_never_exceed_nvd_limit(self):
        client = FakeClient([page([]), page([])])
        sync_nvd(self.db, start_year=2020, end_year=2026, max_pages=2, client=client,
                 now=lambda: datetime(2026, 9, 30, tzinfo=timezone.utc), progress=lambda _: None)
        for url, _ in client.requests:
            params = parse_qs(urlsplit(url).query)
            self.assertLess(parse_time(params["pubEndDate"][0]) - parse_time(params["pubStartDate"][0]), WINDOW)
            self.assertEqual(params["resultsPerPage"], ["2000"])
        self.assertFalse(get_meta(self.db, "nvd_bootstrap_complete"))

    def test_extend_range_retains_cache_and_backfills_only_added_year(self):
        self.complete_bootstrap()
        later = datetime(2021, 1, 3, 12, tzinfo=timezone.utc)
        client = FakeClient([page([])])
        sync_nvd(self.db, start_year=2020, end_year=2021, client=client, now=lambda: later, max_pages=1, progress=lambda _: None)
        params = parse_qs(urlsplit(client.requests[0][0]).query)
        self.assertEqual(params["pubStartDate"], ["2021-01-01T00:00:00.000Z"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM cves").fetchone()[0], 1)
        self.assertFalse(get_meta(self.db, "nvd_bootstrap_complete"))

    def test_kev_hashes_and_catalog_removals(self):
        first = FakeClient([catalog([kev(), kev("CVE-2020-1001")], {"etag": '"version-1"'})])
        stats = sync_kev(self.db, client=first, now=lambda: NOW, progress=lambda _: None)
        self.assertEqual(stats["changed"], 2)
        second = FakeClient([catalog([kev(description="Updated action"), kev("CVE-2020-1002")])])
        stats = sync_kev(self.db, client=second, now=lambda: NOW, progress=lambda _: None)
        self.assertEqual(stats["changed"], 2)
        self.assertEqual(stats["removed"], 1)
        self.assertEqual(second.requests[0][1], {"If-None-Match": '"version-1"'})
        self.assertEqual([row[0] for row in self.db.execute("SELECT cve_id FROM kev ORDER BY cve_id")], ["CVE-2020-1000", "CVE-2020-1002"])

    def test_kev_not_modified_preserves_payloads_and_updates_check_time(self):
        sync_kev(self.db, client=FakeClient([catalog([kev()], {"etag": '"abc"', "last-modified": "Fri, 03 Jan 2020 12:00:00 GMT"})]), now=lambda: NOW, progress=lambda _: None)
        client = FakeClient([JsonResponse(304, None, {})])
        later = NOW + timedelta(hours=1)
        stats = sync_kev(self.db, client=client, now=lambda: later, progress=lambda _: None)
        self.assertTrue(stats["not_modified"])
        self.assertEqual(get_meta(self.db, "kev_last_sync"), timestamp(later))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM kev").fetchone()[0], 1)

    def test_invalid_or_failed_kev_catalog_preserves_previous_state(self):
        sync_kev(self.db, client=FakeClient([catalog([kev()])]), now=lambda: NOW, progress=lambda _: None)
        invalid = catalog([kev("CVE-2020-1001")])
        invalid.data["count"] = 999
        for response, exception in ((invalid, ValueError), (catalog([]), ValueError), (FetchError("Failure"), FetchError)):
            with self.assertRaises(exception):
                sync_kev(self.db, client=FakeClient([response]), now=lambda: NOW + timedelta(hours=1), progress=lambda _: None)
        self.assertEqual(get_meta(self.db, "kev_last_sync"), timestamp(NOW))
        self.assertEqual(self.db.execute("SELECT cve_id FROM kev").fetchone()[0], "CVE-2020-1000")

    def test_kev_storage_failure_rolls_back_catalog_atomically(self):
        sync_kev(self.db, client=FakeClient([catalog([kev()])]), now=lambda: NOW, progress=lambda _: None)
        calls = 0

        def fail_second_record(db, item):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("Simulated storage failure")
            return upsert_kev(db, item)

        with patch("fetch_cisakev.upsert_kev", side_effect=fail_second_record):
            with self.assertRaises(RuntimeError):
                sync_kev(self.db, client=FakeClient([catalog([kev(description="Correction"), kev("CVE-2020-1001")])]),
                         now=lambda: NOW + timedelta(hours=1), progress=lambda _: None)
        self.assertEqual(get_meta(self.db, "kev_last_sync"), timestamp(NOW))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM kev").fetchone()[0], 1)
        self.assertEqual(json.loads(self.db.execute("SELECT payload FROM kev").fetchone()[0])["shortDescription"], "Example")


class HttpTests(unittest.TestCase):
    def test_only_fixed_https_upstreams_and_no_cross_host_key(self):
        client = JsonClient()
        for url in ("http://services.nvd.nist.gov/rest/json/cves/2.0", "https://attacker.invalid/", NVD_API + "#fragment"):
            with self.assertRaises(FetchError):
                client.get(url)
        with self.assertRaises(FetchError):
            client.get(CISA_FEED, {"apiKey": "secret"})
        with self.assertRaises(FetchError):
            client.get(NVD_API, {"apiKey": "injected\r\nHeader: value"})

    @patch("pipeline.http.time.sleep")
    def test_retryable_errors_are_bounded_and_redirects_fail(self, sleep):
        class Opener:
            def __init__(self, error):
                self.calls = 0
                self.error = error

            def open(self, *args, **kwargs):
                self.calls += 1
                raise self.error

        for error in (URLError("private details"), HTTPError(NVD_API, 429, "rate limit", {"Retry-After": "1"}, None)):
            client = JsonClient(max_attempts=3)
            client._opener = Opener(error)
            with self.assertRaises(FetchError) as failure:
                client.get(NVD_API, {"apiKey": "secret"})
            self.assertEqual(client._opener.calls, 3)
            self.assertNotIn("secret", str(failure.exception))
        client = JsonClient(max_attempts=3)
        client._opener = Opener(HTTPError(NVD_API, 302, "redirect", {"Location": "https://attacker.invalid"}, None))
        with self.assertRaises(FetchError):
            client.get(NVD_API)
        self.assertEqual(client._opener.calls, 1)

    def test_retry_after_is_bounded(self):
        self.assertEqual(retry_delay("999999", 1), 120.0)
        self.assertEqual(retry_delay("2", 1), 2.0)
        self.assertEqual(retry_delay("invalid", 2), 4.0)


if __name__ == "__main__":
    unittest.main()
