"""Meaningful aggregation, publication, and link-safety regression checks."""

import gzip
import json
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

import export_dashboard as exporter


def cpe(part="a", vendor="acme", product="widget", version="*"):
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def metric(score, source="nvd@nist.gov", kind="Primary"):
    return {"source": source, "type": kind, "cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"}}


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "cache.sqlite3"
        self.output = self.root / "public" / "data"
        self.connection = sqlite3.connect(self.db)
        self.connection.executescript("""
            CREATE TABLE cves(cve_id TEXT PRIMARY KEY,published TEXT,modified TEXT,payload TEXT,content_hash TEXT);
            CREATE TABLE kev(cve_id TEXT PRIMARY KEY,payload TEXT,content_hash TEXT);
            CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
        """)
        self.metadata("nvd_bootstrap_complete", True)
        self.metadata("nvd_coverage_end", "2026-09-30T12:00:00Z")

    def tearDown(self):
        self.connection.close()
        self.temp.cleanup()

    def metadata(self, key, value):
        self.connection.execute("INSERT OR REPLACE INTO metadata VALUES(?,?)", (key, json.dumps(value)))
        self.connection.commit()

    def add_cve(self, cve_id, published="2026-09-01T00:00:00.000Z", **data):
        payload = {"id": cve_id, "published": published, "lastModified": published,
                   "descriptions": [{"lang": "en", "value": "Test description"}], **data}
        self.connection.execute("INSERT INTO cves VALUES(?,?,?,?,?)",
                                (cve_id, published, published, json.dumps(payload), "hash"))
        self.connection.commit()

    def add_kev(self, cve_id, **data):
        self.connection.execute("INSERT INTO kev VALUES(?,?,?)",
                                (cve_id, json.dumps({"cveID": cve_id, **data}), "hash"))
        self.connection.commit()

    def exported_records(self):
        summary = exporter.export_dashboard(self.db, self.output)
        records = []
        for year in summary["years"]:
            for month in year["months"]:
                for path in month["paths"]:
                    records.extend(json.loads(gzip.decompress((self.output / path).read_bytes()))["records"])
        return summary, records

    def test_compressed_summary_matches_plain_snapshot(self):
        self.add_cve("CVE-2026-0001")
        summary, _ = self.exported_records()
        compressed = json.loads(gzip.decompress((self.output / "summary.json.gz").read_bytes()))
        plain = json.loads((self.output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(compressed, summary)
        self.assertEqual(compressed, plain)

    def test_vulnerable_recursive_cpe_dedup_and_category_totals(self):
        self.add_cve("CVE-2026-0001", configurations=[{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": cpe()},
            {"vulnerable": True, "criteria": cpe(version="1.0")},
            {"vulnerable": False, "criteria": cpe(vendor="irrelevant", product="platform")},
        ], "children": [{"cpeMatch": [
            {"vulnerable": True, "criteria": cpe(product="second")},
            {"vulnerable": True, "criteria": cpe("o", "other", "system")},
        ]}]}]}], metrics={"cvssMetricV31": [metric(9.8)]})
        self.add_kev("CVE-2026-0001")
        summary, records = self.exported_records()
        self.assertEqual(records[0]["vendors"], ["acme", "other"])
        self.assertEqual(len(records[0]["products"]), 3)
        self.assertTrue(all(item["years"]["2026"]["total"] == 1 for item in summary["products"]))
        acme = next(item for item in summary["publishers"] if item["name"] == "acme")
        self.assertEqual(acme["years"]["2026"]["total"], 1)
        year = summary["years"][-1]
        self.assertEqual(year["categories"]["Application"]["total"], 1)
        self.assertEqual(year["categories"]["OS"]["total"], 1)
        self.assertEqual(year["kevSeverity"]["Critical"], 1)

    def test_cna_fallback_consensus_provenance_and_category_aggregation(self):
        self.add_cve("CVE-2026-0001", configurations=[{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": cpe("a", "acme", "widget")},
        ]}]}])
        self.add_cve("CVE-2026-0002", affected=[{"source": "cna@example.com", "affectedData": [
            {"vendor": "Acme", "product": "Widget", "defaultStatus": "affected"},
            {"vendor": "Acme", "product": "Widget", "versions": [{"status": "affected", "version": "1"}]},
        ]}])
        self.add_cve("CVE-2026-0003", descriptions=[{"lang": "en", "value": "Widget is a Python library."}])
        self.add_cve("CVE-2026-0004", vulnStatus="Rejected",
                     descriptions=[{"lang": "en", "value": "Rejected: issue in Linux kernel."}])
        summary, records = self.exported_records()
        by_id = {item["id"]: item for item in records}
        fallback = by_id["CVE-2026-0002"]
        self.assertEqual(fallback["categories"], ["Application"])
        self.assertEqual(fallback["categoryMethod"], "affected")
        self.assertEqual(fallback["categoryAuthority"], "inferred")
        self.assertEqual(len(fallback["products"]), 1)
        self.assertEqual(fallback["vendors"], ["acme"])
        self.assertEqual(by_id["CVE-2026-0003"]["products"], [])
        self.assertEqual(summary["years"][-1]["categories"]["Application"]["total"], 3)
        self.assertEqual(summary["years"][-1]["categories"]["Unknown"]["total"], 0)
        classification = summary["classification"]
        self.assertEqual(classification["authoritative"], 1)
        self.assertEqual(classification["inferred"], 2)
        self.assertEqual(classification["unresolved"], 0)
        self.assertEqual(classification["unresolvedByStatus"], {})
        self.assertEqual(classification["previouslyUnclassified"], 2)
        self.assertEqual(classification["recovered"], 2)
        self.assertEqual(classification["fullyRecovered"], 2)
        self.assertEqual(classification["methods"], {"cpe": 1, "affected": 1, "kev": 0,
                                                    "description": 1, "unresolved": 0})
        self.assertEqual(summary["years"][-1]["classification"], classification)
        self.assertNotIn("CVE-2026-0004", by_id)
        self.assertEqual(summary["excludedRejected"], 1)

    def test_embedded_cna_cpe_authoritative_totals_preserve_ambiguous_cpe(self):
        self.add_cve("CVE-2026-0001", affected=[{"source": "cna@example.com", "affectedData": [
            {"vendor": "Acme", "product": "Router", "defaultStatus": "affected", "cpes": ["cpe:/h:acme:router:1"]},
        ]}])
        self.add_cve("CVE-2026-0002", descriptions=[{"lang": "en", "value": "In the Linux kernel, an issue exists."}],
                     configurations=[{"nodes": [{"cpeMatch": [
                         {"vulnerable": True, "criteria": cpe("a", "acme", "ambiguous")},
                         {"vulnerable": True, "criteria": cpe("o", "acme", "ambiguous")},
                     ]}]}])
        summary, records = self.exported_records()
        by_id = {item["id"]: item for item in records}
        self.assertEqual(by_id["CVE-2026-0001"]["categoryAuthority"], "authoritative")
        self.assertEqual(by_id["CVE-2026-0002"]["categories"], ["Unknown"])
        self.assertEqual(summary["classification"]["authoritative"], 1)
        self.assertEqual(summary["classification"]["unresolved"], 1)
        self.assertEqual(summary["years"][-1]["categories"]["Hardware"]["total"], 1)

    def test_escaped_colon_and_backslash_cpe_fields(self):
        value = cpe(vendor=r"acme\:labs", product=r"path\\tool")
        self.assertEqual(exporter.parse_cpe(value), ("acme:labs", "path\\tool", "Application"))
        self.assertEqual(exporter.parse_cpe("cpe:/h:acme:widget%3Aplus:1.0"), ("acme", "widget:plus", "Hardware"))
        self.assertIsNone(exporter.parse_cpe("not-a-cpe"))

    def test_unknown_zero_v4_precedence_and_primary_nvd(self):
        self.add_cve("CVE-2026-0001", metrics={})
        self.add_cve("CVE-2026-0002", metrics={"cvssMetricV31": [metric(0)]})
        self.add_cve("CVE-2026-0003", metrics={
            "cvssMetricV40": [metric(8.5, "vendor", "Secondary"), metric(9.9)],
            "cvssMetricV31": [metric(4.0)],
        })
        self.add_cve("CVE-2026-0004", metrics={"cvssMetricV2": [metric(10)]})
        summary, records = self.exported_records()
        by_id = {item["id"]: item for item in records}
        self.assertEqual(by_id["CVE-2026-0001"]["severity"], "Unknown")
        self.assertIsNone(by_id["CVE-2026-0001"]["score"])
        self.assertEqual(by_id["CVE-2026-0002"]["severity"], "Low")
        self.assertEqual(by_id["CVE-2026-0002"]["score"], 0)
        self.assertEqual(by_id["CVE-2026-0003"]["cvssVersion"], "4.0")
        self.assertEqual(by_id["CVE-2026-0003"]["score"], 9.9)
        self.assertEqual(by_id["CVE-2026-0004"]["severity"], "High")
        self.assertEqual(summary["years"][-1]["severity"]["Unknown"], 1)

    def test_rejected_tombstones_are_excluded_from_all_publication_paths(self):
        # Publication year comes from NVD, even when the CVE identifier is older.
        self.add_cve("CVE-2018-0001", vulnStatus="  rEjEcTeD  ",
                     configurations=[{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                      "criteria": cpe("o", "acme", "widget")}]}]}],
                     metrics={"cvssMetricV31": [metric(9.8)]},
                     weaknesses=[{"description": [{"value": "CWE-79"}]}])
        self.add_cve("CVE-2026-0004", affected=[{"affectedData": [{"vendor": "acme", "product": "widget",
                                                                    "defaultStatus": "affected"}]}])
        self.add_cve("CVE-2019-0002", published="2019-06-01T00:00:00Z")
        self.add_cve("CVE-2019-0005", published="2019-06-02T00:00:00Z", vulnStatus="Rejected")
        self.add_kev("CVE-2018-0001")
        self.add_kev("CVE-2019-0002")
        self.add_kev("CVE-2019-0005")
        self.add_kev("CVE-2014-0003")
        summary, records = self.exported_records()
        self.assertEqual(summary["totalCves"], 1)
        self.assertEqual(summary["totalKev"], 0)
        self.assertEqual(summary["catalogKev"], 2)
        self.assertEqual(summary["excludedRejected"], 1)
        self.assertEqual(summary["catalogExcludedRejected"], 2)
        self.assertEqual(records[0]["id"], "CVE-2026-0004")
        self.assertEqual(records[0]["severity"], "Unknown")
        self.assertEqual(records[0]["categories"], ["Unknown"])
        self.assertEqual(summary["years"][-1]["critical"], 0)
        self.assertEqual(summary["years"][-1]["categories"]["OS"]["total"], 0)
        self.assertEqual(summary["years"][-1]["insights"]["causes"], {})
        self.assertEqual(summary["classification"]["unresolvedByStatus"], {"Unknown": 1})
        catalog = json.loads((self.output / "kev.json").read_text(encoding="utf-8"))
        self.assertEqual(len(catalog["vulnerabilities"]), 2)
        self.assertEqual({record["id"] for record in summary["priorityRecords"]}, {"CVE-2019-0002", "CVE-2014-0003"})
        self.assertEqual(self.connection.execute("SELECT count(*) FROM cves").fetchone()[0], 4)

    def test_unattributed_records_do_not_create_a_synthetic_publisher(self):
        self.add_cve("CVE-2026-0001")
        summary, records = self.exported_records()
        self.assertEqual(summary["totalCves"], 1)
        self.assertEqual(summary["publishers"], [])
        self.assertEqual(summary["rankingsLimit"]["totalPublishers"], 0)
        self.assertEqual(records[0]["vendors"], [])

    def test_insights_entity_dedup_and_same_period_comparisons(self):
        self.metadata("nvd_coverage_end", "2026-09-30T12:00:00Z")
        common = {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": cpe(version="1")},
            {"vulnerable": True, "criteria": cpe(version="2")},
            {"vulnerable": True, "criteria": cpe(product="second")},
        ]}]}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}}]},
                "weaknesses": [{"description": [{"value": "CWE-79"}, {"value": "CWE-79"},
                                                    {"value": "CWE-89"}, {"value": "CWE-999999"}]}]}
        self.add_cve("CVE-2025-0001", published="2025-09-30T12:00:00Z", **common)
        self.add_cve("CVE-2025-0002", published="2025-09-30T12:00:00.001Z", **common)
        self.add_cve("CVE-2026-0003", published="2026-09-01T00:00:00Z", **common)
        self.add_kev("CVE-2025-0001", dateAdded="2026-09-01")
        summary, records = self.exported_records()
        previous = next(year for year in summary["years"] if year["year"] == 2025)
        self.assertEqual(previous["total"], 2)
        self.assertEqual(previous["through"]["total"], 1)
        self.assertEqual(previous["through"]["categories"]["Application"]["total"], 1)
        expected = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        self.assertEqual(previous["through"]["insights"]["causeKnown"], expected)
        self.assertEqual(previous["through"]["insights"]["causes"]["CWE-79"], expected)
        publisher = summary["publishers"][0]
        self.assertEqual(publisher["years"]["2025"]["total"], 2)
        self.assertEqual(publisher["throughYears"]["2025"]["total"], 1)
        self.assertEqual(publisher["throughYears"]["2025"]["insights"]["causeKnown"], expected)
        self.assertTrue(all(item["years"]["2025"]["insights"]["causeKnown"][0] == 2 for item in summary["products"]))
        self.assertNotIn("CWE-999999", records[0]["insights"]["causes"])
        self.assertIn("copyright", summary["weaknessLabels"])
        self.assertIn("license", summary["weaknessLabels"])

    def test_tactical_candidates_include_recent_legacy_kev_without_nvd_details_and_are_bounded(self):
        for number in range(35):
            self.add_kev(f"CVE-2014-{number:04}", dateAdded=f"2026-09-{min(number + 1, 30):02}",
                         shortDescription="CISA catalog description", vendorProject="Acme", product="Widget")
        summary, _ = self.exported_records()
        self.assertEqual(summary["priorityRecordsCount"], 35)
        self.assertEqual(len(summary["priorityRecords"]), 30)
        self.assertEqual(summary["priorityRecords"][0]["kevDetails"]["dateAdded"], "2026-09-30")
        self.assertFalse(summary["priorityRecords"][0]["nvdCached"])
        self.assertEqual(summary["priorityRecords"][0]["published"], "")
        self.assertEqual(summary["priorityRecords"][0]["severity"], "Unknown")
        self.assertIsNone(summary["priorityRecords"][0]["score"])

    def test_https_references_reject_credentials_and_browser_ambiguity(self):
        good = "https://example.com/advisory?id=123"
        bad = ["javascript:alert(1)", "http://example.com", "https://user:pass@example.com/a",
               "https://example.com\\@evil.com", "https://example.com/\nlink", "https://example.com:bad/"]
        self.add_cve("CVE-2026-0001", references=[{"url": value} for value in [good, good, *bad]])
        _, records = self.exported_records()
        self.assertEqual(records[0]["references"], [good])

    def test_incomplete_refuses_publication_and_empty_preview_is_honest(self):
        self.output.mkdir(parents=True)
        (self.output / "existing.json").write_text("preserve", encoding="utf-8")
        self.metadata("nvd_bootstrap_complete", False)
        with self.assertRaises(exporter.ExportError):
            exporter.export_dashboard(self.db, self.output)
        self.assertEqual((self.output / "existing.json").read_text(encoding="utf-8"), "preserve")
        summary = exporter.export_dashboard(self.db, self.output, allow_incomplete=True)
        self.assertFalse(summary["coverage"]["bootstrapComplete"])
        self.assertEqual(summary["totalCves"], 0)
        self.assertEqual(summary["catalogKev"], 0)
        self.assertFalse((self.output / "existing.json").exists())

    def test_bounded_shards_and_newest_first(self):
        for number in range(5):
            self.add_cve(f"CVE-2026-{number:04}", published=f"2026-09-{number + 1:02}T00:00:00Z")
        with patch.object(exporter, "SHARD_SIZE", 2):
            summary, records = self.exported_records()
        month = summary["years"][-1]["months"][8]
        self.assertEqual(month["count"], 5)
        self.assertEqual(len(month["paths"]), 3)
        self.assertEqual([item["id"] for item in records], [f"CVE-2026-{number:04}" for number in reversed(range(5))])
        self.assertTrue(all(len(json.loads(gzip.decompress((self.output / path).read_bytes()))["records"]) <= 2
                            for path in month["paths"]))

    def test_gzip_shards_are_deterministic_and_header_has_no_timestamp(self):
        self.add_cve("CVE-2026-0001")
        summary, _ = self.exported_records()
        path = self.output / summary["years"][-1]["months"][8]["paths"][0]
        first = path.read_bytes()
        self.assertTrue(str(path).endswith(".json.gz"))
        self.assertEqual(first[4:8], b"\0\0\0\0")
        self.assertEqual(first[3] & 8, 0)  # No source filename in the gzip header.
        self.exported_records()
        self.assertEqual(path.read_bytes(), first)

    def test_configured_coverage_includes_extended_end_year(self):
        self.metadata("nvd_range_start", "2020-01-01T00:00:00.000Z")
        self.metadata("nvd_range_end", "2027-12-31T23:59:59.999Z")
        self.add_cve("CVE-2027-0001", published="2027-01-15T00:00:00.000Z")
        summary, records = self.exported_records()
        self.assertEqual(summary["years"][-1]["year"], 2027)
        self.assertEqual(summary["years"][-1]["total"], 1)
        self.assertEqual(records[0]["id"], "CVE-2027-0001")

    def test_rankings_limits_preserve_full_category_and_record_totals(self):
        self.add_cve("CVE-2026-0001", configurations=[{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": cpe("a", "first", "widget")},
        ]}]}])
        self.add_cve("CVE-2026-0002", configurations=[{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": cpe("o", "second", "system")},
        ]}]}])
        with patch.object(exporter, "PRODUCTS_LIMIT", 1), patch.object(exporter, "PUBLISHERS_LIMIT", 1):
            summary, records = self.exported_records()
        self.assertEqual(len(summary["products"]), 1)
        self.assertEqual(len(summary["publishers"]), 1)
        self.assertEqual(summary["rankingsLimit"]["totalProducts"], 2)
        self.assertEqual(summary["rankingsLimit"]["totalPublishers"], 2)
        self.assertEqual(summary["totalCves"], 2)
        self.assertEqual(len(records), 2)
        self.assertEqual(summary["years"][-1]["categories"]["OS"]["total"], 1)
        self.assertEqual(summary["years"][-1]["categories"]["Application"]["total"], 1)

    def test_kev_removed_from_current_catalog_is_removed_from_records(self):
        self.add_cve("CVE-2026-0001")
        self.add_kev("CVE-2026-0001")
        summary, records = self.exported_records()
        self.assertEqual(summary["totalKev"], 1)
        self.assertTrue(records[0]["kev"])
        self.connection.execute("DELETE FROM kev")
        self.connection.commit()
        summary, records = self.exported_records()
        self.assertEqual(summary["totalKev"], 0)
        self.assertFalse(records[0]["kev"])
        self.assertIsNone(records[0]["kevDetails"])

    def test_interrupted_publication_recovers_backup_before_refusing_partial(self):
        backup = self.output.parent / ".data-backup"
        backup.mkdir(parents=True)
        (backup / "existing.json").write_text("preserve", encoding="utf-8")
        self.metadata("nvd_bootstrap_complete", False)
        with self.assertRaises(exporter.ExportError):
            exporter.export_dashboard(self.db, self.output)
        self.assertEqual((self.output / "existing.json").read_text(encoding="utf-8"), "preserve")
        self.assertFalse(backup.exists())

    def test_failed_swap_recovers_existing_snapshot(self):
        self.output.mkdir(parents=True)
        (self.output / "existing.json").write_text("preserve", encoding="utf-8")
        original_replace = exporter.os.replace

        def fail_stage(source, destination):
            if "-stage-" in Path(source).name:
                raise OSError("simulated publication failure")
            return original_replace(source, destination)

        with patch.object(exporter.os, "replace", side_effect=fail_stage):
            with self.assertRaises(OSError):
                exporter.export_dashboard(self.db, self.output)
        self.assertEqual((self.output / "existing.json").read_text(encoding="utf-8"), "preserve")
        self.assertFalse((self.output.parent / ".data-backup").exists())

    def test_transient_backup_permission_failure_retries_and_preserves_publication(self):
        self.output.mkdir(parents=True)
        (self.output / "existing.json").write_text("preserve", encoding="utf-8")
        original_remove = exporter.shutil.rmtree
        attempts = 0

        def locked_once(directory, **kwargs):
            nonlocal attempts
            if Path(directory).name == ".data-backup":
                attempts += 1
                if attempts == 1:
                    raise PermissionError("simulated OneDrive lock")
            return original_remove(directory, **kwargs)

        with patch.object(exporter.shutil, "rmtree", side_effect=locked_once), patch.object(exporter.time, "sleep"):
            summary = exporter.export_dashboard(self.db, self.output)
        self.assertEqual(attempts, 2)
        self.assertEqual(summary["totalCves"], 0)
        self.assertTrue((self.output / "summary.json").exists())
        self.assertFalse((self.output.parent / ".data-backup").exists())

    def test_persistent_backup_lock_reports_failure_without_removing_published_data(self):
        self.output.mkdir(parents=True)
        (self.output / "existing.json").write_text("preserve", encoding="utf-8")
        original_remove = exporter.shutil.rmtree

        def always_locked(directory, **kwargs):
            if Path(directory).name == ".data-backup":
                raise PermissionError("persistent OneDrive lock")
            return original_remove(directory, **kwargs)

        with patch.object(exporter.shutil, "rmtree", side_effect=always_locked), patch.object(exporter.time, "sleep"):
            with self.assertRaises(PermissionError):
                exporter.export_dashboard(self.db, self.output)
        self.assertTrue((self.output / "summary.json").exists())
        self.assertEqual((self.output.parent / ".data-backup" / "existing.json").read_text(encoding="utf-8"), "preserve")

    def test_transient_directory_rename_permission_failure_retries(self):
        original_replace = exporter.os.replace
        attempts = 0

        def locked_once(source, destination):
            nonlocal attempts
            if "-stage-" in Path(source).name:
                attempts += 1
                if attempts == 1:
                    raise PermissionError("simulated OneDrive directory lock")
            return original_replace(source, destination)

        with patch.object(exporter.os, "replace", side_effect=locked_once), patch.object(exporter.time, "sleep"):
            exporter.export_dashboard(self.db, self.output)
        self.assertEqual(attempts, 2)
        self.assertTrue((self.output / "summary.json").exists())

    @unittest.skipUnless(exporter.os.name == "nt", "Windows directory attributes")
    def test_onedrive_readonly_output_is_cleared_before_retrying_rename(self):
        source = self.output.parent / "readonly-source"
        destination = self.output.parent / "renamed-source"
        source.mkdir(parents=True)
        source.chmod(source.stat().st_mode & ~stat.S_IWRITE)
        original_replace = exporter.os.replace

        def require_writable(source_path, destination_path):
            if not source_path.stat().st_mode & stat.S_IWRITE:
                raise PermissionError("OneDrive read-only directory")
            return original_replace(source_path, destination_path)

        with patch.object(exporter.os, "replace", side_effect=require_writable), patch.object(exporter.time, "sleep"):
            exporter.replace_directory(source, destination)
        self.assertFalse(source.exists())
        self.assertTrue(destination.is_dir())


if __name__ == "__main__":
    unittest.main()
