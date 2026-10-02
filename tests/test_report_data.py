"""Complete scoped report facts, attribution, and bounded evidence regression checks."""

import gzip
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import export_dashboard as exporter
from pipeline.report_data import ReportFactPacks, compact_record, empty_stats


def product(name="widget", vendor="acme", category="Application"):
    return {"id": hashlib.sha256(f"{vendor}\0{name}".encode()).hexdigest()[:24],
            "name": name, "vendor": vendor, "category": category}


def record(number, products=None, kev=False, category="Application", score=8.0, status="Analyzed"):
    return {"id": f"CVE-2026-{number:04}", "published": f"2026-09-{min(number, 30):02}T00:00:00Z",
            "modified": "2026-09-30T00:00:00Z", "description": "Published source description",
            "products": products or [], "vendors": sorted({item["vendor"] for item in products or []}),
            "categories": [category], "categoryEvidence": [{"category": category, "source": "cpe",
                "reason": "Vulnerable CPE product type", "authoritative": True}],
            "categoryAuthority": "authoritative", "categoryMethod": "cpe", "status": status,
            "severity": "High", "score": score, "vector": "CVSS:3.1/AV:N/PR:N/C:H/I:H/A:H",
            "cvssVersion": "3.1", "kev": kev,
            "kevDetails": {"cveID": f"CVE-2026-{number:04}", "dateAdded": "2026-09-30",
                "vendorProject": "Acme", "product": "Widget", "requiredAction": "Apply vendor mitigations.",
                "dueDate": "2026-10-15", "knownRansomwareCampaignUse": "Known", "notes": "Source note"} if kev else None,
            "references": ["https://example.com/advisory"], "weaknesses": ["CWE-79"],
            "insights": {"causes": ["CWE-79"], "impacts": ["confidentiality", "integrity", "availability"],
                "impactKnown": True, "remoteUnauthenticated": True}, "nvdCached": True}


class ReportFactsTests(unittest.TestCase):
    def builder(self, products, all_products=None):
        values = {**empty_stats(), "year": 2026, "categories": {category: empty_stats()
            for category in ("OS", "Application", "Hardware", "Unknown")}}
        values["through"] = {**empty_stats(), "categories": {category: empty_stats()
            for category in ("OS", "Application", "Hardware", "Unknown")}}
        return ReportFactPacks(products, all_products or {item["id"]: item for item in products},
            {2026: values}, "2026-09-30T00:00:00Z", {"start": "2020-01-01T00:00:00Z", "end": "2026-09-30T00:00:00Z"},
            {"partialYear": 2026, "endMonthDay": "09-30", "endTime": "00:00:00Z"})

    def entity(self, **kwargs):
        return {**product(**kwargs), "years": {"2026": empty_stats()}, "throughYears": {"2026": empty_stats()}}

    def test_kevs_are_complete_uncapped_deduplicated_per_subject_with_source_details(self):
        entity = self.entity()
        reports = self.builder([entity])
        for number in range(1, 36):
            reports.add_record(record(number, [entity, entity], kev=True), True)
        product_pack = reports.pack(f"product:{entity['id']}")
        category_pack = reports.pack("category:Application")
        self.assertEqual(len(product_pack["relatedKev"]), 35)
        self.assertEqual(len(category_pack["relatedKev"]), 35)
        self.assertEqual(product_pack["years"][0]["classification"]["authoritative"], 35)
        self.assertEqual(product_pack["relatedKev"][0]["kevDetails"]["requiredAction"], "Apply vendor mitigations.")
        self.assertEqual(product_pack["relatedKev"][0]["kevDetails"]["knownRansomwareCampaignUse"], "Known")
        self.assertEqual(product_pack["relatedKev"][0]["references"], ["https://example.com/advisory"])

    def test_examples_bounded_and_ordered_by_explicit_score_and_date(self):
        entity = self.entity()
        reports = self.builder([entity])
        for number in range(1, 36):
            reports.add_record(record(number, [entity], score=number / 4), True)
        examples = reports.pack(f"product:{entity['id']}")["examples"]
        self.assertEqual(len(examples), 10)
        self.assertEqual(examples[0]["id"], "CVE-2026-0035")
        self.assertEqual(examples[-1]["id"], "CVE-2026-0026")
        self.assertTrue(all(not item["kev"] for item in examples))

    def test_supplemental_kevs_exact_product_matching_are_separate_from_counts_and_known_category(self):
        entity = self.entity()
        reports = self.builder([entity])
        covered = record(1, [entity], kev=True)
        reports.add_record(covered, True)
        legacy = record(2, kev=True)
        legacy.update({"published": "", "nvdCached": False, "categoryAuthority": "inferred", "categoryMethod": "kev"})
        not_exact = record(3, kev=True)
        not_exact["kevDetails"]["product"] = "Widget Pro"
        unresolved = record(4, kev=True, category="Unknown")
        unresolved["categoryAuthority"] = "unresolved"
        unresolved["kevDetails"]["product"] = "Different"
        reports.add_supplemental([covered, legacy, legacy, not_exact, unresolved])
        product_pack = reports.pack(f"product:{entity['id']}")
        self.assertEqual([item["id"] for item in product_pack["supplementalKev"]], ["CVE-2026-0002"])
        self.assertEqual(len(product_pack["relatedKev"]), 1)
        self.assertEqual(product_pack["years"][0]["classification"]["authoritative"], 1)
        self.assertEqual(len(reports.pack("category:Application")["supplementalKev"]), 2)
        self.assertEqual(reports.pack("category:Unknown")["supplementalKev"], [])
        self.assertEqual(len(reports.pack("category:All")["supplementalKev"]), 3)

    def test_category_top_products_include_entities_outside_global_cap_and_deduplicate_counts(self):
        selected, outside = self.entity(), self.entity(name="uncapped")
        reports = self.builder([selected], {item["id"]: item for item in (selected, outside)})
        reports.add_record(record(1, [outside, outside], kev=True), True)
        reports.add_record(record(2, [outside]), False)
        reports.add_record(record(3, [selected]), True)
        pack = reports.pack("category:Application")
        self.assertEqual(pack["topProducts"]["2026"][0]["id"], outside["id"])
        self.assertEqual(pack["topProducts"]["2026"][0]["total"], 2)
        self.assertEqual(pack["topProductsThrough"]["2026"][0]["total"], 1)
        self.assertEqual(pack["years"][0]["classification"]["authoritative"], 3)
        self.assertEqual(pack["years"][0]["through"]["classification"]["authoritative"], 2)

    def test_rejected_and_unrelated_product_do_not_enter_scoped_evidence(self):
        entity = self.entity()
        reports = self.builder([entity])
        reports.add_record(record(1, [entity], kev=True, status="  REJECTED  "), True)
        reports.add_record(record(2, [self.entity(name="unrelated")], kev=True), True)
        reports.add_supplemental([record(3, kev=True, status="Rejected")])
        pack = reports.pack(f"product:{entity['id']}")
        self.assertEqual(pack["relatedKev"], [])
        self.assertEqual(pack["supplementalKev"], [])
        self.assertEqual(pack["examples"], [])
        self.assertEqual(pack["years"][0]["classification"]["authoritative"], 0)

    def test_compact_source_bounds_disclosed_and_subject_product_preserved(self):
        entity = self.entity()
        reports = self.builder([entity])
        products = [self.entity(name=f"product{index}") for index in range(25)] + [entity]
        source = record(1, products, kev=True)
        source["description"] = "a" * 6000
        source["references"] = [f"https://example.com/{number}" for number in range(40)]
        reports.add_record(source, True)
        evidence = reports.pack(f"product:{entity['id']}")["relatedKev"][0]
        self.assertEqual(len(evidence["description"]), 5000)
        self.assertEqual(len(evidence["references"]), 30)
        self.assertEqual(len(evidence["products"]), 20)
        self.assertIn(entity["id"], {item["id"] for item in evidence["products"]})
        self.assertEqual(evidence["sourceDetail"]["productCount"], 26)
        self.assertTrue(evidence["sourceDetail"]["descriptionTruncated"])

    def test_invalid_report_product_identifier_refuses_unsafe_paths(self):
        with self.assertRaises(ValueError):
            self.builder([{**self.entity(), "id": "../../unsafe"}])

    def test_export_integration_writes_fact_packs_and_keeps_rejected_tombstones(self):
        with tempfile.TemporaryDirectory() as temporary:
            db, output = Path(temporary) / "cache.sqlite3", Path(temporary) / "data"
            with closing(sqlite3.connect(db)) as connection:
                connection.executescript("CREATE TABLE cves(cve_id TEXT,published TEXT,modified TEXT,payload TEXT);"
                    "CREATE TABLE kev(cve_id TEXT,payload TEXT);CREATE TABLE metadata(key TEXT,value TEXT);")
                connection.execute("INSERT INTO metadata VALUES(?,?)", ("nvd_bootstrap_complete", "true"))
                connection.execute("INSERT INTO metadata VALUES(?,?)", ("nvd_coverage_end", '"2026-09-30T12:00:00Z"'))
                for number, status in ((1, "Analyzed"), (2, "Rejected")):
                    raw = {"id": f"CVE-2026-{number:04}", "vulnStatus": status,
                        "descriptions": [{"lang": "en", "value": "Test source"}],
                        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                            "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}]}]}]}
                    connection.execute("INSERT INTO cves VALUES(?,?,?,?)", (raw["id"], "2026-09-01T00:00:00Z",
                        "2026-09-01T00:00:00Z", json.dumps(raw)))
                    connection.execute("INSERT INTO kev VALUES(?,?)", (raw["id"], json.dumps(record(number, kev=True)["kevDetails"])))
                connection.commit()
            summary = exporter.export_dashboard(db, output)
            self.assertEqual(set(summary["reportPaths"]["categories"]), {"All", "OS", "Application", "Hardware", "Unknown"})
            self.assertEqual(len(summary["reportPaths"]["products"]), 1)
            relative = next(iter(summary["reportPaths"]["products"].values()))
            pack = json.loads(gzip.decompress((output / relative).read_bytes()))
            self.assertEqual(pack["subject"]["name"], "widget")
            self.assertEqual(len(pack["relatedKev"]), 1)
            self.assertEqual(pack["relatedKev"][0]["id"], "CVE-2026-0001")
            self.assertEqual(pack["years"][-1]["total"], 1)
            self.assertEqual(pack["years"][-1]["through"]["total"], 1)
            self.assertEqual(pack["years"][-1]["classification"]["authoritative"], 1)
            self.assertEqual(pack["supplementalKev"], [])
            self.assertLess(len(gzip.decompress((output / relative).read_bytes())), 8_000_000)


if __name__ == "__main__":
    unittest.main()
