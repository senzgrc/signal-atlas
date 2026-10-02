"""Reported weakness and CVSS potential-impact inference checks."""

import unittest

from pipeline.insights import comparison_window, increment_insights, insight_stats, record_insights, within_comparison


class InsightTests(unittest.TestCase):
    def test_weakness_ids_are_deduplicated_and_placeholders_do_not_count(self):
        result = record_insights(["CWE-79", "CWE-79", "CWE-89", "NVD-CWE-noinfo", "NVD-CWE-Other",
                                  "CWE-0", "CWE-0079", "CWE-999999"], None, None, {"CWE-79", "CWE-89"})
        self.assertEqual(result["causes"], ["CWE-79", "CWE-89"])
        self.assertFalse(result["impactKnown"])
        self.assertIsNone(result["remoteUnauthenticated"])

    def test_v3_complete_vector_counts_potential_impacts_and_network_no_privileges(self):
        result = record_insights([], "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N")
        self.assertTrue(result["impactKnown"])
        self.assertEqual(result["impacts"], ["confidentiality", "integrity"])
        self.assertTrue(result["remoteUnauthenticated"])

    def test_v2_partial_complete_and_none_potential_impact(self):
        result = record_insights([], "2.0", "(AV:N/AC:L/Au:N/C:P/I:C/A:N)")
        self.assertEqual(result["impacts"], ["confidentiality", "integrity"])
        self.assertTrue(result["remoteUnauthenticated"])
        none = record_insights([], "2.0", "AV:L/AC:H/Au:S/C:N/I:N/A:N")
        self.assertTrue(none["impactKnown"])
        self.assertEqual(none["impacts"], [])
        self.assertFalse(none["remoteUnauthenticated"])

    def test_v4_requires_all_vulnerable_and_subsequent_system_impact_fields(self):
        result = record_insights([], "4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N")
        self.assertTrue(result["impactKnown"])
        self.assertEqual(result["impacts"], ["confidentiality", "integrity"])
        base_only = record_insights([], "4.0", "CVSS:4.0/AV:L/PR:L/VC:N/VI:H/VA:H")
        self.assertFalse(base_only["impactKnown"])
        self.assertEqual(base_only["impacts"], [])
        self.assertFalse(base_only["remoteUnauthenticated"])

    def test_malformed_duplicate_invalid_version_or_missing_triple_remains_unknown(self):
        examples = [
            ("3.1", "CVSS:3.1/AV:N/PR:N/C:H/I:H"),
            ("3.1", "CVSS:3.1/AV:N/PR:N/C:H/I:H/A:H/C:N"),
            ("3.1", "CVSS:3.0/AV:N/PR:N/C:H/I:H/A:H"),
            ("3.1", "CVSS:3.1/AV:N/PR:N/C:P/I:H/A:H"),
            ("3.1", "CVSS:3.1/AV:N/PR:N/C:H/I:H/A:H/BAD:Q"),
            ("3.1", "CVSS:3.1/AV:N/PR:N/C:H/I:H/A:H "),
            ("4.0", "CVSS:4.0/AV:N/PR:N/VC:H/VI:H/VA:H/SC:N"),
            (None, "CVSS:3.1/AV:N/PR:N/C:H/I:H/A:H"),
        ]
        for version, vector in examples:
            with self.subTest(vector=vector):
                result = record_insights([], version, vector)
                self.assertFalse(result["impactKnown"])
                self.assertEqual(result["impacts"], [])

    def test_partial_authentication_stays_unknown(self):
        result = record_insights([], "3.1", "CVSS:3.1/AV:N/C:H/I:H/A:H")
        self.assertTrue(result["impactKnown"])
        self.assertIsNone(result["remoteUnauthenticated"])

    def test_aggregation_bins_and_multi_cwe_coverage_deduplicate_per_record(self):
        target = insight_stats()
        record = {"severity": "Critical", "kev": True,
                  "insights": {"causes": ["CWE-79", "CWE-89", "CWE-79"],
                               "impactKnown": True, "impacts": ["integrity", "integrity"],
                               "remoteUnauthenticated": True}}
        increment_insights(target, record)
        expected = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        self.assertEqual(target["causeKnown"], expected)
        self.assertEqual(target["impactKnown"], expected)
        self.assertEqual(target["remoteUnauthenticated"], expected)
        self.assertEqual(target["reachKnown"], expected)
        self.assertEqual(target["causes"]["CWE-79"], expected)
        self.assertEqual(target["causes"]["CWE-89"], expected)
        self.assertEqual(target["impacts"]["integrity"], expected)
        self.assertEqual(target["impacts"]["availability"], [0] * 10)

    def test_comparison_cutoff_exact_time_same_period_and_timezone(self):
        window = comparison_window("2026-09-30T19:48:32.143Z")
        self.assertEqual(window["partialYear"], 2026)
        self.assertEqual(window["endMonthDay"], "09-30")
        self.assertTrue(within_comparison("2025-09-30T19:48:32.143Z", window))
        self.assertFalse(within_comparison("2025-09-30T19:48:32.144Z", window))
        self.assertTrue(within_comparison("2024-09-30T15:48:32.143-04:00", window))
        self.assertFalse(within_comparison("2024-10-01T00:00:00Z", window))

    def test_leap_cutoff_clamps_without_including_march(self):
        window = comparison_window("2024-02-29T12:00:00Z")
        self.assertTrue(within_comparison("2023-02-28T12:00:00Z", window))
        self.assertFalse(within_comparison("2023-02-28T12:00:01Z", window))
        self.assertTrue(within_comparison("2020-02-29T12:00:00Z", window))
        self.assertFalse(within_comparison("2020-03-01T00:00:00Z", window))

    def test_completed_year_has_no_partial_cutoff(self):
        self.assertIsNone(comparison_window("2026-12-31T23:59:59.999Z"))
        self.assertIsNone(comparison_window(None))
        self.assertTrue(within_comparison("2025-12-31T23:59:59Z", None))


if __name__ == "__main__":
    unittest.main()
