"""Regression checks for evidence priority and misleading platform context."""

import unittest

from export_dashboard import parse_cpe
from pipeline.classification import ProductTaxonomy, classify_cve


def affected(product, vendor="acme", **fields):
    return {"product": product, "vendor": vendor,
            "versions": [{"version": "1", "status": "affected"}], **fields}


def classify(entries=None, description="", products=None, kev=None, taxonomy=None, status="Deferred"):
    cve = {"vulnStatus": status, "affected": [{"source": "cna@example.com", "affectedData": entries or []}]}
    return classify_cve(cve, products or [], description, kev, taxonomy, parse_cpe)


class ClassificationTests(unittest.TestCase):
    def test_vulnerable_cpe_always_wins_over_prose_and_affected(self):
        products = [{"id": "x", "name": "widget", "vendor": "acme", "category": "Application"}]
        result = classify([affected("Linux", "Linux")], "In the Linux kernel, an issue exists.", products)
        self.assertEqual(result["categories"], ["Application"])
        self.assertEqual(result["categoryAuthority"], "authoritative")
        self.assertEqual(result["categoryMethod"], "cpe")
        self.assertEqual(result["products"], products)

    def test_ambiguous_cpe_cannot_be_reclassified_from_description(self):
        products = [{"id": "x", "name": "widget", "vendor": "acme", "category": "Unknown"}]
        result = classify([affected("Linux", "Linux")], "In the Linux kernel, an issue exists.", products)
        self.assertEqual(result["categories"], ["Unknown"])
        self.assertEqual(result["categoryMethod"], "unresolved")
        self.assertEqual(result["products"], products)

    def test_cna_embedded_cpe_is_authoritative_and_ignores_runtime_platform(self):
        result = classify([affected("Widget", cpes=["cpe:/a:acme:widget:1"], platforms=["Linux"])])
        self.assertEqual(result["categories"], ["Application"])
        self.assertEqual(result["categoryMethod"], "affected")
        self.assertEqual(result["categoryAuthority"], "authoritative")
        self.assertTrue(result["categoryEvidence"][0]["authoritative"])
        self.assertEqual(result["products"][0]["source"], "affected")

    def test_cna_unaffected_or_unknown_versions_are_not_attributed(self):
        result = classify([affected("Linux", "Linux", defaultStatus="unaffected",
                                    versions=[{"status": "unaffected", "version": "1"}]),
                           {"product": "WordPress plugin", "vendor": "acme", "defaultStatus": "unknown"}])
        self.assertEqual(result["categories"], ["Unknown"])
        self.assertEqual(result["products"], [])
        self.assertEqual(result["vendors"], [])

    def test_default_affected_with_fixed_versions_still_attributes(self):
        result = classify([affected("Linux", "Linux", defaultStatus="affected",
                                    versions=[{"status": "unaffected", "version": "6.0"}])])
        self.assertEqual(result["categories"], ["OS"])
        self.assertEqual(result["categoryAuthority"], "inferred")

    def test_version_change_to_affected_is_credible(self):
        result = classify([affected("widget library", versions=[{"version": "0", "status": "unaffected",
                                    "changes": [{"at": "1", "status": "affected"}]}])])
        self.assertEqual(result["categories"], ["Application"])

    def test_exact_vendor_product_consensus_and_conflicts(self):
        taxonomy = ProductTaxonomy()
        taxonomy.add("Acme", "Widget", "Application")
        result = classify([affected("Widget", "Acme")], taxonomy=taxonomy)
        self.assertEqual(result["categories"], ["Application"])
        self.assertEqual(result["categoryAuthority"], "inferred")
        taxonomy.add("Acme", "Widget", "OS")
        self.assertEqual(classify([affected("Widget", "Acme")], taxonomy=taxonomy)["categories"], ["Unknown"])
        self.assertEqual(classify([affected("Widget", "Different")], taxonomy=taxonomy)["categories"], ["Unknown"])

    def test_conflicting_cna_cpe_types_do_not_fall_back_to_prose(self):
        result = classify([affected("Linux", "Linux", cpes=["cpe:/o:linux:linux:1", "cpe:/a:linux:linux:1"])],
                          "In the Linux kernel, a vulnerability exists.")
        self.assertEqual(result["categories"], ["Unknown"])
        self.assertEqual(result["products"][0]["category"], "Unknown")
        result = classify([affected("Widget", cpes=["cpe:/o:acme:widget:1"]),
                           affected("Widget", cpes=["cpe:/a:acme:widget:1"])])
        self.assertEqual(result["categories"], ["Unknown"])

    def test_explicit_cna_cpe_priority_over_duplicate_inferred_name(self):
        result = classify([affected("Linux", "Linux"),
                           affected("Linux", "Linux", cpes=["cpe:/a:linux:linux:1"])])
        self.assertEqual(result["categories"], ["Application"])
        self.assertEqual(result["products"][0]["category"], "Application")
        self.assertEqual(result["categoryAuthority"], "authoritative")

    def test_package_collection_is_application_even_on_os_platforms(self):
        result = classify([affected("widget", collectionURL="https://registry.npmjs.org", packageName="widget",
                                    platforms=["Linux", "Windows"])])
        self.assertEqual(result["categories"], ["Application"])
        result = classify([affected("widget", collectionURL="https://registry.npmjs.org.evil.example", packageName="widget")])
        self.assertEqual(result["categories"], ["Unknown"])

    def test_descriptions_of_plugins_and_libraries_are_application(self):
        for description in ["The Widget plugin for WordPress is vulnerable to cross-site scripting.",
                            "Widget is a Python library running on Linux and Windows."]:
            result = classify(description=description)
            self.assertEqual(result["categories"], ["Application"])
            self.assertEqual(result["categoryMethod"], "description")
            self.assertEqual(result["products"], [])
            self.assertEqual(result["vendors"], [])

    def test_os_runtime_mention_does_not_classify_unknown_product_as_os(self):
        result = classify([affected("widget", platforms=["Linux"])],
                          "A vulnerability in Widget when running on Linux allows information disclosure.")
        self.assertEqual(result["categories"], ["Unknown"])
        self.assertEqual(result["products"][0]["category"], "Unknown")
        for name in ["Linux client", "Microsoft Windows Defender", "Widget for Linux"]:
            self.assertEqual(classify([affected(name)])["categories"], ["Unknown"])

    def test_direct_kernel_context_and_firmware(self):
        self.assertEqual(classify(description="In the Linux kernel, a memory safety issue was resolved.")["categories"], ["OS"])
        result = classify([affected("Widget firmware")], "Widget firmware before 1.1 is vulnerable.")
        self.assertEqual(result["categories"], ["Hardware"])
        self.assertEqual(result["categoryMethod"], "affected")

    def test_hardware_driver_is_application_and_processor_is_hardware(self):
        self.assertEqual(classify([affected("GPU driver", "NVIDIA")])["categories"], ["Application"])
        self.assertEqual(classify([affected("Processors", "AMD")])["categories"], ["Hardware"])
        self.assertEqual(classify([affected("Image Processor", "Acme")])["categories"], ["Unknown"])
        self.assertEqual(classify([affected("BIOS updater", "Acme")])["categories"], ["Application"])
        self.assertEqual(classify(description="A vulnerability in Widget application when interacting with firmware allows an attack.")["categories"], ["Unknown"])

    def test_rejected_records_remain_unresolved_despite_product_text(self):
        result = classify([affected("Linux", "Linux")], "The WordPress plugin is vulnerable.", status="Rejected")
        self.assertEqual(result["categories"], ["Unknown"])
        self.assertEqual(result["products"], [])

    def test_kev_named_product_can_infer_type_but_not_vendor_product_attribution(self):
        result = classify(kev={"vendorProject": "Acme", "product": "Router firmware"})
        self.assertEqual(result["categories"], ["Hardware"])
        self.assertEqual(result["categoryMethod"], "kev")
        self.assertEqual(result["categoryAuthority"], "inferred")
        self.assertEqual(result["products"], [])

    def test_multicategory_record_deduplicates_category_evidence(self):
        result = classify([affected("Linux", "Linux"), affected("Widget library"), affected("Widget library")])
        self.assertEqual(result["categories"], ["OS", "Application"])
        self.assertEqual(len(result["products"]), 2)
        self.assertEqual(len(result["categoryEvidence"]), 2)

    def test_placeholder_product_and_vendor_are_never_invented(self):
        result = classify([affected("n/a", "n/a")], "A vulnerability allows privilege escalation on Linux.")
        self.assertEqual(result["categories"], ["Unknown"])
        self.assertEqual(result["products"], [])
        result = classify([affected("Widget library", "n/a")])
        self.assertEqual(result["products"][0]["vendor"], "Unknown")
        self.assertEqual(result["vendors"], [])


if __name__ == "__main__":
    unittest.main()
