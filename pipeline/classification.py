"""Conservative, explainable product classification for cached CVE records.

CPE parts are authoritative. CNA product attribution requires an explicitly
affected version/default, while a category inferred from names or prose stays
labelled as inferred. Execution platforms and vulnerability types are never
used as product categories. Rules enrich records; they do not filter ingestion.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import re
from typing import Any
from urllib.parse import urlsplit


CLASSIFICATION_VERSION = 1
CATEGORY_ORDER = ("OS", "Application", "Hardware", "Unknown")
PLACEHOLDERS = {"", "*", "-", "n/a", "na", "none", "unknown", "unspecified",
                "not applicable", "not available", "multiple products", "all products"}
PACKAGE_COLLECTIONS = {"registry.npmjs.org", "www.npmjs.com", "pypi.org", "rubygems.org",
                       "crates.io", "packagist.org", "repo.maven.apache.org", "repo1.maven.org",
                       "wordpress.org", "plugins.jenkins.io", "pkg.go.dev", "nuget.org",
                       "www.nuget.org", "extensions.joomla.org", "marketplace.visualstudio.com"}


def normalized_name(value: str) -> str:
    """Normalize case/separators only; do not merge vendor or product aliases."""
    return " ".join(re.findall(r"\w+", value.casefold().replace("_", " ")))


class ProductTaxonomy:
    """An exact vendor/product lookup; conflicting CPE parts stay ambiguous."""

    def __init__(self) -> None:
        self.parts: dict[tuple[str, str], set[str]] = defaultdict(set)

    def add(self, vendor: str, product: str, category: str) -> None:
        self.parts[(normalized_name(vendor), normalized_name(product))].add(category)

    def lookup(self, vendor: str, product: str) -> str | None:
        values = self.parts.get((normalized_name(vendor), normalized_name(product)), set())
        return next(iter(values)) if len(values) == 1 and "Unknown" not in values else None

    def ambiguous(self, vendor: str, product: str) -> bool:
        values = self.parts.get((normalized_name(vendor), normalized_name(product)), set())
        return bool(values) and (len(values) > 1 or "Unknown" in values)


def affected_entries(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Read NVD affected[].affectedData[] and the original CNA affected form."""
    result = []
    affected = cve.get("affected")
    if not isinstance(affected, list):
        return result
    for item in affected:
        if not isinstance(item, dict):
            continue
        nested = item.get("affectedData")
        if isinstance(nested, list):
            result.extend(entry for entry in nested if isinstance(entry, dict))
        elif "product" in item or "packageName" in item:
            result.append(item)
    return result


def explicitly_affected(item: dict[str, Any]) -> bool:
    if item.get("defaultStatus") == "affected":
        return True
    versions = item.get("versions")
    if not isinstance(versions, list):
        return False
    for version in versions:
        if not isinstance(version, dict):
            continue
        if version.get("status") == "affected":
            return True
        changes = version.get("changes")
        if isinstance(changes, list) and any(isinstance(change, dict) and
                                            change.get("status") == "affected" for change in changes):
            return True
    return False


def valid_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = " ".join(value.split())
    return name.casefold() if name.casefold() not in PLACEHOLDERS else None


def name_category(name: str, vendor: str = "") -> tuple[str, str] | None:
    """A bounded vocabulary for primary product names, never host platforms."""
    value = normalized_name(name)
    publisher = normalized_name(vendor)
    if re.search(r"\b(?:plugin|plugins|plug in|extension|extensions|theme|library|framework|"
                 r"browser|cms|web application|web app|sdk|driver|drivers|git server|database|"
                 r"utility|tool|tools|updater)\b", value):
        return "Application", "Application, extension, or software-library product name"
    # Match complete OS names/version prefixes. 'Foo for Linux' is not Linux.
    os_names = ("linux kernel", "microsoft windows", "windows server", "windows 10", "windows 11",
                "apple macos", "macos", "apple ios", "apple ipados", "freebsd", "openbsd",
                "netbsd", "red hat enterprise linux", "suse linux enterprise", "ubuntu linux",
                "debian linux", "cisco ios xe", "cisco ios xr", "cisco ios", "junos os")
    host_context = re.search(r"\b(?:for|client|utility|tool|tools|defender|subsystem)\b", value)
    if not host_context and any(value == term or value.startswith(term + " ") for term in os_names):
        return "OS", "Recognized operating-system product name"
    if (value == "linux" and publisher in {"linux", "linux foundation"}) or (
            value in {"windows", "android", "ios", "ipados", "mac os x"} and
            publisher in {"microsoft", "google", "apple"}):
        return "OS", "Recognized operating-system publisher and product"
    if re.search(r"\b(?:firmware|bios|uefi|router|routers|printer|printers|camera|cameras|"
                 r"microcontroller|chipset|motherboard|programmable logic controller)\b", value):
        return "Hardware", "Device or firmware product name"
    if (publisher in {"amd", "intel", "intel corporation", "arm"} or
            re.match(r"^(?:intel|amd|arm)\b", value)) and re.search(r"\b(?:processors?|cpus?|chipsets?)\b", value):
        return "Hardware", "Processor or chipset identified by the affected product name"
    return None


def description_category(description: str) -> tuple[str, str] | None:
    """Only consider an explicit product definition or primary product context."""
    head = " ".join(description[:1000].casefold().split())
    first = head[:400]
    # Common CNA wording directly identifies the vulnerable extension.
    if re.search(r"\b(?:plugin|theme|extension) for (?:wordpress|joomla|drupal)\b", first):
        return "Application", "Description identifies a vulnerable CMS extension"
    if re.search(r"\b(?:wordpress|joomla|drupal) (?:plugin|theme|extension)\b", first):
        return "Application", "Description identifies a vulnerable CMS extension"
    if re.search(r"\bis (?:an? )?(?:[\w-]+ ){0,8}(?:library|framework|web application|"
                 r"application|web app|content management system|knowledge management system|"
                 r"git server|database|browser|plugin|package|sdk)\b", first):
        return "Application", "Opening description defines the affected software product"
    # OS names in a runtime/platform clause do not establish the affected product.
    if re.match(r"^(?:in (?:the )?|the )?linux kernel\b", first) or re.match(
            r"^(?:a |an )?vulnerability\b.{0,140}\bin (?:the )?linux kernel\b", first):
        if not re.search(r"\b(?:plugin|library|application|framework)\b", first):
            return "OS", "Opening description identifies the Linux kernel as the affected product"
    if not re.search(r"\b(?:library|application|framework|utility|tool|updater)\b", first):
        if re.match(r"^(?:a |an )?(?:security )?(?:issue|vulnerability)\s+(?:exists\s+)?in "
                    r"(?:the )?(?:[a-z0-9()._-]+\s+){0,5}(?:firmware|bios|uefi)\b", first) or re.match(
                    r"^.{0,100}\bfirmware (?:before|prior to|versions?|contains?|has|is vulnerable)\b", first):
            return "Hardware", "Opening description identifies vulnerable device firmware"
    return None


def evidence(category: str, source: str, reason: str, authoritative: bool = False) -> dict[str, Any]:
    return {"category": category, "source": source, "reason": reason, "authoritative": authoritative}


def classification_result(products: list[dict[str, str]], evidence_items: list[dict[str, Any]],
                          method: str) -> dict[str, Any]:
    categories = [category for category in CATEGORY_ORDER
                  if any(item["category"] == category for item in evidence_items)] or ["Unknown"]
    known = [item for item in evidence_items if item["category"] != "Unknown"]
    authority = ("authoritative" if known and all(item["authoritative"] for item in known)
                 else "inferred" if known else "unresolved")
    unique = {(item["category"], item["source"], item["reason"], item["authoritative"]): item
              for item in evidence_items}
    return {"products": products, "vendors": sorted({item["vendor"] for item in products
                                                      if item["vendor"] != "Unknown"}),
            "categories": categories, "categoryEvidence": list(unique.values()),
            "categoryMethod": method if known else "unresolved", "categoryAuthority": authority}


def classify_cve(cve: dict[str, Any], cpe_products: list[dict[str, str]], description: str,
                 kev: dict[str, Any] | None = None, taxonomy: ProductTaxonomy | None = None,
                 parse_cpe: Any = None) -> dict[str, Any]:
    """Prefer vulnerable CPE, then explicitly affected CNA products, then prose."""
    if cpe_products:
        return classification_result(cpe_products, [
            evidence(item["category"], "cpe", "Vulnerable CPE product type" if item["category"] !=
                     "Unknown" else "CPE product type is ambiguous or unsupported", True)
            for item in cpe_products], "cpe")
    if str(cve.get("vulnStatus", "")).casefold() == "rejected":
        return classification_result([], [evidence("Unknown", "description", "Rejected CVE record")],
                                     "unresolved")
    attributed: dict[tuple[str, str], dict[str, Any]] = {}
    product_evidence: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in affected_entries(cve):
        if not explicitly_affected(item):
            continue
        name = valid_name(item.get("product")) or valid_name(item.get("packageName"))
        if not name:
            continue
        vendor = valid_name(item.get("vendor")) or "Unknown"
        categories: set[str] = set()
        cpes = item.get("cpes")
        if parse_cpe and isinstance(cpes, list):
            categories = {parsed[2] for value in cpes if (parsed := parse_cpe(value)) is not None}
        if categories:
            category = next(iter(categories)) if len(categories) == 1 else "Unknown"
            entry_evidence = evidence(category, "affected", "Explicit CPE type in CNA affected product metadata",
                                      True)
        elif taxonomy and (category := taxonomy.lookup(vendor, name)):
            entry_evidence = evidence(category, "affected", "Exact CNA vendor/product matches unanimous vulnerable CPE types")
        elif taxonomy and taxonomy.ambiguous(vendor, name):
            category = "Unknown"
            entry_evidence = evidence(category, "affected", "Cached vulnerable CPE types conflict for this exact CNA vendor/product")
        else:
            category, reason = "Unknown", "CNA names the affected product; its type is unresolved"
            collection = item.get("collectionURL")
            try:
                host = urlsplit(collection).hostname if isinstance(collection, str) else None
            except ValueError:
                host = None
            if host in PACKAGE_COLLECTIONS and valid_name(item.get("packageName")):
                category, reason = "Application", "Affected package belongs to a software package collection"
            elif (match := name_category(name, vendor)):
                category, reason = match
            entry_evidence = evidence(category, "affected", reason)
        pair = (vendor, name)
        product_evidence[pair].append(entry_evidence)
        previous = attributed.get(pair)
        if previous:
            if previous["category"] != category:
                previous["category"] = "Unknown"
        else:
            attributed[pair] = {"id": hashlib.sha256(f"{vendor}\0{name}".encode()).hexdigest()[:24],
                                "name": name, "vendor": vendor, "category": category,
                                "source": "affected"}
    inferred: list[dict[str, Any]] = []
    for pair, items in product_evidence.items():
        authoritative = [item for item in items if item["authoritative"]]
        preferred = authoritative or items
        categories = {item["category"] for item in preferred}
        known = categories - {"Unknown"}
        if len(known) > 1 or (authoritative and "Unknown" in categories):
            attributed[pair]["category"] = "Unknown"
            inferred.append(evidence("Unknown", "affected", "Conflicting CPE types in CNA affected metadata", bool(authoritative)))
        elif known:
            attributed[pair]["category"] = next(iter(known))
            inferred.extend(item for item in preferred if item["category"] != "Unknown")
        else:
            attributed[pair]["category"] = "Unknown"
            inferred.extend(preferred)
    # Preserve uncertain CNA products but classify the CVE's primary description
    # when all product types remain unknown. Never invent a product from prose.
    if any(item["category"] != "Unknown" for item in inferred):
        return classification_result(list(attributed.values()), inferred, "affected")
    if any(item["authoritative"] or "CPE types conflict" in item["reason"] for item in inferred):
        return classification_result(list(attributed.values()), inferred, "unresolved")
    if kev:
        product = valid_name(kev.get("product"))
        vendor = valid_name(kev.get("vendorProject")) or ""
        if product and (match := name_category(product, vendor)):
            category, reason = match
            return classification_result(list(attributed.values()), [evidence(category, "kev", reason)], "kev")
    if match := description_category(description):
        category, reason = match
        return classification_result(list(attributed.values()), [evidence(category, "description", reason)], "description")
    return classification_result(list(attributed.values()), inferred or [
        evidence("Unknown", "description", "Insufficient evidence to identify the affected product type")], "unresolved")
