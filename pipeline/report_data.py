"""Bounded, auditable fact packs for executive vulnerability reports.

Facts preserve published CVE/CISA evidence. Known exploitation is CISA catalog
membership; CVSS is potential technical impact. These datasets do not infer an
organization's exposure, threat actors, incident likelihood, or financial loss.
"""

from __future__ import annotations

from collections import defaultdict
import re
import json
from typing import Any, Callable, Iterable

from pipeline.classification import normalized_name
from pipeline.insights import insight_stats


CATEGORIES = ("All", "OS", "Application", "Hardware", "Unknown")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")
EXAMPLE_LIMIT = 10


def classification_counts() -> dict[str, Any]:
    return {"authoritative": 0, "inferred": 0, "unresolved": 0,
            "methods": dict.fromkeys(("cpe", "affected", "kev", "description", "unresolved"), 0)}


def increment_classification(target: dict[str, Any], record: dict[str, Any]) -> None:
    authority = record.get("categoryAuthority", "unresolved")
    method = record.get("categoryMethod", "unresolved")
    target[authority if authority in ("authoritative", "inferred", "unresolved") else "unresolved"] += 1
    target["methods"][method if method in target["methods"] else "unresolved"] += 1


def compact_record(record: dict[str, Any]) -> dict[str, Any]:
    """Keep meaningful evidence, with explicit bounds for lengthy source text.

References and descriptions can be unusually large. The CVE identifier still
links to the complete NVD entry; truncation is disclosed alongside each record.
    """
    keys = ("id", "published", "modified", "status", "severity", "score", "cvssVersion", "vector",
            "vendors", "categories", "categoryEvidence", "categoryMethod", "categoryAuthority", "kev",
            "kevDetails", "weaknesses", "insights", "nvdCached")
    result = {key: record[key] for key in keys if key in record}
    description = record.get("description", "")
    result["description"] = description[:5000] if isinstance(description, str) else ""
    products = record.get("products", [])
    references = record.get("references", [])
    result["products"] = products[:20]
    result["references"] = references[:30]
    result["sourceDetail"] = {"descriptionTruncated": isinstance(description, str) and len(description) > 5000,
                               "productCount": len(products), "referenceCount": len(references)}
    return result


def example_order(record: dict[str, Any]) -> tuple[float, str, str]:
    score = record.get("score")
    return (float(score) if isinstance(score, (int, float)) else -1,
            str(record.get("published", "")), str(record.get("id", "")))


def stats_copy(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items()
            if key in ("total", "critical", "kev", "severity", "kevSeverity", "insights")}


def empty_stats() -> dict[str, Any]:
    return {"total": 0, "critical": 0, "kev": 0,
            "severity": dict.fromkeys(SEVERITIES, 0), "kevSeverity": dict.fromkeys(SEVERITIES, 0),
            "insights": insight_stats()}


def compact_counts() -> list[int]:
    # total, critical, KEV; five severity bins; five KEV severity bins.
    return [0] * 13


def increment_counts(values: list[int], record: dict[str, Any]) -> None:
    index = SEVERITIES.index(record["severity"])
    values[0] += 1
    values[1] += int(record["severity"] == "Critical")
    values[2] += int(record["kev"])
    values[3 + index] += 1
    if record["kev"]:
        values[8 + index] += 1


def unpack_counts(values: list[int]) -> dict[str, Any]:
    return {"total": values[0], "critical": values[1], "kev": values[2],
            "severity": dict(zip(SEVERITIES, values[3:8])),
            "kevSeverity": dict(zip(SEVERITIES, values[8:13]))}


class ReportFactPacks:
    """Collect one shard at a time; keep only KEV records and ten examples/scope."""

    def __init__(self, products: list[dict[str, Any]], all_products: dict[str, dict[str, Any]],
                 year_data: dict[int, dict[str, Any]], generated_at: str,
                 coverage: dict[str, Any], window: dict[str, Any] | None) -> None:
        self.products = {item["id"]: item for item in products}
        if any(not re.fullmatch(r"[0-9a-f]{24}", key) for key in self.products):
            raise ValueError("Report products require valid exported product identifiers")
        self.all_products = all_products
        self.year_data = year_data
        self.generated_at, self.coverage, self.window = generated_at, coverage, window
        self.subjects = {f"product:{key}": {"kind": "product", "id": key, "name": item["name"],
                                             "vendor": item["vendor"], "category": item["category"]}
                         for key, item in self.products.items()}
        self.subjects.update({f"category:{key}": {"kind": "category", "id": key, "name": key, "category": key}
                              for key in CATEGORIES})
        self.kev: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.supplemental: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.classification: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
        self.through_classification: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
        self.category_counts: dict[str, dict[tuple[str, int], list[int]]] = defaultdict(dict)
        self.category_through_counts: dict[str, dict[tuple[str, int], list[int]]] = defaultdict(dict)
        self.covered_kev_ids: set[str] = set()

    def add_record(self, record: dict[str, Any], through: bool) -> None:
        if str(record.get("status", "")).strip().casefold() == "rejected":
            return
        year = int(record["published"][:4])
        product_by_id = {item["id"]: item for item in record["products"]}
        categories = set(record["categories"]).intersection(CATEGORIES)
        keys = [f"category:{category}" for category in categories | {"All"}]
        keys.extend(f"product:{key}" for key in product_by_id if key in self.products)
        compact = compact_record(record)
        for key in keys:
            increment_classification(self.classification[key].setdefault(year, classification_counts()), record)
            if through:
                increment_classification(self.through_classification[key].setdefault(year, classification_counts()), record)
            scoped = compact
            if key.startswith("product:") and key.split(":", 1)[1] not in {p["id"] for p in compact["products"]}:
                scoped = {**compact, "products": [product_by_id[key.split(":", 1)[1]], *compact["products"][:19]]}
            if record["kev"]:
                self.kev[key].append(scoped)
            else:
                examples = self.examples[key]
                if len(examples) < EXAMPLE_LIMIT or example_order(record) > example_order(examples[-1]):
                    examples.append(scoped)
                    examples.sort(key=example_order, reverse=True)
                    del examples[EXAMPLE_LIMIT:]
        if record["kev"]:
            self.covered_kev_ids.add(record["id"])
        # Category product rankings use products of that type, with distinct
        # CVE counts; the entire product dictionary is eligible before caps.
        for item in product_by_id.values():
            category = item["category"]
            if category not in categories or item["id"] not in self.all_products:
                continue
            pair = (item["id"], year)
            increment_counts(self.category_counts[category].setdefault(pair, compact_counts()), record)
            if through:
                increment_counts(self.category_through_counts[category].setdefault(pair, compact_counts()), record)

    def add_supplemental(self, records: Iterable[dict[str, Any]]) -> None:
        exact = defaultdict(list)
        for key, product in self.products.items():
            exact[(normalized_name(product["vendor"]), normalized_name(product["name"]))].append(key)
        seen: set[str] = set()
        for record in records:
            if record["id"] in self.covered_kev_ids or record["id"] in seen:
                continue
            if str(record.get("status", "")).strip().casefold() == "rejected":
                continue
            seen.add(record["id"])
            compact = compact_record(record)
            advisory = record.get("kevDetails") or {}
            matching = set(exact.get((normalized_name(str(advisory.get("vendorProject", ""))),
                                      normalized_name(str(advisory.get("product", "")))), []))
            matching.update(item["id"] for item in record.get("products", []) if item["id"] in self.products)
            self.supplemental["category:All"].append({**compact, "reportMatch": "Catalog advisory outside covered NVD publication records"})
            for key in matching:
                self.supplemental[f"product:{key}"].append({**compact, "reportMatch": "Exact vendor/product or cached product identifier"})
            if record.get("categoryAuthority") != "unresolved":
                for category in set(record.get("categories", [])) - {"Unknown", "All"}:
                    if category in CATEGORIES:
                        self.supplemental[f"category:{category}"].append({**compact,
                            "reportMatch": "Supported category evidence; supplemental catalog advisory"})

    def top_products(self, category: str, year: int, through: bool = False) -> list[dict[str, Any]]:
        candidates = []
        if category == "All":
            for product in self.all_products.values():
                values = product.get("throughYears" if through else "years", {}).get(str(year))
                if values and values["total"]:
                    candidates.append({**{key: product[key] for key in ("id", "name", "vendor", "category")},
                                       **{key: value for key, value in stats_copy(values).items() if key != "insights"}})
        else:
            counts = self.category_through_counts if through else self.category_counts
            for (product_id, item_year), values in counts[category].items():
                if item_year == year and values[0]:
                    product = self.all_products[product_id]
                    candidates.append({**{key: product[key] for key in ("id", "name", "vendor")},
                                       "category": category, **unpack_counts(values)})
        return sorted(candidates, key=lambda item: (-item["total"], item["vendor"], item["name"]))[:10]

    def pack(self, key: str) -> dict[str, Any]:
        subject = self.subjects[key]
        result: dict[str, Any] = {"schemaVersion": 1, "subject": subject, "generatedAt": self.generated_at,
            "coverage": self.coverage, "comparisonWindow": self.window, "years": [],
            "relatedKev": sorted(self.kev[key], key=lambda r: (str((r.get("kevDetails") or {}).get("dateAdded", "")),
                                                                  example_order(r)), reverse=True),
            "supplementalKev": sorted(self.supplemental[key], key=lambda r: str((r.get("kevDetails") or {}).get("dateAdded", "")), reverse=True),
            "examples": self.examples[key],
            "methodology": {"relatedKev": "Complete matching KEV CVEs in the covered NVD publication records; not a top-30 sample.",
                "supplementalKev": "Separate legacy or CISA-only advisories with exact product attribution or supported category evidence. They do not increase NVD counts.",
                "examples": "Up to ten non-KEV CVEs ordered by selected CVSS base score descending, then publication date descending. This is not an organizational risk score.",
                "classification": "Counts reflect the CVE's published or inferred category evidence, including records without product type attribution.",
                "topProducts": "Distinct CVEs for affected products of the selected type; all cached product identities are eligible before selecting ten. Category counts can overlap.",
                "sourceDetails": "Descriptions retain up to 5,000 characters, product associations 20, and source references 30; sourceDetail discloses truncation. Full original details remain at NVD/CISA."}}
        for year, data in self.year_data.items():
            if subject["kind"] == "product":
                entity = self.products[subject["id"]]
                values = entity["years"].get(str(year), empty_stats())
                through_values = entity.get("throughYears", {}).get(str(year), empty_stats())
            else:
                category = subject["id"]
                values = data if category == "All" else data["categories"][category]
                through_values = data.get("through", {}) if category == "All" else data.get("through", {}).get("categories", {}).get(category, {})
            row = {"year": year, **stats_copy(values),
                   "classification": self.classification[key].get(year, classification_counts())}
            if self.window is not None:
                row["through"] = {**stats_copy(through_values),
                                  "classification": self.through_classification[key].get(year, classification_counts())}
            result["years"].append(row)
        if subject["kind"] == "category":
            result["topProducts"] = {str(year): self.top_products(subject["id"], year) for year in self.year_data}
            if self.window is not None:
                result["topProductsThrough"] = {str(year): self.top_products(subject["id"], year, True) for year in self.year_data}
        return result

    def write(self, stage: Any, writer: Callable[[Any, Any], None]) -> dict[str, dict[str, str]]:
        paths: dict[str, dict[str, str]] = {"products": {}, "categories": {}}
        for key, subject in self.subjects.items():
            group = "products" if subject["kind"] == "product" else "categories"
            relative = f"intel/{group}-{subject['id']}.json.gz"
            pack = self.pack(key)
            if len(json.dumps(pack, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")) > 8_000_000:
                raise ValueError(f"Report fact pack exceeds its 8 MB decoded limit: {subject['id']}")
            writer(stage / relative, pack)
            paths[group][subject["id"]] = relative
        return paths
