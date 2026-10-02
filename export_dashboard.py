#!/usr/bin/env python3
"""Export a consistent SQLite cache snapshot as static dashboard JSON.

Run the ingestion pipeline before publishing. Incomplete backfills require the
explicit --allow-incomplete flag, which is intended for local smoke checks.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
from typing import Any, Callable, Iterator
from urllib.parse import quote, unquote, urlsplit

from pipeline.classification import CLASSIFICATION_VERSION, ProductTaxonomy, classify_cve
from pipeline.insights import comparison_window, increment_insights, insight_stats, record_insights, within_comparison
from pipeline.report_data import ReportFactPacks


SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")
CATEGORIES = ("OS", "Application", "Hardware", "Unknown")
SHARD_SIZE = 1000
PUBLISHERS_LIMIT = 250
PRODUCTS_LIMIT = 500


class ExportError(RuntimeError):
    """A cache or publication problem that must not publish partial output."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def stats(with_insights: bool = False) -> dict[str, Any]:
    result = {
        "total": 0,
        "critical": 0,
        "kev": 0,
        "severity": dict.fromkeys(SEVERITIES, 0),
        "kevSeverity": dict.fromkeys(SEVERITIES, 0),
    }
    if with_insights:
        result["insights"] = insight_stats()
    return result


def increment(target: dict[str, Any], severity: str, is_kev: bool,
              record: dict[str, Any] | None = None) -> None:
    target["total"] += 1
    target["critical"] += int(severity == "Critical")
    target["kev"] += int(is_kev)
    target["severity"][severity] += 1
    if is_kev:
        target["kevSeverity"][severity] += 1
    if record is not None and "insights" in target:
        increment_insights(target["insights"], record)


def split_cpe(value: str) -> list[str]:
    """Split formatted CPE fields while honoring escaped colons/backslashes."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        raise ValueError("CPE ends with an incomplete escape")
    fields.append("".join(current))
    return fields


def parse_cpe(value: Any) -> tuple[str, str, str] | None:
    if not isinstance(value, str):
        return None
    try:
        fields = split_cpe(value)
    except ValueError:
        return None
    if fields[:2] == ["cpe", "2.3"] and len(fields) == 13:
        part, vendor, product = fields[2:5]
    elif fields and fields[0] == "cpe" and len(fields) >= 4 and fields[1].startswith("/"):
        part, vendor, product = fields[1][1:], unquote(fields[2]), unquote(fields[3])
    else:
        return None
    if vendor in ("", "*", "-") or product in ("", "*", "-"):
        return None
    vendor = vendor.casefold().replace("_", " ")
    product = product.casefold().replace("_", " ")
    category = {"a": "Application", "o": "OS", "h": "Hardware"}.get(part, "Unknown")
    return vendor, product, category


def extract_products(cve: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    """Include only vulnerable matches, including those in nested AND/OR nodes."""
    pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    pending: list[Any] = list(cve.get("configurations") or [])
    while pending:
        node = pending.pop()
        if not isinstance(node, dict):
            continue
        for match in node.get("cpeMatch") or []:
            if not isinstance(match, dict) or match.get("vulnerable") is not True:
                continue
            parsed = parse_cpe(match.get("criteria", match.get("cpe23Uri")))
            if parsed:
                vendor, product, category = parsed
                pairs[(vendor, product)].add(category)
        for key in ("nodes", "children"):
            children = node.get(key)
            if isinstance(children, list):
                pending.extend(children)
    products = []
    for (vendor, name), categories in sorted(pairs.items()):
        # A vendor/product mapped to several CPE parts cannot honestly receive
        # a single known category. Keep it once and expose the ambiguity.
        category = next(iter(categories)) if len(categories) == 1 else "Unknown"
        product_id = hashlib.sha256(f"{vendor}\0{name}".encode("utf-8")).hexdigest()[:24]
        products.append({"id": product_id, "name": name, "vendor": vendor, "category": category})
    return sorted({vendor for vendor, _ in pairs}), products


def extract_cvss(cve: dict[str, Any]) -> tuple[str, float | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    if not isinstance(metrics, dict):
        return "Unknown", None, None, None
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        candidates = [item for item in (metrics.get(key) or []) if isinstance(item, dict)]
        candidates.sort(key=lambda item: (
            not (item.get("type") == "Primary" and item.get("source") == "nvd@nist.gov"),
            item.get("type") != "Primary", item.get("source") != "nvd@nist.gov",
        ))
        for item in candidates:
            data = item.get("cvssData") or {}
            if not isinstance(data, dict):
                continue
            raw_score = data.get("baseScore")
            if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
                continue
            score = float(raw_score)
            if not math.isfinite(score) or not 0 <= score <= 10:
                continue
            if version != "2.0" and score >= 9:
                severity = "Critical"
            elif score >= 7:
                severity = "High"
            elif score >= 4:
                severity = "Medium"
            else:
                severity = "Low"
            vector = data.get("vectorString")
            return severity, score, version, vector if isinstance(vector, str) else None
    return "Unknown", None, None, None


def safe_https_url(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 8192:
        return False
    if any(char.isspace() or ord(char) < 32 or char == "\\" for char in value):
        return False
    try:
        parts = urlsplit(value)
        return (parts.scheme.lower() == "https" and bool(parts.hostname)
                and parts.username is None and parts.password is None
                and (parts.port is None or 0 < parts.port <= 65535))
    except ValueError:
        return False


def record_from_cve(cve_id: str, cve: dict[str, Any], published: str,
                    modified: str, kev: dict[str, Any] | None,
                    taxonomy: ProductTaxonomy | None = None,
                    cpe_products: list[dict[str, str]] | None = None,
                    valid_cwes: set[str] | None = None) -> dict[str, Any]:
    descriptions = [item for item in (cve.get("descriptions") or []) if isinstance(item, dict)]
    english = [item for item in descriptions if item.get("lang") == "en"]
    description = next((item["value"] for item in (english or descriptions)
                        if isinstance(item.get("value"), str) and item["value"]), "")
    severity, score, version, vector = extract_cvss(cve)
    products = extract_products(cve)[1] if cpe_products is None else cpe_products
    classification = classify_cve(cve, products, description, kev, taxonomy, parse_cpe)
    references = sorted({item["url"] for item in (cve.get("references") or [])
                         if isinstance(item, dict) and safe_https_url(item.get("url"))})
    weaknesses = sorted({description["value"]
                         for item in (cve.get("weaknesses") or []) if isinstance(item, dict)
                         for description in (item.get("description") or [])
                         if isinstance(description, dict)
                         and isinstance(description.get("value"), str)
                         and re.fullmatch(r"CWE-\d+|NVD-CWE-noinfo|NVD-CWE-Other", description["value"])})
    return {
        "id": cve_id, "description": description, "published": published,
        "modified": modified, "status": cve.get("vulnStatus") or "Unknown",
        "severity": severity, "score": score, "cvssVersion": version, "vector": vector,
        **classification, "kev": kev is not None,
        "kevDetails": kev, "references": references, "weaknesses": weaknesses,
        "insights": record_insights(weaknesses, version, vector, valid_cwes),
    }


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def write_record_shard(path: Path, data: Any) -> None:
    """Keep complete records compact with reproducible gzip headers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    with path.open("wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, compresslevel=6, mtime=0) as compressed:
            compressed.write(payload + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def coverage_years(metadata: dict[str, Any]) -> tuple[int, ...]:
    """The ingestion range timestamps are inclusive, including the end year."""
    start = metadata.get("nvd_range_start") or "2020-01-01T00:00:00Z"
    end = metadata.get("nvd_range_end") or "2026-12-31T23:59:59.999Z"
    try:
        first = datetime.fromisoformat(start.replace("Z", "+00:00")).year
        last = datetime.fromisoformat(end.replace("Z", "+00:00")).year
    except (AttributeError, TypeError, ValueError) as error:
        raise ExportError("Invalid configured NVD coverage timestamps") from error
    if first > last or last >= 9999:
        raise ExportError("Invalid configured NVD coverage year range")
    return tuple(range(first, last + 1))


def parse_payload(raw: Any, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise ExportError(f"Invalid cached JSON for {label}") from error
    if not isinstance(payload, dict):
        raise ExportError(f"Expected a JSON object for {label}")
    return payload


def read_metadata(connection: sqlite3.Connection) -> dict[str, Any]:
    metadata = {}
    for key, raw in connection.execute("SELECT key, value FROM metadata"):
        try:
            metadata[key] = json.loads(raw)
        except (TypeError, ValueError) as error:
            raise ExportError(f"Invalid metadata JSON for {key}") from error
    return metadata


def ranking(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    items.sort(key=lambda item: (-sum(year["total"] for year in item["years"].values()),
                                 item["name"], item.get("vendor", "")))
    return items[:limit]


def is_rejected(cve: dict[str, Any]) -> bool:
    status = cve.get("vulnStatus")
    return isinstance(status, str) and status.strip().casefold() == "rejected"


def product_taxonomy(connection: sqlite3.Connection | None,
                     rejected_ids: set[str] | None = None) -> ProductTaxonomy:
    """Build a category consensus from every explicitly vulnerable cached CPE.

    Exact vendor/product pairs only; conflicting types are kept in the lookup
    so a later CNA record cannot inherit a misleading category.
    """
    taxonomy = ProductTaxonomy()
    if connection:
        for cve_id, payload in connection.execute("SELECT cve_id, payload FROM cves"):
            cve = parse_payload(payload, cve_id)
            if is_rejected(cve):
                if rejected_ids is not None:
                    rejected_ids.add(cve_id)
                continue
            _, products = extract_products(cve)
            for item in products:
                taxonomy.add(item["vendor"], item["name"], item["category"])
    return taxonomy


def weakness_labels() -> dict[str, Any]:
    path = Path(__file__).resolve().parent / "pipeline" / "cwe_names.json"
    try:
        labels = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ExportError("The bundled MITRE CWE weakness catalog is missing or invalid") from error
    if not isinstance(labels, dict) or not isinstance(labels.get("names"), dict):
        raise ExportError("The bundled MITRE CWE weakness catalog has an invalid schema")
    if any(not re.fullmatch(r"CWE-[1-9]\d{0,5}", key) or not isinstance(value, str)
           for key, value in labels["names"].items()):
        raise ExportError("The bundled MITRE CWE weakness catalog contains invalid labels")
    # Include license and attribution with the published label dataset.
    return labels


def add_entity_insights(stage: Path, year_data: dict[int, dict[str, Any]],
                        publishers: list[dict[str, Any]], products: list[dict[str, Any]],
                        window: dict[str, Any] | None, reports: ReportFactPacks | None = None) -> None:
    """Aggregate retained rankings from bounded shards instead of all 100k+ products.

All entities keep complete counts before ranking. Only published entities need
the more detailed CWE bins; loading one shard at a time bounds memory usage.
"""
    publisher_lookup = {item["name"]: item for item in publishers}
    product_lookup = {item["id"]: item for item in products}
    for item in publishers + products:
        for values in item["years"].values():
            values["insights"] = insight_stats()
        for values in item.get("throughYears", {}).values():
            values["insights"] = insight_stats()
    for year in year_data.values():
        for month in year["months"]:
            for relative in month["paths"]:
                with gzip.open(stage / relative, "rt", encoding="utf-8") as handle:
                    records = json.load(handle)["records"]
                for record in records:
                    key = str(record["published"][:4])
                    through = window is not None and within_comparison(record["published"], window)
                    if reports is not None:
                        reports.add_record(record, through)
                    entities = [publisher_lookup[name] for name in set(record["vendors"])
                                if name in publisher_lookup]
                    entities.extend(product_lookup[item_id] for item_id in {p["id"] for p in record["products"]}
                                    if item_id in product_lookup)
                    for entity in entities:
                        increment_insights(entity["years"][key]["insights"], record)
                        if through:
                            increment_insights(entity["throughYears"][key]["insights"], record)


def classification_stats() -> dict[str, Any]:
    return {"version": CLASSIFICATION_VERSION, "authoritative": 0, "inferred": 0, "unresolved": 0,
            "methods": dict.fromkeys(("cpe", "affected", "kev", "description", "unresolved"), 0),
            "unresolvedByStatus": {}, "remainingUnknownByStatus": {},
            "previouslyUnclassified": 0, "recovered": 0, "fullyRecovered": 0,
            "remainingUnknown": 0, "partiallyClassified": 0}


def increment_classification(target: dict[str, Any], record: dict[str, Any],
                             previously_unknown: bool) -> None:
    target[record["categoryAuthority"]] += 1
    target["methods"][record["categoryMethod"]] += 1
    target["previouslyUnclassified"] += int(previously_unknown)
    target["recovered"] += int(previously_unknown and record["categoryMethod"] != "cpe" and
                              record["categoryAuthority"] != "unresolved")
    target["fullyRecovered"] += int(previously_unknown and "Unknown" not in record["categories"])
    if record["categoryAuthority"] == "unresolved":
        status = str(record["status"])
        target["unresolvedByStatus"][status] = target["unresolvedByStatus"].get(status, 0) + 1
    if "Unknown" in record["categories"]:
        target["remainingUnknown"] += 1
        target["partiallyClassified"] += int(len(record["categories"]) > 1)
        status = str(record["status"])
        target["remainingUnknownByStatus"][status] = target["remainingUnknownByStatus"].get(status, 0) + 1


def build_snapshot(connection: sqlite3.Connection | None, stage: Path,
                   allow_incomplete: bool) -> dict[str, Any]:
    metadata = read_metadata(connection) if connection else {}
    complete = metadata.get("nvd_bootstrap_complete") is True
    if not complete and not allow_incomplete:
        raise ExportError("NVD bootstrap is incomplete. Finish ingestion before publishing; "
                          "use --allow-incomplete only for local previews.")
    generated_at = utc_now()
    years = coverage_years(metadata)
    labels = weakness_labels()
    valid_cwes = set(labels["names"])
    try:
        window = comparison_window(metadata.get("nvd_coverage_end"))
    except (AttributeError, TypeError, ValueError) as error:
        raise ExportError("Invalid NVD coverage end timestamp") from error
    kev = {cve_id: parse_payload(payload, cve_id)
           for cve_id, payload in connection.execute("SELECT cve_id, payload FROM kev")} if connection else {}
    rejected_ids: set[str] = set()
    taxonomy = product_taxonomy(connection, rejected_ids)
    catalog_excluded_rejected = len(rejected_ids.intersection(kev))
    kev = {cve_id: advisory for cve_id, advisory in kev.items() if cve_id not in rejected_ids}
    excluded_rejected = 0
    classification = classification_stats()
    year_data = {year: {
        "year": year, **stats(True),
        "classification": classification_stats(),
        "categories": {category: stats(True) for category in CATEGORIES},
        "months": [{"month": f"{year}-{month:02}", "count": 0, "paths": []} for month in range(1, 13)],
    } for year in years}
    if window is not None:
        for year in year_data.values():
            year["through"] = {**stats(True), "categories": {category: stats(True) for category in CATEGORIES}}
    publishers: dict[str, dict[str, Any]] = {}
    products: dict[str, dict[str, Any]] = {}
    priority_records: dict[str, dict[str, Any]] = {}
    current_month: str | None = None
    shard: list[dict[str, Any]] = []
    shard_number = 0

    def flush_shard() -> None:
        nonlocal shard, shard_number
        if not shard or current_month is None:
            return
        shard_number += 1
        relative = f"records/{current_month}-{shard_number:04}.json.gz"
        write_record_shard(stage / relative, {"schemaVersion": 1, "month": current_month, "records": shard})
        year, month = map(int, current_month.split("-"))
        year_data[year]["months"][month - 1]["paths"].append(relative)
        shard = []

    rows: Iterator[Any] = iter(connection.execute(
        "SELECT cve_id, published, modified, payload FROM cves "
        "WHERE published >= ? AND published < ? ORDER BY published DESC, modified DESC, cve_id",
        (f"{years[0]:04}-01-01", f"{years[-1] + 1:04}-01-01"),
    )) if connection else iter(())
    for cve_id, published, modified, payload in rows:
        if not isinstance(published, str) or not re.match(r"^\d{4}-\d{2}-\d{2}(?:T|$)", published):
            raise ExportError(f"Invalid publication timestamp for {cve_id}")
        try:
            datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError as error:
            raise ExportError(f"Invalid publication timestamp for {cve_id}") from error
        raw_cve = parse_payload(payload, cve_id)
        if is_rejected(raw_cve):
            excluded_rejected += 1
            continue
        month = published[:7]
        year = int(published[:4])
        if month != current_month:
            flush_shard()
            current_month, shard_number = month, 0
        _, original_products = extract_products(raw_cve)
        previously_unknown = not original_products or any(item["category"] == "Unknown" for item in original_products)
        record = record_from_cve(cve_id, raw_cve, published, modified or "", kev.get(cve_id),
                                 taxonomy, original_products, valid_cwes)
        increment_classification(classification, record, previously_unknown)
        increment_classification(year_data[year]["classification"], record, previously_unknown)
        severity, is_kev = record["severity"], record["kev"]
        through = window is not None and within_comparison(published, window)
        increment(year_data[year], severity, is_kev, record)
        if through:
            increment(year_data[year]["through"], severity, is_kev, record)
        year_data[year]["months"][int(month[5:]) - 1]["count"] += 1
        for category in set(record["categories"]):
            increment(year_data[year]["categories"][category], severity, is_kev, record)
            if through:
                increment(year_data[year]["through"]["categories"][category], severity, is_kev, record)
        for name in set(record["vendors"]):
            publisher = publishers.setdefault(name, {"name": name, "years": {}})
            increment(publisher["years"].setdefault(str(year), stats()), severity, is_kev)
            if window is not None:
                values = publisher.setdefault("throughYears", {}).setdefault(str(year), stats())
                if through:
                    increment(values, severity, is_kev)
        for item in {item["id"]: item for item in record["products"]}.values():
            product = products.setdefault(item["id"], {**item, "years": {}})
            if product["category"] != item["category"]:
                product["category"] = "Unknown"
            increment(product["years"].setdefault(str(year), stats()), severity, is_kev)
            if window is not None:
                values = product.setdefault("throughYears", {}).setdefault(str(year), stats())
                if through:
                    increment(values, severity, is_kev)
        if is_kev:
            record["nvdCached"] = True
            priority_records[cve_id] = record
        shard.append(record)
        if len(shard) == SHARD_SIZE:
            flush_shard()
    flush_shard()
    ranked_publishers = ranking(list(publishers.values()), PUBLISHERS_LIMIT)
    ranked_products = ranking(list(products.values()), PRODUCTS_LIMIT)
    coverage = {
        "start": metadata.get("nvd_coverage_start") or metadata.get("nvd_range_start") or "2020-01-01T00:00:00Z",
        "end": metadata.get("nvd_coverage_end"), "nvdLastSync": metadata.get("nvd_last_sync"),
        "kevLastSync": metadata.get("kev_last_sync"), "bootstrapComplete": complete,
    }
    reports = ReportFactPacks(ranked_products, products, year_data, generated_at, coverage, window)
    add_entity_insights(stage, year_data, ranked_publishers, ranked_products, window, reports)
    # Tactical candidates include the complete KEV catalog, including legacy
    # advisories without an NVD record in this publication-year cache.
    for cve_id, advisory in kev.items():
        if cve_id in priority_records:
            continue
        cached = connection.execute("SELECT published, modified, payload FROM cves WHERE cve_id = ?",
                                    (cve_id,)).fetchone() if connection else None
        if cached is not None:
            published, modified, payload = cached
            raw = parse_payload(payload, cve_id)
            candidate = record_from_cve(cve_id, raw, published, modified or "", advisory, taxonomy,
                                       valid_cwes=valid_cwes)
            candidate["nvdCached"] = True
        else:
            raw = {"descriptions": [{"lang": "en", "value": advisory.get("shortDescription", "")}]}
            candidate = record_from_cve(cve_id, raw, "", "", advisory, taxonomy, valid_cwes=valid_cwes)
            candidate["nvdCached"] = False
        priority_records[cve_id] = candidate
    reports.add_supplemental(priority_records.values())
    try:
        report_paths = reports.write(stage, write_record_shard)
    except ValueError as error:
        raise ExportError(str(error)) from error
    tactical = sorted(priority_records.values(), key=lambda record: (
        str(record["kevDetails"].get("dateAdded", "")),
        record["score"] if record["score"] is not None else -1,
        record["id"],
    ), reverse=True)[:30]
    summary = {
        "schemaVersion": 1, "generatedAt": generated_at,
        "coverage": coverage,
        "totalCves": sum(item["total"] for item in year_data.values()),
        "totalKev": sum(item["kev"] for item in year_data.values()),
        "catalogKev": len(kev),
        "excludedRejected": excluded_rejected,
        "catalogExcludedRejected": catalog_excluded_rejected,
        "recordCompression": "gzip",
        "reportPaths": report_paths,
        "comparisonWindow": window,
        "weaknessLabels": labels,
        "insightMethodology": {
            "bins": [*SEVERITIES, *(f"KEV {severity}" for severity in SEVERITIES)],
            "causes": "Reported CWE weakness types; not proven incident root causes. Multiple types can overlap.",
            "impacts": "Potential confidentiality, integrity, and availability impact from the selected base CVSS vector. "
                       "Missing or invalid vectors are unknown; multiple impacts can overlap.",
            "remoteUnauthenticated": "Network attack vector and no required privileges/authentication; "
                                     "does not imply no user interaction or prerequisites.",
        },
        "priorityRecords": tactical,
        "priorityRecordsCount": len(priority_records),
        "priorityRecordsScope": "Current KEV catalog, excluding known rejected CVEs; newest dateAdded first, then CVSS score. "
                                "NVD details are included when cached; legacy records can have unknown metrics.",
        "classification": classification,
        "years": list(year_data.values()),
        "publishers": ranked_publishers,
        "products": ranked_products,
        "rankingsLimit": {
            "publishers": PUBLISHERS_LIMIT, "products": PRODUCTS_LIMIT,
            "totalPublishers": len(publishers), "totalProducts": len(products),
            "order": "Total distinct CVEs across all covered years, descending",
            "note": "Rankings are capped; monthly records retain all CVEs and products. "
                    "Publisher and product totals can overlap; category totals deduplicate CVEs "
                    "within each category and can overlap across categories.",
        },
    }
    write_json(stage / "kev.json", {
        "schemaVersion": 1, "generatedAt": generated_at,
        "catalogVersion": metadata.get("kev_catalog_version"),
        "dateReleased": metadata.get("kev_date_released"),
        "vulnerabilities": [kev[cve_id] for cve_id in sorted(kev)],
    })
    write_json(stage / "summary.json", summary)
    write_record_shard(stage / "summary.json.gz", summary)
    return summary


@contextmanager
def publication_lock(path: Path) -> Iterator[None]:
    """Advisory OS locks automatically release even if the exporter crashes."""
    with path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ExportError("Another exporter is publishing to this output directory") from error
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def retry_filesystem(operation: Callable[[], None]) -> None:
    """OneDrive/Windows may briefly retain directory handles after a rename."""
    delays = (0.1, 0.25, 0.5, 1.0)
    for attempt in range(len(delays) + 1):
        try:
            operation()
            return
        except OSError as error:
            transient = isinstance(error, PermissionError) or getattr(error, "winerror", None) in (5, 32, 33)
            if not transient or attempt == len(delays):
                raise
            time.sleep(delays[attempt])


def replace_directory(source: Path, destination: Path) -> None:
    def replace() -> None:
        try:
            os.replace(source, destination)
        except PermissionError:
            # OneDrive can mark our generated directories read-only. Resolve
            # and verify the exact source before clearing that attribute.
            if os.name == "nt" and source.exists():
                if source.is_symlink() or source.resolve() != source.absolute():
                    raise ExportError("Refusing to change an unsafe export source")
                source.chmod(source.stat().st_mode | stat.S_IWRITE)
            raise
    retry_filesystem(replace)


def checked_remove(directory: Path, parent: Path) -> None:
    resolved = directory.resolve()
    if directory.is_symlink() or resolved != directory.absolute() or resolved.parent != parent:
        raise ExportError(f"Refusing to remove an unsafe export directory: {directory}")

    def remove_readonly(function: Callable[..., Any], filename: str, info: Any) -> None:
        error = info[1]
        candidate = Path(filename)
        target = candidate.resolve()
        if candidate.is_symlink() or not target.is_relative_to(resolved):
            raise ExportError(f"Refusing to change permissions outside the export directory: {candidate}")
        if isinstance(error, FileNotFoundError):
            return
        if not (isinstance(error, PermissionError) or getattr(error, "winerror", None) in (5, 32, 33)):
            raise error
        # chmod on Windows clears the read-only attribute. Every target above
        # has been resolved and checked against the directory being removed.
        candidate.chmod(candidate.stat().st_mode | stat.S_IWRITE)
        if function in (os.unlink, os.remove, os.rmdir):
            function(filename)
        else:
            # Retrying scandir/open directly would skip the directory walk;
            # restart rmtree under the bounded outer retry instead.
            raise error

    def remove_tree() -> None:
        if directory.exists():
            shutil.rmtree(directory, onerror=remove_readonly)

    retry_filesystem(remove_tree)


def export_dashboard(db: Path | str, output: Path | str,
                     allow_incomplete: bool = False) -> dict[str, Any]:
    db = Path(db).resolve()
    requested_output = Path(output).absolute()
    if requested_output.is_symlink():
        raise ExportError("Output must be a real directory, not a symbolic link")
    output = requested_output.resolve()
    parent = output.parent
    if output == parent or db == output or output in db.parents:
        raise ExportError("Output cannot be a filesystem root or contain the SQLite cache")
    if output.exists() and not output.is_dir():
        raise ExportError("Output exists and is not a directory")
    parent.mkdir(parents=True, exist_ok=True)
    backup = parent / f".{output.name}-backup"
    lock = parent / f".{output.name}-export.lock"
    with publication_lock(lock):
        # Recover a snapshot interrupted between the two directory renames.
        if backup.exists():
            if backup.is_symlink() or not backup.is_dir():
                raise ExportError("Unsafe backup directory prevents publication")
            if not output.exists():
                replace_directory(backup, output)
            else:
                checked_remove(backup, parent)
        stage = Path(tempfile.mkdtemp(prefix=f".{output.name}-stage-", dir=parent))
        connection: sqlite3.Connection | None = None
        try:
            if db.exists():
                uri = "file:" + quote(db.as_posix(), safe="/:") + "?mode=ro"
                connection = sqlite3.connect(uri, uri=True)
                connection.execute("BEGIN")
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {"cves", "kev", "metadata"}.issubset(tables):
                    if not tables and allow_incomplete:
                        connection.close()
                        connection = None
                    else:
                        raise ExportError("Cache schema is missing; run ingestion first")
            elif not allow_incomplete:
                raise ExportError("Cache does not exist; run ingestion first")
            summary = build_snapshot(connection, stage, allow_incomplete)
            if connection:
                connection.close()
                connection = None
            if output.exists():
                replace_directory(output, backup)
            try:
                replace_directory(stage, output)
            except BaseException:
                if backup.exists() and not output.exists():
                    replace_directory(backup, output)
                raise
            if backup.exists():
                checked_remove(backup, parent)
            return summary
        finally:
            if connection:
                connection.close()
            if stage.exists():
                checked_remove(stage, parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("cache/vulnerabilities.sqlite3"))
    parser.add_argument("--output", type=Path, default=Path("public/data"))
    parser.add_argument("--allow-incomplete", action="store_true",
                        help="Export honest partial/empty data for local previews only")
    args = parser.parse_args(argv)
    try:
        summary = export_dashboard(args.db, args.output, args.allow_incomplete)
    except (ExportError, sqlite3.Error, OSError) as error:
        print(f"Export failed: {error}", file=sys.stderr)
        return 1
    print(f"Exported {summary['totalCves']:,} CVEs and {summary['catalogKev']:,} "
          f"catalog KEV records to {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
