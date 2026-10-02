#!/usr/bin/env python3
"""Cache every NVD CVE in a publication range, then fetch changed records only.

No keyword, product, severity, or rejected-record filters are applied. Run the
same command again to resume a stopped backfill or refresh a complete cache.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from pipeline.cache import connect_db, get_meta, parse_time, set_meta, timestamp, upsert_cve, validate_cve
from pipeline.http import FetchError, JsonClient, NVD_API

PAGE_SIZE = 2000
WINDOW = timedelta(days=120)
OVERLAP = timedelta(minutes=10)
MILLISECOND = timedelta(milliseconds=1)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def make_state(phase: str, start: datetime, end: datetime) -> dict:
    return {"phase": phase, "window_start": timestamp(start), "window_end": timestamp(min(start + WINDOW - MILLISECOND, end)),
            "end": timestamp(end), "index": 0}


def validate_page(data: object, requested_index: int) -> list[dict]:
    if not isinstance(data, dict) or data.get("format") != "NVD_CVE" or data.get("version") != "2.0":
        raise ValueError("Unexpected NVD API format/version")
    for name in ("startIndex", "resultsPerPage", "totalResults"):
        if type(data.get(name)) is not int or data[name] < 0:
            raise ValueError(f"Invalid NVD pagination field: {name}")
    parse_time(data.get("timestamp"))
    items = data.get("vulnerabilities")
    if not isinstance(items, list) or data["startIndex"] != requested_index or data["resultsPerPage"] != len(items) or len(items) > PAGE_SIZE:
        raise ValueError("NVD page does not match the requested pagination")
    if items and requested_index + len(items) > data["totalResults"]:
        raise ValueError("NVD page exceeds totalResults")
    if not items and requested_index < data["totalResults"]:
        raise ValueError("NVD returned an empty page before the end of its results")
    cves = []
    identifiers = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Invalid NVD vulnerability wrapper")
        cve = item.get("cve")
        validate_cve(cve)
        if cve["id"] in identifiers:
            raise ValueError("NVD returned duplicate identifiers within a page")
        identifiers.add(cve["id"])
        cves.append(cve)
    return cves


def sync_nvd(db: sqlite3.Connection, *, start_year: int = 2020, end_year: int = 2026,
             max_pages: int | None = None, client: JsonClient | None = None, now=None, progress=print) -> dict:
    """Fetch bounded date windows. Each validated page and cursor commit atomically."""
    if not 1900 <= start_year <= end_year <= 9998:
        raise ValueError("Years must satisfy 1900 <= start-year <= end-year <= 9998")
    if max_pages is not None and max_pages < 1:
        raise ValueError("max-pages must be positive")
    now = now or utc_now
    run_start = parse_time(timestamp(now()))
    range_start = datetime(start_year, 1, 1, tzinfo=timezone.utc)
    range_end = datetime(end_year + 1, 1, 1, tzinfo=timezone.utc) - MILLISECOND
    if range_start > run_start:
        raise ValueError("The publication range starts in the future")
    configured_start = get_meta(db, "nvd_range_start")
    configured_end = get_meta(db, "nvd_range_end")
    extend_range = configured_start is not None and configured_end != timestamp(range_end)
    if configured_start and configured_start != timestamp(range_start):
        raise ValueError("This cache already uses a different start year; use a new --db for a different start year")
    if extend_range and (parse_time(configured_end) > range_end or not get_meta(db, "nvd_bootstrap_complete", False) or get_meta(db, "nvd_sync_state") is not None):
        raise ValueError("Complete the current sync before extending end-year; shrinking a cached range requires a new --db")
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    client = client or JsonClient(min_interval=0.7 if api_key else 6.1)
    state = get_meta(db, "nvd_sync_state")
    if configured_start is None or extend_range:
        bootstrap_end = min(run_start, range_end)
        publication_start = parse_time(configured_end) + MILLISECOND if extend_range else range_start
        if publication_start > bootstrap_end:
            raise ValueError("The additional publication years start in the future")
        state = make_state("publication", publication_start, bootstrap_end)
        catchup_start = get_meta(db, "nvd_last_sync", timestamp(run_start)) if extend_range else timestamp(run_start)
        with db:
            set_meta(db, "nvd_range_start", timestamp(range_start))
            set_meta(db, "nvd_range_end", timestamp(range_end))
            set_meta(db, "nvd_coverage_start", timestamp(range_start))
            if not extend_range:
                set_meta(db, "nvd_coverage_end", None)
            set_meta(db, "nvd_bootstrap_start", timestamp(run_start))
            set_meta(db, "nvd_bootstrap_catchup_start", catchup_start)
            set_meta(db, "nvd_bootstrap_end", timestamp(bootstrap_end))
            set_meta(db, "nvd_bootstrap_complete", False)
            set_meta(db, "nvd_sync_state", state)
    elif state is None:
        if not get_meta(db, "nvd_bootstrap_complete", False):
            raise ValueError("Incomplete cache is missing its resume checkpoint")
        last_sync = parse_time(get_meta(db, "nvd_last_sync"))
        state = make_state("incremental", max(range_start, last_sync - OVERLAP), run_start)
        if parse_time(state["window_start"]) > run_start:
            raise ValueError("Cache sync watermark is ahead of the current UTC time")
        with db:
            set_meta(db, "nvd_sync_state", state)

    stats = {"pages": 0, "received": 0, "changed": 0, "complete": False}
    while state is not None:
        if max_pages is not None and stats["pages"] >= max_pages:
            break
        phase = state["phase"]
        if phase not in ("publication", "catchup", "incremental") or type(state["index"]) is not int or state["index"] < 0:
            raise ValueError("Invalid cache resume checkpoint")
        window_start, window_end = parse_time(state["window_start"]), parse_time(state["window_end"])
        if window_start > window_end or window_end - window_start >= WINDOW:
            raise ValueError("Invalid cache date-window checkpoint")
        prefix = "pub" if phase == "publication" else "lastMod"
        params = {prefix + "StartDate": timestamp(window_start), prefix + "EndDate": timestamp(window_end),
                  "resultsPerPage": PAGE_SIZE, "startIndex": state["index"]}
        progress(f"NVD {phase}: {params[prefix + 'StartDate']} to {params[prefix + 'EndDate']} (offset {state['index']})")
        response = client.get(NVD_API + "?" + urlencode(params), headers=headers)
        if response.status != 200:
            raise FetchError("NVD returned an unexpected response status")
        records = validate_page(response.data, state["index"])
        date_field = "published" if phase == "publication" else "lastModified"
        if any(not window_start <= parse_time(record[date_field]) <= window_end for record in records):
            raise ValueError("NVD returned a record outside the requested date window")
        next_index = state["index"] + len(records)
        window_finished = next_index >= response.data["totalResults"]
        next_state = dict(state, index=next_index)
        finished_sync = False
        if window_finished:
            target_end = parse_time(state["end"])
            if window_end < target_end:
                next_state = make_state(phase, window_end + MILLISECOND, target_end)
            elif phase == "publication":
                # Include changes/new historical records that arrived during backfill.
                catchup_start = max(range_start, parse_time(get_meta(db, "nvd_bootstrap_catchup_start", get_meta(db, "nvd_bootstrap_start"))) - OVERLAP)
                catchup_end = max(parse_time(timestamp(now())), catchup_start)
                next_state = make_state("catchup", catchup_start, catchup_end)
            else:
                next_state = None
                finished_sync = True
        changed = 0
        with db:
            for record in records:
                # lastModified requests may include CVEs published before/after our requested coverage.
                if range_start <= parse_time(record["published"]) <= range_end:
                    changed += upsert_cve(db, record)
            set_meta(db, "nvd_sync_state", next_state)
            if window_finished and phase == "publication":
                set_meta(db, "nvd_coverage_end", timestamp(window_end))
            elif window_finished:
                set_meta(db, "nvd_last_sync", timestamp(window_end))
                set_meta(db, "nvd_coverage_end", timestamp(min(window_end, range_end)))
            if finished_sync:
                set_meta(db, "nvd_bootstrap_complete", True)
        state = next_state
        stats["pages"] += 1
        stats["received"] += len(records)
        stats["changed"] += changed
    stats["complete"] = state is None and get_meta(db, "nvd_bootstrap_complete", False)
    progress(f"NVD: {stats['pages']} pages, {stats['received']} received, {stats['changed']} new/changed; {'complete' if stats['complete'] else 'checkpoint saved; rerun to continue'}")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="cache/vulnerabilities.sqlite3", help="Persistent SQLite cache")
    parser.add_argument("--start-year", type=int, default=2020)
    parser.add_argument("--end-year", type=int, default=2026)
    parser.add_argument("--max-pages", type=int, help="Stop normally after this many requests; rerun to resume")
    args = parser.parse_args()
    db = None
    try:
        db = connect_db(args.db)
        sync_nvd(db, start_year=args.start_year, end_year=args.end_year, max_pages=args.max_pages)
    except (FetchError, ValueError, sqlite3.Error) as exc:
        print(f"NVD sync failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("NVD sync interrupted; committed checkpoints are safe. Rerun the same command.", file=sys.stderr)
        return 130
    finally:
        if db is not None:
            db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
