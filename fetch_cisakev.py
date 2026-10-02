#!/usr/bin/env python3
"""Cache the full CISA Known Exploited Vulnerabilities catalog without product filters.

CISA publishes a complete catalog, not a delta API. Conditional HTTP avoids
unchanged downloads; payload hashes avoid rewriting unchanged advisories.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timezone

from pipeline.cache import connect_db, get_meta, parse_time, set_meta, timestamp, upsert_kev, validate_kev
from pipeline.http import CISA_FEED, FetchError, JsonClient


def validate_catalog(data: object) -> list[dict]:
    if not isinstance(data, dict) or not isinstance(data.get("catalogVersion"), str) or not data["catalogVersion"]:
        raise ValueError("Invalid CISA KEV catalog version")
    parse_time(data.get("dateReleased"))
    entries = data.get("vulnerabilities")
    if not isinstance(entries, list) or type(data.get("count")) is not int or data["count"] != len(entries):
        raise ValueError("CISA KEV catalog count does not match its entries")
    # Reject a truncated/empty feed before destructive removal reconciliation.
    if not entries:
        raise ValueError("CISA KEV catalog is unexpectedly empty")
    seen = set()
    for item in entries:
        validate_kev(item)
        if item["cveID"] in seen:
            raise ValueError("CISA KEV catalog contains duplicate identifiers")
        seen.add(item["cveID"])
    return entries


def sync_kev(db: sqlite3.Connection, *, client: JsonClient | None = None, now=None, progress=print) -> dict:
    now = now or (lambda: datetime.now(timezone.utc))
    started = timestamp(now())
    client = client or JsonClient()
    headers = {}
    for key, header in (("kev_etag", "If-None-Match"), ("kev_last_modified", "If-Modified-Since")):
        value = get_meta(db, key)
        if value:
            headers[header] = value
    # A missing table must never accept a 304 just because stale validators exist.
    has_cache = db.execute("SELECT EXISTS(SELECT 1 FROM kev)").fetchone()[0]
    if not has_cache:
        headers = {}
    response = client.get(CISA_FEED, headers=headers)
    if response.status == 304:
        if not has_cache:
            raise FetchError("CISA returned not-modified without an existing cached catalog")
        with db:
            set_meta(db, "kev_last_sync", started)
        progress("CISA KEV: catalog unchanged (HTTP 304)")
        return {"received": 0, "changed": 0, "removed": 0, "not_modified": True}
    if response.status != 200:
        raise FetchError("CISA returned an unexpected response status")
    entries = validate_catalog(response.data)
    changed = 0
    with db:
        # A temporary table supports full-catalog removals without SQL variable limits.
        db.execute("CREATE TEMP TABLE IF NOT EXISTS current_kev(cve_id TEXT PRIMARY KEY)")
        db.execute("DELETE FROM current_kev")
        for item in entries:
            changed += upsert_kev(db, item)
            db.execute("INSERT INTO current_kev(cve_id) VALUES (?)", (item["cveID"],))
        removed = db.execute("DELETE FROM kev WHERE cve_id NOT IN (SELECT cve_id FROM current_kev)").rowcount
        set_meta(db, "kev_catalog_version", response.data["catalogVersion"])
        set_meta(db, "kev_date_released", response.data["dateReleased"])
        set_meta(db, "kev_etag", response.headers.get("etag"))
        set_meta(db, "kev_last_modified", response.headers.get("last-modified"))
        set_meta(db, "kev_last_sync", started)
    stats = {"received": len(entries), "changed": changed, "removed": removed, "not_modified": False}
    progress(f"CISA KEV: {stats['received']} catalog entries, {changed} new/changed, {removed} removed")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="cache/vulnerabilities.sqlite3", help="Persistent SQLite cache")
    args = parser.parse_args()
    db = None
    try:
        db = connect_db(args.db)
        sync_kev(db)
    except (FetchError, ValueError, sqlite3.Error) as exc:
        print(f"CISA KEV sync failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("CISA KEV sync interrupted; the previous committed catalog is preserved.", file=sys.stderr)
        return 130
    finally:
        if db is not None:
            db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
