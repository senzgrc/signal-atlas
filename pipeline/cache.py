"""SQLite cache. Callers own transactions so records and checkpoints commit together."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")


def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise ValueError("Expected an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Expected an ISO 8601 timestamp") from exc
    # NVD timestamps have no offset and are documented as UTC.
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def valid_cve_id(value: Any) -> bool:
    return isinstance(value, str) and CVE_ID.fullmatch(value) is not None


def validate_cve(cve: Any) -> None:
    if not isinstance(cve, dict) or not valid_cve_id(cve.get("id")):
        raise ValueError("Invalid NVD CVE identifier")
    parse_time(cve.get("published"))
    parse_time(cve.get("lastModified"))
    for name in ("descriptions", "references", "weaknesses", "configurations"):
        if name in cve and not isinstance(cve[name], list):
            raise ValueError(f"Invalid NVD {name} field")
    if "metrics" in cve and not isinstance(cve["metrics"], dict):
        raise ValueError("Invalid NVD metrics field")
    if "descriptions" in cve:
        for item in cve["descriptions"]:
            if not isinstance(item, dict) or not isinstance(item.get("lang"), str) or not isinstance(item.get("value"), str):
                raise ValueError("Invalid NVD description")


def validate_kev(item: Any) -> None:
    if not isinstance(item, dict) or not valid_cve_id(item.get("cveID")):
        raise ValueError("Invalid CISA KEV identifier")
    for name in ("vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate"):
        if not isinstance(item.get(name), str):
            raise ValueError(f"Invalid CISA KEV {name} field")
    for name in ("dateAdded", "dueDate"):
        try:
            datetime.strptime(item[name], "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError(f"Invalid CISA KEV {name} date") from exc


def connect_db(path: str | Path) -> sqlite3.Connection:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=30000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            published TEXT NOT NULL,
            modified TEXT NOT NULL,
            payload TEXT NOT NULL,
            content_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS cves_published ON cves(published);
        CREATE INDEX IF NOT EXISTS cves_modified ON cves(modified);
        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            content_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    return db


def get_meta(db: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = db.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


def set_meta(db: sqlite3.Connection, key: str, value: Any) -> None:
    db.execute(
        "INSERT INTO metadata(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)),
    )


def encoded_payload(payload: dict) -> tuple[str, str]:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def upsert_cve(db: sqlite3.Connection, cve: dict) -> bool:
    validate_cve(cve)
    payload, digest = encoded_payload(cve)
    cursor = db.execute("""
        INSERT INTO cves(cve_id, published, modified, payload, content_hash) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET published=excluded.published, modified=excluded.modified,
            payload=excluded.payload, content_hash=excluded.content_hash
        WHERE cves.content_hash != excluded.content_hash AND excluded.modified >= cves.modified
    """, (cve["id"], timestamp(parse_time(cve["published"])), timestamp(parse_time(cve["lastModified"])), payload, digest))
    return cursor.rowcount > 0


def upsert_kev(db: sqlite3.Connection, item: dict) -> bool:
    validate_kev(item)
    payload, digest = encoded_payload(item)
    cursor = db.execute("""
        INSERT INTO kev(cve_id, payload, content_hash) VALUES (?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET payload=excluded.payload, content_hash=excluded.content_hash
        WHERE kev.content_hash != excluded.content_hash
    """, (item["cveID"], payload, digest))
    return cursor.rowcount > 0
