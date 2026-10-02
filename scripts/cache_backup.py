"""Portable, consistent SQLite backups for CI eviction recovery."""
import argparse
from contextlib import closing
import gzip
import shutil
import sqlite3
import tempfile
from pathlib import Path


def cache_paths(directory):
    """All published and temporary paths stay within the selected cache directory."""
    root = Path(directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    database = root / "vulnerabilities.sqlite3"
    archive = database.with_suffix(".sqlite3.gz")
    return root, database, archive


def validate_database(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as check:
        if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Invalid SQLite backup")


def require_empty_target(database):
    paths = [database, *(Path(str(database) + suffix) for suffix in ("-wal", "-shm", "-journal"))]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise ValueError("Refusing to replace an existing or open SQLite cache")


def backup_cache(directory):
    root, database, archive = cache_paths(directory)
    if not database.is_file():
        raise ValueError("Cannot back up a missing SQLite cache")
    # The unique staging directory belongs to this operation and is contained
    # under root. Every handle is closed before cleanup or Windows file moves.
    with tempfile.TemporaryDirectory(prefix=".cache-backup-", dir=root) as temporary:
        staging = Path(temporary)
        snapshot = staging / "snapshot.sqlite3"
        compressed = staging / "snapshot.sqlite3.gz"
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as source, closing(sqlite3.connect(snapshot)) as target:
            source.backup(target)
        validate_database(snapshot)
        with snapshot.open("rb") as source, gzip.open(compressed, "wb") as target:
            shutil.copyfileobj(source, target)
        # A failed/interrupted compression leaves the previous backup intact.
        compressed.replace(archive)
    return archive


def restore_cache(directory):
    root, database, archive = cache_paths(directory)
    require_empty_target(database)
    with tempfile.TemporaryDirectory(prefix=".cache-backup-", dir=root) as temporary:
        snapshot = Path(temporary) / "snapshot.sqlite3"
        with gzip.open(archive, "rb") as source, snapshot.open("wb") as target:
            shutil.copyfileobj(source, target)
        validate_database(snapshot)
        require_empty_target(database)
        snapshot.replace(database)
    return database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("backup", "restore"))
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parents[1] / "cache",
                        help="Directory containing vulnerabilities.sqlite3 and its compressed backup")
    args = parser.parse_args()
    operation = backup_cache if args.command == "backup" else restore_cache
    operation(args.directory)


if __name__ == "__main__":
    main()
