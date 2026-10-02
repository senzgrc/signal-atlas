"""Backup snapshot consistency, Windows file handles, and atomic publication."""

import gzip
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from scripts.cache_backup import backup_cache, restore_cache


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "vulnerabilities.sqlite3"
        self.archive = self.root / "vulnerabilities.sqlite3.gz"
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("CREATE TABLE records(id TEXT PRIMARY KEY, payload TEXT)")
            db.execute("INSERT INTO records VALUES ('CVE-2020-1000', 'Original')")
            db.commit()

    def tearDown(self):
        self.temporary.cleanup()

    def assert_staging_cleaned(self):
        self.assertEqual(list(self.root.glob(".cache-backup-*")), [])

    def test_backup_and_restore_round_trip(self):
        self.assertEqual(backup_cache(self.root), self.archive)
        self.database.unlink()
        self.assertEqual(restore_cache(self.root), self.database)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT payload FROM records").fetchone()[0], "Original")
        self.assert_staging_cleaned()

    def test_backup_includes_committed_wal_records(self):
        with closing(sqlite3.connect(self.database)) as live:
            live.execute("PRAGMA journal_mode=WAL")
            live.execute("INSERT INTO records VALUES ('CVE-2020-1001', 'Committed WAL')")
            live.commit()
            self.assertTrue(Path(str(self.database) + "-wal").exists())
            backup_cache(self.root)
        self.database.unlink()
        restore_cache(self.root)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM records").fetchone()[0], 2)

    def test_restore_refuses_existing_database_or_journal_files(self):
        backup_cache(self.root)
        before = self.database.read_bytes()
        with self.assertRaises(ValueError):
            restore_cache(self.root)
        self.assertEqual(self.database.read_bytes(), before)
        self.database.unlink()
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(self.database) + suffix)
            sidecar.write_bytes(b"Still in use")
            with self.assertRaises(ValueError):
                restore_cache(self.root)
            self.assertFalse(self.database.exists())
            sidecar.unlink()
        self.assert_staging_cleaned()

    def test_failed_compression_preserves_previous_published_backup(self):
        backup_cache(self.root)
        before = self.archive.read_bytes()
        with patch("scripts.cache_backup.shutil.copyfileobj", side_effect=OSError("Simulated disk failure")):
            with self.assertRaises(OSError):
                backup_cache(self.root)
        self.assertEqual(self.archive.read_bytes(), before)
        self.assert_staging_cleaned()

    def test_failed_first_backup_never_publishes_partial_archive(self):
        with patch("scripts.cache_backup.shutil.copyfileobj", side_effect=OSError("Simulated disk failure")):
            with self.assertRaises(OSError):
                backup_cache(self.root)
        self.assertFalse(self.archive.exists())
        self.assert_staging_cleaned()

    def test_corrupt_restore_does_not_publish_database(self):
        self.database.unlink()
        with gzip.open(self.archive, "wb") as archive:
            archive.write(b"Not a SQLite database")
        with self.assertRaises(sqlite3.DatabaseError):
            restore_cache(self.root)
        self.assertFalse(self.database.exists())
        self.assert_staging_cleaned()

    def test_missing_source_is_not_silently_created(self):
        self.database.unlink()
        with self.assertRaises(ValueError):
            backup_cache(self.root)
        self.assertFalse(self.database.exists())
        self.assertFalse(self.archive.exists())

    def test_all_sqlite_connections_close_before_file_publication(self):
        actual_connect = sqlite3.connect
        actual_replace = Path.replace
        connections = []

        class TrackedConnection:
            def __init__(self, inner):
                self.inner = inner
                self.closed = False

            def execute(self, *args, **kwargs):
                return self.inner.execute(*args, **kwargs)

            def backup(self, target):
                return self.inner.backup(target.inner)

            def close(self):
                self.inner.close()
                self.closed = True

        def tracked_connect(*args, **kwargs):
            connection = TrackedConnection(actual_connect(*args, **kwargs))
            connections.append(connection)
            return connection

        def checked_replace(path, target):
            self.assertTrue(connections)
            self.assertTrue(all(connection.closed for connection in connections))
            return actual_replace(path, target)

        with patch("scripts.cache_backup.sqlite3.connect", side_effect=tracked_connect), patch.object(Path, "replace", checked_replace):
            backup_cache(self.root)
            self.database.unlink()
            restore_cache(self.root)
        self.assert_staging_cleaned()


if __name__ == "__main__":
    unittest.main()
