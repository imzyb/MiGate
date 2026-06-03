import sqlite3
from pathlib import Path

import pytest

from migate.backup.manager import BackupManager


def _create_test_db(db_path: Path):
    """Create a minimal SQLite database for testing."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO test (name) VALUES ('hello')")
    conn.commit()
    conn.close()


def test_create_backup_creates_file(tmp_path):
    db_path = tmp_path / "test.db"
    _create_test_db(db_path)
    mgr = BackupManager(db_path)

    backup_path = mgr.create_backup()

    assert backup_path.exists()
    assert backup_path.name.startswith("migate_backup_")
    assert backup_path.suffix == ".db"
    # Verify the backup is a valid SQLite database with data
    conn = sqlite3.connect(str(backup_path))
    row = conn.execute("SELECT name FROM test").fetchone()
    conn.close()
    assert row[0] == "hello"


def test_list_backups_returns_entries(tmp_path):
    db_path = tmp_path / "test.db"
    _create_test_db(db_path)
    mgr = BackupManager(db_path)

    mgr.create_backup()
    backups = mgr.list_backups()

    assert len(backups) == 1
    assert "name" in backups[0]
    assert "size" in backups[0]
    assert "created" in backups[0]
    assert backups[0]["name"].startswith("migate_backup_")


def test_list_backups_empty_when_no_backups(tmp_path):
    db_path = tmp_path / "test.db"
    _create_test_db(db_path)
    mgr = BackupManager(db_path)

    assert mgr.list_backups() == []


def test_restore_backup_works(tmp_path):
    db_path = tmp_path / "test.db"
    _create_test_db(db_path)
    mgr = BackupManager(db_path)

    backup_path = mgr.create_backup()

    # Modify the original database
    conn = sqlite3.connect(str(db_path))
    conn.execute("INSERT INTO test (name) VALUES ('world')")
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM test").fetchone()[0]
    conn.close()
    assert count == 2

    # Restore from backup
    success = mgr.restore_backup(backup_path.name)
    assert success is True

    # Verify restored data
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute("SELECT name FROM test").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "hello"


def test_restore_backup_creates_safety_backup(tmp_path):
    db_path = tmp_path / "test.db"
    _create_test_db(db_path)
    mgr = BackupManager(db_path)

    first_backup = mgr.create_backup()

    # Modify db, then restore
    conn = sqlite3.connect(str(db_path))
    conn.execute("INSERT INTO test (name) VALUES ('world')")
    conn.commit()
    conn.close()

    mgr.restore_backup(first_backup.name)

    # Should have original backup + safety backup
    backups = mgr.list_backups()
    assert len(backups) >= 2


def test_restore_backup_returns_false_for_missing(tmp_path):
    db_path = tmp_path / "test.db"
    _create_test_db(db_path)
    mgr = BackupManager(db_path)

    success = mgr.restore_backup("nonexistent_backup.db")
    assert success is False


def test_delete_backup_removes_file(tmp_path):
    db_path = tmp_path / "test.db"
    _create_test_db(db_path)
    mgr = BackupManager(db_path)

    backup_path = mgr.create_backup()
    assert backup_path.exists()

    success = mgr.delete_backup(backup_path.name)
    assert success is True
    assert not backup_path.exists()


def test_delete_backup_returns_false_for_missing(tmp_path):
    db_path = tmp_path / "test.db"
    _create_test_db(db_path)
    mgr = BackupManager(db_path)

    success = mgr.delete_backup("nonexistent_backup.db")
    assert success is False
