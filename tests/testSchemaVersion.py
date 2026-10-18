import sqlite3

import pytest

from marsadix import db


def test_fresh_db_gets_current_schema_version():
    conn = db.connect(":memory:")
    db.init_db(conn)
    row = conn.execute("SELECT version FROM schema_info").fetchone()
    assert row["version"] == db.SCHEMA_VERSION


def test_init_db_is_idempotent():
    conn = db.connect(":memory:")
    db.init_db(conn)
    db.init_db(conn)  # must not raise, must not duplicate the version row
    rows = conn.execute("SELECT version FROM schema_info").fetchall()
    assert len(rows) == 1


def test_old_schema_db_raises_clear_error(tmp_path):
    path = str(tmp_path / "old.db")
    raw = sqlite3.connect(path)
    raw.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_id INTEGER, host TEXT)")
    raw.commit()
    raw.close()

    conn = db.connect(path)
    with pytest.raises(db.SchemaVersionError, match="predates schema"):
        db.init_db(conn)


def test_future_schema_version_raises_clear_error(tmp_path):
    path = str(tmp_path / "future.db")
    conn = db.connect(path)
    db.init_db(conn)
    conn.execute("UPDATE schema_info SET version = ?", (db.SCHEMA_VERSION + 1,))
    conn.commit()
    conn.close()

    conn2 = db.connect(path)
    with pytest.raises(db.SchemaVersionError, match="schema v"):
        db.init_db(conn2)
