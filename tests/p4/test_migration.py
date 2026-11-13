import sqlite3
from marsadix.dbutil import columns, has_table
from marsadix.db_v4 import migrate_v3_to_v4, get_user_version
from .conftest import make_v3, seed_basic


def test_migration_preserves_data_and_adds_schema(v3db):
    sid = seed_basic(v3db)
    v3db.execute("INSERT INTO findings(scan_id,host,title,severity) VALUES (?,?,?,?)", (sid, "h", "Old finding", "high"))
    v3db.execute("INSERT INTO alerts(dedup_key,message) VALUES ('old-key','old msg')")
    v3db.commit()
    before = {t: v3db.execute(f"SELECT * FROM {t}").fetchall() for t in ("scans", "assets", "technologies", "findings", "alerts", "cves")}
    migrate_v3_to_v4(v3db)
    assert get_user_version(v3db) == 4
    for t in ("remediation", "attack_surface_scores", "monitor_runs"):
        assert has_table(v3db, t)
    assert {"group_key", "attempts", "last_error", "delivered"} <= set(columns(v3db, "alerts"))
    assert {"dedup_key", "cvss", "risk_score", "monitor_run_id"} <= set(columns(v3db, "findings"))
    assert "criticality" in columns(v3db, "assets")
    for t, rows in before.items():
        n = len(rows[0]) if rows else 0
        assert [r[:n] for r in v3db.execute(f"SELECT * FROM {t}").fetchall()] == rows
    assert v3db.execute("SELECT criticality FROM assets").fetchone()[0] == "medium"
    assert v3db.execute("SELECT delivered FROM alerts WHERE dedup_key='old-key'").fetchone()[0] == 0


def test_migration_idempotent(v3db):
    migrate_v3_to_v4(v3db)
    migrate_v3_to_v4(v3db)
    assert get_user_version(v3db) == 4


def test_migration_on_file_db_roundtrip(tmp_path):
    p = tmp_path / "marsadix.db"
    c = sqlite3.connect(p)
    make_v3(c)
    seed_basic(c)
    c.close()
    c = sqlite3.connect(p)
    migrate_v3_to_v4(c)
    c.close()
    c = sqlite3.connect(p)
    assert get_user_version(c) == 4 and c.execute("SELECT count(*) FROM technologies").fetchone()[0] == 1


def test_remediation_constraints(db):
    import pytest
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO remediation(match_type,match_value,title,fix_text) VALUES ('bogus','x','t','f')")


def test_findings_dedup_unique_index(db):
    sid = seed_basic(db)
    db.execute("INSERT INTO findings(scan_id,title,dedup_key) VALUES (?,?,?)", (sid, "a", "k"))
    db.execute("INSERT INTO findings(scan_id,title) VALUES (?,?)", (sid, "no key 1"))
    db.execute("INSERT INTO findings(scan_id,title) VALUES (?,?)", (sid, "no key 2"))
    import pytest
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO findings(scan_id,title,dedup_key) VALUES (?,?,?)", (sid, "b", "k"))
