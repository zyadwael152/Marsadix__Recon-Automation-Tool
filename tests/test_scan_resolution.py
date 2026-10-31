import logging

import pytest

from marsadix import db
from marsadix.models import Scan, ScanMode
from marsadix_member2.config import Member2Config
from marsadix_member2.pipeline import run_web_pipeline
from marsadix_member2.storage import load_scan


@pytest.fixture
def scan_conn(tmp_path):
    conn = db.connect(str(tmp_path / "scan.db"))
    db.init_db(conn)
    yield conn
    conn.close()


def _save(conn, target, mode=ScanMode.FULL, scope_file=None):
    scan = Scan(target=target, mode=mode, scope_file=scope_file)
    scan.id = db.save_scan(conn, scan)
    return scan.id


def test_explicit_scan_id_is_kept_when_target_matches(scan_conn):
    scan_id = _save(scan_conn, "example.com")

    row = load_scan(scan_conn, target="EXAMPLE.COM", scan_id=scan_id)

    assert row["id"] == scan_id
    assert row["target"] == "example.com"


def test_mismatched_scan_id_resolves_latest_scan_for_target(scan_conn, caplog):
    old_id = _save(scan_conn, "example.com")
    wanted_id = _save(scan_conn, "testphp.vulnweb.com")

    with caplog.at_level(logging.WARNING, logger="marsadix_member2.storage"):
        row = load_scan(scan_conn, target="testphp.vulnweb.com", scan_id=old_id)

    assert row["id"] == wanted_id
    assert row["target"] == "testphp.vulnweb.com"
    assert (
        f"[!] Warning: scan_id {old_id} belongs to 'example.com'. "
        f"Auto-resolved/created scan_id {wanted_id} for 'testphp.vulnweb.com'."
    ) in caplog.text


def test_mismatched_scan_id_creates_scan_when_target_has_none(scan_conn, caplog):
    old_id = _save(scan_conn, "example.com")

    with caplog.at_level(logging.WARNING, logger="marsadix_member2.storage"):
        row = load_scan(scan_conn, target="testphp.vulnweb.com", scan_id=old_id)

    assert row["id"] != old_id
    assert row["target"] == "testphp.vulnweb.com"
    assert row["mode"] == "passive"
    assert (
        f"[!] Warning: scan_id {old_id} belongs to 'example.com'. "
        f"Auto-resolved/created scan_id {row['id']} for 'testphp.vulnweb.com'."
    ) in caplog.text
    saved = scan_conn.execute(
        "SELECT target FROM scans WHERE id=?", (row["id"],)).fetchone()
    assert saved["target"] == "testphp.vulnweb.com"


def test_no_scan_id_uses_latest_scan_for_target(scan_conn):
    _save(scan_conn, "example.com")
    latest_id = _save(scan_conn, "testphp.vulnweb.com")

    row = load_scan(scan_conn, target="https://TestPHP.vulnweb.com/path")

    assert row["id"] == latest_id


def test_missing_scan_id_resolves_existing_target_scan(scan_conn, caplog):
    wanted_id = _save(scan_conn, "testphp.vulnweb.com")

    with caplog.at_level(logging.WARNING, logger="marsadix_member2.storage"):
        row = load_scan(scan_conn, target="testphp.vulnweb.com", scan_id=99999)

    assert row["id"] == wanted_id
    assert "scan_id 99999 was not found" in caplog.text


def test_unknown_target_with_no_scan_id_is_created(scan_conn, caplog):
    with caplog.at_level(logging.WARNING, logger="marsadix_member2.storage"):
        row = load_scan(scan_conn, target="new.example")

    assert row["target"] == "new.example"
    assert row["mode"] == "passive"
    assert "no scan found for 'new.example'. Created scan_id" in caplog.text


def test_pipeline_auto_creates_scan_with_full_mode_when_scope_is_supplied(
        scan_conn, tmp_path, monkeypatch):
    old_id = _save(scan_conn, "example.com")
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n", encoding="utf-8")
    cfg = Member2Config(
        db_path=str(tmp_path / "scan.db"),
        output_dir=str(tmp_path / "out"),
        tools_dir=str(tmp_path / "no-tools"),
        archive_sources=(),
    )
    monkeypatch.setattr(cfg, "write_outputs", False)

    report = run_web_pipeline(
        conn=scan_conn,
        target="127.0.0.1",
        scan_id=old_id,
        scope_path=str(scope),
        config=cfg,
        use_archive=False,
        crawl=False,
        check_status=False,
        discover_hosts=False,
        dry_run=True,
    )

    assert report.scan_id != old_id
    assert report.target == "127.0.0.1"
    assert report.mode == "full"
    row = scan_conn.execute(
        "SELECT target, mode, scope_file FROM scans WHERE id=?",
        (report.scan_id,)).fetchone()
    assert row["target"] == "127.0.0.1"
    assert row["mode"] == "full"
    assert row["scope_file"] == str(scope)
