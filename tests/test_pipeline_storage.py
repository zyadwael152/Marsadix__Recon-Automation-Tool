import json

import pytest

from marsadix import db
from marsadix.models import Scan, ScanMode, WebItemKind
from marsadix.web_recon.config import Member2Config
from marsadix.web_recon.normalize import normalize_url
from marsadix.web_recon.pipeline import run_web_pipeline
from marsadix.web_recon.storage import CollectedURL, store_web_items
from marsadix.web_recon.tools import ToolResolver


@pytest.fixture
def scan_db(tmp_path):
    path = tmp_path / "scan.db"
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n", encoding="utf-8")
    conn = db.connect(str(path))
    db.init_db(conn)
    scan = Scan(target="localhost", mode=ScanMode.FULL, scope_file=str(scope))
    scan.id = db.save_scan(conn, scan)
    yield conn, scan.id, scope
    conn.close()


def test_store_dedupes_and_uses_discovery_source_enum(scan_db):
    conn, scan_id, _ = scan_db
    a = CollectedURL(normalize_url("http://e.test/a"), "wayback", status_code=200)
    result = store_web_items(conn, scan_id, [a])
    assert result.stored == 1
    row = db.get_web_items(conn, scan_id)[0]
    assert row["url"] == "http://e.test/a"
    assert row["source"] == "passive"


def test_full_pipeline_against_local_server(scan_db, local_server, tmp_path, monkeypatch):
    conn, scan_id, _ = scan_db
    monkeypatch.setattr(ToolResolver, "path", lambda self, name: None)
    cfg = Member2Config(
        db_path=str(tmp_path / "scan.db"),
        output_dir=str(tmp_path / "out"),
        tools_dir=str(tmp_path / "no-tools"),
        archive_sources=(),
        rate_limit=50,
        max_pages=20,
        max_js_files=10,
        max_http_checks=100,
        crawler_backend="builtin",
        request_timeout=5,
    )
    report = run_web_pipeline(
        conn=conn, scan_id=scan_id,
        config=cfg, seeds=[local_server],
        use_archive=False, crawl=True, check_status=True,
        discover_hosts=False,
    )
    assert report.status == "completed"
    assert report.candidates >= 5
    assert report.stored >= 5
    assert report.archive_records == 0

    rows = db.get_web_items(conn, scan_id)
    urls = {r["url"] for r in rows}
    assert local_server in urls
    assert local_server + "about" in urls
    assert local_server + "static/app.js" in urls
    assert local_server + "api/v2/items?q=1" in urls
    assert local_server + "missing" not in urls
    assert all(r["source"] in ("active", "js", "passive") for r in rows)
    assert any(r["source"] == "js" for r in rows)
    assert any(r["kind"] == WebItemKind.JS_FILE.value for r in rows)

    summary = json.loads((tmp_path / "out" / "localhost_m2_summary.json").read_text())
    assert summary["stored"] == report.stored
    assert (tmp_path / "out" / "localhost_m2_all_urls.txt").is_file()
    assert report.duration_ms >= 0
    assert any(o.name == "builtin-crawler" for o in report.outcomes)
    assert any(o.name == "js-extractor" for o in report.outcomes)
    assert report.security_findings > 0
    assert report.findings_stored > 0
    assert db.get_findings(conn, scan_id)
    assert conn.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()[0] == "completed"


def test_passive_mode_never_contacts_target(scan_db, tmp_path, monkeypatch):
    conn, scan_id, scope = scan_db
    conn.execute("UPDATE scans SET mode='passive' WHERE id=?", (scan_id,))
    conn.commit()
    monkeypatch.setattr(ToolResolver, "path", lambda self, name: None)
    cfg = Member2Config(db_path=str(tmp_path / "scan.db"), tools_dir=str(tmp_path / "x"),
                        archive_sources=(), output_dir=str(tmp_path / "out"))
    report = run_web_pipeline(
        conn=conn, scan_id=scan_id, config=cfg,
        seeds=[], use_archive=False, crawl=True,
        check_status=True, discover_hosts=True,
    )
    assert report.status == "completed"
    assert report.stored == 0
    assert any("passive" in note for note in report.skipped)
    assert report.outcomes == []


def test_mode_override_keeps_existing_active_scan_passive(
        scan_db, local_server, tmp_path, monkeypatch):
    conn, scan_id, _ = scan_db
    monkeypatch.setattr(ToolResolver, "path", lambda self, name: None)
    cfg = Member2Config(
        db_path=str(tmp_path / "scan.db"),
        output_dir=str(tmp_path / "out"),
        tools_dir=str(tmp_path / "no-tools"),
        archive_sources=(), rate_limit=50, crawler_backend="builtin",
        request_timeout=5,
    )
    report = run_web_pipeline(
        conn=conn, scan_id=scan_id, config=cfg, seeds=[local_server],
        use_archive=False, crawl=True, check_status=True,
        discover_hosts=True, mode="passive",
    )
    assert report.mode == "passive"
    assert report.stored == 1
    assert report.outcomes == []
    rows = db.get_web_items(conn, scan_id)
    assert rows[0]["url"] == local_server
    assert rows[0]["status_code"] is None
    assert any("security inspection skipped" in note for note in report.skipped)
    assert any("nuclei skipped" in note for note in report.skipped)
