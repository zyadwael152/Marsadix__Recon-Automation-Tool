import pytest

from marsadix import db
from marsadix.core.diff import compute_diff, get_target_timeline, run_diff, run_stage
from marsadix.core.pipeline import Context
from marsadix.core.scope import Scope
from marsadix.models import (
    Asset, DiscoverySource, Finding, FindingSource, Scan, ScanStatus, Service,
    Severity, Technology,
)


def _mk_scan(conn, target, status="completed", is_baseline=False):
    scan = Scan(target=target, status=ScanStatus(status), is_baseline=is_baseline)
    scan.id = db.save_scan(conn, scan)
    return scan


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def test_compute_diff_detects_everything(conn):
    old = _mk_scan(conn, "example.com", is_baseline=True)
    new = _mk_scan(conn, "example.com")

    db.save_many(conn, "assets", [
        Asset(scan_id=old.id, host="api.example.com", in_scope=True),
        Asset(scan_id=old.id, host="old.example.com", in_scope=True),
    ])
    db.save_many(conn, "assets", [
        Asset(scan_id=new.id, host="api.example.com", in_scope=True),
        Asset(scan_id=new.id, host="new.example.com", in_scope=True),
    ])

    db.save_many(conn, "services", [Service(scan_id=old.id, host="api.example.com", port=443)])
    db.save_many(conn, "services", [
        Service(scan_id=new.id, host="api.example.com", port=443),
        Service(scan_id=new.id, host="api.example.com", port=8080),
    ])

    db.save_many(conn, "technologies", [
        Technology(scan_id=old.id, host="api.example.com", name="nginx", version="1.18")])
    db.save_many(conn, "technologies", [
        Technology(scan_id=new.id, host="api.example.com", name="nginx", version="1.24")])

    db.save_many(conn, "findings", [
        Finding(scan_id=old.id, host="old.example.com", source=FindingSource.NUCLEI,
                title="Old exposure", template_id="exposure-1")])
    db.save_many(conn, "findings", [
        Finding(scan_id=new.id, host="new.example.com", source=FindingSource.NUCLEI,
                title="New exposure", template_id="exposure-2")])

    diff = compute_diff(conn, old.id, new.id)
    assert diff.new_assets == ["new.example.com"]
    assert diff.removed_assets == ["old.example.com"]
    assert diff.new_ports == ["api.example.com:8080"]
    assert diff.closed_ports == []
    assert diff.changed_technologies == ["api.example.com: nginx 1.18 -> 1.24"]
    assert diff.new_findings == ["new.example.com: New exposure"]
    assert diff.resolved_findings == ["old.example.com: Old exposure"]


def test_run_diff_needs_two_scans(conn, capsys):
    assert run_diff(conn, "example.com") == 1
    assert "need at least 2 scans" in capsys.readouterr().err


def test_run_diff_prints_report(conn, capsys):
    old = _mk_scan(conn, "example.com", is_baseline=True)
    new = _mk_scan(conn, "example.com")
    db.save_many(conn, "assets", [Asset(scan_id=new.id, host="new.example.com", in_scope=True)])

    rc = run_diff(conn, "example.com")
    out = capsys.readouterr().out
    assert rc == 0
    assert "Diff for example.com" in out
    assert "new.example.com" in out


def test_run_stage_baseline_creates_no_alerts(conn):
    scan = _mk_scan(conn, "example.com", status="running", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="api.example.com", in_scope=True)])
    ctx = Context(conn=conn, scan=scan, scope=Scope.from_target("example.com"),
                  config=__import__("marsadix.core.config", fromlist=["Config"]).Config())

    run_stage(ctx)
    assert db.get_pending_alerts(conn) == []


def test_run_stage_flags_new_asset_after_baseline(conn):
    from marsadix.core.config import Config

    baseline = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=baseline.id, host="api.example.com", in_scope=True)])
    db.update_tracked_assets(conn, "example.com", ["api.example.com"], baseline.id)

    scan2 = _mk_scan(conn, "example.com", status="running")
    db.save_many(conn, "assets", [
        Asset(scan_id=scan2.id, host="api.example.com", in_scope=True),
        Asset(scan_id=scan2.id, host="dev.example.com", in_scope=True),
    ])
    ctx = Context(conn=conn, scan=scan2, scope=Scope.from_target("example.com"), config=Config())

    run_stage(ctx)
    alerts = db.get_pending_alerts(conn)
    assert len(alerts) == 1
    assert alerts[0]["host"] == "dev.example.com"
    assert alerts[0]["alert_type"] == "new_asset"


def test_run_stage_is_idempotent_no_duplicate_alerts(conn):
    from marsadix.core.config import Config

    baseline = _mk_scan(conn, "example.com", is_baseline=True)
    db.update_tracked_assets(conn, "example.com", ["api.example.com"], baseline.id)

    scan2 = _mk_scan(conn, "example.com", status="running")
    db.save_many(conn, "assets", [Asset(scan_id=scan2.id, host="dev.example.com", in_scope=True)])
    ctx = Context(conn=conn, scan=scan2, scope=Scope.from_target("example.com"), config=Config())

    run_stage(ctx)
    run_stage(ctx)  # simulate accidental re-run
    assert len(db.get_pending_alerts(conn)) == 1  # still just one, not two


def test_get_target_timeline_orders_oldest_first(conn):
    s1 = _mk_scan(conn, "example.com", is_baseline=True)
    s2 = _mk_scan(conn, "example.com")
    db.save_many(conn, "assets", [Asset(scan_id=s2.id, host="api.example.com", in_scope=True)])

    timeline = get_target_timeline(conn, "example.com")
    assert [t["scan_id"] for t in timeline] == [s1.id, s2.id]
    assert timeline[1]["asset_count"] == 1


def test_run_snapshots_no_scans_returns_error(conn, capsys):
    from marsadix.core.diff import run_snapshots
    rc = run_snapshots(conn, "example.com")
    assert rc == 1
    assert "no scans found" in capsys.readouterr().err


def test_run_snapshots_lists_all_scans_in_order(conn, capsys):
    from marsadix.core.diff import run_snapshots
    s1 = _mk_scan(conn, "example.com", is_baseline=True)
    s2 = _mk_scan(conn, "example.com")
    db.save_many(conn, "assets", [Asset(scan_id=s2.id, host="api.example.com", in_scope=True)])

    rc = run_snapshots(conn, "example.com")
    out = capsys.readouterr().out
    assert rc == 0
    assert f"#{s1.id}" in out and f"#{s2.id}" in out
    assert out.index(f"#{s1.id}") < out.index(f"#{s2.id}")  # oldest first
    assert "(baseline)" in out
