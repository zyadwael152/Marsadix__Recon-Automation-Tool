import pytest

from marsadix import db
from marsadix.core.graph import (
    blast_radius, build_graph, get_shared_infrastructure, run_graph, run_stage,
)
from marsadix.core.pipeline import Context
from marsadix.core.config import Config
from marsadix.core.scope import Scope
from marsadix.models import (
    Asset, DetectionStatus, Finding, FindingSource, Scan, ScanStatus, Service,
    Severity, Technology,
)


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def _mk_scan(conn, target="example.com", is_baseline=True):
    scan = Scan(target=target, status=ScanStatus.COMPLETED, is_baseline=is_baseline)
    scan.id = db.save_scan(conn, scan)
    return scan


def _seed(conn, scan_id):
    """Two hosts sharing one IP, one service with a CPE, one tech, one CVE finding."""
    db.save_many(conn, "assets", [
        Asset(scan_id=scan_id, host="api.example.com", ip="93.184.216.34",
              asn="AS15133", asn_owner="EdgeCast", in_scope=True, confidence_score=80),
        Asset(scan_id=scan_id, host="app.example.com", ip="93.184.216.34",
              asn="AS15133", asn_owner="EdgeCast", in_scope=True, confidence_score=60),
    ])
    db.save_many(conn, "services", [
        Service(scan_id=scan_id, host="api.example.com", port=443, name="https",
                product="nginx", version="1.24", cpe="cpe:/a:nginx:nginx:1.24"),
    ])
    db.save_many(conn, "technologies", [
        Technology(scan_id=scan_id, host="api.example.com", name="nginx", version="1.24",
                   cpe="cpe:/a:nginx:nginx:1.24"),
    ])
    db.save_many(conn, "findings", [
        Finding(scan_id=scan_id, host="api.example.com", source=FindingSource.CVE_MATCH,
                title="nginx 1.24 vulnerable to CVE-2024-9999", severity=Severity.HIGH,
                technology="nginx", cve_id="CVE-2024-9999", in_kev=True,
                status=DetectionStatus.DETECTED),
    ])


def test_build_graph_creates_expected_nodes_and_edges(conn):
    scan = _mk_scan(conn)
    _seed(conn, scan.id)

    counts = build_graph(conn, scan.id)
    assert counts["nodes"] > 0 and counts["edges"] > 0

    graph = db.get_graph(conn, scan.id)
    node_types = {n["node_type"] for n in graph["nodes"]}
    assert {"subdomain", "ip", "asn", "service", "cpe", "technology", "cve", "finding"} <= node_types

    relations = {e["relation"] for e in graph["edges"]}
    assert {"resolves_to", "belongs_to", "exposes", "runs", "has_cpe", "uses",
            "found_on", "listed_in", "affected_by"} <= relations


def test_build_graph_is_idempotent(conn):
    scan = _mk_scan(conn)
    _seed(conn, scan.id)

    build_graph(conn, scan.id)
    n1 = len(db.get_graph(conn, scan.id)["nodes"])
    e1 = len(db.get_graph(conn, scan.id)["edges"])
    build_graph(conn, scan.id)  # re-run
    n2 = len(db.get_graph(conn, scan.id)["nodes"])
    e2 = len(db.get_graph(conn, scan.id)["edges"])
    assert (n1, e1) == (n2, e2)


def test_shared_infrastructure_detects_shared_ip(conn):
    scan = _mk_scan(conn)
    _seed(conn, scan.id)
    build_graph(conn, scan.id)

    clusters = get_shared_infrastructure(conn, scan.id)
    assert "resolves_to" in clusters
    shared_ip_group = next(iter(clusters["resolves_to"].values()))
    assert set(shared_ip_group) == {"subdomain:api.example.com", "subdomain:app.example.com"}


def test_shared_infrastructure_empty_when_nothing_shared(conn):
    scan = _mk_scan(conn)
    db.save_many(conn, "assets", [
        Asset(scan_id=scan.id, host="a.example.com", ip="1.1.1.1", in_scope=True),
        Asset(scan_id=scan.id, host="b.example.com", ip="2.2.2.2", in_scope=True),
    ])
    build_graph(conn, scan.id)
    assert get_shared_infrastructure(conn, scan.id) == {}


def test_blast_radius_reaches_the_cve_from_the_finding(conn):
    scan = _mk_scan(conn)
    _seed(conn, scan.id)
    build_graph(conn, scan.id)

    finding_row = conn.execute("SELECT id FROM findings WHERE scan_id=?", (scan.id,)).fetchone()
    radius = blast_radius(conn, scan.id, f"finding:{finding_row['id']}", max_hops=2)
    ids = {r["id"] for r in radius}
    assert "subdomain:api.example.com" in ids
    assert "cve:CVE-2024-9999" in ids


def test_run_graph_no_scan_returns_error(conn, capsys):
    rc = run_graph(conn, "example.com")
    assert rc == 1
    assert "no scans found" in capsys.readouterr().err


def test_run_graph_prints_summary(conn, capsys):
    scan = _mk_scan(conn)
    _seed(conn, scan.id)

    rc = run_graph(conn, "example.com")
    out = capsys.readouterr().out
    assert rc == 0
    assert "Knowledge Graph for example.com" in out
    assert "Shared infrastructure" in out
    assert "CVE-2024-9999" in out


def test_pipeline_graph_stage_builds_automatically(conn):
    scan = _mk_scan(conn, is_baseline=True)
    _seed(conn, scan.id)
    ctx = Context(conn=conn, scan=scan, scope=Scope.from_target("example.com"), config=Config())

    run_stage(ctx)

    graph = db.get_graph(conn, scan.id)
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0
