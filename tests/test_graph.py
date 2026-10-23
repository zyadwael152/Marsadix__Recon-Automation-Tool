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


# ---------------------------------------------------------------------------
# Regression tests for the graph bugs found in code review
# ---------------------------------------------------------------------------

def test_build_graph_service_on_host_missing_from_assets(conn):
    """Used to crash with IntegrityError (FK) -- the whole graph stage failed."""
    scan = _mk_scan(conn)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="a.example.com", ip="1.1.1.1", in_scope=True)])
    db.save_many(conn, "services", [Service(scan_id=scan.id, host="b.example.com", port=80, name="http")])

    build_graph(conn, scan.id)

    g = db.get_graph(conn, scan.id)
    ids = {n["id"] for n in g["nodes"]}
    assert {"subdomain:a.example.com", "subdomain:b.example.com", "port:b.example.com:80"} <= ids
    # the host we had to infer is flagged as such, not passed off as inventory
    inferred = next(n for n in g["nodes"] if n["id"] == "subdomain:b.example.com")
    assert '"inferred": true' in inferred["attrs"]


def test_build_graph_finding_with_technology_not_in_technologies_table(conn):
    scan = _mk_scan(conn)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="a.example.com", ip="1.1.1.1", in_scope=True)])
    db.save_many(conn, "findings", [
        Finding(scan_id=scan.id, host="a.example.com", title="x", cve_id="CVE-2024-1", technology="nginx")])

    build_graph(conn, scan.id)

    g = db.get_graph(conn, scan.id)
    assert "technology:a.example.com:nginx" in {n["id"] for n in g["nodes"]}
    rels = {(e["src_id"], e["dst_id"], e["relation"]) for e in g["edges"]}
    assert ("technology:a.example.com:nginx", "cve:CVE-2024-1", "affected_by") in rels
    assert ("subdomain:a.example.com", "technology:a.example.com:nginx", "uses") in rels


def test_build_graph_finding_on_host_missing_from_assets(conn):
    scan = _mk_scan(conn)
    db.save_many(conn, "findings", [Finding(scan_id=scan.id, host="ghost.example.com", title="x")])

    counts = build_graph(conn, scan.id)

    assert counts["nodes"] == 2          # the finding + the inferred host
    assert counts["edges"] == 1          # found_on


def test_older_scan_graph_survives_a_newer_scan(conn):
    """
    Nodes shared between scans (same IP, same host) used to be re-tagged with
    the newest scan_id, so the older scan's graph lost them: 3 nodes -> 0.
    """
    def seed(scan_id):
        db.save_many(conn, "assets", [
            Asset(scan_id=scan_id, host="a.example.com", ip="1.1.1.1", in_scope=True),
            Asset(scan_id=scan_id, host="b.example.com", ip="1.1.1.1", in_scope=True)])

    s1 = _mk_scan(conn)
    seed(s1.id)
    build_graph(conn, s1.id)
    before = db.get_graph(conn, s1.id)

    s2 = _mk_scan(conn, is_baseline=False)
    seed(s2.id)
    build_graph(conn, s2.id)

    after = db.get_graph(conn, s1.id)
    assert len(before["nodes"]) == 3
    assert {n["id"] for n in after["nodes"]} == {n["id"] for n in before["nodes"]}
    assert len(after["edges"]) == len(before["edges"])
    assert len(db.get_graph(conn, s2.id)["nodes"]) == 3
    # and the per-scan queries still work on the OLD scan
    assert "ip:1.1.1.1" in next(iter(get_shared_infrastructure(conn, s1.id)["resolves_to"]))


def test_node_attributes_are_kept_per_scan(conn):
    s1 = _mk_scan(conn)
    db.save_many(conn, "assets", [Asset(scan_id=s1.id, host="a.example.com", in_scope=True, confidence_score=20)])
    build_graph(conn, s1.id)
    s2 = _mk_scan(conn, is_baseline=False)
    db.save_many(conn, "assets", [Asset(scan_id=s2.id, host="a.example.com", in_scope=True, confidence_score=80)])
    build_graph(conn, s2.id)

    a1 = next(n for n in db.get_graph(conn, s1.id)["nodes"] if n["id"] == "subdomain:a.example.com")
    a2 = next(n for n in db.get_graph(conn, s2.id)["nodes"] if n["id"] == "subdomain:a.example.com")
    assert '"confidence_score": 20' in a1["attrs"]
    assert '"confidence_score": 80' in a2["attrs"]


def test_rebuild_drops_stale_graph_rows(conn):
    scan = _mk_scan(conn)
    db.save_many(conn, "assets", [
        Asset(scan_id=scan.id, host="a.example.com", ip="1.1.1.1", in_scope=True),
        Asset(scan_id=scan.id, host="b.example.com", ip="2.2.2.2", in_scope=True)])
    build_graph(conn, scan.id)
    conn.execute("DELETE FROM assets WHERE scan_id=? AND host='b.example.com'", (scan.id,))
    conn.commit()

    build_graph(conn, scan.id)

    ids = {n["id"] for n in db.get_graph(conn, scan.id)["nodes"]}
    assert "subdomain:b.example.com" not in ids
    assert "ip:2.2.2.2" not in ids


def test_build_graph_counts_match_what_get_graph_returns(conn):
    scan = _mk_scan(conn)
    _seed(conn, scan.id)
    counts = build_graph(conn, scan.id)
    g = db.get_graph(conn, scan.id)
    assert counts == {"nodes": len(g["nodes"]), "edges": len(g["edges"])}


def test_get_neighbors_treats_scan_id_zero_as_a_scan(conn):
    # `if scan_id:` used to ignore a (hypothetical) scan id 0 and search every scan
    conn.execute("INSERT INTO graph_nodes (id, node_type, label) VALUES ('a','x','a'), ('b','x','b')")
    conn.execute("INSERT INTO graph_edges (src_id, dst_id, relation, scan_id) VALUES ('a','b','r', NULL)")
    conn.commit()
    assert db.get_neighbors(conn, "a", scan_id=0) == []
    assert [n["id"] for n in db.get_neighbors(conn, "a")] == ["b"]


# ---------------------------------------------------------------------------
# Technology version is part of a technology node's identity
# ---------------------------------------------------------------------------

def test_two_versions_of_same_technology_on_one_host_are_two_nodes(conn):
    scan = _mk_scan(conn)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="a.example.com", ip="1.1.1.1", in_scope=True)])
    db.save_many(conn, "technologies", [
        Technology(scan_id=scan.id, host="a.example.com", name="nginx", version="1.18"),
        Technology(scan_id=scan.id, host="a.example.com", name="nginx", version="1.24"),
    ])
    build_graph(conn, scan.id)

    g = db.get_graph(conn, scan.id)
    techs = {n["id"]: n["label"] for n in g["nodes"] if n["node_type"] == "technology"}
    assert techs == {"technology:a.example.com:nginx:1.18": "nginx 1.18",
                     "technology:a.example.com:nginx:1.24": "nginx 1.24"}
    uses = {(e["src_id"], e["dst_id"]) for e in g["edges"] if e["relation"] == "uses"}
    assert ("subdomain:a.example.com", "technology:a.example.com:nginx:1.18") in uses
    assert ("subdomain:a.example.com", "technology:a.example.com:nginx:1.24") in uses


def test_technology_without_version_keeps_a_versionless_id(conn):
    scan = _mk_scan(conn)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="a.example.com", in_scope=True)])
    db.save_many(conn, "technologies", [Technology(scan_id=scan.id, host="a.example.com", name="react")])
    build_graph(conn, scan.id)
    assert "technology:a.example.com:react" in {n["id"] for n in db.get_graph(conn, scan.id)["nodes"]}


def test_finding_by_technology_name_links_every_version_on_the_host(conn):
    """A finding only carries the technology NAME, so with 2 versions present we
    cannot know which is affected -- both are linked to the CVE."""
    scan = _mk_scan(conn)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="a.example.com", in_scope=True)])
    db.save_many(conn, "technologies", [
        Technology(scan_id=scan.id, host="a.example.com", name="nginx", version="1.18"),
        Technology(scan_id=scan.id, host="a.example.com", name="nginx", version="1.24"),
    ])
    db.save_many(conn, "findings", [
        Finding(scan_id=scan.id, host="a.example.com", title="x", cve_id="CVE-2024-5", technology="nginx")])
    build_graph(conn, scan.id)

    affected = {e["src_id"] for e in db.get_graph(conn, scan.id)["edges"] if e["relation"] == "affected_by"}
    assert affected == {"technology:a.example.com:nginx:1.18", "technology:a.example.com:nginx:1.24"}
