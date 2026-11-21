"""The knowledge graph links every subdomain under its parent ("contains"), not only through shared IPs."""

from marsadix import db
from marsadix.core.graph import _n_finding, _parent_host, blast_radius, build_graph
from marsadix.models import Asset, Finding, Scan, ScanStatus

ROOT = "0xnull.site"


def test_parent_is_the_closest_known_ancestor_or_the_root():
    known = {ROOT, "ctf.0xnull.site", "b.0xnull.site", "a.b.0xnull.site", "c.d.0xnull.site"}
    assert _parent_host("ctf.0xnull.site", known, ROOT) == ROOT
    assert _parent_host("a.b.0xnull.site", known, ROOT) == "b.0xnull.site"
    assert _parent_host("c.d.0xnull.site", known, ROOT) == ROOT          # d.0xnull.site was never found
    assert _parent_host(ROOT, known, ROOT) is None
    assert _parent_host("evil.org", known, ROOT) is None


def test_a_recorded_parent_host_wins_when_it_is_known_and_safe():
    known = {ROOT, "x.0xnull.site", "y.0xnull.site"}
    assert _parent_host("y.0xnull.site", known, ROOT, {"y.0xnull.site": "x.0xnull.site"}) == "x.0xnull.site"
    assert _parent_host("y.0xnull.site", known, ROOT, {"y.0xnull.site": "nope.0xnull.site"}) == ROOT
    loop = known | {"a.x.0xnull.site"}
    assert _parent_host("x.0xnull.site", loop, ROOT, {"x.0xnull.site": "a.x.0xnull.site"}) == ROOT


def _scan(conn, hosts):
    scan = Scan(target=ROOT, status=ScanStatus.RUNNING)
    scan.id = db.save_scan(conn, scan)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host=h, in_scope=True) for h in hosts])
    return scan


def _contains(conn, scan_id):
    g = db.get_graph(conn, scan_id)
    return {(e["src_id"], e["dst_id"]) for e in g["edges"] if e["relation"] == "contains"}


def test_subdomains_hang_under_their_parent_in_the_graph():
    conn = db.connect(":memory:")
    db.init_db(conn)
    scan = _scan(conn, [ROOT, "ctf.0xnull.site", "depi.0xnull.site", "b.0xnull.site", "a.b.0xnull.site",
                        "c.d.0xnull.site"])
    build_graph(conn, scan.id)
    s = lambda h: f"subdomain:{h}"
    assert _contains(conn, scan.id) == {
        (s(ROOT), s("ctf.0xnull.site")), (s(ROOT), s("depi.0xnull.site")), (s(ROOT), s("b.0xnull.site")),
        (s("b.0xnull.site"), s("a.b.0xnull.site")), (s(ROOT), s("c.d.0xnull.site"))}
    build_graph(conn, scan.id)                                              # rebuilding does not duplicate anything
    assert len(_contains(conn, scan.id)) == 5
    conn.close()


def test_the_apex_node_is_created_when_it_is_not_an_asset():
    conn = db.connect(":memory:")
    db.init_db(conn)
    scan = _scan(conn, ["ctf.0xnull.site"])
    build_graph(conn, scan.id)
    nodes = {n["id"] for n in db.get_graph(conn, scan.id)["nodes"]}
    assert f"subdomain:{ROOT}" in nodes
    assert _contains(conn, scan.id) == {(f"subdomain:{ROOT}", "subdomain:ctf.0xnull.site")}
    conn.close()


def test_blast_radius_does_not_walk_the_naming_hierarchy():
    conn = db.connect(":memory:")
    db.init_db(conn)
    scan = _scan(conn, [ROOT, "ctf.0xnull.site", "www.0xnull.site"])
    f = Finding(scan_id=scan.id, host="ctf.0xnull.site", title="t")
    db.save_many(conn, "findings", [f])
    fid = db.get_findings(conn, scan.id)[0]["id"]
    build_graph(conn, scan.id)
    reached = {r["label"] for r in blast_radius(conn, scan.id, _n_finding(fid), max_hops=3)}
    assert "ctf.0xnull.site" in reached
    assert "www.0xnull.site" not in reached and ROOT not in reached
    conn.close()
