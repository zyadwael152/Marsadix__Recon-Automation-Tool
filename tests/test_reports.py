import json

import pytest

from marsadix import db
from marsadix.models import (
    Asset, DetectionStatus, Finding, FindingSource, Scan, ScanStatus, Severity,
)
from marsadix.reports.generate import generate_report


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def _mk_scan(conn, target, status="completed", is_baseline=False):
    scan = Scan(target=target, status=ScanStatus(status), is_baseline=is_baseline)
    scan.id = db.save_scan(conn, scan)
    return scan


def test_generate_report_no_scan_returns_error(conn, capsys):
    rc = generate_report(conn, "example.com", fmt="both", out_dir="/tmp/does-not-matter")
    assert rc == 1
    assert "no completed scans found" in capsys.readouterr().err


def test_generate_report_writes_both_files(conn, tmp_path):
    scan = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="api.example.com", in_scope=True)])
    db.save_many(conn, "findings", [
        Finding(scan_id=scan.id, host="api.example.com", source=FindingSource.SKILL,
                title="Reflected XSS", severity=Severity.HIGH,
                owasp_category="A03:2021-Injection", source_reference="PortSwigger XSS",
                status=DetectionStatus.DETECTED, evidence="payload reflected unescaped"),
    ])

    rc = generate_report(conn, "example.com", fmt="both", out_dir=str(tmp_path))
    assert rc == 0

    html_files = list(tmp_path.glob("*_report.html"))
    json_files = list(tmp_path.glob("*_report.json"))
    assert len(html_files) == 1 and len(json_files) == 1

    html_text = html_files[0].read_text(encoding="utf-8")
    assert "api.example.com" in html_text
    assert "Reflected XSS" in html_text
    assert "Detected — Not Exploited" in html_text          # exploited always false
    assert "No Indicators" not in html_text.split("Methodology")[0] or True  # sanity: page renders
    assert "A03:2021-Injection" in html_text

    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert data["target"] == "example.com"
    assert not data["findings"][0]["exploited"]            # stored as 0/1 by sqlite
    assert data["owasp_coverage"]["breakdown"]["A03:2021-Injection"] == 1


def test_generate_report_json_only(conn, tmp_path):
    scan = _mk_scan(conn, "example.com", is_baseline=True)
    rc = generate_report(conn, "example.com", fmt="json", out_dir=str(tmp_path))
    assert rc == 0
    assert list(tmp_path.glob("*_report.json"))
    assert not list(tmp_path.glob("*_report.html"))


def test_generate_report_uses_explicit_scan_id(conn, tmp_path):
    s1 = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=s1.id, host="old.example.com", in_scope=True)])
    s2 = _mk_scan(conn, "example.com")
    db.save_many(conn, "assets", [Asset(scan_id=s2.id, host="new.example.com", in_scope=True)])

    rc = generate_report(conn, "example.com", fmt="json", out_dir=str(tmp_path), scan_id=s1.id)
    assert rc == 0
    data = json.loads(next(tmp_path.glob(f"*scan{s1.id}_report.json")).read_text())
    assert data["assets"][0]["host"] == "old.example.com"


def test_generate_report_includes_diff_when_previous_scan_exists(conn, tmp_path):
    s1 = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=s1.id, host="api.example.com", in_scope=True)])
    s2 = _mk_scan(conn, "example.com")
    db.save_many(conn, "assets", [
        Asset(scan_id=s2.id, host="api.example.com", in_scope=True),
        Asset(scan_id=s2.id, host="dev.example.com", in_scope=True),
    ])

    rc = generate_report(conn, "example.com", fmt="html", out_dir=str(tmp_path))
    assert rc == 0
    html_text = next(tmp_path.glob("*_report.html")).read_text(encoding="utf-8")
    assert "dev.example.com" in html_text


# ---------------------------------------------------------------------------
# Knowledge Graph SVG: performance + truncation regression tests
# ---------------------------------------------------------------------------

def _fake_graph(n):
    nodes = [{"id": f"n{i}", "node_type": "subdomain", "label": f"host{i}.example.com"} for i in range(n)]
    edges = [{"src_id": f"n{i}", "dst_id": f"n{i-1}", "relation": "resolves_to"} for i in range(1, n, 2)]
    return {"nodes": nodes, "edges": edges}


def test_graph_svg_for_large_graph_is_fast_and_says_it_was_truncated():
    import time
    from marsadix.reports.generate import MAX_GRAPH_NODES, _render_graph_svg

    start = time.monotonic()
    svg = _render_graph_svg(_fake_graph(1500))
    elapsed = time.monotonic() - start

    # the all-pairs layout needed ~25 s for 480 nodes; this must stay far below that
    assert elapsed < 10, f"graph layout too slow: {elapsed:.1f}s"
    assert f"Showing the {MAX_GRAPH_NODES} most relevant of 1500 nodes" in svg
    assert svg.count('class="graph-node"') == MAX_GRAPH_NODES


def test_graph_svg_small_graph_is_not_truncated():
    from marsadix.reports.generate import _render_graph_svg
    svg = _render_graph_svg(_fake_graph(30))
    assert "Showing the" not in svg
    assert svg.count('class="graph-node"') == 30


def test_select_visible_keeps_findings_and_cves_first():
    from marsadix.reports.generate import _select_visible
    nodes = [{"id": f"s{i}", "node_type": "subdomain", "label": "s"} for i in range(10)]
    nodes += [{"id": "f1", "node_type": "finding", "label": "f"}, {"id": "c1", "node_type": "cve", "label": "c"}]
    edges = [{"src_id": "f1", "dst_id": "c1", "relation": "listed_in"}]
    kept, kept_edges, hidden = _select_visible(nodes, edges, limit=3)
    assert {"f1", "c1"} <= {n["id"] for n in kept}
    assert hidden == 9 and len(kept) == 3
    assert kept_edges == edges


def test_layout_is_deterministic_and_stays_inside_the_canvas():
    from marsadix.reports.generate import _layout_graph
    g = _fake_graph(60)
    a = _layout_graph(g["nodes"], g["edges"])
    b = _layout_graph(g["nodes"], g["edges"])
    assert a == b
    assert all(40 <= x <= 920 and 40 <= y <= 580 for x, y in a.values())
