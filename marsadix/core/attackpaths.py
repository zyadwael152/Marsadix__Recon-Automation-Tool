"""
Attack paths, the Attack Path Time Machine (C17) and `marsadix investigate` (C21).

An attack path is a chain through the Knowledge Graph from an internet-facing
subdomain to something that can hurt:

    subdomain -> port -> service -> cpe -> ...         (what it exposes / runs)
    subdomain -> technology -> cve                      (an outdated component)
    subdomain -> finding                                (a detection on that host)

Only "exposure" relations are followed (exposes, runs, has_cpe, uses,
affected_by, found_on). Pure infrastructure links (resolves_to, belongs_to,
behind) are NOT part of a path: two hosts sharing an IP is a blast-radius fact
(`marsadix graph`), not an attack path.

One shortest path is kept per (subdomain, target) pair, so the numbers stay
readable and two scans can be compared by plain set difference of path strings.
"""

from __future__ import annotations

import json
import sys
from collections import deque
from typing import Dict, List, Optional

from .. import db
from .graph import _n_subdomain, blast_radius, build_graph

_FORWARD = {"exposes", "runs", "has_cpe", "uses", "affected_by"}
_RISK_TYPES = {"cve", "finding"}
MAX_HOPS = 6


def compute_attack_paths(graph: dict, max_hops: int = MAX_HOPS) -> List[List[str]]:
    """Shortest exposure path from every subdomain to every reachable cve/finding node."""
    types = {n["id"]: n.get("node_type") for n in graph.get("nodes", [])}
    adj: Dict[str, List[str]] = {}
    for e in graph.get("edges", []):
        rel = e.get("relation")
        if rel in _FORWARD:
            adj.setdefault(e["src_id"], []).append(e["dst_id"])
        elif rel == "found_on":                       # finding -> subdomain; walk it as subdomain -> finding
            adj.setdefault(e["dst_id"], []).append(e["src_id"])
    paths: List[List[str]] = []
    for start in sorted(i for i, t in types.items() if t == "subdomain"):
        prev = {start: None}
        queue = deque([(start, 0)])
        while queue:
            node, depth = queue.popleft()
            if depth >= max_hops:
                continue
            for nxt in sorted(adj.get(node, [])):
                if nxt in prev:
                    continue
                prev[nxt] = node
                queue.append((nxt, depth + 1))
        for node in sorted(prev):
            if node != start and types.get(node) in _RISK_TYPES:
                chain, cur = [], node
                while cur is not None:
                    chain.append(cur)
                    cur = prev[cur]
                paths.append(list(reversed(chain)))
    return paths


def _sig(path: List[str], graph: Optional[dict] = None) -> str:
    """
    Readable, comparable text for one path. Finding nodes are keyed by database id
    (finding:12), which is different in every scan, so when the graph is given they
    are written by title instead: the same finding in two scans is then the SAME path.
    """
    if graph is None:
        return " > ".join(path)
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    return " > ".join(
        f"finding:{nodes[i].get('label')}" if nodes.get(i, {}).get("node_type") == "finding" else i
        for i in path)


def _graph_for(conn, scan_id: int) -> dict:
    g = db.get_graph(conn, scan_id)
    if not g["nodes"]:                                # scan predates / skipped the graph stage
        build_graph(conn, scan_id)
        g = db.get_graph(conn, scan_id)
    return g


def time_machine(conn, target: str, limit: Optional[int] = None) -> List[dict]:
    """
    One entry per COMPLETED scan (oldest first): its paths and what changed since the
    previous entry. {"scan_id", "started_at", "paths": [...], "opened": [...], "closed": [...]}
    """
    scans = conn.execute(
        "SELECT id, started_at FROM scans WHERE target=? AND status='completed' "
        "ORDER BY started_at ASC, id ASC", (target,)).fetchall()
    if limit:
        scans = scans[-limit:]
    out, prev = [], None
    for s in scans:
        graph = _graph_for(conn, s["id"])
        paths = sorted({_sig(p, graph) for p in compute_attack_paths(graph)})
        cur = set(paths)
        out.append({"scan_id": s["id"], "started_at": s["started_at"], "paths": paths,
                    "opened": sorted(cur - prev) if prev is not None else [],
                    "closed": sorted(prev - cur) if prev is not None else []})
        prev = cur
    return out


def run_timemachine(conn, target: str, limit: Optional[int] = None, as_json: bool = False) -> int:
    steps = time_machine(conn, target, limit)
    if not steps:
        print(f"error: no completed scans of {target!r}. Run `marsadix scan {target}` first.", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(steps, indent=2))
        return 0
    print(f"Attack Path Time Machine for {target} ({len(steps)} completed scan(s)):\n")
    for i, st in enumerate(steps):
        change = "  (first snapshot)" if i == 0 else f"  +{len(st['opened'])} opened  -{len(st['closed'])} closed"
        print(f"scan #{st['scan_id']}  {st['started_at']}  paths: {len(st['paths'])}{change}")
        for p in st["opened"]:
            print(f"    + {p}")
        for p in st["closed"]:
            print(f"    - {p}")
    if len(steps) == 1:
        print("\nOnly one completed scan so far: run another scan later to see how paths change.")
    return 0


# -------------------------------------------------------------- investigate
def run_investigate(conn, target: str, host: str, scan_id: Optional[int] = None) -> int:
    """Everything known about ONE host: its data in a scan, paths through it, blast radius, history."""
    host = host.strip().lower().rstrip(".")
    if scan_id is None:
        latest = (db.get_latest_scans(conn, target, limit=1, completed_only=True)
                  or db.get_latest_scans(conn, target, limit=1))
        if not latest:
            print(f"error: no scans of {target!r}. Run `marsadix scan {target}` first.", file=sys.stderr)
            return 1
        scan_id = latest[0]["id"]
    elif conn.execute("SELECT 1 FROM scans WHERE id=? AND target=?", (scan_id, target)).fetchone() is None:
        print(f"error: scan #{scan_id} is not a scan of {target!r}.", file=sys.stderr)
        return 1

    asset = next((dict(a) for a in db.get_assets(conn, scan_id) if a["host"] == host), None)
    if asset is None:
        print(f"error: {host!r} is not an asset of {target!r} in scan #{scan_id}.", file=sys.stderr)
        return 1

    print(f"Investigation: {host}  (target {target}, scan #{scan_id})\n")
    print("Asset")
    print(f"  IP: {asset.get('ip') or '-'}   in scope: {'yes' if asset.get('in_scope') else 'no'}   "
          f"CDN: {asset.get('cdn_name') or ('yes' if asset.get('is_cdn') else 'no')}   ASN: {asset.get('asn') or '-'}")
    print(f"  found by: {', '.join(db.get_asset_sources(conn, scan_id, host)) or asset.get('source') or '-'}   "
          f"confidence: {asset.get('confidence_score')}/100   depth: {asset.get('depth')}")

    services = [s for s in db.get_services(conn, scan_id) if s["host"] == host]
    print(f"\nOpen ports / services ({len(services)})")
    for s in sorted(services, key=lambda r: r["port"]):
        prod = " ".join(x for x in (s["name"], s["product"], s["version"]) if x)
        print(f"  {s['port']}/{s['protocol']}  {prod or '-'}")

    techs = [t for t in db.get_technologies(conn, scan_id) if t["host"] == host]
    print(f"\nTechnologies ({len(techs)})")
    for t in techs:
        print(f"  {t['name']} {t['version'] or ''}".rstrip() + f"  [{t['confidence']}]")

    findings = [f for f in db.get_findings(conn, scan_id) if f["host"] == host]
    print(f"\nFindings ({len(findings)})")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}  ({f['status']}, {f['confidence']})"
              + (f"  {f['cve_id']}" if f["cve_id"] else ""))

    node = _n_subdomain(host)
    graph = _graph_for(conn, scan_id)
    paths = [p for p in compute_attack_paths(graph) if p[0] == node]
    print(f"\nAttack paths from this host ({len(paths)})")
    for p in paths:
        print("  " + _sig(p, graph))

    radius = blast_radius(conn, scan_id, node, max_hops=2)
    print(f"\nBlast radius, 2 hops ({len(radius)} node(s))")
    for n in radius[:25]:
        print(f"  {'.' * n['hops']} {n['node_type']}: {n['label']}")
    if len(radius) > 25:
        print(f"  ... and {len(radius) - 25} more (see `marsadix graph`)")

    seen_in = [r["scan_id"] for r in conn.execute(
        "SELECT DISTINCT a.scan_id FROM assets a JOIN scans s ON s.id=a.scan_id "
        "WHERE s.target=? AND a.host=? ORDER BY a.scan_id", (target, host))]
    print(f"\nHistory: seen in {len(seen_in)} scan(s): {', '.join('#' + str(i) for i in seen_in)}")
    return 0
