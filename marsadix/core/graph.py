"""
Knowledge Graph  (Core role owns this file; G1 storage lives in db.py).

The relational tables (assets, services, technologies, findings, cves) hold
facts in isolation. This module links them: it reads one scan's facts and
writes graph_nodes/graph_edges rows (db.upsert_graph_node / db.add_graph_edge)
so questions like "what else shares this IP?" or "what breaks if this CVE is
exploited?" have an answer instead of requiring a manual JOIN safari.

Two entry points:

    run_stage(ctx)
        Pipeline stage "graph", runs automatically after "track" at the end
        of every scan (see STAGES in core/pipeline.py). Silently (re)builds
        the graph for the scan that just finished. Safe to re-run: node/edge
        writes are idempotent (INSERT OR REPLACE / INSERT OR IGNORE).

    run_graph(conn, target, scan_id=None) -> int
        Entry point for `marsadix graph <target>`. Builds the graph (if not
        already built) then prints a human-readable summary: node/edge
        counts, shared-infrastructure clusters, and -- for every finding
        with a CVE -- what else sits on the same host (blast radius).

Reusable, non-CLI building blocks other code can call directly:

    build_graph(conn, scan_id) -> dict           (G2, the builder itself)
    get_shared_infrastructure(conn, scan_id)      (G3: shared IP/ASN/CDN clusters)
    blast_radius(conn, scan_id, node_id, max_hops)  (G4: what's reachable from a node)

Node ids are deterministic strings ("subdomain:api.example.com",
"cve:CVE-2024-1234"...) so the same real-world entity always maps to the
same node, scan after scan -- that's what makes cross-scan graph queries
possible later (e.g. for the Attack Path Time Machine, C17).
"""

from __future__ import annotations

import logging
import sys
from collections import defaultdict
from typing import Optional

from .. import db

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# node id helpers (deterministic: same entity -> same id, every scan)
# --------------------------------------------------------------------------

def _n_subdomain(host: str) -> str:
    return f"subdomain:{host}"


def _n_ip(ip: str) -> str:
    return f"ip:{ip}"


def _n_asn(asn: str) -> str:
    return f"asn:{asn}"


def _n_cdn(name: str) -> str:
    return f"cdn:{name}"


def _n_port(host: str, port: int) -> str:
    return f"port:{host}:{port}"


def _n_service(host: str, port: int, name: str) -> str:
    return f"service:{host}:{port}:{name}"


def _n_cpe(cpe: str) -> str:
    return f"cpe:{cpe}"


def _n_technology(host: str, name: str) -> str:
    return f"technology:{host}:{name}"


def _n_cve(cve_id: str) -> str:
    return f"cve:{cve_id}"


def _n_finding(finding_id: int) -> str:
    return f"finding:{finding_id}"


# --------------------------------------------------------------------------
# builder (G1 storage + G2 builder)
# --------------------------------------------------------------------------

def build_graph(conn, scan_id: int) -> dict:
    """
    Read one scan's assets/services/technologies/findings and write the
    corresponding nodes/edges. Returns {"nodes": n, "edges": n} written.
    Idempotent: calling this again for the same scan just re-writes the
    same rows (upsert / INSERT OR IGNORE), so it's safe to call from both
    the automatic pipeline stage and the `marsadix graph` CLI command.
    """
    n_nodes = n_edges = 0

    def node(node_id: str, node_type: str, label: str, attrs: Optional[dict] = None) -> str:
        nonlocal n_nodes
        db.upsert_graph_node(conn, node_id, node_type, label, scan_id, attrs)
        n_nodes += 1
        return node_id

    def edge(src: str, dst: str, relation: str) -> None:
        nonlocal n_edges
        db.add_graph_edge(conn, src, dst, relation, scan_id)
        n_edges += 1

    for a in db.get_assets(conn, scan_id):
        host = a["host"]
        sub = node(_n_subdomain(host), "subdomain", host,
                   {"in_scope": bool(a["in_scope"]), "confidence_score": a["confidence_score"]})

        if a["ip"]:
            ip = node(_n_ip(a["ip"]), "ip", a["ip"])
            edge(sub, ip, "resolves_to")
            if a["asn"]:
                asn = node(_n_asn(a["asn"]), "asn", a["asn_owner"] or a["asn"])
                edge(ip, asn, "belongs_to")
        elif a["asn"]:
            asn = node(_n_asn(a["asn"]), "asn", a["asn_owner"] or a["asn"])
            edge(sub, asn, "belongs_to")

        if a["is_cdn"] and a["cdn_name"]:
            cdn = node(_n_cdn(a["cdn_name"]), "cdn", a["cdn_name"])
            edge(sub, cdn, "behind")

    for s in db.get_services(conn, scan_id):
        host, port = s["host"], s["port"]
        sub = _n_subdomain(host)
        p = node(_n_port(host, port), "port", f"{host}:{port}", {"protocol": s["protocol"]})
        edge(sub, p, "exposes")

        if s["name"] or s["product"]:
            svc_label = s["product"] or s["name"]
            svc = node(_n_service(host, port, s["name"] or "service"), "service", svc_label,
                       {"version": s["version"], "banner": s["banner"]})
            edge(p, svc, "runs")
            if s["cpe"]:
                cpe = node(_n_cpe(s["cpe"]), "cpe", s["cpe"])
                edge(svc, cpe, "has_cpe")

    for t in db.get_technologies(conn, scan_id):
        host = t["host"]
        sub = _n_subdomain(host)
        tech = node(_n_technology(host, t["name"]), "technology",
                    f"{t['name']} {t['version']}".strip(),
                    {"cpe": t["cpe"], "category": t["category"]})
        edge(sub, tech, "uses")
        if t["cpe"]:
            cpe = node(_n_cpe(t["cpe"]), "cpe", t["cpe"])
            edge(tech, cpe, "has_cpe")

    for f in db.get_findings(conn, scan_id):
        host = f["host"]
        sub = _n_subdomain(host)
        finding = node(_n_finding(f["id"]), "finding", f["title"],
                       {"severity": f["severity"], "status": f["status"],
                        "owasp_category": f["owasp_category"], "exploited": False})
        edge(finding, sub, "found_on")
        if f["cve_id"]:
            cve = node(_n_cve(f["cve_id"]), "cve", f["cve_id"], {"in_kev": bool(f["in_kev"])})
            edge(finding, cve, "listed_in")
            if f["technology"]:
                edge(_n_technology(host, f["technology"]), cve, "affected_by")
            else:
                edge(sub, cve, "affected_by")

    return {"nodes": n_nodes, "edges": n_edges}


def run_stage(ctx) -> None:
    """Pipeline stage "graph": silently (re)builds the graph after a scan."""
    counts = build_graph(ctx.conn, ctx.scan.id)
    log.info("graph: built %d nodes, %d edges for scan #%s",
              counts["nodes"], counts["edges"], ctx.scan.id)


# --------------------------------------------------------------------------
# queries (G3 shared infrastructure, G4 blast radius)
# --------------------------------------------------------------------------

def get_shared_infrastructure(conn, scan_id: int) -> dict:
    """
    Group subdomains that share the same IP, ASN or CDN. A cluster of size
    1 is not "shared" with anything, so only clusters with 2+ members are
    returned -- these are the interesting ones: forgotten assets on shared
    infrastructure, or signs of the same backend serving several hostnames.
    """
    by_relation: dict[str, dict[str, list[str]]] = {
        "resolves_to": defaultdict(list),   # same IP
        "belongs_to": defaultdict(list),    # same ASN
        "behind": defaultdict(list),        # same CDN
    }
    rows = conn.execute(
        "SELECT src_id, dst_id, relation FROM graph_edges "
        "WHERE scan_id=? AND relation IN ('resolves_to','belongs_to','behind')",
        (scan_id,)).fetchall()
    for r in rows:
        by_relation[r["relation"]][r["dst_id"]].append(r["src_id"])

    clusters = {}
    for relation, groups in by_relation.items():
        shared = {dst: sorted(members) for dst, members in groups.items() if len(members) > 1}
        if shared:
            clusters[relation] = shared
    return clusters


def blast_radius(conn, scan_id: int, node_id: str, max_hops: int = 2) -> list[dict]:
    """
    Breadth-first walk outward from `node_id` up to `max_hops` edges, in
    either direction. Answers "what else is affected if this node is
    compromised / changes?" (the Butterfly Effect / Blast Radius idea, G4)
    without the caller needing to know the graph's shape in advance.
    Returns a list of {"id", "label", "node_type", "hops"} dicts, nearest first.
    """
    seen = {node_id}
    frontier = [node_id]
    out = []
    for hop in range(1, max_hops + 1):
        next_frontier = []
        for nid in frontier:
            for nb in db.get_neighbors(conn, nid, scan_id):
                if nb["id"] in seen:
                    continue
                seen.add(nb["id"])
                next_frontier.append(nb["id"])
                row = conn.execute(
                    "SELECT node_type, label FROM graph_nodes WHERE id=?", (nb["id"],)
                ).fetchone()
                out.append({
                    "id": nb["id"],
                    "label": row["label"] if row else nb["id"],
                    "node_type": row["node_type"] if row else "unknown",
                    "hops": hop,
                })
        frontier = next_frontier
        if not frontier:
            break
    return out


# --------------------------------------------------------------------------
# `marsadix graph <target>` CLI command
# --------------------------------------------------------------------------

def run_graph(conn, target: str, scan_id: Optional[int] = None) -> int:
    """Entry point for `marsadix graph`. Builds + prints a summary. Returns an exit code."""
    if scan_id is None:
        latest = db.get_latest_scans(conn, target, limit=1)
        if not latest:
            print(f"error: no scans found for {target!r}. Run `marsadix scan {target}` first.",
                  file=sys.stderr)
            return 1
        scan_id = latest[0]["id"]

    counts = build_graph(conn, scan_id)
    print(f"Knowledge Graph for {target} (scan #{scan_id}): "
          f"{counts['nodes']} nodes, {counts['edges']} edges")

    type_counts = conn.execute(
        "SELECT node_type, COUNT(*) AS n FROM graph_nodes WHERE scan_id=? "
        "GROUP BY node_type ORDER BY n DESC", (scan_id,)).fetchall()
    if type_counts:
        print("\nNodes by type:")
        for r in type_counts:
            print(f"  {r['node_type']:<12} {r['n']}")

    clusters = get_shared_infrastructure(conn, scan_id)
    if clusters:
        print("\nShared infrastructure:")
        for relation, groups in clusters.items():
            for dst, members in groups.items():
                label = conn.execute(
                    "SELECT label FROM graph_nodes WHERE id=?", (dst,)).fetchone()
                label = label["label"] if label else dst
                print(f"  [{relation}] {label}: {', '.join(members)}")
    else:
        print("\nShared infrastructure: none detected.")

    cve_findings = conn.execute(
        "SELECT id, title, host, cve_id FROM findings "
        "WHERE scan_id=? AND cve_id IS NOT NULL", (scan_id,)).fetchall()
    if cve_findings:
        print("\nBlast radius for CVE-linked findings:")
        for f in cve_findings[:10]:
            radius = blast_radius(conn, scan_id, _n_finding(f["id"]), max_hops=2)
            others = [r["label"] for r in radius if r["node_type"] != "subdomain" or r["label"] != f["host"]]
            print(f"  {f['cve_id']} on {f['host']}: reaches {len(radius)} node(s)"
                  + (f" -> {', '.join(others[:5])}" if others else ""))

    return 0
