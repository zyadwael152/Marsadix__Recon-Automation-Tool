"""Report glue for M15-M19: risk table, Top-N fixes, misconfiguration patterns, attack-surface score,
remediation text.  Used by ``reports/generate.py`` (HTML/JSON) and ``reports/export.py`` (JSON/CSV/SARIF).

All functions are read-only by default (no DB writes) and use only stored data.
"""
from __future__ import annotations

import html
import sqlite3
from typing import Any, Dict, List, Optional

from .. import attack_surface, p4data, patterns as pat, remediation_db
from ..risk import RiskedFinding, finding_from_row, top_fixes

__all__ = ["collect_risked_findings", "build_p4_report_data", "render_p4_html", "augment_report_json", "p4_csv_rows",
           "sarif_results"]

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def collect_risked_findings(conn: sqlite3.Connection, target: str = "*") -> List[RiskedFinding]:
    ctx = p4data.asset_context(conn)
    out = []
    rows = p4data.scope_rows(p4data.load_findings(conn, source="monitor", open_only=True), p4data.target_scan_ids(conn, target))
    for row in rows:
        if not row.get("cve_id"):
            continue
        rem = remediation_db.lookup(conn, {"cve_id": row["cve_id"], "title": row.get("title"), "description": row.get("description"),
                                           "product": row.get("product")})
        out.append(finding_from_row(row, ctx.get(str(row.get("host"))), rem))
    out.sort(key=lambda f: (-(f.risk.score if f.risk else 0), f.host, f.cve_id))
    return out


def build_p4_report_data(conn: sqlite3.Connection, target: str = "*", top: int = 10, record: bool = False) -> Dict[str, Any]:
    risked = collect_risked_findings(conn, target)
    levels: Dict[str, int] = {}
    for f in risked:
        levels[f.risk.level] = levels.get(f.risk.level, 0) + 1
    found = pat.hunt(pat.load_pattern_data(conn, target=target))
    patterns_out = []
    for p in found:
        rem = remediation_db.lookup(conn, {"skill": p.remediation_key, "owasp": p.owasp, "title": p.title})
        d = p.to_dict()
        d["remediation"] = rem.fix_text
        d["effort"] = rem.effort
        patterns_out.append(d)
    return {
        "risk": {"findings": [f.to_dict() for f in risked], "by_level": levels},
        "top_fixes": [t.to_dict() for t in top_fixes(risked, top)],
        "patterns": patterns_out,
        "attack_surface": attack_surface.posture_for_report(conn, target, persist=record),
    }


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def render_p4_html(data: Dict[str, Any]) -> str:
    a = data["attack_surface"]
    arrow = {"improving": "▲ improving", "worsening": "▼ worsening", "stable": "● stable"}.get(a["trend"], a["trend"])
    delta = "" if a.get("delta") is None else f" ({a['delta']:+.1f} vs previous {a['previous_score']:.1f})"
    parts = [f'<section id="marsadix-p4"><h2>Attack surface score</h2>'
             f'<p><strong>{a["score"]:.1f}/100</strong> grade {_e(a["grade"])} - {_e(arrow)}{_e(delta)} '
             f'<small>({_e(a["direction"])})</small></p><ul>' + "".join(f"<li>{_e(r)}</li>" for r in a["reasons"]) + "</ul>"]
    parts.append("<h2>Top fixes</h2><table><tr><th>#</th><th>CVE</th><th>Host</th><th>Risk</th><th>Why</th><th>Action</th><th>Effort</th></tr>")
    for i, t in enumerate(data["top_fixes"], 1):
        parts.append(f"<tr><td>{i}</td><td>{_e(t['cve_id'])}</td><td>{_e(t['host'])}</td><td>{t['risk_score']:.1f}</td>"
                     f"<td>{_e(t['reason'])}</td><td>{_e(t['action'])}</td><td>{_e(t['effort'])}</td></tr>")
    parts.append("</table><h2>CVE risk</h2><table><tr><th>CVE</th><th>Host</th><th>Product</th><th>Risk</th><th>Priority</th><th>Remediation</th></tr>")
    for f in data["risk"]["findings"]:
        parts.append(f"<tr><td>{_e(f['cve_id'])}</td><td>{_e(f['host'])}</td><td>{_e(f['product'])} {_e(f['version'])}</td>"
                     f"<td>{f['risk_score']:.1f} ({_e(f['risk_level'])})</td><td>{f['priority_score']:.1f}</td><td>{_e(f['remediation'])}</td></tr>")
    parts.append("</table><h2>Misconfiguration patterns</h2><table><tr><th>Severity</th><th>Rule</th><th>Host</th><th>Status</th><th>Evidence</th><th>Remediation</th></tr>")
    for p in data["patterns"]:
        parts.append(f"<tr><td>{_e(p['severity'])}</td><td>{_e(p['title'])}</td><td>{_e(p['host'])}</td><td>{_e(p['status'])}</td>"
                     f"<td>{_e('; '.join(p['evidence'])[:400])}</td><td>{_e(p['remediation'])}</td></tr>")
    parts.append("</table></section>")
    return "".join(parts)


def augment_report_json(report: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(report)
    out["risk"] = data["risk"]
    out["top_fixes"] = data["top_fixes"]
    out["patterns"] = data["patterns"]
    out["attack_surface"] = data["attack_surface"]
    return out


def p4_csv_rows(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for f in data["risk"]["findings"]:
        rows.append({"type": "cve", "id": f["cve_id"], "host": f["host"], "severity": f["priority_level"], "risk_score": f["risk_score"],
                     "priority_score": f["priority_score"], "cvss": f["cvss"], "epss": f["epss"], "kev": f["kev"],
                     "confidence": f["confidence"], "status": "open", "remediation": f["remediation"], "effort": f["effort"]})
    for p in data["patterns"]:
        rows.append({"type": "pattern", "id": p["rule_id"], "host": p["host"], "severity": p["severity"], "risk_score": "", "priority_score": "",
                     "cvss": "", "epss": "", "kev": "", "confidence": p["confidence"], "status": p["status"],
                     "remediation": p["remediation"], "effort": p["effort"]})
    return rows


def sarif_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    res = []
    for f in data["risk"]["findings"]:
        res.append({"ruleId": f["cve_id"], "level": _SARIF_LEVEL.get(f["risk_level"], "warning"),
                    "message": {"text": f"{f['cve_id']} on {f['host']} ({f['product']} {f['version']}): risk {f['risk_score']}"},
                    "locations": [{"logicalLocations": [{"name": f["host"], "kind": "host"}]}],
                    "properties": {"risk_score": f["risk_score"], "kev": f["kev"], "confidence": f["confidence"], "remediation": f["remediation"]}})
    for p in data["patterns"]:
        res.append({"ruleId": p["rule_id"], "level": _SARIF_LEVEL.get(p["severity"], "warning"),
                    "message": {"text": f"{p['title']}: {'; '.join(p['evidence'])[:300]}"},
                    "locations": [{"logicalLocations": [{"name": p["host"], "kind": "host"}]}],
                    "properties": {"status": p["status"], "owasp": p["owasp"], "confidence": p["confidence"], "remediation": p["remediation"]}})
    return res
