"""M17 - attack-surface score (0-100) with trend.

Direction: **100 = healthiest, 0 = worst**.

    penalty (total, capped to 100)
      findings   = 55 * (1 - exp(-raw / 30)),  raw = sum(sev_weight * (0.5 + risk/100))
                   sev_weight: critical 8, high 4, medium 1.5, low 0.5, info 0; missing risk -> 50
                   (saturating, so 1000 low findings cannot hide one critical, and more findings never help)
      kev        = min(20, 7 * internet-facing KEV findings + 3 * internal KEV findings)
      unresolved = min(10, 2 * open findings with risk >= 70)
      exposure   = min(5, 0.25 * internet-facing assets)
      coverage   = 5 * (1 - versioned_technologies / technologies)   (unknown versions hide risk)
      drift      = min(5, 0.5 * (new findings + new hosts + new open ports since the previous run))
    score = clamp(100 - penalty, 0, 100), 1 decimal

Trend vs the previous stored run: delta >= +2 improving, delta <= -2 worsening, else stable
(first run: stable).  ``reasons`` lists every non-zero penalty.  Deterministic: no randomness,
no clock inputs.  One row per scan/monitor run is stored in ``attack_surface_scores``.
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

from . import p4data
from .dbutil import fetch_all, fetch_one, has_table

__all__ = ["AttackSurfaceInputs", "AttackSurfaceScore", "compute_score", "collect_inputs", "record_score",
           "history", "latest_score", "posture_for_report", "SEVERITY_WEIGHT", "TREND_THRESHOLD"]

SEVERITY_WEIGHT = {"critical": 8.0, "high": 4.0, "medium": 1.5, "low": 0.5, "info": 0.0}
TREND_THRESHOLD = 2.0
CLOSED = ("fixed", "resolved", "closed", "false_positive", "accepted")


@dataclass
class AttackSurfaceInputs:
    findings: List[Dict[str, Any]] = field(default_factory=list)   # key, severity, risk, kev, internet_facing, open
    internet_assets: int = 0
    total_assets: int = 0
    technologies: int = 0
    versioned_technologies: int = 0
    finding_keys: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)

    def snapshot(self) -> Dict[str, Any]:
        return {"finding_keys": sorted(self.finding_keys)[:5000], "hosts": sorted(self.hosts), "ports": sorted(self.ports),
                "internet_assets": self.internet_assets, "total_assets": self.total_assets, "technologies": self.technologies,
                "versioned_technologies": self.versioned_technologies, "open_findings": len([f for f in self.findings if f.get("open", True)])}


@dataclass
class AttackSurfaceScore:
    score: float
    previous_score: Optional[float]
    delta: Optional[float]
    trend: str
    reasons: List[str]
    penalties: Dict[str, float] = field(default_factory=dict)
    grade: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def _grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def compute_score(inputs: AttackSurfaceInputs, previous: Optional[Dict[str, Any]] = None,
                  previous_score: Optional[float] = None) -> AttackSurfaceScore:
    reasons: List[str] = []
    open_f = [f for f in inputs.findings if f.get("open", True)]
    raw = 0.0
    for f in open_f:
        risk = f.get("risk")
        risk = 50.0 if risk is None else max(0.0, min(100.0, float(risk)))
        raw += SEVERITY_WEIGHT.get(str(f.get("severity", "info")).lower(), 0.0) * (0.5 + risk / 100.0)
    p_find = 55.0 * (1.0 - math.exp(-raw / 30.0))
    kev_ext = sum(1 for f in open_f if f.get("kev") and f.get("internet_facing", True))
    kev_int = sum(1 for f in open_f if f.get("kev") and not f.get("internet_facing", True))
    p_kev = min(20.0, 7.0 * kev_ext + 3.0 * kev_int)
    unresolved = sum(1 for f in open_f if (f.get("risk") or 0) >= 70)
    p_unres = min(10.0, 2.0 * unresolved)
    p_exp = min(5.0, 0.25 * inputs.internet_assets)
    cov = (inputs.versioned_technologies / inputs.technologies) if inputs.technologies else 1.0
    p_cov = 5.0 * (1.0 - min(1.0, max(0.0, cov)))
    drift = 0
    if previous:
        drift = (len(set(inputs.finding_keys) - set(previous.get("finding_keys", []))) +
                 len(set(inputs.hosts) - set(previous.get("hosts", []))) +
                 len(set(inputs.ports) - set(previous.get("ports", []))))
    p_drift = min(5.0, 0.5 * drift)
    pens = {"findings": p_find, "kev": p_kev, "unresolved_high_risk": p_unres, "exposure": p_exp, "coverage": p_cov, "drift": p_drift}
    if p_find:
        reasons.append(f"-{p_find:.1f}: {len(open_f)} open finding(s), weighted severity/risk {raw:.1f}")
    if p_kev:
        reasons.append(f"-{p_kev:.1f}: {kev_ext} internet-facing and {kev_int} internal known-exploited (KEV) finding(s)")
    if p_unres:
        reasons.append(f"-{p_unres:.1f}: {unresolved} unresolved finding(s) with risk >= 70")
    if p_exp:
        reasons.append(f"-{p_exp:.1f}: {inputs.internet_assets} internet-facing asset(s)")
    if p_cov:
        reasons.append(f"-{p_cov:.1f}: version coverage {cov:.0%} ({inputs.versioned_technologies}/{inputs.technologies} technologies)")
    if p_drift:
        reasons.append(f"-{p_drift:.1f}: {drift} new finding/host/port since the previous run")
    score = round(max(0.0, min(100.0, 100.0 - sum(pens.values()))), 1)
    if not reasons:
        reasons.append("no open findings or exposure penalties")
    prev = previous_score
    delta = None if prev is None else round(score - prev, 1)
    trend = "stable" if delta is None else "improving" if delta >= TREND_THRESHOLD else "worsening" if delta <= -TREND_THRESHOLD else "stable"
    if prev is None:
        reasons.append("first recorded run - no trend yet")
    else:
        reasons.append(f"{trend}: {prev:.1f} -> {score:.1f} ({delta:+.1f})")
    return AttackSurfaceScore(score, prev, delta, trend, reasons, {k: round(v, 2) for k, v in pens.items()}, _grade(score))


def collect_inputs(conn: sqlite3.Connection, target: str = "*") -> AttackSurfaceInputs:
    scan_ids: Optional[Set[int]] = None
    if target != "*" and has_table(conn, "scans"):
        scan_ids = {r["id"] for r in fetch_all(conn, "SELECT id FROM scans WHERE target=?", (target,))}

    def scoped(rows):
        return rows if scan_ids is None else [r for r in rows if r.get("scan_id") in scan_ids]

    assets = scoped(p4data.load_assets(conn))
    ctx = {str(a["host"]): a for a in assets if a.get("host")}
    facing = {h: str(a.get("internet_facing", 1)).lower() not in ("0", "false") for h, a in ctx.items()}
    techs = scoped(p4data.load_technologies(conn))
    services = scoped(p4data.load_services(conn))
    findings = scoped(p4data.load_findings(conn))
    inp = AttackSurfaceInputs()
    inp.total_assets = len(ctx)
    inp.internet_assets = sum(1 for v in facing.values() if v)
    inp.hosts = sorted(ctx)
    inp.technologies = len(techs)
    inp.versioned_technologies = sum(1 for t in techs if str(t.get("version") or "").strip() not in ("", "*", "-"))
    inp.ports = sorted(f"{s.get('host')}:{s.get('port')}" for s in services if str(s.get("state") or "open").lower() == "open")
    for f in findings:
        key = str(f.get("dedup_key") or f"id:{f.get('id')}")
        is_open = str(f.get("status") or "open").lower() not in CLOSED
        host = str(f.get("host") or "")
        inp.findings.append({"key": key, "severity": str(f.get("severity") or "info").lower(), "risk": f.get("risk_score"),
                             "kev": bool(int(f.get("kev") or 0)), "internet_facing": facing.get(host, True), "open": is_open})
        if is_open:
            inp.finding_keys.append(key)
    return inp


def latest_score(conn: sqlite3.Connection, target: str = "*") -> Optional[Dict[str, Any]]:
    if not has_table(conn, "attack_surface_scores"):
        return None
    r = fetch_one(conn, "SELECT * FROM attack_surface_scores WHERE target=? ORDER BY id DESC LIMIT 1", (target,))
    if r:
        r["reasons"] = json.loads(r["reasons"] or "[]")
        r["inputs"] = json.loads(r["inputs"] or "{}")
    return r


def history(conn: sqlite3.Connection, target: str = "*", limit: int = 20) -> List[Dict[str, Any]]:
    if not has_table(conn, "attack_surface_scores"):
        return []
    rows = fetch_all(conn, "SELECT id, target, run_type, run_ref, score, previous_score, delta, trend, created_at FROM attack_surface_scores WHERE target=? ORDER BY id DESC LIMIT ?", (target, limit))
    return rows


def record_score(conn: sqlite3.Connection, *, target: str = "*", run_type: str = "monitor", run_ref: Optional[int] = None,
                 persist: bool = True) -> AttackSurfaceScore:
    """Compute the score for the current stored data, compare with the previous run and (optionally) store it."""
    inputs = collect_inputs(conn, target)
    prev = latest_score(conn, target)
    result = compute_score(inputs, prev["inputs"] if prev else None, prev["score"] if prev else None)
    if persist:
        conn.execute("INSERT INTO attack_surface_scores(target,run_type,run_ref,score,previous_score,delta,trend,reasons,inputs) VALUES (?,?,?,?,?,?,?,?,?)",
                     (target, run_type, run_ref, result.score, result.previous_score, result.delta, result.trend,
                      json.dumps(result.reasons), json.dumps(inputs.snapshot())))
        conn.commit()
    return result


def posture_for_report(conn: sqlite3.Connection, target: str = "*", *, persist: bool = False) -> Dict[str, Any]:
    """Drop-in replacement for the placeholder ``_preliminary_posture_score()`` (returns a plain dict)."""
    r = record_score(conn, target=target, run_type="report", persist=persist)
    d = r.to_dict()
    d["direction"] = "100 = healthiest, 0 = worst"
    return d
