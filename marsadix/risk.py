"""M15 - context-aware risk score (0-100) and Top-N remediation list.

Difference from ``matching/priority.py``: priority knows only the *vulnerability*
(CVSS, EPSS, KEV, confidence).  Risk adds *where it lives*.

    risk = 0.70 * priority.score
         + exposure        internet-facing: +15 (direct)  / +8 (behind a CDN/WAF)
                           not internet-facing (internal): -10
         + criticality     critical +8 / high +4 / medium 0 / low -4
         + kev_exposed     +7 when the CVE is in CISA KEV *and* the asset is internet-facing
    clamped to [0, 100], rounded to 1 decimal.

CDN note: a CDN/WAF adds friction but does not fix an application vulnerability and the
origin is often still reachable, so exposure is reduced (15 -> 8), not removed.

Every term is in ``reasons``.  Levels: >=80 critical, >=60 high, >=35 medium, else low.

``top_fixes`` groups findings that are fixed by the same action (same host + product),
ranks groups by ``(max risk + 0.1 * sum(other risks, capped at 10)) * effort_factor`` where
effort_factor is low 1.00 / medium 0.90 / high 0.80 (risk dominates; effort breaks near ties).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .matching.models import CVE, Asset, Confidence, Priority
from .matching.priority import compute_priority, level_for_score
from .remediation_db import GENERIC_ENTRY, RemediationEntry

__all__ = ["Risk", "RiskedFinding", "TopFix", "compute_risk", "assess", "top_fixes", "EFFORT_FACTOR", "finding_from_row"]

PRIORITY_WEIGHT = 0.70
EXPOSURE_DIRECT, EXPOSURE_CDN, EXPOSURE_INTERNAL = 15.0, 8.0, -10.0
CRITICALITY_POINTS = {"critical": 8.0, "high": 4.0, "medium": 0.0, "low": -4.0}
KEV_EXPOSED_BONUS = 7.0
EFFORT_FACTOR = {"low": 1.0, "medium": 0.9, "high": 0.8}


@dataclass(frozen=True)
class Risk:
    score: float
    level: str
    reasons: Tuple[str, ...]


def compute_risk(priority: Priority, *, internet_facing: bool = True, behind_cdn: bool = False,
                 criticality: str = "medium", kev: bool = False) -> Risk:
    reasons = [f"base priority {priority.score:.1f} ({priority.level.label}) x {PRIORITY_WEIGHT} = {priority.score * PRIORITY_WEIGHT:.1f}"]
    score = priority.score * PRIORITY_WEIGHT
    if internet_facing and behind_cdn:
        pts, why = EXPOSURE_CDN, "internet-facing behind CDN/WAF (reduced exposure)"
    elif internet_facing:
        pts, why = EXPOSURE_DIRECT, "internet-facing, directly reachable"
    else:
        pts, why = EXPOSURE_INTERNAL, "not internet-facing (internal only)"
    score += pts
    reasons.append(f"{why} {pts:+.0f}")
    crit = (criticality or "medium").lower()
    crit = crit if crit in CRITICALITY_POINTS else "medium"
    score += CRITICALITY_POINTS[crit]
    reasons.append(f"asset criticality {crit} {CRITICALITY_POINTS[crit]:+.0f}")
    if kev and internet_facing:
        score += KEV_EXPOSED_BONUS
        reasons.append(f"known-exploited CVE on an internet-facing asset {KEV_EXPOSED_BONUS:+.0f}")
    score = round(max(0.0, min(100.0, score)), 1)
    return Risk(score, level_for_score(score).label, tuple(reasons))


@dataclass
class RiskedFinding:
    cve_id: str
    host: str
    product: str = ""
    version: str = ""
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: bool = False
    confidence: Confidence = Confidence.LOW
    priority: Optional[Priority] = None
    risk: Optional[Risk] = None
    description: str = ""
    internet_facing: bool = True
    behind_cdn: bool = False
    criticality: str = "medium"
    remediation: Optional[RemediationEntry] = None
    finding_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id, "host": self.host, "product": self.product, "version": self.version,
            "cvss": self.cvss, "epss": self.epss, "kev": self.kev, "confidence": self.confidence.label,
            "priority_score": self.priority.score if self.priority else None,
            "priority_level": self.priority.level.label if self.priority else None,
            "risk_score": self.risk.score if self.risk else None, "risk_level": self.risk.level if self.risk else None,
            "risk_reasons": list(self.risk.reasons) if self.risk else [],
            "internet_facing": self.internet_facing, "behind_cdn": self.behind_cdn, "criticality": self.criticality,
            "remediation": self.remediation.fix_text if self.remediation else None,
            "effort": self.remediation.effort if self.remediation else None,
        }


def assess(cve: CVE, asset: Asset, confidence: Confidence, priority: Optional[Priority] = None) -> Tuple[Priority, Risk]:
    priority = priority or compute_priority(cve.cvss, cve.epss, bool(cve.kev), confidence)
    return priority, compute_risk(priority, internet_facing=asset.internet_facing, behind_cdn=asset.behind_cdn,
                                  criticality=asset.criticality, kev=bool(cve.kev))


def _truthy(v: Any, default: bool) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes") if isinstance(v, str) else bool(v)


def finding_from_row(row: Mapping[str, Any], asset_row: Optional[Mapping[str, Any]] = None,
                     remediation: Optional[RemediationEntry] = None) -> RiskedFinding:
    """Rebuild a RiskedFinding (and recompute priority/risk deterministically) from a stored finding row."""
    asset_row = asset_row or {}
    conf = Confidence.coerce(row.get("confidence"))
    cvss = row.get("cvss")
    epss = row.get("epss")
    kev = _truthy(row.get("kev"), False)
    pr = compute_priority(None if cvss is None else float(cvss), None if epss is None else float(epss), kev, conf)
    facing = _truthy(asset_row.get("internet_facing"), True)
    cdn = asset_row.get("behind_cdn")
    cdn = (_truthy(cdn, False) if cdn is not None
           else bool(_truthy(asset_row.get("is_cdn"), False) or asset_row.get("cdn") or asset_row.get("cdn_name")))
    crit = str(asset_row.get("criticality") or "medium").lower()
    return RiskedFinding(
        cve_id=str(row.get("cve_id") or row.get("title") or ""), host=str(row.get("host") or ""),
        product=str(row.get("product") or ""), version=str(row.get("version") or ""), cvss=cvss, epss=epss, kev=kev,
        confidence=conf, priority=pr, risk=compute_risk(pr, internet_facing=facing, behind_cdn=cdn, criticality=crit, kev=kev),
        description=str(row.get("description") or ""), internet_facing=facing, behind_cdn=cdn, criticality=crit,
        remediation=remediation, finding_id=row.get("id"))


@dataclass
class TopFix:
    cve_id: str
    cve_ids: List[str]
    host: str
    risk_score: float
    reason: str
    action: str
    effort: str
    rank_score: float
    fixes_count: int
    title: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def top_fixes(findings: Iterable[RiskedFinding], limit: int = 10) -> List[TopFix]:
    groups: Dict[Tuple[str, str], List[RiskedFinding]] = {}
    for f in findings:
        if f.risk is None:
            continue
        groups.setdefault((f.host, (f.product or f.cve_id).lower()), []).append(f)
    out: List[TopFix] = []
    for (host, _), items in groups.items():
        items.sort(key=lambda f: (-f.risk.score, f.cve_id))
        top = items[0]
        rem = top.remediation or GENERIC_ENTRY
        others = sum(f.risk.score for f in items[1:])
        rank = (top.risk.score + 0.1 * min(others, 100.0)) * EFFORT_FACTOR.get(rem.effort, 0.9)
        bits = []
        if top.kev:
            bits.append("known exploited (KEV)")
        bits.append("internet-facing" + (" behind CDN" if top.behind_cdn else "") if top.internet_facing else "internal asset")
        if top.cvss is not None:
            bits.append(f"CVSS {top.cvss:.1f}")
        if top.epss is not None:
            bits.append(f"EPSS {top.epss:.2f}")
        if len(items) > 1:
            bits.append(f"fixing this also resolves {len(items) - 1} other CVE(s)")
        out.append(TopFix(top.cve_id, [f.cve_id for f in items], host, top.risk.score, "; ".join(bits), rem.fix_text,
                          rem.effort, round(rank, 2), len(items), rem.title))
    out.sort(key=lambda t: (-t.rank_score, -t.risk_score, t.host, t.cve_id))
    return out[: max(0, limit)]
