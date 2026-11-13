"""M10 - deterministic 0-100 priority score (no asset context; see risk.py).

score = 6.0 * cvss            (0-60; missing CVSS -> DEFAULT_CVSS, with a reason)
      + 20.0 * epss           (0-20; EPSS is a probability 0..1; missing -> 0)
      + 20 if KEV             (known exploited)
      + confidence modifier   (HIGH +5, MEDIUM 0, LOW -10)
clamped to [0, 100], rounded to 1 decimal.

Levels: >=80 CRITICAL, >=60 HIGH, >=35 MEDIUM, else LOW.
KEV forces level >= CRITICAL and a score floor of 80.
Every term is non-decreasing in its input, so the score is monotonic.
"""
from __future__ import annotations

from typing import List, Optional

from .models import CVE, Confidence, Priority, PriorityLevel

__all__ = ["DEFAULT_CVSS", "compute_priority", "priority_for", "level_for_score"]

DEFAULT_CVSS = 5.0
CVSS_WEIGHT = 6.0
EPSS_WEIGHT = 20.0
KEV_BONUS = 20.0
KEV_FLOOR = 80.0
CONFIDENCE_MOD = {Confidence.HIGH: 5.0, Confidence.MEDIUM: 0.0, Confidence.LOW: -10.0}
THRESHOLDS = ((80.0, PriorityLevel.CRITICAL), (60.0, PriorityLevel.HIGH), (35.0, PriorityLevel.MEDIUM))


def level_for_score(score: float) -> PriorityLevel:
    for threshold, level in THRESHOLDS:
        if score >= threshold:
            return level
    return PriorityLevel.LOW


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def compute_priority(cvss: Optional[float], epss: Optional[float], kev: bool,
                     confidence: Confidence) -> Priority:
    reasons: List[str] = []
    if cvss is None:
        cvss_v = DEFAULT_CVSS
        reasons.append(f"CVSS missing - default {DEFAULT_CVSS} assumed")
    else:
        cvss_v = _clamp(float(cvss), 0.0, 10.0)
        reasons.append(f"CVSS {cvss_v:.1f} -> +{cvss_v * CVSS_WEIGHT:.1f}")
    score = cvss_v * CVSS_WEIGHT
    if epss is None:
        reasons.append("EPSS missing - treated as 0")
        epss_v = 0.0
    else:
        epss_v = _clamp(float(epss), 0.0, 1.0)
        reasons.append(f"EPSS {epss_v:.3f} -> +{epss_v * EPSS_WEIGHT:.1f}")
    score += epss_v * EPSS_WEIGHT
    if kev:
        score += KEV_BONUS
        reasons.append(f"in CISA KEV (known exploited) -> +{KEV_BONUS:.0f}")
    conf = Confidence.coerce(confidence)
    mod = CONFIDENCE_MOD[conf]
    score += mod
    reasons.append(f"confidence {conf.label} -> {mod:+.0f}")
    score = _clamp(score, 0.0, 100.0)
    if kev and score < KEV_FLOOR:
        score = KEV_FLOOR
        reasons.append(f"KEV floor applied (score >= {KEV_FLOOR:.0f})")
    score = round(score, 1)
    level = level_for_score(score)
    if kev and level < PriorityLevel.CRITICAL:
        level = PriorityLevel.CRITICAL
    reasons.append(f"level {level.label} (score {score})")
    return Priority(level, score, tuple(reasons))


def priority_for(cve: CVE, confidence: Confidence) -> Priority:
    return compute_priority(cve.cvss, cve.epss, bool(cve.kev), confidence)
