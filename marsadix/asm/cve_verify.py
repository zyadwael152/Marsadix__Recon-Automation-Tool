"""
cve_verify.py — Post-Nuclei CVE verification layer (v3.0)
==========================================================
v3.0: بيستخدم version_detect.py بدل الـ detection logic اليدوي.
الـ detection logic كلها انتقلت لـ version_detect.py.
الملف ده مسؤول بس عن:
  1. استدعاء version_detect.detect()
  2. إيجاد الـ version المناسبة للـ CVE
  3. المقارنة بالـ affected range
  4. تحديث الـ Finding confidence
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, List
from urllib.parse import urlsplit
from packaging.version import Version, InvalidVersion

from .version_detect import detect as _detect, DetectionResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CVE affected ranges
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AffectedRange:
    introduced: str
    fixed: str
    component: str         # اسم الـ tech في version_detect

    def is_affected(self, version_str: str) -> Optional[bool]:
        try:
            return Version(self.introduced) <= Version(version_str) < Version(self.fixed)
        except InvalidVersion:
            return None


# قاموس الـ CVEs
# component: نفس الـ name المستخدم في version_detect.py
CVE_RANGES: dict[str, list[AffectedRange]] = {
    "CVE-2026-111497": [
        AffectedRange("1.0.3", "1.0.10", "brotli"),
        AffectedRange("1.1.0", "1.1.1",  "brotli"),
        AffectedRange("1.2.0", "1.2.1",  "brotli"),
    ],
    "CVE-2025-22873": [
        AffectedRange("0.0.1", "0.35.0", "golang"),
    ],
    # ضيفي CVEs جديدة هنا بس — الـ detection بيتولاه version_detect.py
}

# CVE → الـ component اللي نبحث عنه في نتايج version_detect
CVE_COMPONENT_MAP: dict[str, str] = {
    "CVE-2026-111497": "brotli",
    "CVE-2025-22873":  "golang",
    # مثال:
    # "CVE-2021-44228": "log4j",
    # "CVE-2022-22965": "spring",
}


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    cve_id: str
    host: str
    detected_version: Optional[str] = None
    detection_method: Optional[str] = None
    is_affected: Optional[bool] = None
    component_present: Optional[bool] = None
    suggested_confidence: str = "low"
    notes: str = ""
    all_technologies: list = field(default_factory=list)   # كل اللي لقاه version_detect


# ---------------------------------------------------------------------------
# Main verify function
# ---------------------------------------------------------------------------

def verify_cve(cve_id: str, url: str, timeout: float = 10.0) -> VerificationResult:
    """
    الدالة الرئيسية.
    بتستخدم version_detect للـ detection وبتقارن بالـ CVE range.
    """
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    res = VerificationResult(cve_id=cve_id, host=host)

    # خطوة 1: كتشف كل الـ technologies على الـ target
    try:
        detection: DetectionResult = _detect(url, timeout=timeout)
        res.all_technologies = detection.technologies
    except Exception as exc:
        res.notes = f"version_detect failed: {exc}"
        return res

    # خطوة 2: إيجاد الـ component المرتبط بالـ CVE
    component = CVE_COMPONENT_MAP.get(cve_id)
    if not component:
        res.notes = (
            f"No component mapping for {cve_id}. "
            f"Detected technologies: "
            f"{[t.name for t in detection.technologies[:5]]}"
        )
        return res

    # خطوة 3: هل الـ component موجود على الـ target؟
    comp_match = detection.get(component)
    res.component_present = comp_match is not None

    if not res.component_present:
        res.notes = (
            f"Component '{component}' not detected on {host}. "
            f"Detected: {[t.name for t in detection.technologies[:8]]}. "
            f"CVE {cve_id} likely does not apply."
        )
        res.suggested_confidence = "low"
        return res

    # خطوة 4: هل عندنا version رقم؟
    if not comp_match.version:
        res.detected_version = None
        res.detection_method = comp_match.method
        res.notes = (
            f"'{component}' detected (method: {comp_match.method}, "
            f"confidence: {comp_match.confidence}%) but version unknown. "
            f"Cannot confirm if vulnerable to {cve_id}."
        )
        res.suggested_confidence = "medium" if comp_match.confidence >= 70 else "low"
        return res

    # خطوة 5: قارن بالـ affected range
    res.detected_version = comp_match.version
    res.detection_method = comp_match.method

    ranges = CVE_RANGES.get(cve_id, [])
    if not ranges:
        res.notes = f"No affected ranges defined for {cve_id}."
        res.suggested_confidence = "low"
        return res

    for r in ranges:
        affected = r.is_affected(comp_match.version)
        if affected is True:
            res.is_affected = True
            # الـ confidence بيعتمد على دقة الـ detection
            if comp_match.confidence >= 85:
                res.suggested_confidence = "high"
            elif comp_match.confidence >= 60:
                res.suggested_confidence = "medium"
            else:
                res.suggested_confidence = "low"
            res.notes = (
                f"VULNERABLE: {component} {comp_match.version} is in "
                f"affected range [{r.introduced}, {r.fixed}). "
                f"Detection: {comp_match.method} (confidence {comp_match.confidence}%)."
            )
            return res

        elif affected is False:
            res.is_affected = False
            res.suggested_confidence = "confirmed_not_affected"
            res.notes = (
                f"NOT VULNERABLE: {component} {comp_match.version} is "
                f"NOT in affected range [{r.introduced}, {r.fixed}). "
                f"Detection: {comp_match.method}. False positive."
            )
            return res

    res.notes = (
        f"Version {comp_match.version} detected but could not be "
        f"matched to any known range for {cve_id}."
    )
    res.suggested_confidence = "low"
    return res


# ---------------------------------------------------------------------------
# Apply to Finding
# ---------------------------------------------------------------------------

def apply_verification(finding, result: VerificationResult):
    """
    Returns None → confirmed false positive (يتحذف).
    Returns finding → محدّث بالـ confidence الجديد.
    """
    if result.suggested_confidence == "confirmed_not_affected":
        logger.info("Dropping FP: %s on %s — %s",
                    result.cve_id, result.host, result.notes)
        return None

    # حدّث evidence
    try:
        import json
        ev = json.loads(finding.evidence) if finding.evidence else {}
        ev["verification"] = {
            "detected_version":   result.detected_version,
            "detection_method":   result.detection_method,
            "is_affected":        result.is_affected,
            "component_present":  result.component_present,
            "suggested_confidence": result.suggested_confidence,
            "notes":              result.notes,
            "all_technologies":   [
                {"name": t.name, "version": t.version, "confidence": t.confidence}
                for t in (result.all_technologies or [])[:10]
            ],
        }
        finding.evidence = json.dumps(ev, sort_keys=True, default=str)[:4000]
    except Exception:
        pass

    # حدّث confidence
    _MAP = {
        "high":   _conf("CONFIRMED"),
        "medium": _conf("LIKELY"),
        "low":    _conf("LOW"),
    }
    new_conf = _MAP.get(result.suggested_confidence)
    if new_conf and result.suggested_confidence != "low":
        finding.confidence       = new_conf
        finding.verified         = (result.suggested_confidence == "high")
        finding.verification_method = result.detection_method or \
                                       getattr(finding, "verification_method", None)
    return finding


def _conf(name: str):
    try:
        from marsadix.models import Confidence
        return getattr(Confidence, name, None)
    except ImportError:
        return None
