"""M9 - match confidence.

Base confidence comes from how the asset version was obtained:

    VERIFIED / NMAP / BANNER   -> HIGH
    HTTPX / FINGERPRINT        -> MEDIUM
    INFERRED / UNKNOWN         -> LOW

Adjustments (applied in order):
1. No asset version at all, or the version was not actually compared against a
   range/exact version  -> LOW if the version is unknown, otherwise capped at
   MEDIUM ("never HIGH when the version was not compared").
2. Unverified AND platform condition -> one level lower (floor LOW).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from .cpe import CPEParseError, parse_cpe_cached
from .models import Asset, Confidence, MatchResult, VersionSource

__all__ = ["SOURCE_CONFIDENCE", "ConfidenceResult", "base_confidence", "assess"]

SOURCE_CONFIDENCE = {
    VersionSource.VERIFIED: Confidence.HIGH,
    VersionSource.NMAP: Confidence.HIGH,
    VersionSource.BANNER: Confidence.HIGH,
    VersionSource.HTTPX: Confidence.MEDIUM,
    VersionSource.FINGERPRINT: Confidence.MEDIUM,
    VersionSource.INFERRED: Confidence.LOW,
    VersionSource.UNKNOWN: Confidence.LOW,
}


@dataclass(frozen=True)
class ConfidenceResult:
    level: Confidence
    reasons: Tuple[str, ...]


def base_confidence(source: VersionSource) -> Confidence:
    return SOURCE_CONFIDENCE[VersionSource.coerce(source)]


def assess(match: MatchResult, asset: Asset = None) -> ConfidenceResult:
    asset = asset or match.asset
    source = VersionSource.coerce(asset.version_source)
    level = base_confidence(source)
    reasons = [f"version source '{source.value}' -> {level.label}"]
    if _version_unknown(asset):
        if level > Confidence.LOW:
            level = Confidence.LOW
        reasons.append("asset version unknown -> low")
    elif not match.version_compared and level > Confidence.MEDIUM:
        level = Confidence.MEDIUM
        reasons.append("version not compared -> capped at medium")
    if match.platform_unverified and level > Confidence.LOW:
        level = Confidence(level - 1)
        reasons.append("platform condition unverified -> downgraded one level")
    return ConfidenceResult(level, tuple(reasons))


def _cpe_version(asset: Asset) -> str:
    try:
        return parse_cpe_cached(asset.cpe).version
    except CPEParseError:
        return ""


def _version_unknown(asset: Asset) -> bool:
    v = (asset.version or "").strip()
    return v in ("", "*", "-") and _cpe_version(asset) in ("", "*", "-")
