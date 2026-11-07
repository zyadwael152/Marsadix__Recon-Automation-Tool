"""Adapter: Person 3 (storage/recon) models -> Person 4 (matching) models.

Works with dataclass/ORM objects *and* plain dict rows (sqlite rows converted to
dict), so it can be used straight on DB output.

CVE:        cve_id->id, cvss_score->cvss, epss_score->epss, in_kev->kev,
            cpe_matches->configurations (list[str] | list[cpeMatch dict] |
            NVD configurations | JSON text)
Technology: host, cpe, version; source/confidence -> VersionSource;
            internet_facing / behind_cdn derived from the stored asset row.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .models import CVE, Asset, VersionSource

__all__ = ["to_p4_cve", "to_p4_asset", "map_version_source", "normalize_configurations",
           "build_assets"]


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        v = obj.get(name, default)
    else:
        v = getattr(obj, name, default)
    return default if v is None else v


def _truthy(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y")
    return bool(v)


def _float(v: Any) -> Optional[float]:
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


def normalize_configurations(raw: Any) -> List[Dict[str, Any]]:
    if raw in (None, "", [], {}):
        return []
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    plain: List[Dict[str, Any]] = []
    configs: List[Dict[str, Any]] = []
    for item in raw:
        if isinstance(item, str):
            plain.append({"vulnerable": True, "criteria": item})
        elif isinstance(item, dict):
            if "nodes" in item or "children" in item:
                configs.append(item)
            elif "cpeMatch" in item or "cpe_match" in item:
                configs.append({"nodes": [item]})
            elif "criteria" in item or "cpe23Uri" in item:
                plain.append(item)
    if plain:
        configs.append({"nodes": [{"operator": "OR", "negate": False, "cpeMatch": plain}]})
    return configs


def to_p4_cve(obj: Any) -> CVE:
    cwe = _get(obj, "cwe", None) or _get(obj, "cwes", None) or []
    if isinstance(cwe, str):
        cwe = [c.strip() for c in cwe.split(",") if c.strip()]
    return CVE(
        id=str(_get(obj, "cve_id", "") or _get(obj, "id", "")),
        cvss=_float(_get(obj, "cvss_score", None) if _get(obj, "cvss_score", None) is not None else _get(obj, "cvss", None)),
        epss=_float(_get(obj, "epss_score", None) if _get(obj, "epss_score", None) is not None else _get(obj, "epss", None)),
        kev=_truthy(_get(obj, "in_kev", _get(obj, "kev", False))),
        configurations=normalize_configurations(_get(obj, "cpe_matches", _get(obj, "configurations", None))),
        description=str(_get(obj, "description", "") or ""),
        cwe=list(cwe),
    )


_SOURCE_WORDS = (
    (("verified", "manual", "authenticated", "confirmed"), VersionSource.VERIFIED),
    (("nmap",), VersionSource.NMAP),
    (("banner",), VersionSource.BANNER),
    (("httpx", "wappalyzer", "whatweb", "header", "http"), VersionSource.HTTPX),
    (("fingerprint", "favicon", "tls", "template", "nuclei"), VersionSource.FINGERPRINT),
    (("infer", "guess", "heuristic"), VersionSource.INFERRED),
)


def map_version_source(source: Any, confidence: Any = None, has_version: bool = True) -> VersionSource:
    if not has_version:
        return VersionSource.UNKNOWN
    s = str(source or "").strip().lower()
    for words, vs in _SOURCE_WORDS:
        if any(w in s for w in words):
            return vs
    c = confidence
    if isinstance(c, (int, float)) and not isinstance(c, bool):
        return VersionSource.BANNER if c >= 0.8 else VersionSource.FINGERPRINT if c >= 0.5 else VersionSource.INFERRED
    c = str(c or "").strip().lower()
    if c in ("high", "certain", "confirmed"):
        return VersionSource.BANNER
    if c in ("medium", "med", "moderate"):
        return VersionSource.FINGERPRINT
    if c in ("low", "tentative", "weak"):
        return VersionSource.INFERRED
    return VersionSource.UNKNOWN


def to_p4_asset(tech: Any, asset_row: Any = None, host_platforms: Iterable[str] = ()) -> Asset:
    """Convert a Technology (object/dict) + its stored asset row to an Asset."""
    host = str(_get(tech, "host", "") or _get(asset_row or {}, "host", ""))
    cpe = str(_get(tech, "cpe", "") or "")
    version = _get(tech, "version", None)
    version = str(version).strip() if version not in (None, "") else None
    cdn = _get(asset_row or {}, "behind_cdn", None)
    if cdn is None:
        cdn = bool(_get(asset_row or {}, "cdn", "") or _get(asset_row or {}, "cdn_name", ""))
    facing = _get(asset_row or {}, "internet_facing", None)
    crit = str(_get(asset_row or {}, "criticality", "medium") or "medium").lower()
    if crit not in ("low", "medium", "high", "critical"):
        crit = "medium"
    platforms = [p for p in host_platforms if p and p != cpe]
    return Asset(
        host=host, cpe=cpe, version=version,
        version_source=map_version_source(_get(tech, "source", ""), _get(tech, "confidence", None),
                                          has_version=bool(version)),
        internet_facing=True if facing is None else _truthy(facing),
        behind_cdn=_truthy(cdn), criticality=crit, platform_cpes=platforms,
        name=str(_get(tech, "name", "") or ""),
        scan_id=_get(tech, "scan_id", None) if _get(tech, "scan_id", None) is not None else _get(asset_row or {}, "scan_id", None),
        technology_id=_get(tech, "id", None),
    )


def build_assets(techs: Iterable[Any], asset_rows: Mapping[str, Any] = None) -> List[Asset]:
    """Convert many technologies; other CPEs on the same host become platform_cpes."""
    techs = [t for t in techs if _get(t, "cpe", "")]
    by_host: Dict[str, List[str]] = {}
    for t in techs:
        by_host.setdefault(str(_get(t, "host", "")), []).append(str(_get(t, "cpe", "")))
    out = []
    for t in techs:
        host = str(_get(t, "host", ""))
        out.append(to_p4_asset(t, (asset_rows or {}).get(host), by_host.get(host, [])))
    return out
