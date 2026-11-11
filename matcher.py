"""M8 - CVE <-> asset matcher over NVD-shaped configurations.

Semantics (documented decisions)
--------------------------------
* A configuration list is OR'ed (NVD semantics).  A configuration/node has an
  ``operator`` (AND/OR, default OR), optional ``negate``, ``cpeMatch`` entries
  (also accepts legacy ``cpe_match`` / ``cpe23Uri``) and nested ``children``.
* An empty node (no entries, no children) never matches.
* ``vulnerable: false`` entries are *platform conditions*.  They can make an
  AND node stricter but can never create a match on their own: a configuration
  only matches if at least one *vulnerable* entry matched.  In an OR node that
  mixes vulnerable and platform entries only the vulnerable side counts.
* Platform conditions are verified against ``Asset.platform_cpes`` (other CPEs
  seen on the host).  If the asset has no platform CPE of that ``part`` the
  condition is *unverified*: it is assumed satisfied and flagged so confidence
  is downgraded.
* AND nodes require every entry/child; OR nodes require any.
* Unknown asset version + version-constrained CVE: matched with
  ``version_compared=False`` when ``allow_unknown_version`` (default) so the
  confidence layer can rate it LOW; otherwise no match.
* Malformed asset/CVE CPEs and versions are skipped and recorded in
  ``Matcher.errors``; they never abort a batch.
* CVE entries with ANY vendor/product are not indexed (never match).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .cpe import CPE, CPEParseError, parse_cpe_cached
from .models import CVE, Asset, MatchResult
from .version import Version, VersionParseError, parse_version, version_in_range

__all__ = ["Matcher", "CVEIndex", "match_all", "evaluate"]

_log = logging.getLogger("marsadix.matching")
_MAX_DEPTH = 16
_RANGE_KEYS = ("versionStartIncluding", "versionStartExcluding",
               "versionEndIncluding", "versionEndExcluding")


def _specific(v: Optional[str]) -> bool:
    return bool(v) and v not in ("*", "-")


@dataclass
class _NR:  # node result
    matched: bool = False
    hit: bool = False            # a vulnerable entry positively matched
    compared: bool = False       # version actually compared for the hits
    unverified: bool = False     # an unverified platform condition was relied on
    has_vuln: bool = False
    criteria: Tuple[str, ...] = ()
    unknown_version: bool = False


@dataclass
class _Prepared:
    asset: Asset
    cpe: CPE
    version: Optional[str]
    version_obj: Optional[Version]
    platforms: List[CPE]


def _entries(node: Dict[str, Any]) -> list:
    return node.get("cpeMatch") or node.get("cpe_match") or []


def _criteria(entry: Dict[str, Any]) -> Optional[str]:
    c = entry.get("criteria") or entry.get("cpe23Uri") or entry.get("cpe22Uri")
    return c if isinstance(c, str) and c else None


def _walk_vuln_keys(node: Any, out: set, depth: int = 0) -> None:
    if not isinstance(node, dict) or depth > _MAX_DEPTH:
        return
    for e in _entries(node):
        if not isinstance(e, dict) or e.get("vulnerable", True) is False:
            continue
        c = _criteria(e)
        if not c:
            continue
        try:
            cpe = parse_cpe_cached(c)
        except CPEParseError:
            _log.warning("skipping malformed CVE CPE in index")
            continue
        if cpe.vendor in ("", "*") or cpe.product in ("", "*"):
            continue
        out.add(cpe.key)
    for key in ("nodes", "children"):
        for ch in node.get(key) or []:
            _walk_vuln_keys(ch, out, depth + 1)


class CVEIndex:
    """Index of CVEs by ``(part, vendor, product)`` of their vulnerable CPEs."""

    def __init__(self, cves: Iterable[CVE]):
        self._by_key: Dict[Tuple[str, str, str], List[CVE]] = {}
        for cve in cves:
            keys: set = set()
            for cfg in cve.configurations or []:
                _walk_vuln_keys(cfg, keys)
            for k in keys:
                self._by_key.setdefault(k, []).append(cve)

    def candidates(self, key: Tuple[str, str, str]) -> List[CVE]:
        return self._by_key.get(key, [])

    def __len__(self) -> int:
        return len(self._by_key)


class Matcher:
    def __init__(self, *, allow_unknown_version: bool = True):
        self.allow_unknown_version = allow_unknown_version
        self.errors: List[str] = []

    # -- preparation -------------------------------------------------------
    def prepare(self, asset: Asset) -> _Prepared:
        cpe = parse_cpe_cached(asset.cpe)
        version: Optional[str] = None
        if _specific(cpe.version):
            version = cpe.version
        elif asset.version and _specific(str(asset.version).strip()):
            version = str(asset.version).strip()
        vobj = None
        if version is not None:
            try:
                vobj = parse_version(version)
            except VersionParseError:
                _log.debug("unparseable asset version for host %s", asset.host)
        platforms: List[CPE] = []
        for p in asset.platform_cpes or []:
            try:
                platforms.append(parse_cpe_cached(p))
            except CPEParseError:
                _log.debug("skipping malformed platform CPE for host %s", asset.host)
        return _Prepared(asset, cpe, version, vobj, platforms)

    # -- entry matching ----------------------------------------------------
    @staticmethod
    def _same_product(a: CPE, b: CPE) -> bool:
        def eq(x: str, y: str) -> bool:
            return x in ("", "*") or y in ("", "*") or x.lower() == y.lower()
        return (a.part.lower() == b.part.lower() and eq(a.vendor, b.vendor)
                and eq(a.product, b.product))

    @staticmethod
    def _target_sw_ok(crit: CPE, other: CPE) -> bool:
        c, o = crit.target_sw, other.target_sw
        if c in ("", "*") or o in ("", "*"):
            return True
        return c.lower() == o.lower()

    @staticmethod
    def _update_ok(crit: CPE, other: CPE) -> bool:
        c, o = crit.update, other.update
        if not _specific(c) or not _specific(o):
            return True
        return c.lower() == o.lower()

    def _version_check(self, entry: Dict[str, Any], crit: CPE, version: Optional[str],
                       vobj: Optional[Version]) -> Tuple[bool, bool, bool]:
        """Return (matched, compared, unknown_version)."""
        has_range = any(entry.get(k) for k in _RANGE_KEYS)
        exact = _specific(crit.version)
        if not has_range and not exact:
            return True, False, False
        if version is None or (vobj is None and has_range):
            return (self.allow_unknown_version, False, True)
        if has_range:
            try:
                ok = version_in_range(
                    vobj, start_incl=entry.get("versionStartIncluding"),
                    start_excl=entry.get("versionStartExcluding"),
                    end_incl=entry.get("versionEndIncluding"),
                    end_excl=entry.get("versionEndExcluding"))
            except VersionParseError:
                return (self.allow_unknown_version, False, True)
            return ok, True, False
        # exact version in the CPE
        try:
            cv = parse_version(crit.version)
        except VersionParseError:
            cv = None
        if cv is not None and vobj is not None:
            return vobj == cv, True, False
        return version.lower() == crit.version.lower(), True, False

    def _vuln_entry(self, entry: Dict[str, Any], prep: _Prepared) -> _NR:
        c = _criteria(entry)
        if not c:
            return _NR(has_vuln=True)
        try:
            crit = parse_cpe_cached(c)
        except CPEParseError:
            _log.warning("skipping malformed CVE CPE entry")
            return _NR(has_vuln=True)
        if crit.vendor in ("", "*") or crit.product in ("", "*"):
            return _NR(has_vuln=True)
        if not self._same_product(crit, prep.cpe):
            return _NR(has_vuln=True)
        if not self._target_sw_ok(crit, prep.cpe) or not self._update_ok(crit, prep.cpe):
            return _NR(has_vuln=True)
        ok, compared, unknown = self._version_check(entry, crit, prep.version, prep.version_obj)
        if not ok:
            return _NR(has_vuln=True)
        return _NR(matched=True, hit=True, compared=compared, has_vuln=True,
                   criteria=(c,), unknown_version=unknown)

    def _platform_entry(self, entry: Dict[str, Any], prep: _Prepared) -> _NR:
        c = _criteria(entry)
        if not c:
            return _NR(matched=False)
        try:
            crit = parse_cpe_cached(c)
        except CPEParseError:
            _log.warning("skipping malformed platform CPE entry")
            return _NR(matched=False)
        same_part = [p for p in prep.platforms if p.part.lower() == crit.part.lower()]
        if not same_part:
            return _NR(matched=True, unverified=True)
        has_range = any(entry.get(k) for k in _RANGE_KEYS)
        for p in same_part:
            if not self._same_product(crit, p):
                continue
            if not has_range and not _specific(crit.version):
                return _NR(matched=True)
            if not _specific(p.version):
                return _NR(matched=True, unverified=True)
            try:
                pv = parse_version(p.version)
                if has_range:
                    if version_in_range(pv, start_incl=entry.get("versionStartIncluding"),
                                        start_excl=entry.get("versionStartExcluding"),
                                        end_incl=entry.get("versionEndIncluding"),
                                        end_excl=entry.get("versionEndExcluding")):
                        return _NR(matched=True)
                elif pv == parse_version(crit.version):
                    return _NR(matched=True)
            except VersionParseError:
                return _NR(matched=True, unverified=True)
        return _NR(matched=False)

    # -- node evaluation ---------------------------------------------------
    def _node(self, node: Any, prep: _Prepared, depth: int = 0) -> _NR:
        if not isinstance(node, dict) or depth > _MAX_DEPTH:
            return _NR()
        entries = [e for e in _entries(node) if isinstance(e, dict)]
        children = [c for c in (node.get("children") or node.get("nodes") or [])]
        if not entries and not children:
            return _NR()  # empty node: never a universal match
        vuln = [self._vuln_entry(e, prep) for e in entries if e.get("vulnerable", True) is not False]
        plat = [self._platform_entry(e, prep) for e in entries if e.get("vulnerable", True) is False]
        kids = [self._node(c, prep, depth + 1) for c in children]
        has_vuln = bool(vuln) or any(k.has_vuln for k in kids)
        op = str(node.get("operator", "OR")).upper()

        if op == "AND":
            items = vuln + plat + kids
            matched = all(i.matched for i in items)
            used = items if matched else []
            hits = [i for i in used if i.hit]
            compared = bool(hits) and all(i.compared for i in hits)
        else:
            contrib = (vuln + [k for k in kids if k.has_vuln]) if has_vuln else (plat + kids)
            used = [i for i in contrib if i.matched]
            matched = bool(used)
            hits = [i for i in used if i.hit]
            compared = any(i.compared for i in hits)
        res = _NR(
            matched=matched,
            hit=bool(hits),
            compared=compared,
            unverified=any(i.unverified for i in used),
            has_vuln=has_vuln,
            criteria=tuple(c for i in hits for c in i.criteria),
            unknown_version=any(i.unknown_version for i in hits),
        )
        if node.get("negate"):
            res = _NR(matched=not res.matched, hit=False, has_vuln=has_vuln)
        return res

    def evaluate_prepared(self, cve: CVE, prep: _Prepared) -> Optional[MatchResult]:
        best: Optional[_NR] = None
        for cfg in cve.configurations or []:
            if not isinstance(cfg, dict):
                continue
            if "nodes" in cfg and not _entries(cfg):
                node = {"operator": cfg.get("operator", "OR"), "negate": cfg.get("negate"),
                        "children": cfg.get("nodes") or []}
            else:
                node = cfg
            r = self._node(node, prep)
            if not (r.matched and r.hit):
                continue
            if best is None or (r.compared, not r.unverified) > (best.compared, not best.unverified):
                best = r
        if best is None:
            return None
        notes = []
        if best.unknown_version:
            notes.append("asset version unknown - version range not compared")
        if best.unverified:
            notes.append("platform condition could not be verified")
        return MatchResult(cve=cve, asset=prep.asset,
                           matched_criteria=tuple(sorted(set(best.criteria))),
                           version_compared=best.compared,
                           platform_unverified=best.unverified, notes=tuple(notes))

    def evaluate(self, cve: CVE, asset: Asset) -> Optional[MatchResult]:
        try:
            prep = self.prepare(asset)
        except (CPEParseError, ValueError, AttributeError, TypeError) as exc:
            self.errors.append(f"asset {asset.host}: {type(exc).__name__}")
            return None
        return self.evaluate_prepared(cve, prep)

    def match_all(self, assets: Iterable[Asset], cves: Iterable[CVE]) -> List[MatchResult]:
        index = CVEIndex(cves)
        out: List[MatchResult] = []
        for asset in assets:
            try:
                prep = self.prepare(asset)
            except Exception as exc:  # bad asset must not stop the batch
                self.errors.append(f"asset {getattr(asset, 'host', '?')}: {type(exc).__name__}")
                _log.warning("skipping malformed asset (%s)", type(exc).__name__)
                continue
            for cve in index.candidates(prep.cpe.key):
                try:
                    r = self.evaluate_prepared(cve, prep)
                except Exception as exc:
                    self.errors.append(f"cve {cve.id}: {type(exc).__name__}")
                    _log.warning("skipping CVE %s (%s)", cve.id, type(exc).__name__)
                    continue
                if r is not None:
                    out.append(r)
        out.sort(key=lambda r: (r.cve.id, r.asset.host, r.asset.cpe))
        return out


def match_all(assets: Iterable[Asset], cves: Iterable[CVE], *, allow_unknown_version: bool = True) -> List[MatchResult]:
    return Matcher(allow_unknown_version=allow_unknown_version).match_all(assets, cves)


def evaluate(cve: CVE, asset: Asset, *, allow_unknown_version: bool = True) -> Optional[MatchResult]:
    return Matcher(allow_unknown_version=allow_unknown_version).evaluate(cve, asset)
