"""Load scan context and persist normalized WebItems through `marsadix.db`.

No SQL schema changes and no direct table DDL: inserts go through
`db.save_many(conn, "web_items", [...])`, which in turn uses the shared
`WebItem` model.  Output files are convenience copies, not the source of
truth.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from marsadix import db
from marsadix.core.scope import Scope, normalize_host
from marsadix.core.textfile import safe_filename
from marsadix.models import DiscoverySource, Scan, ScanMode, WebItem, WebItemKind

from .config import Member2Config
from .errors import ConfigError
from .normalize import NormalizedURL, normalize_url

logger = logging.getLogger(__name__)


@dataclass
class CollectedURL:
    normalized: NormalizedURL
    source: str
    kind: str = "endpoint"
    status_code: Optional[int] = None
    parent_url: Optional[str] = None
    content_type: str = ""

    @property
    def url(self) -> str:
        return self.normalized.url

    @property
    def key(self) -> str:
        return self.normalized.key


@dataclass
class StorageResult:
    stored: int = 0
    skipped_existing: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    output_files: list[str] = field(default_factory=list)


def _canonical_target(value: Optional[str]) -> str:
    """Normalize a target for comparison/storage; never invent one."""
    if value is None or not str(value).strip():
        raise ConfigError("target is required to resolve or create a scan")
    normalized = normalize_host(str(value))
    if not normalized:
        raise ConfigError(f"invalid target: {value!r}")
    return normalized


def _same_target(left: Optional[str], right: Optional[str]) -> bool:
    try:
        return _canonical_target(left) == _canonical_target(right)
    except ConfigError:
        return str(left or "").strip().lower() == str(right or "").strip().lower()


def _latest_scan_for_target(conn, target: str):
    """Return the newest scan for target, comparing normalized hostnames."""
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY started_at DESC, id DESC").fetchall()
    for row in rows:
        if _same_target(row["target"], target):
            return row
    return None


def _create_scan(conn, target: str, *, mode: Optional[str],
                 scope_file: Optional[str], rate_limit: Optional[int]) -> dict:
    selected = mode or ("full" if scope_file else "passive")
    selected = getattr(selected, "value", selected)
    try:
        scan_mode = ScanMode(str(selected).lower())
    except ValueError as exc:
        raise ConfigError(
            f"invalid scan mode {selected!r}; expected passive, standard or full") from exc
    scan = Scan(target=target, mode=scan_mode, scope_file=scope_file,
                rate_limit=rate_limit)
    scan.id = db.save_scan(conn, scan)
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan.id,)).fetchone()
    if row is None:  # save_scan returned a row id but the insert vanished
        raise ConfigError(f"could not create scan for target={target!r}")
    return dict(row)


def load_scan(conn, target: Optional[str] = None, scan_id: Optional[int] = None,
              *, mode: Optional[str] = None,
              scope_file: Optional[str] = None,
              rate_limit: Optional[int] = None) -> dict:
    """Resolve a scan row for the requested target.

    Resolution rules:
    * an explicit scan id is used only when its target matches the requested
      target (or no target was supplied);
    * otherwise the newest scan for the requested target is used;
    * if no scan exists for the target, a new scan row is inserted.

    This keeps a stale/wrong ``--scan-id`` from silently enriching another
    target's scan and removes the old "no scan found" hard failure.
    """
    wanted = _canonical_target(target) if target is not None else None
    supplied_row = None
    if scan_id is not None:
        supplied_row = conn.execute(
            "SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    if supplied_row is not None:
        if wanted is None or _same_target(supplied_row["target"], wanted):
            return dict(supplied_row)

    if wanted is None:
        if scan_id is not None:
            raise ConfigError(
                f"scan_id {scan_id} was not found; supply the target to resolve or create a scan")
        raise ConfigError("either target or scan_id is required")

    resolved = _latest_scan_for_target(conn, wanted)
    if resolved is not None:
        if supplied_row is not None:
            logger.warning(
                "[!] Warning: scan_id %s belongs to '%s'. "
                "Auto-resolved/created scan_id %s for '%s'.",
                scan_id, supplied_row["target"], resolved["id"], wanted)
        elif scan_id is not None:
            logger.warning(
                "[!] Warning: scan_id %s was not found. "
                "Auto-resolved scan_id %s for '%s'.",
                scan_id, resolved["id"], wanted)
        return dict(resolved)

    created = _create_scan(conn, wanted, mode=mode, scope_file=scope_file,
                           rate_limit=rate_limit)
    if supplied_row is not None:
        logger.warning(
            "[!] Warning: scan_id %s belongs to '%s'. "
            "Auto-resolved/created scan_id %s for '%s'.",
            scan_id, supplied_row["target"], created["id"], wanted)
    elif scan_id is not None:
        logger.warning(
            "[!] Warning: scan_id %s was not found. "
            "Created scan_id %s for '%s'.",
            scan_id, created["id"], wanted)
    else:
        logger.warning(
            "[!] Warning: no scan found for '%s'. Created scan_id %s.",
            wanted, created["id"])
    return created


def resolve_scope(scan: dict, scope_path: Optional[str],
                  mode: Optional[str] = None) -> Scope:
    """Prefer an explicit --scope, then the scope file stored on the scan."""
    if scope_path:
        return Scope.from_file(scope_path)
    stored = scan.get("scope_file")
    if stored:
        if os.path.isfile(stored):
            return Scope.from_file(stored)
        logger.warning("scan #%s records scope file %r, which no longer exists",
                       scan.get("id"), stored)
    target = normalize_host(scan.get("target", ""))
    if not target:
        raise ConfigError("scan has an invalid target")
    effective_mode = mode or scan.get("mode") or "passive"
    if effective_mode != "passive":
        raise ConfigError(
            f"scan #{scan.get('id')} is {effective_mode!r}; active web collection "
            f"requires the original --scope file (pass --scope PATH)")
    logger.warning("no scope file recorded; using target + subdomains for passive collection")
    return Scope.from_target(target)


def existing_web_keys(conn, scan_id: int) -> set[str]:
    keys: set[str] = set()
    for row in db.get_web_items(conn, scan_id):
        try:
            keys.add(normalize_url(row["url"]).key)
        except Exception:
            keys.add(str(row["url"]))
    return keys


def _discovery_source(source: str) -> DiscoverySource:
    s = (source or "").lower()
    if s.startswith(("gau", "wayback", "commoncrawl", "archive")):
        return DiscoverySource.PASSIVE
    if s.startswith("js"):
        return DiscoverySource.JS
    return DiscoverySource.ACTIVE


def _kind_enum(kind: str) -> WebItemKind:
    return {
        "url": WebItemKind.URL,
        "js_file": WebItemKind.JS_FILE,
        "endpoint": WebItemKind.ENDPOINT,
        "parameter": WebItemKind.PARAMETER,
    }.get(str(kind).lower(), WebItemKind.ENDPOINT)


def store_web_items(conn, scan_id: int, candidates: Iterable[CollectedURL],
                    *, dry_run: bool = False) -> StorageResult:
    """Deduplicate (in-batch + against DB) and persist through db.save_many."""
    result = StorageResult()
    existing = existing_web_keys(conn, scan_id)
    chosen: dict[str, CollectedURL] = {}
    for item in candidates:
        if item.key in existing:
            result.skipped_existing += 1
            continue
        old = chosen.get(item.key)
        if old is None:
            chosen[item.key] = item
            continue
        # Prefer verified status and richer parent information.
        if old.status_code is None and item.status_code is not None:
            chosen[item.key] = item
        elif old.parent_url is None and item.parent_url is not None:
            chosen[item.key] = item

    models = [
        WebItem(
            scan_id=scan_id,
            host=item.normalized.host,
            url=item.normalized.url,
            kind=_kind_enum(item.kind),
            source=_discovery_source(item.source),
            status_code=item.status_code,
            parent_url=item.parent_url,
            has_params=item.normalized.has_params,
        )
        for item in chosen.values()
    ]
    if not dry_run and models:
        result.stored = db.save_many(conn, "web_items", models)
    for item in chosen.values():
        result.by_kind[item.kind] = result.by_kind.get(item.kind, 0) + 1
    if dry_run:
        result.stored = 0
    logger.info("[+] Stored %d new web item(s) (existing skipped: %d)",
                result.stored, result.skipped_existing)
    return result


def _write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_outputs(config: Member2Config, target: str,
                  candidates: Iterable[CollectedURL],
                  summary: Optional[dict] = None) -> list[str]:
    if not config.write_outputs:
        return []
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = safe_filename(target)
    items = list(candidates)
    groups = {
        "all_urls": sorted({i.url for i in items}),
        "endpoints": sorted({i.url for i in items if i.kind == "endpoint"}),
        "js_files": sorted({i.url for i in items if i.kind == "js_file"}),
        "archive_urls": sorted({i.url for i in items if i.source.startswith(("gau", "wayback", "commoncrawl", "archive"))}),
    }
    written: list[str] = []
    for label, lines in groups.items():
        if not lines:
            continue
        path = out_dir / f"{stem}_m2_{label}.txt"
        _write_lines(path, lines)
        written.append(str(path))
    if summary is not None:
        path = out_dir / f"{stem}_m2_summary.json"
        path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        written.append(str(path))
    return written
