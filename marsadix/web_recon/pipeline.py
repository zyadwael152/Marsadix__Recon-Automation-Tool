"""Member 2 orchestration: archive -> crawl -> JS -> normalize -> verify -> SQLite.

The pipeline is additive to a completed Marsadix scan.  It reads the scan's
scope and existing assets/web items, enriches them, and writes new WebItem rows
through the shared `db.py` helpers.  It never edits the base scan or schema.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from marsadix import db
from marsadix.core import limits
from .archive import ArchiveCollector, host_sources
from .config import Member2Config, load_member2_config
from .crawler import BuiltinCrawler
from .discovery import SubdomainEnumerator
from .errors import (
    TOOL_FAILED, TOOL_SKIPPED, TOOL_TIMEOUT, ConfigError, ToolOutcome, elapsed_ms,
)
from .http_client import SafeHTTPClient
from .js_extract import JsHarvester
from .nuclei import NucleiBatch, run_nuclei
from .normalize import classify_kind, is_under_domain
from .rate_limit import AsyncRateLimiter
from .scope_filter import ScopeEnforcer
from .security import SecurityBatch, SecurityScanner
from .storage import (
    CollectedURL, load_scan, resolve_scope, store_web_items, write_outputs,
)
from .tools import CrawlRecord, ToolResolver
from .verify import StatusVerifier

logger = logging.getLogger(__name__)

_SOURCE_ARCHIVE = ("gau", "wayback", "commoncrawl", "archive")


@dataclass
class WebPipelineReport:
    target: str
    scan_id: int
    mode: str
    status: str = "completed"
    candidates: int = 0
    stored: int = 0
    skipped_existing: int = 0
    counts: dict = field(default_factory=dict)
    source_counts: dict = field(default_factory=dict)
    outcomes: list[ToolOutcome] = field(default_factory=list)
    output_files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    assets_stored: int = 0
    archive_records: int = 0
    duration_ms: int = 0
    checked: int = 0
    findings_stored: int = 0
    nuclei_findings: int = 0
    security_findings: int = 0
    waf: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "mode": self.mode,
            "status": self.status,
            "candidates": self.candidates,
            "stored": self.stored,
            "skipped_existing": self.skipped_existing,
            "counts": dict(self.counts),
            "source_counts": dict(self.source_counts),
            "outcomes": [o.to_dict() for o in self.outcomes],
            "output_files": list(self.output_files),
            "skipped": list(self.skipped),
            "errors": list(self.errors),
            "assets_stored": self.assets_stored,
            "archive_records": self.archive_records,
            "checked": self.checked,
            "findings_stored": self.findings_stored,
            "nuclei_findings": self.nuclei_findings,
            "security_findings": self.security_findings,
            "waf": dict(self.waf),
            "duration_ms": self.duration_ms,
        }


def _source_rank(source: str) -> int:
    source = (source or "").lower()
    if source in ("seed", "existing"):
        return 0
    if source.startswith("js"):
        return 4
    if source.startswith(_SOURCE_ARCHIVE) and not source.startswith("gau"):
        return 3
    if source.startswith("gau"):
        return 3
    if source in ("katana", "builtin"):
        return 2
    return 2


def _kind_rank(kind: str) -> int:
    return {"url": 0, "js_file": 1, "endpoint": 2, "parameter": 3}.get(kind, 4)


def _prefer(new: CollectedURL, old: CollectedURL) -> bool:
    new_tuple = (0 if new.status_code is not None else 1, _source_rank(new.source),
                 _kind_rank(new.kind), 0 if new.parent_url else 1)
    old_tuple = (0 if old.status_code is not None else 1, _source_rank(old.source),
                 _kind_rank(old.kind), 0 if old.parent_url else 1)
    return new_tuple < old_tuple


class _Collector:
    def __init__(self) -> None:
        self.items: list[CollectedURL] = []

    def add(self, normalized, source: str, *, kind: Optional[str] = None,
            status_code: Optional[int] = None, parent_url: Optional[str] = None,
            content_type: str = "") -> CollectedURL:
        chosen_kind = kind or classify_kind(normalized.url, (), content_type)
        item = CollectedURL(
            normalized=normalized, source=source, kind=chosen_kind,
            status_code=status_code, parent_url=parent_url,
            content_type=content_type or "",
        )
        self.items.append(item)
        return item


async def _run_async(
    conn,
    scan: dict,
    config: Member2Config,
    *,
    scope_path: Optional[str],
    scope_obj,
    seeds: Iterable[str],
    use_archive: bool,
    crawl: bool,
    check_status: bool,
    discover_hosts: bool,
    dry_run: bool,
    mode: Optional[str] = None,
) -> WebPipelineReport:
    start = time.monotonic()
    limits.configure(tool_timeout=config.tool_timeout,
                     max_concurrency=config.max_concurrency)
    target = scan["target"]
    scan_id = int(scan["id"])
    effective_mode = str(mode or scan.get("mode") or "passive")
    scope = scope_obj or resolve_scope(scan, scope_path, mode=effective_mode)
    enforcer = ScopeEnforcer(scope, target, allow_private=config.allow_private,
                             dns_timeout=config.dns_timeout)
    limiter = AsyncRateLimiter(config.rate_limit)
    resolver = ToolResolver(config)
    client = SafeHTTPClient(enforcer, config, limiter)
    archives = ArchiveCollector(config, limiter)
    verifier = StatusVerifier(enforcer, config, resolver, client)
    harvester = JsHarvester(enforcer, config, client, scan_id=scan_id)
    builtin = BuiltinCrawler(enforcer, config, client)

    report = WebPipelineReport(target=target, scan_id=scan_id, mode=effective_mode)
    collector = _Collector()
    active_allowed = effective_mode in ("standard", "full")
    full_allowed = effective_mode == "full"

    if not active_allowed:
        if check_status:
            report.skipped.append("status verification disabled: passive mode must not contact the target")
        if crawl:
            report.skipped.append("crawling disabled: passive mode must not contact the target")
        if discover_hosts:
            report.skipped.append("DNS asset discovery disabled: passive mode")
        check_status = False
        crawl = False
        discover_hosts = False
    elif not full_allowed:
        if crawl:
            report.skipped.append("crawling disabled: katana/builtin crawl is full-mode only")
        crawl = False
    extract_js = bool(config.extract_js and full_allowed)

    # ------------------------------------------------------------- existing data
    existing_rows = db.get_web_items(conn, scan_id)
    existing_roots: set[str] = set()
    for row in existing_rows:
        try:
            normalized = enforcer.check(row["url"])
        except Exception:
            continue
        kind = row["kind"] if row["kind"] in ("url", "js_file", "endpoint", "parameter") else "url"
        if kind == "url" and normalized.is_root:
            existing_roots.add(normalized.key)
        collector.add(normalized, "existing", kind=kind,
                      status_code=row["status_code"], parent_url=row["parent_url"])

    for raw in seeds:
        try:
            normalized = enforcer.check(raw)
        except Exception as exc:
            report.errors.append(f"seed rejected: {raw!r} ({exc})")
            continue
        collector.add(normalized, "seed")
        if normalized.is_root:
            existing_roots.add(normalized.key)

    # Asset roots are useful crawl/verification seeds when no live URL exists.
    if active_allowed:
        asset_rows = db.get_assets(conn, scan_id)
        for row in asset_rows:
            if not row["in_scope"] or not enforcer.in_scope(row["host"]):
                continue
            if not any(c.normalized.host == row["host"] and c.normalized.is_root
                       for c in collector.items):
                try:
                    normalized = enforcer.check(f"https://{row['host']}")
                except Exception:
                    continue
                collector.add(normalized, "seed")
                existing_roots.add(normalized.key)

    # ------------------------------------------------------------------ archives
    archive_records = []
    if use_archive and config.archive_sources:
        logger.info("[*] Collecting archived URLs for %s (%s)", target,
                    ",".join(config.archive_sources))
        archive_batch = await archives.collect(target, resolver)
        report.outcomes.extend(archive_batch.outcomes)
        archive_records = archive_batch.records
        report.archive_records = len(archive_records)
        for rec in archive_records:
            try:
                normalized = enforcer.check(rec.url)
            except Exception:
                continue
            if not is_under_domain(normalized.host, target):
                continue
            ctype = rec.mime_type or ""
            kind = "js_file" if (ctype in ("application/javascript", "text/javascript")
                                 or normalized.path.lower().endswith((".js", ".mjs"))) else None
            collector.add(normalized, rec.source, kind=kind,
                          status_code=rec.status_code if rec.status_code and rec.status_code > 0 else None,
                          content_type=ctype)

        if discover_hosts and active_allowed:
            sources = host_sources(archive_records, target)
            if sources:
                try:
                    enumerator = SubdomainEnumerator(config, enforcer, resolver, limiter)
                    report.assets_stored = await enumerator.store(
                        conn, scan_id, target, sources, enforcer)
                except Exception as exc:
                    report.errors.append(f"asset discovery failed: {type(exc).__name__}: {exc}")
            dns_outcome = ToolOutcome(
                "archive-host-discovery", "ok" if report.assets_stored else "skipped",
                discovered=len(host_sources(archive_records, target)),
                kept=report.assets_stored)
            report.outcomes.append(dns_outcome)

    # -------------------------------------------------------------------- crawl
    crawl_seed_urls: list[str] = []
    for item in collector.items:
        if item.normalized.is_root or item.kind == "url":
            if item.status_code is None or item.status_code < 400:
                crawl_seed_urls.append(item.url)
    crawl_seed_urls = list(dict.fromkeys(crawl_seed_urls))[:max(1, config.max_pages)]
    if crawl and crawl_seed_urls:
        backend = config.crawler_backend
        katana_records: list[CrawlRecord] = []
        if backend in ("auto", "katana", "both"):
            if resolver.path("katana"):
                from .tools import run_katana
                katana_records, outcome = await run_katana(crawl_seed_urls, config, resolver)
                report.outcomes.append(outcome)
                for rec in katana_records:
                    try:
                        normalized = enforcer.check(rec.url)
                    except Exception:
                        continue
                    collector.add(normalized, "katana", status_code=rec.status_code,
                                  parent_url=rec.parent_url, content_type=rec.content_type)
            else:
                report.outcomes.append(ToolOutcome(
                    "katana", TOOL_SKIPPED, error="katana not installed; using built-in crawler"))
        if backend in ("builtin", "both") or (backend == "auto" and not katana_records):
            batch = await builtin.crawl(crawl_seed_urls)
            report.outcomes.append(batch.outcome)
            for rec in batch.records:
                try:
                    normalized = enforcer.check(rec.url)
                except Exception:
                    continue
                collector.add(normalized, "builtin", status_code=rec.status_code,
                              parent_url=rec.parent_url, content_type=rec.content_type)
    elif crawl:
        report.skipped.append("crawl skipped: no in-scope seed URLs")

    # --------------------------------------------------------------- javascript
    secret_findings = []
    if extract_js:
        js_candidates = [item.url for item in collector.items if item.kind == "js_file"]
        if js_candidates:
            js_batch = await harvester.harvest(js_candidates)
            report.outcomes.append(js_batch.outcome)
            secret_findings.extend(js_batch.secret_findings)
            for endpoint in js_batch.endpoints:
                try:
                    normalized = enforcer.check(endpoint.url)
                except Exception:
                    continue
                collector.add(normalized, "js", parent_url=endpoint.parent_url)
        else:
            report.skipped.append("JS extraction skipped: no JavaScript URLs discovered")

    # ---------------------------------------------------------- scope + status
    scoped: list[CollectedURL] = []
    for item in collector.items:
        try:
            normalized = enforcer.check(item.url)
        except Exception:
            continue
        item.normalized = normalized
        item.kind = classify_kind(normalized.url, existing_roots, item.content_type)
        if normalized.is_root:
            item.kind = "url"
        scoped.append(item)

    verified = None
    if check_status and scoped:
        batch = await verifier.verify(item.url for item in scoped)
        report.outcomes.append(batch.outcome)
        verified = batch.results
        report.checked = len(verified)

    final: list[CollectedURL] = []
    for item in scoped:
        if verified is not None:
            result = verified.get(item.normalized.key)
            if result is None:
                # Unverified URLs are only kept when the archive provider
                # already supplied an allowed status code.
                if item.status_code is None or not config.status_allowed(item.status_code):
                    continue
            else:
                item.status_code = result.status_code
                item.content_type = result.content_type or item.content_type
                if not config.status_allowed(item.status_code):
                    continue
        elif item.status_code is not None and not config.status_allowed(item.status_code):
            continue
        final.append(item)

    # Deduplicate by canonical key, keeping the richest/most trustworthy copy.
    chosen: dict[str, CollectedURL] = {}
    for item in final:
        old = chosen.get(item.key)
        if old is None or _prefer(item, old):
            chosen[item.key] = item

    # Caps: deterministic, seeds/crawled roots first.
    ordered = sorted(chosen.values(), key=lambda i: (
        0 if i.source in ("seed", "existing") else 1,
        _source_rank(i.source), _kind_rank(i.kind), i.url))
    limited: list[CollectedURL] = []
    per_host: dict[str, int] = {}
    for item in ordered:
        host = item.normalized.host
        if per_host.get(host, 0) >= config.max_per_host:
            continue
        if len(limited) >= config.max_urls:
            break
        per_host[host] = per_host.get(host, 0) + 1
        limited.append(item)

    report.candidates = len(limited)
    report.counts = {}
    report.source_counts = {}
    for item in limited:
        report.counts[item.kind] = report.counts.get(item.kind, 0) + 1
        report.source_counts[item.source] = report.source_counts.get(item.source, 0) + 1

    # ------------------------------------------------- W7 / W9 / W10 / A1-A4
    security_urls = list(dict.fromkeys(
        item.url for item in limited
        if item.kind == "url" or item.normalized.is_root))
    if not security_urls and active_allowed:
        try:
            security_urls = [enforcer.check(f"https://{target}").url]
        except Exception:
            security_urls = []

    security_findings = list(secret_findings)
    nuclei_findings = []
    if active_allowed:
        scanner = SecurityScanner(enforcer, config, client)
        security_batch = SecurityBatch()
        if config.security_headers:
            headers_batch = await scanner.check_headers(security_urls, scan_id=scan_id)
            security_batch.findings.extend(headers_batch.findings)
            security_batch.outcomes.extend(headers_batch.outcomes)
            security_batch.waf.update(headers_batch.waf)
        if config.tls_check:
            tls_batch = await scanner.check_tls(security_urls, scan_id=scan_id)
            security_batch.findings.extend(tls_batch.findings)
            security_batch.outcomes.extend(tls_batch.outcomes)
        security_findings.extend(security_batch.findings)
        report.waf = dict(security_batch.waf)
        report.outcomes.extend(security_batch.outcomes)

        if config.nuclei_enabled:
            nuclei_batch: NucleiBatch = await run_nuclei(
                security_urls, scan_id, target, config, resolver, enforcer)
            if nuclei_batch.outcome is not None:
                report.outcomes.append(nuclei_batch.outcome)
            nuclei_findings = list(nuclei_batch.findings)
    else:
        if config.security_headers or config.tls_check:
            report.skipped.append("security inspection skipped: passive mode")
        if config.nuclei_enabled:
            report.skipped.append("nuclei skipped: passive mode")
    report.security_findings = len(security_findings)
    report.nuclei_findings = len(nuclei_findings)

    if dry_run:
        report.status = "dry-run"
        return report

    storage = store_web_items(conn, scan_id, limited, dry_run=False)
    report.stored = storage.stored
    report.skipped_existing = storage.skipped_existing
    report.counts = storage.by_kind

    unique_findings = {}
    for finding in security_findings + nuclei_findings:
        unique_findings[finding.dedup_key] = finding
    findings = list(unique_findings.values())
    if findings:
        report.findings_stored = db.save_many(conn, "findings", findings)

    failed = [o for o in report.outcomes if o.status in (TOOL_FAILED, TOOL_TIMEOUT)]
    report.status = "partial" if failed or report.errors else "completed"
    report.duration_ms = elapsed_ms(start)
    if config.write_outputs:
        report.output_files = write_outputs(config, target, limited, report.to_dict())
    if str(scan.get("status") or "").lower() in ("pending", "running"):
        db.finish_scan(conn, scan_id,
                       "completed" if report.status == "completed" else "failed")
    return report


def run_web_pipeline(
    conn=None,
    *,
    target: Optional[str] = None,
    scan_id: Optional[int] = None,
    scope_path: Optional[str] = None,
    scope_obj=None,
    config: Optional[Member2Config] = None,
    seeds: Iterable[str] = (),
    use_archive: bool = True,
    crawl: bool = True,
    check_status: Optional[bool] = None,
    discover_hosts: Optional[bool] = None,
    dry_run: bool = False,
    mode: Optional[str] = None,
) -> WebPipelineReport:
    """Synchronous entry point used by the CLI and the stage adapter."""
    cfg = config or load_member2_config()
    if check_status is None:
        check_status = cfg.check_status
    if discover_hosts is None:
        discover_hosts = cfg.discover_hosts

    own_conn = conn is None
    if own_conn:
        conn = db.connect(cfg.db_path)
        db.init_db(conn)
    try:
        scan = load_scan(
            conn, target=target, scan_id=scan_id, mode=mode,
            scope_file=scope_path, rate_limit=cfg.rate_limit)
        return asyncio.run(_run_async(
            conn, scan, cfg, scope_path=scope_path, scope_obj=scope_obj, seeds=seeds,
            use_archive=use_archive, crawl=crawl, check_status=check_status,
            discover_hosts=discover_hosts, dry_run=dry_run, mode=mode))
    finally:
        if own_conn:
            conn.close()


async def run_web_pipeline_async(conn, **kwargs) -> WebPipelineReport:
    """Async variant for tests/embedding (caller owns the connection)."""
    cfg = kwargs.pop("config", None) or load_member2_config()
    if kwargs.get("check_status") is None:
        kwargs["check_status"] = cfg.check_status
    if kwargs.get("discover_hosts") is None:
        kwargs["discover_hosts"] = cfg.discover_hosts
    scope_path = kwargs.pop("scope_path", None)
    mode = kwargs.pop("mode", None)
    scan = load_scan(
        conn, target=kwargs.pop("target", None), scan_id=kwargs.pop("scan_id", None),
        mode=mode, scope_file=scope_path,
        rate_limit=getattr(cfg, "rate_limit", None))
    return await _run_async(
        conn, scan, cfg,
        scope_path=scope_path,
        scope_obj=kwargs.pop("scope_obj", None),
        seeds=kwargs.pop("seeds", ()),
        use_archive=kwargs.pop("use_archive", True),
        crawl=kwargs.pop("crawl", True),
        check_status=kwargs.pop("check_status", True),
        discover_hosts=kwargs.pop("discover_hosts", True),
        dry_run=kwargs.pop("dry_run", False),
        mode=mode,
    )
