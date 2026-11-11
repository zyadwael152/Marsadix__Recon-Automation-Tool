"""Subdomain discovery adapters (passive + active verification).

The base repository already has a full recon stage.  This module does not
replace it; it exposes the Member 2-facing discovery surface separately so the
extension can enrich an existing scan with archive-derived hosts and so the
standalone CLI can run a focused discovery pass.  Storage still goes through
`marsadix.db` and `marsadix.models`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, Optional

from marsadix import db
from marsadix.core.scope import valid_hostname
from marsadix.models import Asset, DiscoverySource
from marsadix.recon.confidence import compute_source_confidence

from .archive import ArchiveCollector, host_sources
from .config import Member2Config
from .errors import TOOL_FAILED, TOOL_OK, ToolOutcome, elapsed_ms, redact
from .normalize import is_under_domain
from .rate_limit import AsyncRateLimiter, backoff_delay
from .scope_filter import ScopeEnforcer
from .tools import ToolResolver, run_subfinder

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryBatch:
    hosts_sources: dict[str, list[str]] = field(default_factory=dict)
    outcomes: list[ToolOutcome] = field(default_factory=list)

    def merge(self, hosts: Iterable[str], source: str) -> int:
        added = 0
        for host in hosts:
            bucket = self.hosts_sources.setdefault(host, [])
            if source not in bucket:
                bucket.append(source)
                added += 1
        return added


class SubdomainEnumerator:
    def __init__(self, config: Member2Config, enforcer: ScopeEnforcer,
                 resolver: Optional[ToolResolver] = None,
                 limiter: Optional[AsyncRateLimiter] = None) -> None:
        self.config = config
        self.enforcer = enforcer
        self.resolver = resolver or ToolResolver(config)
        self.limiter = limiter or AsyncRateLimiter(config.rate_limit)
        self.archives = ArchiveCollector(config, self.limiter)

    async def _get_json(self, url: str, timeout: float) -> tuple[int, bytes]:
        def blocking() -> tuple[int, bytes]:
            req = urllib.request.Request(url, headers={
                "User-Agent": self.config.user_agent,
                "Accept": "application/json",
            })
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                    return resp.status, resp.read(25 * 1024 * 1024)
            except urllib.error.HTTPError as exc:
                return exc.code, b""
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                return 0, b""

        last_status, body = 0, b""
        for attempt in range(self.config.retries + 1):
            await self.limiter.acquire()
            last_status, body = await asyncio.to_thread(blocking)
            if last_status in (200, 204):
                return last_status, body
            if (last_status == 0 or last_status == 429
                    or 500 <= last_status < 600) and attempt < self.config.retries:
                await backoff_delay(attempt)
                continue
            break
        return last_status, body

    async def fetch_crtsh(self, domain: str) -> tuple[list[str], ToolOutcome]:
        start = time.monotonic()
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain, safe='.-')}&output=json"
        try:
            status, body = await self._get_json(url, self.config.archive_timeout)
            if status != 200:
                raise RuntimeError(f"crt.sh returned HTTP {status or 'network error'}")
            data = json.loads(body.decode("utf-8", errors="replace"))
            if not isinstance(data, list):
                raise RuntimeError("crt.sh returned a non-list JSON document")
            hosts: set[str] = set()
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.").rstrip(".")
                    if valid_hostname(name) and is_under_domain(name, domain):
                        hosts.add(name)
            return sorted(hosts), ToolOutcome(
                "crt.sh", TOOL_OK, discovered=len(hosts), kept=len(hosts),
                duration_ms=elapsed_ms(start))
        except Exception as exc:
            message = redact(f"{type(exc).__name__}: {exc}")
            logger.warning("[-] crt.sh discovery failed: %s", message)
            return [], ToolOutcome("crt.sh", TOOL_FAILED,
                                   duration_ms=elapsed_ms(start), error=message)

    async def discover(self, domain: str, *, passive: bool = True,
                       active: bool = False) -> DiscoveryBatch:
        batch = DiscoveryBatch()
        if passive:
            hosts, outcome = await run_subfinder(domain, self.config, self.resolver)
            batch.outcomes.append(outcome)
            if hosts:
                batch.merge((h for h in hosts if self.enforcer.in_scope(h)), "subfinder")

            crt_hosts, crt_outcome = await self.fetch_crtsh(domain)
            batch.outcomes.append(crt_outcome)
            if crt_hosts:
                batch.merge((h for h in crt_hosts if self.enforcer.in_scope(h)), "crt.sh")

            archive_batch = await self.archives.collect(domain, self.resolver)
            batch.outcomes.extend(archive_batch.outcomes)
            sources = host_sources(archive_batch.records, domain)
            for host, names in sources.items():
                if self.enforcer.in_scope(host):
                    for name in (names or ["archive"]):
                        batch.merge([host], name)

        if active:
            verified, dns_outcome = await self.verify_hosts(batch.hosts_sources)
            batch.outcomes.append(dns_outcome)
            batch.hosts_sources = verified

        return batch

    async def verify_hosts(self, hosts_sources: dict[str, list[str]]
                           ) -> tuple[dict[str, list[str]], ToolOutcome]:
        start = time.monotonic()
        verified: dict[str, list[str]] = {}
        sem = asyncio.Semaphore(self.config.max_concurrency)

        async def one(host: str, sources: list[str]) -> None:
            if not self.enforcer.in_scope(host) or not valid_hostname(host):
                return
            async with sem:
                try:
                    await self.enforcer.public_addresses(host)
                except Exception:
                    return
            verified[host] = sources

        await asyncio.gather(*(one(h, s) for h, s in hosts_sources.items()))
        return verified, ToolOutcome(
            "dns-verification", TOOL_OK, discovered=len(hosts_sources),
            kept=len(verified), duration_ms=elapsed_ms(start),
            details={"resolved": len(verified), "candidates": len(hosts_sources)})

    async def store(self, conn, scan_id: int, target: str,
                    hosts_sources: dict[str, list[str]],
                    scope: ScopeEnforcer) -> int:
        """
        Store newly resolved, in-scope hosts as Asset + AssetSource rows.

        Only hosts that resolve to a public (or scope-authorised) address are
        stored, mirroring the base recon stage's "active" semantics.  Existing
        assets are left untouched thanks to INSERT OR IGNORE.
        """
        if not hosts_sources:
            return 0
        existing = {row["host"] for row in db.get_assets(conn, scan_id)}
        candidates = {h: s for h, s in hosts_sources.items()
                      if h not in existing and h != target and scope.in_scope(h)}
        if not candidates:
            return 0

        resolved: dict[str, tuple[str, list[str]]] = {}
        sem = asyncio.Semaphore(self.config.max_concurrency)

        async def resolve(host: str, sources: list[str]) -> None:
            async with sem:
                try:
                    addresses = await self.enforcer.public_addresses(host)
                except Exception:
                    return
                resolved[host] = (addresses[0], sources)

        await asyncio.gather(*(resolve(h, s) for h, s in candidates.items()))
        if not resolved:
            return 0
        scores = compute_source_confidence({h: src for h, (_, src) in resolved.items()})
        assets = [
            Asset(
                scan_id=scan_id, host=host, ip=ip, in_scope=True, depth=1,
                source=DiscoverySource.PASSIVE, parent_host=target,
                confidence_score=scores.get(host, 0),
            )
            for host, (ip, _) in resolved.items()
        ]
        saved = db.save_many(conn, "assets", assets)
        for host, (_, sources) in resolved.items():
            db.save_asset_sources_many(conn, scan_id, host, sources)
        logger.info("[+] Stored %d archive/discovery host(s) as assets", saved)
        return saved
