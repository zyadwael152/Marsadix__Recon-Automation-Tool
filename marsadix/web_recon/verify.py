"""Status-code verification and filtering.

ProjectDiscovery httpx is used when available because it is fast and reports
status/content-type/tech in one pass.  Every input URL is still normalized,
scope-checked and DNS-safety-checked *before* it reaches the tool; httpx is
launched with redirects disabled so it cannot wander off-scope.  If PD httpx is
not installed, the stdlib SafeHTTPClient performs HEAD/GET checks instead.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Iterable, Optional

from .config import Member2Config
from .errors import TOOL_FAILED, TOOL_OK, TOOL_PARTIAL, TOOL_SKIPPED, ToolOutcome, elapsed_ms
from .http_client import SafeHTTPClient
from .normalize import NormalizedURL, normalize_url
from .scope_filter import ScopeEnforcer
from .tools import ToolResolver, VerifyRecord, run_httpx_verify

logger = logging.getLogger(__name__)


@dataclass
class Verification:
    url: str
    status_code: Optional[int]
    content_type: str = ""
    location: str = ""
    ip: Optional[str] = None
    method: str = "httpx"


@dataclass
class VerifyBatch:
    results: dict[str, Verification]
    outcome: ToolOutcome


def _key(url: str) -> str:
    try:
        return normalize_url(url).key
    except Exception:
        return url


class StatusVerifier:
    def __init__(self, enforcer: ScopeEnforcer, config: Member2Config,
                 resolver: ToolResolver, client: SafeHTTPClient) -> None:
        self.enforcer = enforcer
        self.config = config
        self.resolver = resolver
        self.client = client

    async def _safe_inputs(self, urls: list[NormalizedURL]) -> list[NormalizedURL]:
        sem = asyncio.Semaphore(self.config.max_concurrency * 4)

        async def check(item: NormalizedURL) -> bool:
            async with sem:
                try:
                    await self.enforcer.ensure_safe_url(item)
                    return True
                except Exception as exc:
                    logger.debug("dropping unsafe verification target %s: %s", item.host, exc)
                    return False

        flags = await asyncio.gather(*(check(u) for u in urls))
        return [u for u, ok in zip(urls, flags) if ok]

    async def verify(self, urls: Iterable[str]) -> VerifyBatch:
        start = asyncio.get_running_loop().time()
        normalized: list[NormalizedURL] = []
        seen: set[str] = set()
        for raw in urls:
            if len(normalized) >= self.config.max_http_checks:
                break
            try:
                item = self.enforcer.check(raw, strip_tracking=self.config.drop_tracking_params)
            except Exception:
                continue
            if item.key in seen:
                continue
            seen.add(item.key)
            normalized.append(item)

        if not normalized:
            return VerifyBatch({}, ToolOutcome("status-verifier", TOOL_OK,
                                               details={"checked": 0}))
        if not self.config.check_status:
            return VerifyBatch({}, ToolOutcome("status-verifier", TOOL_SKIPPED,
                                               details={"reason": "disabled"}))

        safe_inputs = await self._safe_inputs(normalized)
        if not safe_inputs:
            return VerifyBatch({}, ToolOutcome(
                "status-verifier", TOOL_FAILED,
                error="all verification targets resolved to blocked addresses"))

        pd_httpx = self.resolver.path("httpx")
        results: dict[str, Verification] = {}
        used_tool = False
        missing: list[NormalizedURL] = []

        if pd_httpx:
            used_tool = True
            records, outcome = await run_httpx_verify(
                [u.url for u in safe_inputs], self.config, self.resolver)
            by_key = {_key(r.url): r for r in records}
            for item in safe_inputs:
                rec = by_key.get(item.key) or by_key.get(_key(item.url))
                if rec is None:
                    missing.append(item)
                    continue
                results[item.key] = Verification(
                    url=item.url, status_code=rec.status_code,
                    content_type=rec.content_type, location=rec.location,
                    ip=rec.ip, method="httpx",
                )
            logger.info("[+] httpx verified %d/%d URL(s); %d missing",
                        len(results), len(safe_inputs), len(missing))
            # A handful of URLs that httpx did not emit (e.g. connection
            # failures) get one internal attempt, bounded to keep runtime sane.
            fallback = missing[:min(len(missing), 100)]
            if fallback:
                fallback_results, _ = await self._internal(fallback)
                results.update(fallback_results)
            if outcome.status == TOOL_PARTIAL and not results:
                outcome = ToolOutcome("httpx", TOOL_FAILED, error=outcome.error,
                                      duration_ms=outcome.duration_ms)
        else:
            fallback_results, outcome = await self._internal(safe_inputs)
            results.update(fallback_results)

        filtered = {k: v for k, v in results.items() if self.config.status_allowed(v.status_code)}
        dropped = len(results) - len(filtered)
        if dropped:
            logger.info("[*] Status filter removed %d URL(s) (allowed: %s)",
                        dropped, self.config.status_allow)
        elapsed = int((asyncio.get_running_loop().time() - start) * 1000)
        outcome.duration_ms = elapsed
        outcome.kept = len(filtered)
        outcome.discovered = len(results)
        outcome.details.update({
            "requested": len(normalized), "safe": len(safe_inputs),
            "checked": len(results), "allowed": len(filtered),
            "filter": self.config.status_allow, "backend": "httpx" if used_tool else "stdlib",
        })
        return VerifyBatch(filtered, outcome)

    async def _internal(self, items: list[NormalizedURL]) -> tuple[dict[str, Verification], ToolOutcome]:
        start = asyncio.get_running_loop().time()
        results: dict[str, Verification] = {}
        sem = asyncio.Semaphore(self.config.max_concurrency)

        async def one(item: NormalizedURL) -> None:
            async with sem:
                try:
                    _, result = await self.client.status(item.url)
                except Exception as exc:
                    logger.debug("internal status check failed %s: %s", item.host, type(exc).__name__)
                    return
                if result.error:
                    return
                results[item.key] = Verification(
                    url=item.url, status_code=result.status,
                    content_type=result.content_type,
                    location=result.header("location"), method="stdlib")

        await asyncio.gather(*(one(i) for i in items))
        status = TOOL_OK if results else TOOL_FAILED
        return results, ToolOutcome(
            "status-verifier", status, discovered=len(results), kept=len(results),
            duration_ms=int((asyncio.get_running_loop().time() - start) * 1000),
            details={"backend": "stdlib"})
