"""Web URL collection for Marsadix.

Two collectors share this module because both produce URL records for the
web stage:
  - BuiltinCrawler: dependency-free, bounded, in-scope HTML crawler (W1 fallback
    when katana is missing, and a deterministic surface for tests).
  - ArchiveCollector: gau, Wayback CDX and Common Crawl URL collection (W1).

Provider endpoints are hard-coded HTTPS URLs. No provider-supplied pagination
link is followed, which avoids forwarding requests (or credentials) anywhere
unexpected. Responses are bounded, retried with backoff on 429/5xx, and parsed
defensively because archive APIs occasionally return HTML maintenance pages.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable, Optional
from urllib.parse import urljoin
from urllib.robotparser import RobotFileParser

# TODO: عدّل الـ imports دي بعد ما core يتحدد بالظبط (انظر ملاحظات تحت الكود)
from .config import Member2Config
from .errors import (
    TOOL_FAILED, TOOL_OK, TOOL_PARTIAL, TOOL_SKIPPED, ArchiveError,
    ToolOutcome, elapsed_ms, redact,
)
from ..core.http_client import SafeHTTPClient
from ..core.rate_limit import AsyncRateLimiter, backoff_delay
from ..core.scope_filter import ScopeEnforcer
from .normalize import NormalizedURL, is_under_domain, url_host
from .tools import ArchiveRecord, CrawlRecord, ToolResolver, run_gau

logger = logging.getLogger(__name__)

# ============================================================================
# Builtin crawler
# ============================================================================

_BINARY_TYPES = (
    "image/", "font/", "audio/", "video/", "application/pdf", "application/zip",
    "application/octet-stream", "application/x-",
)


class LinkExtractor(HTMLParser):
    """Collect href/src/action targets without executing or rendering HTML."""

    def __init__(self, max_links: int = 500) -> None:
        super().__init__(convert_charrefs=True)
        self.max_links = max_links
        self.links: list[str] = []
        self.base_href: Optional[str] = None
        self._seen: set[str] = set()

    def _add(self, value: Optional[str]) -> None:
        if not value or len(self.links) >= self.max_links:
            return
        value = value.strip()
        if not value or value.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return
        if value not in self._seen:
            self._seen.add(value)
            self.links.append(value)

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "base" and values.get("href"):
            self.base_href = values["href"]
        elif tag in ("a", "area"):
            self._add(values.get("href"))
        elif tag == "script":
            self._add(values.get("src"))
        elif tag == "link":
            self._add(values.get("href"))
        elif tag == "form":
            self._add(values.get("action"))
        elif tag in ("iframe", "frame"):
            self._add(values.get("src"))
        elif tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            content = values.get("content", "")
            if "url=" in content.lower():
                self._add(content.lower().split("url=", 1)[1].strip().strip("'\""))


@dataclass
class CrawlBatch:
    records: list[CrawlRecord]
    outcome: ToolOutcome


def is_probably_html(content_type: str) -> bool:
    ctype = (content_type or "").lower()
    return not ctype or "html" in ctype or "xml" in ctype


def is_binary(content_type: str) -> bool:
    return any((content_type or "").lower().startswith(prefix) for prefix in _BINARY_TYPES)


class BuiltinCrawler:
    def __init__(self, enforcer: ScopeEnforcer, config: Member2Config,
                 client: SafeHTTPClient) -> None:
        self.enforcer = enforcer
        self.config = config
        self.client = client
        self._robots: dict[str, Optional[RobotFileParser]] = {}

    async def _robots_for(self, normalized: NormalizedURL) -> Optional[RobotFileParser]:
        if not self.config.respect_robots:
            return None
        origin = normalized.origin
        if origin in self._robots:
            return self._robots[origin]
        parser: Optional[RobotFileParser] = None
        try:
            _, result = await self.client.fetch(origin + "/robots.txt", max_bytes=128 * 1024)
            if result.status == 200 and result.text:
                parser = RobotFileParser()
                parser.parse(result.text.splitlines())
        except Exception as exc:
            logger.debug("robots.txt unavailable for %s: %s", normalized.host, type(exc).__name__)
        self._robots[origin] = parser
        return parser

    async def _allowed(self, normalized: NormalizedURL) -> bool:
        parser = await self._robots_for(normalized)
        if parser is None:
            return True
        try:
            return parser.can_fetch(self.config.user_agent, normalized.url)
        except Exception:
            return True

    async def crawl(self, seeds: Iterable[str],
                    max_pages: Optional[int] = None) -> CrawlBatch:
        start = asyncio.get_running_loop().time()
        max_pages = self.config.max_pages if max_pages is None else max_pages
        queue: deque[tuple[NormalizedURL, int, Optional[str]]] = deque()
        seen: set[str] = set()
        records: dict[str, CrawlRecord] = {}
        pages = 0
        errors = 0

        for seed in seeds:
            try:
                normalized = self.enforcer.check(seed)
            except Exception:
                continue
            if normalized.key in seen:
                continue
            seen.add(normalized.key)
            queue.append((normalized, 0, None))

        while queue and pages < max_pages:
            normalized, depth, parent = queue.popleft()
            if not await self._allowed(normalized):
                logger.debug("robots.txt disallows %s", normalized.url)
                continue
            final, result = await self.client.fetch(normalized.url, max_bytes=2_000_000)
            pages += 1
            if result.error:
                errors += 1
                logger.debug("crawl fetch failed %s: %s", normalized.url, result.error)
                continue
            record = CrawlRecord(
                url=final.url,
                status_code=result.status,
                content_type=result.content_type,
                parent_url=parent,
                source="builtin",
            )
            records[final.key] = record
            if result.status is None or result.status >= 400 or is_binary(result.content_type):
                continue
            if depth >= self.config.crawl_depth or not is_probably_html(result.content_type):
                continue
            parser = LinkExtractor(self.config.max_links_per_page)
            try:
                parser.feed(result.text)
            except Exception:
                continue
            base = urljoin(final.url, parser.base_href) if parser.base_href else final.url
            for raw in parser.links:
                try:
                    link = self.enforcer.check(raw, base_url=base)
                except Exception:
                    continue
                if link.key in seen:
                    continue
                seen.add(link.key)
                queue.append((link, depth + 1, final.url))
                if len(queue) + len(records) >= self.config.max_pages * 10:
                    break

        elapsed = int((asyncio.get_running_loop().time() - start) * 1000)
        status = TOOL_OK if not errors else (TOOL_PARTIAL if records else TOOL_FAILED)
        outcome = ToolOutcome(
            "builtin-crawler", status, discovered=len(records), kept=len(records),
            duration_ms=elapsed, error=f"{errors} fetch error(s)" if errors else "",
            details={"pages": pages, "max_pages": max_pages},
        )
        return CrawlBatch(records=list(records.values()), outcome=outcome)


# ============================================================================
# Archive collectors (gau, Wayback CDX, Common Crawl)
# ============================================================================

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
COMMONCRAWL_INDEX = "https://index.commoncrawl.org"
COMMONCRAWL_COLLINFO = f"{COMMONCRAWL_INDEX}/collinfo.json"
_MAX_BYTES = 12 * 1024 * 1024


@dataclass
class ArchiveBatch:
    records: list[ArchiveRecord]
    outcomes: list[ToolOutcome]


def _status(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class ArchiveCollector:
    def __init__(self, config: Member2Config,
                 limiter: Optional[AsyncRateLimiter] = None) -> None:
        self.config = config
        self.limiter = limiter or AsyncRateLimiter(config.rate_limit)
        self._collinfo: Optional[str] = None

    # --------------------------------------------------------------- transport
    async def _fetch(self, url: str, *, accept: str = "application/json") -> tuple[int, bytes]:
        """GET one hard-coded archive URL; returns (status, body)."""
        await self.limiter.acquire()

        def _blocking() -> tuple[int, bytes]:
            req = urllib.request.Request(url, headers={
                "User-Agent": self.config.user_agent,
                "Accept": accept,
                "Accept-Encoding": "identity",
            })
            try:
                with urllib.request.urlopen(req, timeout=self.config.archive_timeout) as resp:  # nosec B310
                    return resp.status, resp.read(_MAX_BYTES)
            except urllib.error.HTTPError as exc:
                try:
                    body = exc.read(_MAX_BYTES)
                except Exception:
                    body = b""
                return exc.code, body
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                return 0, b""

        last_status = 0
        for attempt in range(self.config.retries + 1):
            last_status, body = await asyncio.to_thread(_blocking)
            if last_status in (200, 204):
                return last_status, body
            if last_status == 0 or last_status == 429 or 500 <= last_status < 600:
                if attempt < self.config.retries:
                    logger.debug("archive request retry %d for %s (HTTP %s)",
                                 attempt + 1, urllib.parse.urlsplit(url).netloc, last_status)
                    await backoff_delay(attempt)
                    continue
            break
        return last_status, body

    # ------------------------------------------------------------------ wayback
    async def fetch_wayback(self, domain: str) -> tuple[list[ArchiveRecord], ToolOutcome]:
        start = time.monotonic()
        params = [
            ("url", domain),
            ("matchType", "domain"),
            ("output", "json"),
            ("fl", "original,timestamp,statuscode,mimetype"),
            ("collapse", "urlkey"),
            ("filter", "statuscode:200"),
            ("limit", str(min(self.config.max_archive_urls, 10000))),
        ]
        url = WAYBACK_CDX + "?" + urllib.parse.urlencode(params)
        try:
            status, body = await self._fetch(url)
            if status != 200:
                raise ArchiveError(f"Wayback CDX returned HTTP {status or 'network error'}")
            data = json.loads(body.decode("utf-8", errors="replace"))
            if not isinstance(data, list):
                raise ArchiveError("Wayback CDX returned a non-list JSON document")
            records: list[ArchiveRecord] = []
            if data and isinstance(data[0], list):
                header = [str(h).lower() for h in data[0]]
                rows = data[1:]
            else:
                header = ["original", "timestamp", "statuscode", "mimetype"]
                rows = data
            idx = {name: i for i, name in enumerate(header)}
            for row in rows:
                if not isinstance(row, list):
                    continue

                def cell(name: str, default=""):
                    pos = idx.get(name)
                    return row[pos] if pos is not None and pos < len(row) else default

                original = str(cell("original") or "").strip()
                if not original:
                    continue
                records.append(ArchiveRecord(
                    url=original,
                    source="wayback",
                    status_code=_status(cell("statuscode")),
                    mime_type=str(cell("mimetype") or "").split(";", 1)[0].lower(),
                ))
            records = [r for r in records if url_host(r.url) and is_under_domain(url_host(r.url) or "", domain)]
            records = list({r.url: r for r in records}.values())[:self.config.max_archive_urls]
            logger.info("[+] Wayback CDX returned %d in-scope URL(s)", len(records))
            return records, ToolOutcome(
                "wayback", TOOL_OK, discovered=len(records), kept=len(records),
                duration_ms=elapsed_ms(start), details={"endpoint": WAYBACK_CDX})
        except Exception as exc:
            message = redact(f"{type(exc).__name__}: {exc}")
            logger.warning("[-] Wayback collection failed: %s", message)
            return [], ToolOutcome("wayback", TOOL_FAILED, duration_ms=elapsed_ms(start),
                                   error=message)

    # ------------------------------------------------------------- common crawl
    async def _latest_commoncrawl_index(self) -> str:
        if self._collinfo:
            return self._collinfo
        status, body = await self._fetch(COMMONCRAWL_COLLINFO)
        if status != 200:
            raise ArchiveError(f"Common Crawl collinfo returned HTTP {status or 'network error'}")
        data = json.loads(body.decode("utf-8", errors="replace"))
        if not isinstance(data, list) or not data:
            raise ArchiveError("Common Crawl collinfo was empty")
        # collinfo is newest-first; prefer the first item with an id.
        for item in data:
            if isinstance(item, dict) and item.get("id"):
                self._collinfo = str(item["id"])
                return self._collinfo
        raise ArchiveError("Common Crawl collinfo has no index id")

    async def fetch_commoncrawl(self, domain: str) -> tuple[list[ArchiveRecord], ToolOutcome]:
        start = time.monotonic()
        records: list[ArchiveRecord] = []
        try:
            index = await self._latest_commoncrawl_index()
            for page in range(self.config.archive_pages):
                params = urllib.parse.urlencode([
                    ("url", f"*.{domain}"),
                    ("output", "json"),
                    ("fl", "url,status,mime"),
                    ("filter", "status:200"),
                    ("collapse", "urlkey"),
                    ("page", str(page)),
                ])
                url = f"{COMMONCRAWL_INDEX}/{index}-index?{params}"
                status, body = await self._fetch(url)
                if status != 200 or not body.strip():
                    break
                added = 0
                for line in body.decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(row, dict) or not row.get("url"):
                        continue
                    original = str(row["url"])
                    host = url_host(original)
                    if not host or not is_under_domain(host, domain):
                        continue
                    records.append(ArchiveRecord(
                        url=original, source="commoncrawl",
                        status_code=_status(row.get("status")),
                        mime_type=str(row.get("mime") or "").split(";", 1)[0].lower(),
                    ))
                    added += 1
                    if len(records) >= self.config.max_archive_urls:
                        break
                if added == 0 or len(records) >= self.config.max_archive_urls:
                    break
            records = list({r.url: r for r in records}.values())[:self.config.max_archive_urls]
            logger.info("[+] Common Crawl returned %d in-scope URL(s)", len(records))
            return records, ToolOutcome(
                "commoncrawl", TOOL_OK, discovered=len(records), kept=len(records),
                duration_ms=elapsed_ms(start), details={"index": index})
        except Exception as exc:
            message = redact(f"{type(exc).__name__}: {exc}")
            logger.warning("[-] Common Crawl collection failed: %s", message)
            return [], ToolOutcome("commoncrawl", TOOL_FAILED, duration_ms=elapsed_ms(start),
                                   error=message)

    # -------------------------------------------------------------------- merge
    async def collect(self, domain: str, resolver: ToolResolver) -> ArchiveBatch:
        records: list[ArchiveRecord] = []
        outcomes: list[ToolOutcome] = []

        if "gau" in self.config.archive_sources:
            gau_records, gau_outcome = await run_gau(
                [domain], self.config, resolver,
                providers=tuple(p for p in ("wayback", "commoncrawl")
                                if p in self.config.archive_sources) or ("wayback",))
            records.extend(gau_records)
            outcomes.append(gau_outcome)
        else:
            outcomes.append(ToolOutcome("gau", TOOL_SKIPPED, details={"reason": "disabled"}))

        if "wayback" in self.config.archive_sources:
            wb_records, wb_outcome = await self.fetch_wayback(domain)
            records.extend(wb_records)
            outcomes.append(wb_outcome)
        else:
            outcomes.append(ToolOutcome("wayback", TOOL_SKIPPED, details={"reason": "disabled"}))

        if "commoncrawl" in self.config.archive_sources:
            cc_records, cc_outcome = await self.fetch_commoncrawl(domain)
            records.extend(cc_records)
            outcomes.append(cc_outcome)
        else:
            outcomes.append(ToolOutcome("commoncrawl", TOOL_SKIPPED, details={"reason": "disabled"}))

        # Prefer a record that carries a status code / mime when duplicate URLs
        # arrive from multiple providers.
        merged: dict[str, ArchiveRecord] = {}
        for rec in records:
            existing = merged.get(rec.url)
            if existing is None:
                merged[rec.url] = rec
                continue
            if existing.status_code is None and rec.status_code is not None:
                merged[rec.url] = rec
        result = list(merged.values())[:self.config.max_archive_urls]
        if len(merged) > len(result):
            logger.info("[*] Archive URL cap reached: kept %d of %d", len(result), len(merged))
        return ArchiveBatch(records=result, outcomes=outcomes)


def host_sources(records: Iterable[ArchiveRecord], domain: str) -> dict[str, list[str]]:
    """Map in-scope host -> archive source names."""
    out: dict[str, list[str]] = {}
    for rec in records:
        host = url_host(rec.url)
        if not host or not is_under_domain(host, domain):
            continue
        names = out.setdefault(host, [])
        if rec.source not in names:
            names.append(rec.source)
    return out
