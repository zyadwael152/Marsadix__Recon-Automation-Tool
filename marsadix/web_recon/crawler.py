"""Built-in, dependency-free crawler used as a katana fallback/supplement.

It fetches a bounded number of in-scope HTML pages, extracts links/scripts/
forms, and records status/content-type for every fetched URL.  It is not meant
to replace katana's JS-aware crawler; it keeps the pipeline functional when
katana is missing and provides a deterministic surface for tests.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable, Optional
from urllib.parse import urljoin
from urllib.robotparser import RobotFileParser

from .config import Member2Config
from .errors import TOOL_FAILED, TOOL_OK, TOOL_PARTIAL, ToolOutcome, elapsed_ms
from .http_client import SafeHTTPClient
from .normalize import NormalizedURL
from .scope_filter import ScopeEnforcer
from .tools import CrawlRecord

logger = logging.getLogger(__name__)

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
