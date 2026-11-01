"""Archive URL collection: gau, Wayback CDX and (optional) Common Crawl.

Provider endpoints are hard-coded HTTPS URLs.  No provider-supplied pagination
link is followed, which avoids forwarding requests (or credentials) anywhere
unexpected.  Responses are bounded, retried with backoff on 429/5xx, and parsed
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
from dataclasses import dataclass
from typing import Iterable, Optional

from .config import Member2Config
from .errors import (
    TOOL_FAILED, TOOL_OK, TOOL_SKIPPED, ArchiveError,
    ToolOutcome, elapsed_ms, redact,
)
from .normalize import is_under_domain, url_host
from .rate_limit import AsyncRateLimiter, backoff_delay
from .tools import ArchiveRecord, ToolResolver, run_gau

logger = logging.getLogger(__name__)

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
