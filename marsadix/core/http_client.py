"""Small safe HTTP client used for status checks, JS fetching and the fallback crawler.

Only the standard library is used.  Every request passes the same gates:

1. URL normalization + scope check;
2. DNS resolution + private/loopback/link-local block (unless explicitly in scope);
3. a shared token-bucket rate limiter;
4. a hard socket/read timeout and a response-size cap;
5. redirects are followed manually, one hop at a time, re-checking scope/DNS.

It is intentionally not a browser: no JavaScript execution, no cookies beyond
one request, no POST bodies.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urljoin

from .config import Member2Config
from .errors import ScopeViolation, UnsafeTarget
from .normalize import NormalizedURL, safe_url_for_log
from .rate_limit import AsyncRateLimiter, backoff_delay
from .scope_filter import ScopeEnforcer

logger = logging.getLogger(__name__)

_RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}
_REDIRECT_STATUS = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class HTTPResult:
    requested_url: str
    final_url: str
    status: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.error == "" and self.status is not None

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type", "") or "").split(";", 1)[0].strip().lower()

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype.lower():
            charset = ctype.lower().split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def _read_limited(stream, limit: int) -> tuple[bytes, bool]:
    data = stream.read(limit + 1)
    if len(data) > limit:
        return data[:limit], True
    return data, False


class SafeHTTPClient:
    def __init__(self, enforcer: ScopeEnforcer, config: Member2Config,
                 limiter: Optional[AsyncRateLimiter] = None) -> None:
        self.enforcer = enforcer
        self.config = config
        self.limiter = limiter or AsyncRateLimiter(config.rate_limit)
        self._semaphore = asyncio.Semaphore(config.max_concurrency)

    # ------------------------------------------------------------------ sync core
    def _blocking_request(self, url: str, method: str, max_bytes: int) -> HTTPResult:
        req = urllib.request.Request(url, method=method, headers={
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        handlers = [_NoRedirect()]
        if url.lower().startswith("https://"):
            context = ssl.create_default_context()
            if not self.config.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(req, timeout=self.config.request_timeout) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                body = b""
                truncated = False
                if method != "HEAD":
                    body, truncated = _read_limited(response, max_bytes)
                return HTTPResult(url, response.geturl(), response.status, headers, body, truncated)
        except urllib.error.HTTPError as exc:
            headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
            body = b""
            truncated = False
            if method != "HEAD":
                try:
                    body, truncated = _read_limited(exc, max_bytes)
                except Exception:
                    body = b""
            return HTTPResult(url, exc.geturl() or url, exc.code, headers, body, truncated)
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError, ValueError) as exc:
            return HTTPResult(url, url, None, {}, b"", error=f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------ async API
    async def request(self, raw_url: str, *, method: str = "GET",
                      max_bytes: int = 2_000_000,
                      follow_redirects: Optional[bool] = None,
                      base_url: Optional[str] = None,
                      require_safe_dns: bool = True) -> tuple[NormalizedURL, HTTPResult]:
        current = self.enforcer.check(raw_url, base_url=base_url,
                                      strip_tracking=self.config.drop_tracking_params)
        follow = self.config.follow_redirects if follow_redirects is None else follow_redirects
        visited: set[str] = {current.key}
        hops = 0

        for attempt in range(self.config.retries + 1):
            if require_safe_dns:
                await self.enforcer.ensure_safe_url(current)
            await self.limiter.acquire()
            async with self._semaphore:
                result = await asyncio.to_thread(
                    self._blocking_request, current.url, method, max_bytes)

            retry_after = _retry_after_seconds(result.header("retry-after"))
            if result.status in _RETRY_STATUS and attempt < self.config.retries:
                logger.debug("retrying %s after HTTP %s (attempt %d)",
                             safe_url_for_log(current.url), result.status, attempt + 1)
                await backoff_delay(attempt, retry_after=retry_after)
                continue
            if result.error and attempt < self.config.retries:
                logger.debug("retrying %s after %s", safe_url_for_log(current.url),
                             result.error)
                await backoff_delay(attempt)
                continue
            break

        while (follow and result.status in _REDIRECT_STATUS
               and result.header("location") and hops < _MAX_REDIRECTS):
            hops += 1
            location = urljoin(current.url, result.header("location").strip())
            try:
                target = self.enforcer.check(location, strip_tracking=self.config.drop_tracking_params)
            except ScopeViolation as exc:
                logger.warning("redirect from %s left scope: %s",
                               safe_url_for_log(current.url), exc)
                break
            if target.key in visited:
                break
            visited.add(target.key)
            if require_safe_dns:
                try:
                    await self.enforcer.ensure_safe_url(target)
                except UnsafeTarget as exc:
                    logger.warning("redirect target blocked: %s", exc)
                    break
            current = target
            await self.limiter.acquire()
            async with self._semaphore:
                result = await asyncio.to_thread(
                    self._blocking_request, current.url, method, max_bytes)

        return current, result

    async def fetch(self, raw_url: str, *, max_bytes: int = 2_000_000,
                    method: str = "GET", base_url: Optional[str] = None) -> tuple[NormalizedURL, HTTPResult]:
        return await self.request(raw_url, method=method, max_bytes=max_bytes,
                                  follow_redirects=True, base_url=base_url)

    async def status(self, raw_url: str) -> tuple[NormalizedURL, HTTPResult]:
        """HEAD first; fall back to GET for servers that reject HEAD."""
        normalized, result = await self.request(raw_url, method="HEAD",
                                                max_bytes=4096,
                                                follow_redirects=False)
        if result.status in (400, 403, 405, 501) or result.status is None:
            normalized, result = await self.request(raw_url, method="GET",
                                                    max_bytes=4096,
                                                    follow_redirects=False)
        return normalized, result

    async def status_many(self, urls: Iterable[str], limit: Optional[int] = None
                          ) -> list[tuple[NormalizedURL, HTTPResult]]:
        urls = list(urls)
        if limit is not None:
            urls = urls[:limit]
        tasks = [self.status(u) for u in urls]
        if not tasks:
            return []
        return list(await asyncio.gather(*tasks))


def _retry_after_seconds(value: str) -> Optional[float]:
    if not value:
        return None
    try:
        return float(value.strip())
    except ValueError:
        return None
