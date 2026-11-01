"""Static JavaScript endpoint extraction (no JS execution).

This is a LinkFinder/jsluice-style pass implemented with the standard library:
quoted paths, absolute URLs, fetch/axios/XHR calls and dynamic imports are
collected from JavaScript bodies.  The extractor is intentionally conservative
and never executes code.  Every candidate is resolved against the script URL
and then normalized + scope-checked by the caller.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urljoin

from .config import Member2Config
from .errors import TOOL_FAILED, TOOL_OK, TOOL_PARTIAL, ToolOutcome, elapsed_ms
from .http_client import SafeHTTPClient
from .normalize import normalize_url
from .scope_filter import ScopeEnforcer
from .security import scan_js_secrets

logger = logging.getLogger(__name__)

_ABS = re.compile(r"https?://[^\s\"'`<>\\\x00-\x1f]+", re.IGNORECASE)
_PROTO = re.compile(r"(?<!:)//[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s\"'`<>\\\x00-\x1f]*)?")
_QUOTED = re.compile(r"[\"'`](?P<u>(?:\.{0,2}/|/)[^\"'`\s<>\\\x00-\x1f]{1,500})[\"'`]")
_CALLS = re.compile(
    r"(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|options))?|"
    r"\.open|\.ajax|import|url\s*:|action\s*:)\s*\(?\s*[\"'`]"
    r"(?P<u>[^\"'`\s<>\\\x00-\x1f]{1,500})[\"'`]",
    re.IGNORECASE,
)

_ALLOWED_EXT_HINT = re.compile(r"\.[A-Za-z0-9]{2,8}$")
_TRAILING = ".,;:!?)]}"


@dataclass
class ExtractedEndpoint:
    url: str
    parent_url: str
    source: str = "js"


def _clean_candidate(value: str) -> Optional[str]:
    value = value.strip().rstrip(_TRAILING)
    if not value:
        return None
    lowered = value.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "#")):
        return None
    if "${" in value or "{{" in value or "%7b%7b" in lowered:
        return None
    if any(ord(ch) < 32 or ch == "\\" or ch.isspace() for ch in value):
        return None
    return value


def extract_urls(js_text: str, base_url: str, limit: int = 5000) -> list[str]:
    """Return unique absolute HTTP(S) candidates found in a JS body."""
    if not js_text:
        return []
    # Bundlers/minifiers commonly escape slashes inside string literals.
    js_text = js_text.replace("\\/", "/")
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        if len(found) >= limit:
            return
        candidate = _clean_candidate(raw)
        if not candidate:
            return
        if candidate.startswith("//"):
            candidate = "https:" + candidate
        elif not candidate.startswith(("http://", "https://")):
            if not candidate.startswith(("/", "./", "../")):
                candidate = "/" + candidate
            candidate = urljoin(base_url, candidate)
        try:
            normalized = normalize_url(candidate)
        except Exception:
            return
        if normalized.key in seen:
            return
        seen.add(normalized.key)
        found.append(normalized.url)

    for regex in (_ABS, _PROTO, _CALLS, _QUOTED):
        for match in regex.finditer(js_text):
            value = match.groupdict().get("u") if match.groupdict() else None
            add(value if value is not None else match.group(0))
    return found


def looks_like_js(url: str, content_type: str = "") -> bool:
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype in ("application/javascript", "text/javascript", "application/x-javascript",
                 "text/ecmascript", "application/ecmascript"):
        return True
    path = normalize_url(url).path.lower()
    return path.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))


@dataclass
class JsBatch:
    endpoints: list[ExtractedEndpoint]
    outcome: ToolOutcome
    secret_findings: list = field(default_factory=list)


class JsHarvester:
    def __init__(self, enforcer: ScopeEnforcer, config: Member2Config,
                 client: SafeHTTPClient, scan_id: int = 0) -> None:
        self.enforcer = enforcer
        self.config = config
        self.client = client
        self.scan_id = scan_id

    async def harvest(self, js_urls: Iterable[str]) -> JsBatch:
        start = asyncio.get_running_loop().time()
        selected: list[str] = []
        seen: set[str] = set()
        for raw in js_urls:
            if len(selected) >= self.config.max_js_files:
                break
            try:
                normalized = self.enforcer.check(raw)
            except Exception:
                continue
            if not looks_like_js(normalized.url):
                continue
            if normalized.key in seen:
                continue
            seen.add(normalized.key)
            selected.append(normalized.url)

        endpoints: list[ExtractedEndpoint] = []
        secret_findings: list = []
        parsed = 0
        failed = 0
        seen_endpoints: set[str] = set()

        for js_url in selected:
            _, result = await self.client.fetch(js_url, max_bytes=self.config.max_js_bytes)
            if result.error or result.status is None or result.status >= 400:
                failed += 1
                logger.debug("JS fetch failed %s (status=%s error=%s)",
                             js_url, result.status, result.error)
                continue
            if not result.body:
                continue
            parsed += 1
            if self.config.js_secret_scan:
                secret_findings.extend(scan_js_secrets(
                    result.text, result.final_url or js_url, self.scan_id))
            for raw in extract_urls(result.text, result.final_url or js_url):
                try:
                    normalized = self.enforcer.check(raw)
                except Exception:
                    continue
                if normalized.key in seen_endpoints:
                    continue
                seen_endpoints.add(normalized.key)
                endpoints.append(ExtractedEndpoint(
                    url=normalized.url, parent_url=js_url, source="js"))

        elapsed = elapsed_ms(start)
        if not selected:
            outcome = ToolOutcome("js-extractor", TOOL_OK, details={"js_files": 0})
        else:
            status = TOOL_OK if failed == 0 else (TOOL_PARTIAL if parsed else TOOL_FAILED)
            outcome = ToolOutcome(
                "js-extractor", status, discovered=len(endpoints), kept=len(endpoints),
                duration_ms=elapsed,
                error=f"{failed} JS fetch failure(s)" if failed else "",
                details={"js_files": len(selected), "parsed": parsed,
                         "secrets": len(secret_findings)},
            )
        logger.info("[+] JS extractor: %d/%d script(s), %d endpoint(s), %d secret(s)",
                    parsed, len(selected), len(endpoints), len(secret_findings))
        return JsBatch(endpoints=endpoints, outcome=outcome,
                       secret_findings=secret_findings)
