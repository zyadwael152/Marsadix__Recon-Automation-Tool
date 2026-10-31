"""Passive DNS and certificate-data source clients used by recon discovery.

Requests are bounded by explicit timeouts and page limits. API responses are
closed promptly, provider errors never log credentials, and returned names are
restricted to the requested domain boundary.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import weakref
import urllib.error
import urllib.parse
import urllib.request
from functools import partial
from typing import Any, Dict, Set, Tuple

from ..core import toolstatus

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 15  # seconds
MAX_API_PAGES = 5  # bound API usage and memory on very large domains
PAGE_SIZE = 50
SHODAN_PAGE_SIZE = 100


# Minimum seconds between two requests to the same provider. Recursive discovery asks every
# provider once per sub-target at the same time; free tiers (VirusTotal 4/min, Shodan 1/s,
# OTX anonymous) answer that burst with HTTP 429. Empty dict = no spacing (tests).
PROVIDER_GAP = {"alienvault": 2.0, "virustotal": 1.0, "shodan": 1.1, "censys": 1.0}
_gates: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


async def _throttle(provider: str) -> None:
    gap = PROVIDER_GAP.get(provider, 0)
    if not gap:
        return
    loop = asyncio.get_running_loop()
    st = _gates.setdefault(loop, {"locks": {}, "last": {}})
    lock = st["locks"].setdefault(provider, asyncio.Lock())
    async with lock:
        wait = st["last"].get(provider, -1e9) + gap - loop.time()
        if wait > 0:
            await asyncio.sleep(wait)
        st["last"][provider] = loop.time()


_HTTP_MEANING = {
    401: "key rejected (wrong, expired or wrong format)",
    402: "a paid plan is required",
    403: "key accepted but this plan/permission does not allow the query",
    404: "nothing found",
    429: "rate limited",
}


def _http_note(code: int) -> str:
    return _HTTP_MEANING.get(code, "provider error" if code >= 500 else "request refused")


def _on_http_error(tool: str, label: str, e: urllib.error.HTTPError) -> None:
    """Say WHAT failed (status + meaning, never the key) and record it correctly:
    401-403 = setup problem (denied), everything else = this run is incomplete (failed)."""
    logger.warning("[-] %s failed: HTTP %s - %s.", label, e.code, _http_note(e.code))
    toolstatus.record(tool, "denied" if e.code in (401, 402, 403) else "failed", f"HTTP {e.code}")


def _request_json(url: str, headers: dict | None = None) -> Dict[str, Any]:
    """Fetch one JSON response, always closing the socket/response object."""
    req = urllib.request.Request(url, headers=headers or {})
    # Every caller uses a hardcoded https:// URL; pagination
    # links are re-validated by _next_url_same_host (https + expected host).
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:  # nosec B310
        payload = response.read().decode("utf-8", errors="replace")
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("API returned a non-object JSON response")
        return data


async def _request_json_async(url: str, headers: dict | None = None) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(_request_json, url, headers))


def _root_domain(domain: str) -> str:
    return (domain or "").strip().lower().rstrip(".")


def _under_domain(host: str, domain: str) -> bool:
    """Accept only the root domain or a true subdomain (not evil-example.com)."""
    host = (host or "").strip().lower().rstrip(".")
    domain = _root_domain(domain)
    if not host or not domain or len(host) > 253:
        return False
    labels = host.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           or not all(ch.isalnum() or ch == "-" for ch in label) for label in labels):
        return False
    return host == domain or host.endswith("." + domain)


def _extract_names(items, domain: str, key: str = "id") -> Set[str]:
    names: Set[str] = set()
    for item in items or []:
        if not isinstance(item, dict):
            continue
        value = item.get(key, "")
        if not isinstance(value, str):
            continue
        name = value.strip().lower().lstrip("*.").rstrip(".")
        if _under_domain(name, domain):
            names.add(name)
    return names


def _next_url_same_host(next_url: str, allowed_host: str) -> str | None:
    """Prevent forwarding API credentials to an untrusted pagination URL."""
    if not isinstance(next_url, str) or not next_url:
        return None
    parsed = urllib.parse.urlsplit(next_url)
    if parsed.scheme != "https" or parsed.hostname != allowed_host:
        return None
    return next_url


async def fetch_virustotal(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """Query VirusTotal subdomains, following a bounded number of next links."""
    subdomains: Set[str] = set()
    if not api_key:
        logger.warning("[-] Skipped VirusTotal (No API Key provided).")
        return "virustotal", subdomains

    domain = _root_domain(domain)
    url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain, safe='.-')}/subdomains?limit=40"
    logger.info("[*] Querying VirusTotal...")
    try:
        for _ in range(MAX_API_PAGES):
            await _throttle("virustotal")
            data = await _request_json_async(url, {"x-apikey": api_key})
            subdomains.update(_extract_names(data.get("data", []), domain))
            links = data.get("links")
            next_url = links.get("next") if isinstance(links, dict) else None
            if not next_url:
                break
            safe_next = _next_url_same_host(next_url, "www.virustotal.com")
            if not safe_next or safe_next == url:
                logger.warning("[-] VirusTotal returned an invalid/repeated pagination link; stopping.")
                break
            url = safe_next
        logger.info("[+] VirusTotal discovered %d subdomains (up to %d pages).", len(subdomains), MAX_API_PAGES)
    except urllib.error.HTTPError as e:
        _on_http_error("virustotal", "VirusTotal", e)
    except Exception as e:
        logger.warning("[-] VirusTotal request failed (%s).", type(e).__name__)
        toolstatus.record("virustotal", "failed", type(e).__name__)
    return "virustotal", subdomains


async def fetch_alienvault(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """Query AlienVault OTX passive DNS; one polite retry when the anonymous tier rate-limits."""
    subdomains: Set[str] = set()
    domain = _root_domain(domain)
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain, safe='.-')}/passive_dns"
    logger.info("[*] Querying AlienVault...")
    headers = {"OTX-API-KEY": api_key} if api_key else {}
    try:
        for attempt in (1, 2):
            await _throttle("alienvault")
            try:
                data = await _request_json_async(url, headers)
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt == 1:
                    try:
                        wait = min(30, max(1, int(e.headers.get("Retry-After", 5))))
                    except (TypeError, ValueError, AttributeError):
                        wait = 5
                    logger.info("[*] AlienVault rate-limited; retrying once in %ds.", wait)
                    await asyncio.sleep(wait)
                    continue
                raise
            subdomains.update(_extract_names(data.get("passive_dns", []), domain, key="hostname"))
            break
        logger.info("[+] AlienVault discovered %d subdomains.", len(subdomains))
    except urllib.error.HTTPError as e:
        _on_http_error("alienvault", "AlienVault", e)
    except Exception as e:
        logger.warning("[-] AlienVault request failed (%s).", type(e).__name__)
        toolstatus.record("alienvault", "failed", type(e).__name__)
    return "alienvault", subdomains


async def fetch_shodan(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """Query Shodan host search with bounded page traversal.

    Shodan's documented endpoint requires the API key in the query string. The
    URL is never logged; errors are logged by exception type only. Local process
    or HTTP instrumentation may still observe the URL, so treat this as a
    provider-specific credential-handling limitation.
    """
    subdomains: Set[str] = set()
    if not api_key:
        logger.info("[-] Skipped Shodan (No API Key provided).")
        return "shodan", subdomains

    domain = _root_domain(domain)
    logger.info("[*] Querying Shodan...")
    try:
        for page in range(1, MAX_API_PAGES + 1):
            # the parameter is `key` (it used to be sent as "SHODAN-API-KEY", which Shodan ignores, so
            # EVERY request was rejected as unauthenticated)
            query = urllib.parse.urlencode({"key": api_key, "query": f"hostname:{domain}", "page": page})
            url = f"https://api.shodan.io/shodan/host/search?{query}"
            await _throttle("shodan")
            data = await _request_json_async(url)
            matches = data.get("matches")
            matches = matches if isinstance(matches, list) else []
            for match in matches:
                if not isinstance(match, dict):
                    continue
                hostnames = match.get("hostnames")
                for host in hostnames if isinstance(hostnames, list) else []:
                    if isinstance(host, str) and _under_domain(host, domain):
                        subdomains.add(host.strip().lower().rstrip("."))
            try:
                total = int(data.get("total", 0) or 0)
            except (TypeError, ValueError):
                total = 0
            if not matches or page * SHODAN_PAGE_SIZE >= total:
                break
        logger.info("[+] Shodan discovered %d subdomains (up to %d pages).", len(subdomains), MAX_API_PAGES)
    except urllib.error.HTTPError as e:
        _on_http_error("shodan", "Shodan", e)
    except Exception as e:
        logger.warning("[-] Shodan request failed (%s); API key redacted.", type(e).__name__)
        toolstatus.record("shodan", "failed", type(e).__name__)
    return "shodan", subdomains


def _censys_auth(key: str) -> dict:
    """Censys Search v2 uses HTTP Basic auth with "API_ID:API_SECRET"; a single token is sent as Bearer."""
    if ":" in key:
        return {"Authorization": "Basic " + base64.b64encode(key.encode()).decode()}
    return {"Authorization": f"Bearer {key}"}


async def fetch_censys(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """Query Censys Search API v2 and follow bounded cursor pagination."""
    subdomains: Set[str] = set()
    if not api_key:
        logger.info("[-] Skipped Censys (No API Key provided).")
        return "censys", subdomains

    domain = _root_domain(domain)
    logger.info("[*] Querying Censys...")
    cursor = None
    seen_cursors = set()
    try:
        for _ in range(MAX_API_PAGES):
            params = {"q": f"names: {domain}", "per_page": str(PAGE_SIZE)}
            if cursor:
                params["cursor"] = cursor
            url = "https://search.censys.io/api/v2/hosts/search?" + urllib.parse.urlencode(params)
            await _throttle("censys")
            data = await _request_json_async(url, _censys_auth(api_key))
            result = data.get("result")
            result = result if isinstance(result, dict) else {}
            hits = result.get("hits")
            for hit in hits if isinstance(hits, list) else []:
                if not isinstance(hit, dict):
                    continue
                names = hit.get("names")
                subdomains.update(_extract_names(
                    [{"id": name} for name in (names if isinstance(names, list) else [])], domain))
            links = data.get("links") or result.get("links") or {}
            next_value = links.get("next") if isinstance(links, dict) else None
            next_cursor = None
            if isinstance(next_value, str) and next_value:
                parsed = urllib.parse.urlsplit(next_value)
                query_values = urllib.parse.parse_qs(parsed.query)
                next_cursor = (query_values.get("cursor") or [None])[0]
                if not next_cursor and not next_value.startswith("http"):
                    raw_query = next_value.lstrip("?")
                    query_values = urllib.parse.parse_qs(raw_query)
                    next_cursor = (query_values.get("cursor") or [None])[0] or raw_query
            if not next_cursor or next_cursor in seen_cursors:
                break
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        logger.info("[+] Censys discovered %d subdomains (up to %d pages).", len(subdomains), MAX_API_PAGES)
    except urllib.error.HTTPError as e:
        _on_http_error("censys", "Censys", e)
    except Exception as e:
        logger.warning("[-] Censys request failed (%s).", type(e).__name__)
        toolstatus.record("censys", "failed", type(e).__name__)
    return "censys", subdomains

