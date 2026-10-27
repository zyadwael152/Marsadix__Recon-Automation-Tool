"""Passive DNS and certificate-data source clients used by recon discovery.

Requests are bounded by explicit timeouts and page limits. API responses are
closed promptly, provider errors never log credentials, and returned names are
restricted to the requested domain boundary.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from functools import partial
from typing import Any, Dict, Set, Tuple

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 15  # seconds
MAX_API_PAGES = 5  # bound API usage and memory on very large domains
PAGE_SIZE = 50
SHODAN_PAGE_SIZE = 100


def _request_json(url: str, headers: dict | None = None) -> Dict[str, Any]:
    """Fetch one JSON response, always closing the socket/response object."""
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
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
            data = await _request_json_async(url, {"x-apikey": api_key})
            subdomains.update(_extract_names(data.get("data", []), domain))
            next_url = (data.get("links") or {}).get("next")
            if not next_url:
                break
            safe_next = _next_url_same_host(next_url, "www.virustotal.com")
            if not safe_next or safe_next == url:
                logger.warning("[-] VirusTotal returned an invalid/repeated pagination link; stopping.")
                break
            url = safe_next
        logger.info("[+] VirusTotal discovered %d subdomains (up to %d pages).", len(subdomains), MAX_API_PAGES)
    except Exception as e:
        logger.warning("[-] VirusTotal request failed (%s).", type(e).__name__)
    return "virustotal", subdomains


async def fetch_alienvault(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """Query AlienVault OTX passive DNS; tolerate anonymous-tier rate limits."""
    subdomains: Set[str] = set()
    domain = _root_domain(domain)
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain, safe='.-')}/passive_dns"
    logger.info("[*] Querying AlienVault...")
    try:
        headers = {"X-OTX-API-KEY": api_key} if api_key else {}
        await asyncio.sleep(1)  # reduce anonymous-tier rate-limit pressure
        data = await _request_json_async(url, headers)
        subdomains.update(_extract_names(data.get("passive_dns", []), domain, key="hostname"))
        logger.info("[+] AlienVault discovered %d subdomains.", len(subdomains))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            logger.warning("[-] AlienVault rate-limited (HTTP 429); skipped gracefully.")
        else:
            logger.warning("[-] AlienVault request failed with HTTP %s.", e.code)
    except Exception as e:
        logger.warning("[-] AlienVault request failed (%s).", type(e).__name__)
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
            query = urllib.parse.urlencode({"key": api_key, "query": f"hostname:{domain}", "page": page})
            url = f"https://api.shodan.io/shodan/host/search?{query}"
            data = await _request_json_async(url)
            for match in data.get("matches", []):
                if not isinstance(match, dict):
                    continue
                for host in match.get("hostnames", []):
                    if _under_domain(host, domain):
                        subdomains.add(host.strip().lower().rstrip("."))
            total = int(data.get("total", 0) or 0)
            if not data.get("matches") or page * SHODAN_PAGE_SIZE >= total:
                break
        logger.info("[+] Shodan discovered %d subdomains (up to %d pages).", len(subdomains), MAX_API_PAGES)
    except Exception as e:
        logger.warning("[-] Shodan request failed (%s); API key redacted.", type(e).__name__)
    return "shodan", subdomains


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
            data = await _request_json_async(url, {"Authorization": f"Bearer {api_key}"})
            result = data.get("result") or {}
            for hit in result.get("hits", []):
                if isinstance(hit, dict):
                    subdomains.update(_extract_names([{"id": name} for name in hit.get("names", [])], domain))
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
    except Exception as e:
        logger.warning("[-] Censys request failed (%s).", type(e).__name__)
    return "censys", subdomains


async def fetch_securitytrails(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """Query SecurityTrails' domain subdomain endpoint; skip cleanly without a key."""
    subdomains: Set[str] = set()
    if not api_key:
        logger.info("[-] Skipped SecurityTrails (No API Key provided).")
        return "securitytrails", subdomains

    domain = _root_domain(domain)
    url = f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(domain, safe='.-')}/subdomains"
    logger.info("[*] Querying SecurityTrails...")
    try:
        data = await _request_json_async(url, {"APIKEY": api_key, "Accept": "application/json"})
        for label in data.get("subdomains", []):
            label = str(label).strip().lower().strip(".")
            if label and all(part and len(part) <= 63 and all(ch.isalnum() or ch == "-" for ch in part)
                             and not part.startswith("-") and not part.endswith("-")
                             for part in label.split(".")):
                host = f"{label}.{domain}"
                if _under_domain(host, domain):
                    subdomains.add(host)
        logger.info("[+] SecurityTrails discovered %d subdomains.", len(subdomains))
    except urllib.error.HTTPError as e:
        logger.warning("[-] SecurityTrails request failed with HTTP %s.", e.code)
    except Exception as e:
        logger.warning("[-] SecurityTrails request failed (%s).", type(e).__name__)
    return "securitytrails", subdomains
