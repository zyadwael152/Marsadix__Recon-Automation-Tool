import asyncio
import json
import logging
import urllib.parse
import urllib.request
from functools import partial
from typing import Set, Tuple

logger = logging.getLogger(__name__)

# Default socket timeout for urllib is None (block forever). On a network
# that silently drops packets instead of refusing the connection, that
# means these calls -- and anything awaiting them, including every test
# that runs a scan -- can hang indefinitely. Every urlopen() call in this
# module MUST pass an explicit timeout; this constant is the one place to
# tune it.
HTTP_TIMEOUT = 15  # seconds


async def fetch_virustotal(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """Query VirusTotal and skip if API key is missing"""
    subdomains = set()
    if not api_key:
        logger.warning("[-] Skipped VirusTotal (No API Key provided).")
        return "virustotal", subdomains

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    logger.info("[*] Querying VirusTotal...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url, headers={'x-apikey': api_key})
        response = await loop.run_in_executor(
            None, partial(urllib.request.urlopen, req, timeout=HTTP_TIMEOUT))

        if response.status == 200:
            data = json.loads(response.read().decode())
            for item in data.get('data', []):
                sub = item.get('id', '').lower()
                if sub:
                    subdomains.add(sub)
        logger.info(f"[+] VirusTotal discovered {len(subdomains)} subdomains.")
    except Exception as e:
        logger.warning(f"[-] VirusTotal error: {e}")

    return "virustotal", subdomains


async def fetch_alienvault(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """
    Query AlienVault OTX (Passive DNS). Works without a key (anonymous
    tier), but anonymous requests hit AlienVault's shared rate limit fast
    (HTTP 429). Passing a free OTX account's key via the X-OTX-API-KEY
    header uses that account's own, much higher, limit instead.
    """
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    logger.info("[*] Querying AlienVault...")
    try:
        loop = asyncio.get_event_loop()
        headers = {'X-OTX-API-KEY': api_key} if api_key else {}
        req = urllib.request.Request(url, headers=headers)
        
        # إضافة استراحة بسيطة لتجنب الـ Rate Limit والحظر السريع (429)
        await asyncio.sleep(1)
        
        response = await loop.run_in_executor(
            None, partial(urllib.request.urlopen, req, timeout=HTTP_TIMEOUT))

        if response.status == 200:
            data = json.loads(response.read().decode())
            for item in data.get('passive_dns', []):
                sub = item.get('hostname', '').lower()
                if sub:
                    subdomains.add(sub)
        logger.info(f"[+] AlienVault discovered {len(subdomains)} subdomains.")
    except urllib.error.HTTPError as e:
        if e.code == 429:
            logger.warning("[-] AlienVault rate-limited (HTTP 429). Skipped gracefully.")
        else:
            logger.warning(f"[-] AlienVault error: HTTP Error {e.code}")
    except Exception as e:
        logger.warning(f"[-] AlienVault error: {e}")

    return "alienvault", subdomains


async def fetch_shodan(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """
    Query Shodan's host search for hostnames seen under this domain and
    skip if no API key. Shodan indexes IPs, not domains directly, so the
    search is `hostname:<domain>` and hostnames are read off each match.
    """
    subdomains = set()
    if not api_key:
        logger.info("[-] Skipped Shodan (No API Key provided).")
        return "shodan", subdomains

    query = urllib.parse.quote(f"hostname:{domain}")
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
    logger.info("[*] Querying Shodan...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url)
        response = await loop.run_in_executor(
            None, partial(urllib.request.urlopen, req, timeout=HTTP_TIMEOUT))

        if response.status == 200:
            data = json.loads(response.read().decode())
            for match in data.get('matches', []):
                for host in match.get('hostnames', []):
                    host = host.strip().lower()
                    if host.endswith(domain.lower()):
                        subdomains.add(host)
        logger.info(f"[+] Shodan discovered {len(subdomains)} subdomains.")
    except Exception as e:
        logger.warning(f"[-] Shodan error: {e}")

    return "shodan", subdomains


async def fetch_censys(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """
    Query Censys Search API v2 (single bearer-token key - the older v1 API
    needed an ID+secret pair, v2 only needs one key) for certificate names
    under this domain, and skip if no API key.
    """
    subdomains = set()
    if not api_key:
        logger.info("[-] Skipped Censys (No API Key provided).")
        return "censys", subdomains

    query = urllib.parse.quote(f"names: {domain}")
    url = f"https://search.censys.io/api/v2/hosts/search?q={query}&per_page=50"
    logger.info("[*] Querying Censys...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url, headers={'Authorization': f'Bearer {api_key}'})
        response = await loop.run_in_executor(
            None, partial(urllib.request.urlopen, req, timeout=HTTP_TIMEOUT))

        if response.status == 200:
            data = json.loads(response.read().decode())
            for hit in data.get('result', {}).get('hits', []):
                for name in hit.get('names', []):
                    name = name.strip().lower().lstrip('*.')
                    if name.endswith(domain.lower()):
                        subdomains.add(name)
        logger.info(f"[+] Censys discovered {len(subdomains)} subdomains.")
    except Exception as e:
        logger.warning(f"[-] Censys error: {e}")

    return "censys", subdomains
