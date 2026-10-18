import asyncio
import json
import logging
import urllib.request
from typing import Set, Tuple

logger = logging.getLogger(__name__)

async def fetch_virustotal(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """Query VirusTotal and skip if API key is missing"""
    subdomains = set()
    if not api_key:
        logger.warning("[-] Skipped VirusTotal (No API Key provided).")
        return "virustotal", subdomains
        
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
    logger.info("[*] Querying VirusTotal...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url, headers={'x-apikey': api_key})
        response = await loop.run_in_executor(None, urllib.request.urlopen, req)
        
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

async def fetch_alienvault(domain: str) -> Tuple[str, Set[str]]:
    """Query AlienVault OTX (Passive DNS)"""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    logger.info("[*] Querying AlienVault...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url)
        response = await loop.run_in_executor(None, urllib.request.urlopen, req)
        
        if response.status == 200:
            data = json.loads(response.read().decode())
            for item in data.get('passive_dns', []):
                sub = item.get('hostname', '').lower()
                if sub:
                    subdomains.add(sub)
        logger.info(f"[+] AlienVault discovered {len(subdomains)} subdomains.")
    except Exception as e:
        logger.warning(f"[-] AlienVault error: {e}")
        
    return "alienvault", subdomains
