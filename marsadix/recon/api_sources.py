import asyncio
import json
import logging
import urllib.request
from typing import Set, Tuple

logger = logging.getLogger(__name__)

async def fetch_virustotal(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    """الاستعلام من VirusTotal وتخطي الفحص لو مفيش API Key"""
    subdomains = set()
    if not api_key:
        logger.warning("[-] تم تخطي VirusTotal لعدم توفر API Key.")
        return "virustotal", subdomains
        
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
    logger.info("[*] جاري الاستعلام من VirusTotal...")
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
        logger.info(f"[+] VirusTotal اكتشفت {len(subdomains)} نطاق.")
    except Exception as e:
        logger.warning(f"[-] خطأ في VirusTotal: {e}")
        
    return "virustotal", subdomains

async def fetch_alienvault(domain: str) -> Tuple[str, Set[str]]:
    """الاستعلام من AlienVault OTX (لا يحتاج مفتاح)"""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    logger.info("[*] جاري الاستعلام من AlienVault...")
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
        logger.info(f"[+] AlienVault اكتشفت {len(subdomains)} نطاق.")
    except Exception as e:
        logger.warning(f"[-] خطأ في AlienVault: {e}")
        
    return "alienvault", subdomains
