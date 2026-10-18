import asyncio
import logging
import json
from typing import List, Set

logger = logging.getLogger(__name__)

async def run_httpx(domains: List[str]) -> List[str]:
    """Pass domains to httpx to extract live web servers"""
    if not domains:
        return []
        
    logger.info(f"[*] Running httpx on {len(domains)} resolved subdomains...")
    
    input_data = "\n".join(domains).encode()
    live_urls = []
    
    try:
        process = await asyncio.create_subprocess_exec(
            "httpx", "-silent", "-json",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, _ = await process.communicate(input=input_data)
        
        if stdout:
            for line in stdout.decode().splitlines():
                try:
                    data = json.loads(line)
                    if "url" in data:
                        live_urls.append(data["url"])
                except Exception:
                    continue
                    
        logger.info(f"[+] httpx found {len(live_urls)} live web servers.")
    except Exception as e:
        logger.error(f"[-] httpx failed: {e}")
        
    return live_urls

async def run_katana(urls: List[str]) -> List[str]:
    """Pass live URLs to katana for web crawling and endpoint extraction"""
    if not urls:
        return []
        
    logger.info(f"[*] Running katana on {len(urls)} live URLs to extract endpoints...")
    
    input_data = "\n".join(urls).encode()
    endpoints: Set[str] = set()
    
    try:
        process = await asyncio.create_subprocess_exec(
            "katana", "-silent", "-jc", "-d", "2",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, _ = await process.communicate(input=input_data)
        
        if stdout:
            for line in stdout.decode().splitlines():
                url = line.strip()
                if url:
                    endpoints.add(url)
                    
        logger.info(f"[+] Katana extracted {len(endpoints)} unique endpoints/URLs.")
    except Exception as e:
        logger.error(f"[-] Katana failed: {e}")
        
    return list(endpoints)
