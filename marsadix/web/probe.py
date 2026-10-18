import asyncio
import logging
import json
from typing import List

logger = logging.getLogger(__name__)

async def run_httpx(domains: List[str]) -> List[str]:
    """Pass domains to httpx to extract live web servers"""
    if not domains:
        return []
        
    logger.info(f"[*] Running httpx on {len(domains)} resolved subdomains...")
    
    # Convert the list of domains to a newline-separated string for stdin
    input_data = "\n".join(domains).encode()
    live_urls = []
    
    try:
        # Run httpx in silent mode and output results as JSON
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
