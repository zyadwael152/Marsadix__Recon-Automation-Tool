"""
R16: Virtual Host Discovery (VHost) using ffuf.
Takes an IP and fuzzes the Host header using a wordlist to find hidden
internal applications or unlinked staging environments.
"""

import logging
import json
import asyncio
from typing import List, Set, Optional
from ._proc import run_async

logger = logging.getLogger(__name__)

VHOST_TIMEOUT = 600

async def discover_vhosts(ip: str, domain: str, wordlist_path: str, rate_limit: Optional[int] = None) -> Set[str]:
    """
    Runs ffuf to fuzz the Host header against a specific IP.
    """
    if not ip or not wordlist_path:
        return set()

    logger.info(f"[*] Running VHost discovery on IP: {ip} for domain: {domain} (R16)...")
    
    # We use -mc 200,301,302,401,403 to catch interesting responses, and -ac to auto-calibrate filtering
    cmd = [
        "ffuf", "-silent",
        "-w", wordlist_path,
        "-u", f"http://{ip}/",
        "-H", f"Host: FUZZ.{domain}",
        "-mc", "200,301,302,401,403,404",
        "-ac", # Auto-calibrate filtering (removes false positives)
        "-o", "stdout", # Output to stdout for our parser
        "-of", "json"   # JSON format for easy parsing
    ]
    
    if rate_limit:
        cmd += ["-rate", str(int(rate_limit))]

    # Run ffuf without stdin (it uses the wordlist file directly)
    out = await run_async(cmd, stdin_lines=None, timeout=VHOST_TIMEOUT, name="ffuf-vhost")
    
    if out is None:
        return set()

    vhosts = set()
    try:
        # ffuf outputs a single JSON block at the end when using -of json
        data = json.loads(out)
        for result in data.get("results", []):
            host_val = result.get("host", "")
            if host_val:
                vhosts.add(host_val)
    except Exception as e:
        logger.warning(f"[-] Failed to parse ffuf JSON output: {e}")

    logger.info(f"[+] VHost discovery found {len(vhosts)} hidden host(s) on {ip}.")
    return vhosts
