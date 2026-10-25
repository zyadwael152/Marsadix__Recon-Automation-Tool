"""
R15: Reverse DNS (PTR) lookups on discovered IPs or ASN ranges.
Finds hidden subdomains that are associated with the target's IP space
but weren't found by forward DNS or APIs.
"""

import logging
from typing import List, Set, Optional
from ._proc import run_async

logger = logging.getLogger(__name__)

REVDNS_TIMEOUT = 300

async def reverse_dns_lookup(ips: List[str], rate_limit: Optional[int] = None) -> Set[str]:
    """
    Takes a list of IPs and performs PTR lookups.
    Returns a set of newly discovered hostnames.
    """
    if not ips:
        return set()

    logger.info(f"[*] Running Reverse DNS (PTR) on {len(ips)} IP(s) (R15)...")
    
    cmd = ["dnsx", "-silent", "-ptr", "-resp-only"]
    if rate_limit:
        cmd += ["-rl", str(int(rate_limit))]

    out = await run_async(cmd, stdin_lines=ips, timeout=REVDNS_TIMEOUT, name="dnsx-ptr")
    
    if out is None:
        logger.warning("[-] Reverse DNS failed or dnsx not available.")
        return set()

    # dnsx -ptr -resp-only returns just the hostnames
    discovered = {line.strip().lower().rstrip('.') for line in out.splitlines() if line.strip()}
    logger.info(f"[+] Reverse DNS discovered {len(discovered)} potential hostname(s).")
    
    return discovered
