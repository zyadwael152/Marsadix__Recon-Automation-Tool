import asyncio
import socket
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# socket.gethostbyname() has NO built-in timeout and does not reliably
# respect socket.setdefaulttimeout() on every platform. On a slow or
# unresponsive DNS server it can block for a long time per call -- and this
# runs once per discovered subdomain, so with dozens/hundreds of candidates
# the wait adds up even though no single call is "stuck forever". Bounding
# each lookup with asyncio.wait_for() caps the total time for this stage.
DNS_TIMEOUT = 5  # seconds per subdomain


async def resolve_domain(domain: str) -> Optional[str]:
    """Resolve a domain to its IP address. Returns None if it doesn't resolve."""
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, domain),
            timeout=DNS_TIMEOUT)
    except Exception:
        return None


async def filter_active_subdomains(subdomains_dict: Dict[str, List[str]]) -> Dict[str, dict]:
    """
    Filter out dead subdomains and attach the resolved IP to each survivor.

    Returns {host: {"sources": [...], "ip": "1.2.3.4"}}. The IP is what lets
    the Knowledge Graph (core/graph.py) draw "resolves_to" edges between
    subdomains and the IPs they share -- without it, every subdomain is an
    isolated node with no relationships to show.
    """
    logger.info(f"[*] Starting DNS resolution for {len(subdomains_dict)} subdomains...")

    active_subdomains = {}

    tasks = {
        domain: asyncio.create_task(resolve_domain(domain))
        for domain in subdomains_dict.keys()
    }

    for domain, task in tasks.items():
        ip = await task
        if ip:
            active_subdomains[domain] = {"sources": subdomains_dict[domain], "ip": ip}

    logger.info(f"[+] DNS resolution complete. Active subdomains: {len(active_subdomains)} / {len(subdomains_dict)}")
    return active_subdomains
