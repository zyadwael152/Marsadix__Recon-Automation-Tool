import asyncio
import socket
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

async def resolve_domain(domain: str) -> bool:
    """Check if a domain resolves to an active IP address"""
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, socket.gethostbyname, domain)
        return True
    except Exception:
        return False

async def filter_active_subdomains(subdomains_dict: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Filter out dead subdomains and keep only active ones"""
    logger.info(f"[*] Starting DNS resolution for {len(subdomains_dict)} subdomains...")
    
    active_subdomains = {}
    
    tasks = {
        domain: asyncio.create_task(resolve_domain(domain))
        for domain in subdomains_dict.keys()
    }
    
    for domain, task in tasks.items():
        is_active = await task
        if is_active:
            active_subdomains[domain] = subdomains_dict[domain]
            
    logger.info(f"[+] DNS resolution complete. Active subdomains: {len(active_subdomains)} / {len(subdomains_dict)}")
    return active_subdomains
