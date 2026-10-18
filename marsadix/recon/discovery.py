import asyncio
import json
import logging
import urllib.request
from typing import Set, List, Dict, Tuple
from .merger import merge_and_track
from .api_sources import fetch_virustotal, fetch_alienvault

logger = logging.getLogger(__name__)

async def run_cli_tool(tool_name: str, command: List[str]) -> Tuple[str, Set[str]]:
    subdomains = set()
    logger.info(f"[*] Running {tool_name}...")
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        
        if stdout:
            for line in stdout.decode().splitlines():
                sub = line.strip().lower()
                if sub:
                    subdomains.add(sub)
        logger.info(f"[+] {tool_name} discovered {len(subdomains)} subdomains.")
    except Exception as e:
        logger.warning(f"[-] Skipped {tool_name} due to error: {e}")
    
    return tool_name, subdomains

async def fetch_crtsh(domain: str) -> Tuple[str, Set[str]]:
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info("[*] Querying crt.sh...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = await loop.run_in_executor(None, urllib.request.urlopen, req)
        
        if response.status == 200:
            data = json.loads(response.read().decode())
            for entry in data:
                name_value = entry.get('name_value', '').lower()
                for sub in name_value.split('\n'):
                    sub = sub.strip()
                    if sub and not sub.startswith('*'):
                        subdomains.add(sub)
        logger.info(f"[+] crt.sh discovered {len(subdomains)} subdomains.")
    except Exception as e:
        logger.warning(f"[-] Skipped crt.sh due to error: {e}")
        
    return "crt.sh", subdomains

async def _async_discover(domain: str, api_keys: dict = None) -> Dict[str, List[str]]:
    if api_keys is None:
        api_keys = {}
        
    vt_key = api_keys.get("virustotal")
    
    tasks = [
        run_cli_tool("subfinder", ["subfinder", "-d", domain, "-silent"]),
        run_cli_tool("assetfinder", ["assetfinder", "--subs-only", domain]),
        fetch_crtsh(domain),
        fetch_alienvault(domain),
        fetch_virustotal(domain, vt_key)
    ]
    results = await asyncio.gather(*tasks)
    tool_outputs = {tool_name: subs for tool_name, subs in results}
    
    return merge_and_track(tool_outputs)

def discover_subdomains(domain: str, api_keys: dict = None, *args, **kwargs) -> Dict[str, List[str]]:
    return asyncio.run(_async_discover(domain, api_keys))
