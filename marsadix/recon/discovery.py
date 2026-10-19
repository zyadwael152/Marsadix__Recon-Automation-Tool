import asyncio
import json
import logging
import urllib.request
from functools import partial
from typing import Set, List, Dict, Tuple
from .api_sources import HTTP_TIMEOUT, fetch_virustotal, fetch_alienvault
from .merger import merge_and_track

logger = logging.getLogger(__name__)

async def run_cli_tool(tool_name: str, command: List[str], timeout: int = 120) -> Tuple[str, Set[str]]:
    subdomains = set()
    logger.info(f"[*] Running {tool_name}...")
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            # Don't let one slow source (e.g. amass passive mode on a big
            # target) block the rest of the recon stage indefinitely - kill
            # it, keep whatever the other tools already found, and move on.
            process.kill()
            await process.wait()
            logger.warning(f"[-] {tool_name} timed out after {timeout}s - skipped.")
            return tool_name, subdomains

        if stdout:
            for line in stdout.decode().splitlines():
                sub = line.strip().lower()
                if sub:
                    subdomains.add(sub)
        logger.info(f"[+] {tool_name} discovered {len(subdomains)} subdomains.")
    except Exception as e:
        logger.warning(f"[-] Skipped {tool_name} due to error: {e}")
    
    return tool_name, subdomains

async def run_chaos(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    # chaos needs a ProjectDiscovery API key - skip gracefully instead of
    # letting it fail with a confusing subprocess error, same as VirusTotal.
    if not api_key:
        logger.info("[-] Skipped chaos (No API Key provided).")
        return "chaos", set()
    return await run_cli_tool("chaos", ["chaos", "-d", domain, "-key", api_key, "-silent"])

async def fetch_crtsh(domain: str) -> Tuple[str, Set[str]]:
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info("[*] Querying crt.sh...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = await loop.run_in_executor(
            None, partial(urllib.request.urlopen, req, timeout=HTTP_TIMEOUT))
        
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
    chaos_key = api_keys.get("chaos")
    
    tasks = [
        run_cli_tool("subfinder", ["subfinder", "-d", domain, "-silent"]),
        run_cli_tool("assetfinder", ["assetfinder", "--subs-only", domain]),
        run_cli_tool("amass", ["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=180),
        run_cli_tool("findomain", ["findomain", "-t", domain, "-q"]),
        run_chaos(domain, chaos_key),
        fetch_crtsh(domain),
        fetch_alienvault(domain),
        fetch_virustotal(domain, vt_key)
    ]
    results = await asyncio.gather(*tasks)
    tool_outputs = {tool_name: subs for tool_name, subs in results}
    
    return merge_and_track(tool_outputs)

def discover_subdomains(domain: str, api_keys: dict = None, *args, **kwargs) -> Dict[str, List[str]]:
    return asyncio.run(_async_discover(domain, api_keys))
