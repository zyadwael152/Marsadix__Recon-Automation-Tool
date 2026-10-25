import asyncio
import json
import logging
import urllib.request
from functools import partial
from typing import Set, List, Dict, Tuple
from .api_sources import HTTP_TIMEOUT, fetch_virustotal, fetch_alienvault, fetch_shodan, fetch_censys
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
    if not api_key:
        logger.info("[-] Skipped chaos (No API Key provided).")
        return "chaos", set()
    return await run_cli_tool("chaos", ["chaos", "-d", domain, "-key", api_key, "-silent"])

async def fetch_crtsh(domain: str) -> Tuple[str, Set[str]]:
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info(f"[*] Querying crt.sh for {domain}...")
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

async def _async_discover_single(domain: str, api_keys: dict) -> Dict[str, List[str]]:
    """Runs all discovery tools on a SINGLE domain."""
    vt_key = api_keys.get("virustotal")
    chaos_key = api_keys.get("chaos")
    otx_key = api_keys.get("alienvault")
    shodan_key = api_keys.get("shodan")
    censys_key = api_keys.get("censys")
    
    tasks = [
        run_cli_tool("subfinder", ["subfinder", "-d", domain, "-silent"]),
        run_cli_tool("assetfinder", ["assetfinder", "--subs-only", domain]),
        run_cli_tool("amass", ["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=180),
        run_cli_tool("findomain", ["findomain", "-t", domain, "-q"]),
        run_chaos(domain, chaos_key),
        fetch_crtsh(domain),
        fetch_alienvault(domain, otx_key),
        fetch_virustotal(domain, vt_key),
        fetch_shodan(domain, shodan_key),
        fetch_censys(domain, censys_key)
    ]
    results = await asyncio.gather(*tasks)
    tool_outputs = {tool_name: subs for tool_name, subs in results}
    return merge_and_track(tool_outputs)

async def _async_discover_recursive(domain: str, api_keys: dict, max_depth: int) -> Dict[str, List[str]]:
    """Handles Recursion (R12): Re-scans discovered subdomains up to max_depth."""
    master_results = {}
    targets_to_scan = {domain}
    scanned_targets = set()
    
    for depth in range(1, max_depth + 1):
        if not targets_to_scan:
            break
            
        logger.info(f"[*] === Starting Discovery Depth {depth}/{max_depth} for {len(targets_to_scan)} target(s) ===")
        
        # تشغيل الفحص على كل النطاقات المكتشفة في نفس الوقت
        tasks = [_async_discover_single(t, api_keys) for t in targets_to_scan]
        batch_results = await asyncio.gather(*tasks)
        
        scanned_targets.update(targets_to_scan)
        next_targets = set()
        
        # دمج النتائج وتجهيز الجولة اللي بعدها
        for result_dict in batch_results:
            for sub, sources in result_dict.items():
                if sub not in master_results:
                    master_results[sub] = []
                for src in sources:
                    if src not in master_results[sub]:
                        master_results[sub].append(src)
                        
                # لو النطاق ده جديد ومفحصناهوش قبل كده، ضيفه للجولة الجاية
                if sub not in scanned_targets and sub.endswith(domain):
                    next_targets.add(sub)
                    
        targets_to_scan = next_targets
        
    return master_results

def discover_subdomains(domain: str, api_keys: dict = None, max_depth: int = 1, *args, **kwargs) -> Dict[str, List[str]]:
    if api_keys is None:
        api_keys = {}
    return asyncio.run(_async_discover_recursive(domain, api_keys, max_depth))
