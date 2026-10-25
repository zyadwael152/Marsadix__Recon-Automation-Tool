import asyncio
import json
import logging
import re
import urllib.request
from functools import partial
from typing import Set, List, Dict, Tuple
from .api_sources import HTTP_TIMEOUT, fetch_virustotal, fetch_alienvault, fetch_shodan, fetch_censys
from .merger import merge_and_track

logger = logging.getLogger(__name__)

# فلتر لمنع النطاقات الوهمية والعشوائية الناتجة عن شهادات الـ CT Logs (مثل a258179654.example.com)
_RANDOM_SUB_RE = re.compile(r".*([0-9]{5,}|[a-z0-9]{32,})", re.IGNORECASE)

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
                    # استبعاد الـ Wildcards والدومينات العشوائية الضخمة
                    if sub and not sub.startswith('*') and not _RANDOM_SUB_RE.match(sub):
                        subdomains.add(sub)
        logger.info(f"[+] crt.sh discovered {len(subdomains)} clean subdomains.")
    except Exception as e:
        logger.warning(f"[-] Skipped crt.sh due to error: {e}")
        
    return "crt.sh", subdomains

async def _async_discover_single(domain: str, api_keys: dict) -> Dict[str, List[str]]:
    vt_key = api_keys.get("virustotal")
    chaos_key = api_keys.get("chaos")
    otx_key = api_keys.get("alienvault")
    shodan_key = api_keys.get("shodan")
    censys_key = api_keys.get("censys")
    
    tasks = [
        run_cli_tool("subfinder", ["subfinder", "-d", domain, "-silent"]),
        run_cli_tool("assetfinder", ["assetfinder", "--subs-only", domain]),
        run_cli_tool("amass", ["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=120),
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
    master_results = {}
    targets_to_scan = {domain}
    scanned_targets = set()
    
    for depth in range(1, max_depth + 1):
        if not targets_to_scan:
            break
            
        logger.info(f"[*] === Starting Discovery Depth {depth}/{max_depth} for {len(targets_to_scan)} target(s) ===")
        
        # حماية إضافية: لو عدد الأهداف تجاوز 100 في العمق التاني، نكتفي بهم لمنع الـ Explosion
        if len(targets_to_scan) > 100:
            logger.warning(f"[-] Target list exceeded 100 items at depth {depth}. Limiting recursion batch to top 100.")
            targets_to_scan = set(list(targets_to_scan)[:100])

        tasks = [_async_discover_single(t, api_keys) for t in targets_to_scan]
        batch_results = await asyncio.gather(*tasks)
        
        scanned_targets.update(targets_to_scan)
        next_targets = set()
        
        for result_dict in batch_results:
            for sub, sources in result_dict.items():
                if sub not in master_results:
                    master_results[sub] = []
                for src in sources:
                    if src not in master_results[sub]:
                        master_results[sub].append(src)
                        
                # اختيار النطاقات الحقيقية فقط للعمق اللي بعده (تجنب العشوائيات)
                if sub not in scanned_targets and sub.endswith(domain) and not _RANDOM_SUB_RE.match(sub):
                    # نأخذ فقط الدومينات اللي مقطعها مش أكتر من 4 درجات (مثل a.b.c.example.com) لتجنب الـ Deep nesting الوهمي
                    if sub.count('.') <= domain.count('.') + 3:
                        next_targets.add(sub)
                    
        targets_to_scan = next_targets
        
    return master_results

def discover_subdomains(domain: str, api_keys: dict = None, max_depth: int = 1, *args, **kwargs) -> Dict[str, List[str]]:
    if api_keys is None:
        api_keys = {}
    return asyncio.run(_async_discover_recursive(domain, api_keys, max_depth))
