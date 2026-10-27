import asyncio
import json
import logging
import os
import re
import urllib.request
from functools import partial
from typing import Set, List, Dict, Tuple
from .api_sources import HTTP_TIMEOUT, fetch_virustotal, fetch_alienvault, fetch_shodan, fetch_censys, fetch_securitytrails
from .merger import merge_and_track

logger = logging.getLogger(__name__)

# Validate tool output as hostnames rather than dropping names based on their
# appearance. Long or numeric labels can be real assets (VPNs, CDNs, build IDs).
_HOSTNAME_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$", re.IGNORECASE)

async def run_cli_tool(tool_name: str, command: List[str], timeout: int = 120,
                       env_overrides: dict | None = None) -> Tuple[str, Set[str]]:
    subdomains = set()
    logger.info(f"[*] Running {tool_name}...")
    process = None
    try:
        child_env = os.environ.copy()
        if env_overrides:
            child_env.update({str(k): str(v) for k, v in env_overrides.items() if v is not None})
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_env,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.warning(f"[-] {tool_name} timed out after {timeout}s - skipped.")
            return tool_name, subdomains

        if stdout:
            for line in stdout.decode(errors="replace").splitlines():
                sub = line.strip().lower().rstrip(".")
                # Ignore status/log lines and malformed output, but don't use a
                # heuristic that silently discards legitimate numeric/long names.
                if sub and _HOSTNAME_RE.fullmatch(sub):
                    subdomains.add(sub)
        logger.info(f"[+] {tool_name} discovered {len(subdomains)} subdomains.")
    except Exception as e:
        logger.warning(f"[-] Skipped {tool_name} due to error: {e}")
    
    return tool_name, subdomains

async def run_chaos(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    if not api_key:
        return "chaos", set()
    # ProjectDiscovery supports PDCP_API_KEY via environment; don't put secrets
    # in argv, where process listings can expose them to other local users.
    return await run_cli_tool("chaos", ["chaos", "-d", domain, "-silent"],
                              env_overrides={"PDCP_API_KEY": api_key})

async def fetch_crtsh(domain: str) -> Tuple[str, Set[str]]:
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info(f"[*] Querying crt.sh for {domain}...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        
        # رفع مهلة الانتظار إلى 45 ثانية لتجنب مشاكل بطء سيرفر crt.sh
        response = await loop.run_in_executor(
            None, partial(urllib.request.urlopen, req, timeout=45))
        
        if response.status == 200:
            data = json.loads(response.read().decode())
            for entry in data:
                name_value = entry.get('name_value', '').lower()
                for sub in name_value.split('\n'):
                    sub = sub.strip()
                    # استبعاد الـ Wildcards والدومينات العشوائية الضخمة
                    if sub and not sub.startswith('*') and _HOSTNAME_RE.fullmatch(sub):
                        subdomains.add(sub)
        logger.info(f"[+] crt.sh discovered {len(subdomains)} clean subdomains.")
    except Exception as e:
        logger.warning(f"[-] Skipped crt.sh due to error (Server slow or timeout): {e}")
        
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
        # تم رفع الـ timeout هنا إلى 300 ثانية (5 دقائق) لمنع تايم آوت Amass
        run_cli_tool("amass", ["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=300),
        run_cli_tool("findomain", ["findomain", "-t", domain, "-q"]),
        run_chaos(domain, chaos_key),
        fetch_crtsh(domain),
        fetch_alienvault(domain, otx_key),
        fetch_virustotal(domain, vt_key),
        fetch_shodan(domain, shodan_key),
        fetch_censys(domain, censys_key),
        fetch_securitytrails(domain, api_keys.get("securitytrails")),
    ]
    results = await asyncio.gather(*tasks)
    tool_outputs = {tool_name: subs for tool_name, subs in results}
    return merge_and_track(tool_outputs)

async def _async_discover_recursive(domain: str, api_keys: dict, max_depth: int) -> Dict[str, List[str]]:
    master_results = {}
    targets_to_scan = {domain}
    scanned_targets = set()
    # Depth zero means perform discovery on the root target, but do not recurse.
    effective_depth = max(1, max_depth)
    
    for depth in range(1, effective_depth + 1):
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
                if sub not in scanned_targets and (sub == domain or sub.endswith("." + domain)):
                    # نأخذ فقط الدومينات اللي مقطعها مش أكتر من 4 درجات (مثل a.b.c.example.com) لتجنب الـ Deep nesting الوهمي
                    if sub.count('.') <= domain.count('.') + 3:
                        next_targets.add(sub)
                    
        targets_to_scan = next_targets
        
    return master_results

def discover_subdomains(domain: str, api_keys: dict = None, max_depth: int = 1, *args, **kwargs) -> Dict[str, List[str]]:
    if api_keys is None:
        api_keys = {}
    return asyncio.run(_async_discover_recursive(domain, api_keys, max_depth))
