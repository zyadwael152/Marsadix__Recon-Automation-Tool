import asyncio
import json
import logging
import re
import urllib.error
import urllib.request
from typing import Set, List, Dict, Tuple
from .api_sources import fetch_virustotal, fetch_alienvault, fetch_shodan, fetch_censys
from ..core import limits, toolstatus
from ..core.aproc import run_exec
from .merger import merge_and_track

logger = logging.getLogger(__name__)

# Validate tool output as hostnames rather than dropping names based on their
# appearance. Long or numeric labels can be real assets (VPNs, CDNs, build IDs).
CRTSH_MAX_BYTES = 50 * 1024 * 1024
_PATH_HINT = " Installed it in WSL or another shell? Install it where Marsadix runs, or add its folder to PATH; `marsadix doctor` shows what is found."


def _names_under(domain: str):
    """Regex for hostnames ending in `.domain` (one label or more in front)."""
    return re.compile(r"[a-z0-9][a-z0-9._-]*\." + re.escape(domain.lower().rstrip(".")))
_HOSTNAME_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$", re.IGNORECASE)

async def run_cli_tool(tool_name: str, command: List[str], timeout: int = 120,
                       env_overrides: dict | None = None, domain: str | None = None) -> Tuple[str, Set[str]]:
    """
    Run one subdomain tool and return (name, hostnames).

    * The child gets a minimal environment (core/childenv) plus ONLY the entries
      in `env_overrides` (e.g. chaos' own key) - never the parent's secrets.
    * At most `max_concurrency` tools run at once; timeout never exceeds the
      user's tool_timeout; partial output is kept on timeout.
    * The outcome (ok / timeout / failed / missing) is recorded in
      core/toolstatus so "found nothing" and "tool broke" are no longer the same.
    """
    subdomains: Set[str] = set()
    logger.info(f"[*] Running {tool_name}...")
    timeout = limits.cap_timeout(timeout)
    try:
        async with limits.slot():
            res = await run_exec(command, timeout=timeout, env_extra=env_overrides)
    except FileNotFoundError:
        logger.info(f"[-] {tool_name} was not found on PATH - skipped.{_PATH_HINT}")
        toolstatus.record(tool_name, "missing")
        return tool_name, subdomains
    except Exception as e:
        logger.warning(f"[-] Skipped {tool_name} due to error: {e}")
        toolstatus.record(tool_name, "failed", type(e).__name__)
        return tool_name, subdomains

    lines = [ln for ln in res.stdout.decode(errors="replace").splitlines() if ln.strip()]
    for line in lines:
        sub = line.strip().lower().rstrip(".")
        # Ignore status/log lines and malformed output, but don't use a
        # heuristic that silently discards legitimate numeric/long names.
        if sub and _HOSTNAME_RE.fullmatch(sub):
            subdomains.add(sub)
        elif domain:
            # Some versions print richer lines ("a.example.com (FQDN) --> a_record --> 1.2.3.4"):
            # take the names under the target domain out of the line.
            for m in _names_under(domain).finditer(line.lower()):
                cand = m.group(0).rstrip(".")
                if _HOSTNAME_RE.fullmatch(cand):
                    subdomains.add(cand)

    if lines and not subdomains and not res.timed_out and res.returncode in (0, None):
        # The tool ran and printed something, yet nothing looks like a hostname: its output format
        # is probably not what we parse (a new version). Say so instead of "discovered 0".
        logger.warning(f"[-] {tool_name} printed {len(lines)} line(s) but none contained a hostname "
                       f"(first: {lines[0].strip()[:100]!r}). Check `{tool_name} -h` / your version.")
        toolstatus.record(tool_name, "failed", "output format not recognised")
        return tool_name, subdomains
    if res.timed_out:
        logger.warning(f"[-] {tool_name} timed out after {timeout:g}s; preserving partial output.")
        toolstatus.record(tool_name, "timeout", f"after {timeout:g}s, kept {len(subdomains)} host(s)")
    elif res.truncated:
        logger.warning(f"[-] {tool_name} exceeded the output limit; stopped and kept {len(subdomains)} host(s).")
        toolstatus.record(tool_name, "truncated", f"kept {len(subdomains)} host(s)")
    elif res.returncode not in (0, None):
        err = res.stderr.decode(errors="replace").strip().splitlines()
        logger.warning(f"[-] {tool_name} exited with code {res.returncode}: {err[-1][:200] if err else 'no output'}")
        toolstatus.record(tool_name, "failed", f"exit {res.returncode}, kept {len(subdomains)} host(s)")
    else:
        toolstatus.record(tool_name, "ok")
    logger.info(f"[+] {tool_name} discovered {len(subdomains)} subdomains.")
    return tool_name, subdomains

async def run_chaos(domain: str, api_key: str = None) -> Tuple[str, Set[str]]:
    if not api_key:
        return "chaos", set()
    # ProjectDiscovery supports PDCP_API_KEY via environment; don't put secrets
    # in argv, where process listings can expose them to other local users.
    # chaos-client reads PDCP_API_KEY (not CHAOS_API_KEY); passing the wrong
    # name silently ran the queries unauthenticated.
    return await run_cli_tool("chaos", ["chaos", "-d", domain, "-silent"],
                              env_overrides={"PDCP_API_KEY": api_key})

CRTSH_RETRY_WAITS = (3, 8)          # seconds before the 2nd and 3rd attempt (crt.sh often answers 502/503 under load)


async def fetch_crtsh(domain: str) -> Tuple[str, Set[str]]:
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info(f"[*] Querying crt.sh for {domain}...")
    loop = asyncio.get_running_loop()
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})

    def _fetch() -> Tuple[int, bytes]:
        # The response must be closed explicitly; urlopen() alone leaks a socket until GC.
        # Fixed https URL built above; no user-controlled scheme/host.
        with urllib.request.urlopen(req, timeout=45) as response:  # nosec B310
            # bounded: a huge answer must not be loaded into memory whole
            return response.status, response.read(CRTSH_MAX_BYTES + 1)

    status, body, last_error = None, b"", ""
    for attempt in range(len(CRTSH_RETRY_WAITS) + 1):
        try:
            status, body = await loop.run_in_executor(None, _fetch)
            last_error = ""
            break
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}"
            if e.code < 500 and e.code != 429:
                break                                   # a 4xx will not get better by asking again
        except Exception as e:
            last_error = type(e).__name__
        if attempt < len(CRTSH_RETRY_WAITS):
            wait = CRTSH_RETRY_WAITS[attempt]
            logger.info(f"[*] crt.sh {last_error}; retrying in {wait}s ({attempt + 1}/{len(CRTSH_RETRY_WAITS)}).")
            await asyncio.sleep(wait)

    if status is None:
        logger.warning(f"[-] Skipped crt.sh after {len(CRTSH_RETRY_WAITS) + 1} attempt(s): {last_error}")
        toolstatus.record("crt.sh", "failed", last_error)
        return "crt.sh", subdomains
    if len(body) > CRTSH_MAX_BYTES:
        logger.warning("[-] crt.sh answer exceeded %d MB; skipped (cannot parse a cut-off JSON).", CRTSH_MAX_BYTES // 2**20)
        toolstatus.record("crt.sh", "truncated", "answer too large")
        return "crt.sh", subdomains
    try:
        if status == 200:
            data = json.loads(body.decode(errors="replace"))
            if not isinstance(data, list):
                logger.warning("[-] crt.sh returned an unexpected JSON shape; skipped.")
                toolstatus.record("crt.sh", "failed", "unexpected JSON shape")
                return "crt.sh", subdomains
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                for sub in str(entry.get('name_value', '')).lower().split('\n'):
                    sub = sub.strip()
                    # استبعاد الـ Wildcards والدومينات العشوائية الضخمة
                    if sub and not sub.startswith('*') and _HOSTNAME_RE.fullmatch(sub):
                        subdomains.add(sub)
            toolstatus.record("crt.sh", "ok")
        else:
            toolstatus.record("crt.sh", "failed", f"HTTP {status}")
    except ValueError:
        logger.warning("[-] crt.sh sent an answer that is not valid JSON; skipped.")
        toolstatus.record("crt.sh", "failed", "invalid JSON")
        return "crt.sh", subdomains
    logger.info(f"[+] crt.sh discovered {len(subdomains)} clean subdomains.")
    return "crt.sh", subdomains


async def _async_discover_single(domain: str, api_keys: dict) -> Dict[str, List[str]]:
    vt_key = api_keys.get("virustotal")
    chaos_key = api_keys.get("chaos")
    otx_key = api_keys.get("alienvault")
    shodan_key = api_keys.get("shodan")
    censys_key = api_keys.get("censys")
    
    tasks = [
        run_cli_tool("subfinder", ["subfinder", "-d", domain, "-silent"], domain=domain),
        run_cli_tool("assetfinder", ["assetfinder", "--subs-only", domain], domain=domain),
        # تم رفع الـ timeout هنا إلى 300 ثانية (5 دقائق) لمنع تايم آوت Amass
        run_cli_tool("amass", ["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=300, domain=domain),
        run_cli_tool("findomain", ["findomain", "-t", domain, "-q"], domain=domain),
        run_chaos(domain, chaos_key),
        fetch_crtsh(domain),
        fetch_alienvault(domain, otx_key),
        fetch_virustotal(domain, vt_key),
        fetch_shodan(domain, shodan_key),
        fetch_censys(domain, censys_key),
    ]
    results = await asyncio.gather(*tasks)
    tool_outputs = {tool_name: subs for tool_name, subs in results}
    return merge_and_track(tool_outputs)

async def _async_discover_recursive(domain: str, api_keys: dict, max_depth: int) -> Dict[str, List[str]]:
    master_results = {domain: ["manual"]}
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
            dropped = len(targets_to_scan) - 100
            logger.warning(f"[-] Target list exceeded 100 items at depth {depth}. Limiting recursion batch to first 100 sorted targets.")
            # Not silent: those hosts are not expanded, so this scan is incomplete.
            toolstatus.record("recursion", "truncated", f"depth {depth}: {dropped} target(s) not expanded")
            targets_to_scan = set(sorted(targets_to_scan)[:100])

        tasks = [_async_discover_single(t, api_keys) for t in sorted(targets_to_scan)]
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
