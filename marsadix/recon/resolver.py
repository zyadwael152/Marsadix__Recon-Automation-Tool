"""
R7: DNS resolution (dnsx) with wildcard filtering.

dnsx resolves every candidate in one bulk pass (A + CNAME). If dnsx isn't
installed the old stdlib socket resolver is used instead, so a scan never
fails just because a tool is missing.

Wildcard handling: for hosts that ONLY came from the generated sources
(permutation / bruteforce), random non-existent names under their parent
domain are resolved; if the generated host resolves only to those same
"wildcard" IPs, it's an artifact of *.parent and is dropped. Hosts found by a
passive source (crt.sh, subfinder ...) are never dropped by this - a real
certificate or passive-DNS record is evidence on its own.

Returns {host: {"sources": [...], "ip": first_ip, "ips": [...], "cname": [...]}}
- "sources" and "ip" are what stage.py/graph code already relied on.
"""

import asyncio
import json
import logging
import random
import socket
import string
from collections import Counter
from typing import Dict, List, Optional, Set

from ._proc import run_async

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 5            # seconds per socket lookup (fallback path)
DNSX_TIMEOUT = 600         # whole bulk dnsx run
SOCKET_CONCURRENCY = 100
WILDCARD_PROBES = 2
MAX_WILDCARD_PARENTS = 100

# Source names that mean "we guessed this name" (see permutation.py / bruteforce.py)
GENERATED_SOURCES = frozenset({"alterx", "permutation", "puredns", "wordlist"})


async def _lookup_all(host: str) -> List[str]:
    """All IPv4 and IPv6 addresses for host via the OS resolver, or []."""
    loop = asyncio.get_running_loop()
    try:
        records = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM),
            timeout=DNS_TIMEOUT)
        ips = []
        for record in records:
            address = record[4][0]
            if address not in ips:
                ips.append(address)
        return ips
    except Exception:
        return []


async def resolve_domain(domain: str) -> Optional[str]:
    """Resolve a domain to one IP. Returns None if it doesn't resolve."""
    ips = await _lookup_all(domain)
    return ips[0] if ips else None


def _str_list(value) -> List[str]:
    """dnsx fields are lists of strings; tolerate a bare string, null, or junk entries."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def parse_dnsx_json(text: str) -> Dict[str, dict]:
    """
    Parse `dnsx -json` lines into {host: {"ips": [...], "cname": [...]}}.

    One malformed record (wrong type, missing field, a new dnsx version changing
    a field) is logged and skipped; it never aborts the whole resolution stage.
    """
    out: Dict[str, dict] = {}
    bad = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue                      # a log line, not a record
        if not isinstance(data, dict):
            bad += 1
            continue
        host = data.get("host")
        if not isinstance(host, str):
            bad += 1
            continue
        host = host.strip().lower().rstrip(".")
        # dnsx can return A and AAAA in separate arrays; keep both address families.
        ips = _str_list(data.get("a")) + _str_list(data.get("aaaa"))
        if not host or not ips:
            continue
        entry = out.setdefault(host, {"ips": [], "cname": []})
        for ip in ips:
            if ip not in entry["ips"]:
                entry["ips"].append(ip)
        for cname in _str_list(data.get("cname")):
            cname = cname.lower().rstrip(".")
            if cname and cname not in entry["cname"]:
                entry["cname"].append(cname)
    if bad:
        logger.warning("[-] dnsx: skipped %d record(s) with an unexpected structure.", bad)
    return out


async def resolve_with_dnsx(hosts: List[str], rate_limit: Optional[int] = None,
                            timeout: int = DNSX_TIMEOUT) -> Optional[Dict[str, dict]]:
    """None means dnsx is unavailable/failed - caller falls back to sockets."""
    if not hosts:
        return {}
    cmd = ["dnsx", "-silent", "-a", "-aaaa", "-cname", "-json"]
    if rate_limit:
        cmd += ["-rl", str(int(rate_limit))]
    out = await run_async(cmd, stdin_lines=hosts, timeout=timeout, name="dnsx")
    return None if out is None else parse_dnsx_json(out)


async def _resolve_with_socket(hosts: List[str]) -> Dict[str, dict]:
    sem = asyncio.Semaphore(SOCKET_CONCURRENCY)

    async def one(host):
        async with sem:
            return host, await _lookup_all(host)

    pairs = await asyncio.gather(*(one(h) for h in hosts))
    return {h: {"ips": ips, "cname": []} for h, ips in pairs if ips}


async def detect_wildcard_ips(domain: str, probes: int = WILDCARD_PROBES) -> Set[str]:
    """IPs that random, surely-nonexistent names under `domain` resolve to."""
    ips: Set[str] = set()
    for _ in range(probes):
        # DNS labels do not need a cryptographic RNG.
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))  # nosec B311
        ips.update(await _lookup_all(f"{label}.{domain}"))
    return ips


async def _drop_wildcard_hits(active: Dict[str, dict], domain: str) -> Dict[str, dict]:
    generated = [h for h, info in active.items() if set(info["sources"]) <= GENERATED_SOURCES]
    if not generated:
        return active

    parent_counts = Counter(h.split(".", 1)[1] for h in generated if "." in h)
    parents = {domain} | {p for p, _ in parent_counts.most_common(MAX_WILDCARD_PARENTS)}
    parents = sorted(parents)
    wildcard_ips = dict(zip(parents, await asyncio.gather(*(detect_wildcard_ips(p) for p in parents))))

    dropped = 0
    for host in generated:
        wc = wildcard_ips.get(host.split(".", 1)[1], set())
        if wc and set(active[host]["ips"]) <= wc:
            del active[host]
            dropped += 1
    if dropped:
        logger.info(f"[+] Wildcard filter dropped {dropped} generated host(s) that only matched a wildcard record.")
    return active


async def filter_active_subdomains(subdomains_dict: Dict[str, List[str]], domain: Optional[str] = None,
                                   rate_limit: Optional[int] = None) -> Dict[str, dict]:
    """
    Keep only hosts that resolve and attach their IP(s). Pass `domain` to
    enable the wildcard filter for generated candidates.
    """
    hosts = list(subdomains_dict.keys())
    logger.info(f"[*] Starting DNS resolution for {len(hosts)} subdomains...")

    resolved = await resolve_with_dnsx(hosts, rate_limit)
    engine = "dnsx"
    if resolved is None:
        engine = "socket"
        resolved = await _resolve_with_socket(hosts)

    active = {
        host: {"sources": subdomains_dict[host], "ip": r["ips"][0], "ips": r["ips"], "cname": r["cname"]}
        for host, r in resolved.items() if host in subdomains_dict
    }
    if domain:
        active = await _drop_wildcard_hits(active, domain.lower().strip("."))

    logger.info(f"[+] DNS resolution ({engine}) complete. Active subdomains: {len(active)} / {len(hosts)}")
    return active
