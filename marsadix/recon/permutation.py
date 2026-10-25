"""
R5: Permutation (alterx, with a built-in fallback).

Takes the subdomains already discovered and generates likely siblings
(dev-api, api2, staging.api ...). Generating candidates is offline work, but
RESOLVING them sends DNS queries, so stage.py only calls this when the scan
mode allows it (ctx.allows("standard")). Resolution and wildcard filtering
happen afterwards in resolver.py (R7); this module only produces names.

alterx is used when installed. When it isn't, a small pure-Python generator
(dnsgen-style, no new dependency) produces the candidates instead, so the
feature still works on a machine with only the basic tools.
"""

import logging
import re
from typing import Iterable, List, Set, Tuple

from ._proc import run_async

logger = logging.getLogger(__name__)

DEFAULT_MAX_CANDIDATES = 20000
ALTERX_TIMEOUT = 120

DEFAULT_WORDS = [
    "dev", "test", "staging", "stage", "stg", "uat", "qa", "prod", "preprod",
    "api", "admin", "internal", "int", "beta", "old", "new", "v1", "v2",
    "backup", "portal", "app", "web", "mail", "vpn", "git", "ci", "demo",
    "sandbox", "corp", "m",
]

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_TRAILING_NUM_RE = re.compile(r"^(.*?)(\d+)$")


def _valid_hostname(host: str) -> bool:
    return len(host) <= 253 and all(_LABEL_RE.match(label) for label in host.split("."))


def builtin_permutations(hosts: Iterable[str], domain: str,
                         words: List[str] = None) -> Set[str]:
    """dnsgen-style fallback: word insertion, word-joining and number bumping."""
    words = words or DEFAULT_WORDS
    suffix = "." + domain
    out: Set[str] = set()

    for host in hosts:
        if not host.endswith(suffix):
            continue
        labels = host[:-len(suffix)].split(".")
        first, rest = labels[0], labels[1:]
        tail = ".".join(rest + [domain])

        for w in words:
            out.add(f"{w}.{first}.{tail}")      # dev.api.example.com
            out.add(f"{first}-{w}.{tail}")      # api-dev.example.com
            out.add(f"{w}-{first}.{tail}")      # dev-api.example.com

        m = _TRAILING_NUM_RE.match(first)       # api1 -> api0 / api2
        if m:
            base, digits = m.groups()
            for delta in (-1, 1):
                n = int(digits) + delta
                if n >= 0:
                    out.add(f"{base}{n:0{len(digits)}d}.{tail}")
    return out


async def generate_permutations(hosts: Iterable[str], domain: str,
                                max_candidates: int = DEFAULT_MAX_CANDIDATES) -> Tuple[List[str], str]:
    """
    Returns (candidates, engine). Candidates are valid hostnames under
    `domain` that are NOT already known. engine is "alterx" or "permutation"
    (the built-in fallback) and is used as the discovery-source name, so R3/R4/R17
    can show what the permutation step contributed.
    """
    domain = domain.lower().strip(".")
    known = {h.strip().lower() for h in hosts}
    seeds = sorted(h for h in known if h.endswith("." + domain))
    if not seeds:
        return [], "permutation"

    logger.info(f"[*] Generating permutations from {len(seeds)} known subdomain(s) (R5)...")
    out = await run_async(
        ["alterx", "-silent", "-enrich", "-limit", str(max_candidates)],
        stdin_lines=seeds, timeout=ALTERX_TIMEOUT, name="alterx")

    if out is None:
        engine = "permutation"
        raw = builtin_permutations(seeds, domain)
    else:
        engine = "alterx"
        raw = {line.strip().lower() for line in out.splitlines() if line.strip()}

    candidates = sorted(h for h in raw
                        if h.endswith("." + domain) and h not in known and _valid_hostname(h))
    if len(candidates) > max_candidates:
        logger.warning(f"[-] {len(candidates)} permutations generated - keeping the first {max_candidates}.")
        candidates = candidates[:max_candidates]

    logger.info(f"[+] {engine} produced {len(candidates)} new candidate(s).")
    return candidates, engine
