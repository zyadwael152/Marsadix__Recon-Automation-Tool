"""
R4: Source Confidence.

A host's confidence score (0-100) blends three signals:
  - how many independent sources found it (more sources = more likely real)
  - whether it resolves over DNS (recon/resolver.py already filters to only
    resolving hosts before this runs, so every host reaching this module
    already earns that point)
  - whether it actually responds over HTTP - only checked when the scan
    mode allows contacting the target (passive mode must not send any
    traffic; see core/pipeline.py Context.allows())

Any one signal alone is weak on its own (crt.sh in particular surfaces
long-dead certificate names that still "exist" but are not live); combining
them gets closer to "this host is real and worth attention".
"""

import asyncio
import logging
from typing import Dict, Iterable, List, Set

logger = logging.getLogger(__name__)

SOURCE_WEIGHT = 15    # points per independent source
SOURCE_CAP = 60       # max points from source count alone
RESOLVED_BONUS = 20   # every host here already resolved
HTTP_BONUS = 20
HTTP_CHECK_TIMEOUT = 180  # seconds for the whole batch, not per-host


async def _probe_http_live(hosts: List[str]) -> Set[str]:
    """Which of these hosts respond over HTTP(S), via `httpx -silent`."""
    if not hosts:
        return set()

    live: Set[str] = set()
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            "httpx", "-silent",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        input_data = "\n".join(hosts).encode()
        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(input=input_data), timeout=HTTP_CHECK_TIMEOUT)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.warning(
                f"[-] HTTP confidence check timed out after {HTTP_CHECK_TIMEOUT}s - "
                f"scoring without it for any host not already confirmed.")
            return live

        for line in stdout.decode(errors="replace").splitlines():
            url = line.strip()
            if url:
                # httpx -silent prints a bare URL, e.g. https://sub.example.com
                host = url.split("://", 1)[-1].split("/", 1)[0]
                live.add(host)
    except Exception as e:
        logger.warning(f"[-] HTTP confidence check skipped: {e}")

    return live


def compute_source_confidence(hosts_sources: Dict[str, List[str]],
                               http_live: Iterable[str] = ()) -> Dict[str, int]:
    """
    hosts_sources: {host: [source names]} - every host here already resolved.
    http_live: hosts confirmed to respond over HTTP. Empty when not checked
    (e.g. passive mode) - those hosts simply don't get the HTTP bonus.
    """
    live_set = set(http_live)
    scores = {}
    for host, sources in hosts_sources.items():
        score = min(SOURCE_CAP, len(sources) * SOURCE_WEIGHT)
        score += RESOLVED_BONUS
        if host in live_set:
            score += HTTP_BONUS
        scores[host] = min(100, score)
    return scores


async def score_hosts(ctx, hosts_sources: Dict[str, List[str]]) -> Dict[str, int]:
    """
    Entry point for stage.py. Only attempts the HTTP check when the scan
    mode allows touching the target (ctx.allows("standard")); a passive
    scan's hosts are scored from sources + DNS resolution alone.
    """
    allows = getattr(ctx, "allows", None)
    allows_http = allows("standard") if callable(allows) else False

    http_live: Set[str] = set()
    if allows_http:
        logger.info(f"[*] Checking HTTP response for {len(hosts_sources)} host(s) (R4)...")
        http_live = await _probe_http_live(list(hosts_sources.keys()))
        logger.info(f"[+] {len(http_live)} host(s) responded over HTTP.")
    else:
        logger.info("[-] Skipping HTTP confidence check (passive mode - no traffic to target).")

    return compute_source_confidence(hosts_sources, http_live)
