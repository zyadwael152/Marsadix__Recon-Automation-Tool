"""
Web stage: probe the discovered hosts with httpx, crawl them with katana.

Both tools send traffic to the target, so this stage obeys two rules:

1. MODE (C15) -- what the scan mode allows:

       passive   -> the stage is skipped: nothing here may touch the target
       standard  -> httpx only (one request per host: "are you alive?")
       full      -> httpx + katana crawl (many requests per host)

2. SCOPE -- only hosts that are in scope are ever handed to a tool. The
   recon stage stores EVERY resolved name (crt.sh in particular returns names
   from other domains that share a certificate) and merely flags them
   in_scope=0, so selecting "all assets" would probe things we are not
   authorised to touch. The scope is checked again here (not just the stored
   flag), and tool OUTPUT is checked too, because a crawler follows links
   to hosts that were never in the input list.
"""

import asyncio
import logging
import os
from typing import Iterable, List

from .. import db
from .probe import run_httpx, run_katana

logger = logging.getLogger(__name__)


def _scoped(ctx, urls: Iterable[str]) -> List[str]:
    """Keep only URLs whose host is in scope (Scope.check accepts full URLs)."""
    return [u for u in urls if ctx.in_scope(u)]


def _write_lines(path: str, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Web stage (mode: %s) ===", ctx.mode)

    if not ctx.allows("standard"):
        reason = (f"mode '{ctx.mode}' makes no contact with the target "
                  f"(use --mode standard or full to probe it)")
        logger.info("[-] Web stage skipped: %s", reason)
        return {"skipped": reason, "live_urls": [], "endpoints": []}

    assets = db.get_assets(ctx.conn, ctx.scan.id)
    all_hosts = {a["host"] for a in assets}
    hosts = sorted({a["host"] for a in assets if a["in_scope"] and ctx.in_scope(a["host"])})
    if len(all_hosts) != len(hosts):
        logger.info("[*] %d of %d discovered hosts are out of scope and will not be probed",
                    len(all_hosts) - len(hosts), len(all_hosts))
    if not hosts:
        logger.warning("[-] No in-scope hosts to probe. Skipping Web stage.")
        return {"live_urls": [], "endpoints": []}

    logger.info("[+] Probing %d in-scope host(s)", len(hosts))
    live_urls = _scoped(ctx, asyncio.run(run_httpx(hosts)))

    endpoints: List[str] = []
    if live_urls and ctx.allows("full"):
        endpoints = _scoped(ctx, asyncio.run(run_katana(live_urls)))
    elif live_urls:
        logger.info("[*] Crawling skipped: katana only runs in --mode full")

    out_dir = ctx.config.output_dir
    os.makedirs(out_dir, exist_ok=True)
    if live_urls:
        path = os.path.join(out_dir, f"{ctx.target}_live_urls.txt")
        _write_lines(path, live_urls)
        logger.info("[+] Saved %d live URLs to %s", len(live_urls), path)
    if endpoints:
        path = os.path.join(out_dir, f"{ctx.target}_endpoints.txt")
        _write_lines(path, endpoints)
        logger.info("[+] Saved %d endpoints to %s", len(endpoints), path)

    return {"live_urls": live_urls, "endpoints": endpoints}
