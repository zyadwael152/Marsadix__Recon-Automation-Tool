"""
Web stage: probe the discovered hosts with httpx, crawl them with katana, and
store what was found.

Both tools send traffic to the target, so this stage obeys three rules:

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

3. RATE (C6) -- the scan's rate limit (requests/second) is passed to both tools.

Results go to the web_items table (live URLs with their HTTP status, plus
crawled endpoints / JS files) so reports and later stages can use them; the
txt files in config.output_dir are kept as a convenience for other tools.
"""

import asyncio
import logging
import os
from typing import Iterable, List
from urllib.parse import urlsplit

from .. import db
from ..core import netguard
from ..core.scope import normalize_host
from ..models import Confidence, DiscoverySource, Technology, WebItem, WebItemKind
from . import fingerprint
from .probe import run_httpx, run_katana

logger = logging.getLogger(__name__)


def _scoped(ctx, urls: Iterable[str]) -> List[str]:
    """Keep only URLs whose host is in scope (Scope.check accepts full URLs)."""
    return [u for u in urls if ctx.in_scope(u)]


def _write_lines(path: str, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _canonical(url: str) -> str:
    return url.rstrip("/")


def _endpoint_item(scan_id: int, url: str) -> WebItem:
    parts = urlsplit(url)
    is_js = parts.path.lower().endswith((".js", ".mjs"))
    return WebItem(
        scan_id=scan_id,
        host=normalize_host(url) or parts.netloc,
        url=url,
        kind=WebItemKind.JS_FILE if is_js else WebItemKind.ENDPOINT,
        source=DiscoverySource.ACTIVE,
        has_params=bool(parts.query),
    )


def _technologies(scan_id: int, host: str, record: dict) -> List[Technology]:
    """Technologies httpx saw on one host: wappalyzer matches + the Server header."""
    found = fingerprint.merge_technologies(
        fingerprint.parse_tech(record.get("tech")),
        fingerprint.parse_server_header(record.get("webserver")))
    return [Technology(
        scan_id=scan_id, host=host, name=name, version=version,
        cpe=fingerprint.cpe_for(name, version), category=fingerprint.category_for(name),
        source="httpx",
        # a version read from a header/page is evidence, not proof (backports,
        # masked banners): LIKELY at best, CONFIRMED only after a safe check
        confidence=Confidence.LIKELY if version else Confidence.POSSIBLE)
        for name, version in found]


def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Web stage (mode: %s) ===", ctx.mode)

    if not ctx.allows("standard"):
        reason = (f"mode '{ctx.mode}' makes no contact with the target "
                  f"(use --mode standard or full to probe it)")
        logger.info("[-] Web stage skipped: %s", reason)
        return {"skipped": reason, "live_urls": [], "endpoints": []}

    scan_id = ctx.scan.id
    assets = db.get_assets(ctx.conn, scan_id)
    all_hosts = {a["host"] for a in assets}
    hosts = sorted({a["host"] for a in assets if a["in_scope"] and ctx.in_scope(a["host"])})
    if len(all_hosts) != len(hosts):
        logger.info("[*] %d of %d discovered hosts are out of scope and will not be probed",
                    len(all_hosts) - len(hosts), len(all_hosts))

    # An in-scope NAME can be made to resolve to 127.0.0.1, 10.x or the cloud
    # metadata address (see core/netguard.py): never probe those unless the scope
    # file lists the address explicitly.
    known_ip = {a["host"]: netguard.asset_ip(a) for a in assets}
    internal = {h: netguard.blocked_reason(known_ip[h], ctx.scope) for h in hosts if known_ip.get(h)}
    for h, why in sorted(internal.items()):
        if why:
            logger.warning("[!] %s resolves to %s (%s): not probed. If this is an authorised "
                           "internal test, list the address or range in the scope file.", h, known_ip[h], why)
    hosts = [h for h in hosts if not internal.get(h)]
    if not hosts:
        logger.warning("[-] No in-scope hosts to probe. Skipping Web stage.")
        return {"live_urls": [], "endpoints": []}

    rate = ctx.scan.rate_limit or ctx.config.rate_limit
    logger.info("[+] Probing %d in-scope host(s) at <= %s req/s", len(hosts), rate)

    probed = asyncio.run(run_httpx(hosts, rate))
    live = [r for r in probed if ctx.in_scope(r["url"])]
    # The name may have resolved differently when httpx asked than when recon did.
    # The request has already gone out, but nothing more is done with such a host
    # (no crawl, nothing stored from it).
    for r in [r for r in live if r.get("ip") and netguard.blocked_reason(r["ip"], ctx.scope)]:
        logger.warning("[!] %s answered from %s (%s): discarded, not crawled",
                       r["url"], r["ip"], netguard.blocked_reason(r["ip"], ctx.scope))
    live = [r for r in live if not (r.get("ip") and netguard.blocked_reason(r["ip"], ctx.scope))]
    live_urls = [r["url"] for r in live]

    # Recon stores the base source+DNS confidence. This is the only HTTP probe
    # in the pipeline, so apply the HTTP bonus here rather than running httpx a
    # second time inside the Recon stage.
    from ..recon.confidence import compute_source_confidence
    source_map = {a["host"]: db.get_asset_sources(ctx.conn, scan_id, a["host"])
                  for a in assets}
    scores = compute_source_confidence(source_map, {
        normalize_host(r["url"]) for r in live if normalize_host(r["url"])
    })
    for host, score in scores.items():
        ctx.conn.execute(
            "UPDATE assets SET confidence_score=? WHERE scan_id=? AND host=?",
            (score, scan_id, host))
    ctx.conn.commit()

    endpoints: List[str] = []
    if live_urls and ctx.allows("full"):
        seen = {_canonical(u) for u in live_urls}           # the roots are already stored as live URLs
        endpoints = [u for u in _scoped(ctx, asyncio.run(run_katana(live_urls, rate)))
                     if _canonical(u) not in seen]
    elif live_urls:
        logger.info("[*] Crawling skipped: katana only runs in --mode full")

    # ---- what probing learned about each host: IP, CDN, technologies + versions
    host_set = set(hosts)
    technologies: List[Technology] = []
    for r in live:
        host = r.get("input") if r.get("input") in host_set else (normalize_host(r["url"]) or r["url"])
        db.update_asset_network(ctx.conn, scan_id, host, ip=r.get("ip"),
                                is_cdn=bool(r.get("cdn")), cdn_name=r.get("cdn_name"))
        technologies += _technologies(scan_id, host, r)
    tech_stored = db.save_many(ctx.conn, "technologies", technologies)
    cdn_hosts = sum(1 for r in live if r.get("cdn"))
    logger.info("[+] Stored %d technology/version record(s); %d host(s) behind a CDN",
                tech_stored, cdn_hosts)

    # ---- store in the database (UNIQUE(scan_id, url, kind): a re-run adds nothing twice)
    items = [WebItem(scan_id=scan_id, host=normalize_host(r["url"]) or r["url"], url=r["url"],
                     kind=WebItemKind.URL, source=DiscoverySource.ACTIVE,
                     status_code=r["status_code"], has_params=False) for r in live]
    items += [_endpoint_item(scan_id, u) for u in endpoints]
    stored = db.save_many(ctx.conn, "web_items", items)
    logger.info("[+] Stored %d web item(s): %d live URL(s), %d endpoint(s)/JS file(s)",
                stored, len(live), len(endpoints))

    # ---- plain-text copies (output_dir, which .gitignore already covers)
    out_dir = ctx.config.output_dir
    os.makedirs(out_dir, exist_ok=True)
    if live_urls:
        _write_lines(os.path.join(out_dir, f"{ctx.target}_live_urls.txt"), live_urls)
    if endpoints:
        _write_lines(os.path.join(out_dir, f"{ctx.target}_endpoints.txt"), endpoints)

    return {"live_urls": live_urls, "endpoints": endpoints, "stored": stored,
            "technologies": tech_stored}
