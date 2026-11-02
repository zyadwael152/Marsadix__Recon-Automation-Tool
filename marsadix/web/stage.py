"""
Web stage: probe in-scope hosts with httpx, crawl them with katana, and store
the results.

Rules this stage follows:

1. MODE (C15): passive never contacts the target. standard runs httpx only
   (one request per host). full adds the katana crawl.
2. SCOPE: only in-scope hosts are handed to a tool. Tool output is filtered
   again, because a crawler follows links to hosts that were never in the input.
3. RATE (C6): the scan's rate limit is passed to both tools.

Results go to web_items and technologies. Plain-text copies go to output_dir.
"""

import asyncio
import logging
import os
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from .. import db
from ..core import netguard
from ..core.confidence import compute_source_confidence
from ..core.scope import normalize_host
from ..core.textfile import safe_filename
from ..models import Confidence, DiscoverySource, Technology, WebItem, WebItemKind
from . import fingerprint
from .probe import run_gau, run_httpx, run_katana

logger = logging.getLogger(__name__)


def _result(**overrides) -> dict:
    """Every return path uses the same keys, so the pipeline can rely on them."""
    base = {
        "skipped": None,
        "live_urls": [],
        "endpoints": [],
        "archived_urls": [],
        "archived_stored": 0,
        "stored": 0,
        "technologies": 0,
    }
    base.update(overrides)
    return base


def _scoped(ctx, urls: Iterable[str]) -> List[str]:
    return [u for u in urls if ctx.in_scope(u)]


def _canonical(url: str) -> str:
    return url.rstrip("/")


def _is_js(path: str) -> bool:
    return path.lower().endswith((".js", ".mjs"))


def _archive_item(scan_id: int, url: str) -> WebItem:
    parts = urlsplit(url)
    is_root = parts.path in ("", "/") and not parts.query
    if _is_js(parts.path):
        kind = WebItemKind.JS_FILE
    elif is_root:
        kind = WebItemKind.URL
    else:
        kind = WebItemKind.ENDPOINT
    return WebItem(
        scan_id=scan_id, host=normalize_host(url) or parts.netloc, url=url,
        kind=kind, source=DiscoverySource.PASSIVE, has_params=bool(parts.query),
    )


def _endpoint_item(scan_id: int, url: str) -> WebItem:
    parts = urlsplit(url)
    return WebItem(
        scan_id=scan_id, host=normalize_host(url) or parts.netloc, url=url,
        kind=WebItemKind.JS_FILE if _is_js(parts.path) else WebItemKind.ENDPOINT,
        source=DiscoverySource.ACTIVE, has_params=bool(parts.query),
    )


def _technologies(scan_id: int, host: str, record: dict) -> List[Technology]:
    """Wappalyzer matches plus the Server header, for one host."""
    found = fingerprint.merge_technologies(
        fingerprint.parse_tech(record.get("tech")),
        fingerprint.parse_server_header(record.get("webserver")),
    )
    return [
        Technology(
            scan_id=scan_id, host=host, name=name, version=version,
            cpe=fingerprint.cpe_for(name, version),
            category=fingerprint.category_for(name),
            source="httpx",
            # A version from a header or page is evidence, not proof (backports,
            # masked banners). CONFIRMED needs a safe check.
            confidence=Confidence.LIKELY if version else Confidence.POSSIBLE,
        )
        for name, version in found
    ]


def _write_outputs(out_dir: str, target: str, files: Dict[str, List[str]]) -> None:
    """Write each non-empty list to <output_dir>/<target>_<suffix>.txt."""
    os.makedirs(out_dir, exist_ok=True)
    stem = safe_filename(target)
    for suffix, lines in files.items():
        if not lines:
            continue
        with open(os.path.join(out_dir, f"{stem}_{suffix}.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


def _collect_hosts(ctx, scan_id: int) -> tuple:
    """
    Returns (assets, hosts_to_probe). Filters out out-of-scope hosts and hosts
    that resolve to internal addresses (see core/netguard.py).
    """
    assets = db.get_assets(ctx.conn, scan_id)
    all_hosts = {a["host"] for a in assets}
    hosts = sorted({a["host"] for a in assets if a["in_scope"] and ctx.in_scope(a["host"])})
    if len(all_hosts) != len(hosts):
        logger.info("[*] %d of %d discovered hosts are out of scope and will not be probed",
                    len(all_hosts) - len(hosts), len(all_hosts))

    known_ip = {a["host"]: netguard.asset_ip(a) for a in assets}
    internal = {h: netguard.blocked_reason(known_ip[h], ctx.scope)
                for h in hosts if known_ip.get(h)}
    for h, why in sorted(internal.items()):
        if why:
            logger.warning("[!] %s resolves to %s (%s): not probed. If this is an "
                           "authorised internal test, list the address in the scope file.",
                           h, known_ip[h], why)
    return assets, [h for h in hosts if not internal.get(h)]


def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Web stage (mode: %s) ===", ctx.mode)
    scan_id = ctx.scan.id
    out_dir = ctx.config.output_dir

    # gau reads public archives and never contacts the target, so it runs in
    # every mode. None = gau not installed. [] = ran with no results.
    gau_result = asyncio.run(run_gau(ctx.target, timeout=ctx.config.tool_timeout))
    archived_urls = _scoped(ctx, gau_result or [])
    archived_stored = db.save_many(
        ctx.conn, "web_items", [_archive_item(scan_id, u) for u in archived_urls]
    ) if archived_urls else 0
    _write_outputs(out_dir, ctx.target, {"archived_urls": archived_urls})

    if not ctx.allows("standard"):
        if gau_result is None:
            reason = (f"mode '{ctx.mode}' makes no contact with the target and gau is "
                      "not installed, so archived URL collection was skipped")
            logger.info("[-] Web stage skipped: %s", reason)
            return _result(skipped=reason)
        logger.info("[+] Passive archived URL collection stored %d item(s).", archived_stored)
        return _result(archived_urls=archived_urls, archived_stored=archived_stored)

    assets, hosts = _collect_hosts(ctx, scan_id)
    if not hosts:
        logger.warning("[-] No in-scope hosts to probe. Skipping Web stage.")
        return _result(skipped="no in-scope hosts to probe",
                       archived_urls=archived_urls, archived_stored=archived_stored)

    rate = ctx.scan.rate_limit or ctx.config.rate_limit
    logger.info("[+] Probing %d in-scope host(s) at <= %s req/s", len(hosts), rate)
    probed = asyncio.run(run_httpx(hosts, rate, timeout=ctx.config.tool_timeout))

    # Re-check the scope and the resolved IP. The name may resolve differently
    # at probe time than it did during recon.
    live = []
    for r in probed:
        if not ctx.in_scope(r["url"]):
            continue
        blocked = netguard.blocked_reason(r["ip"], ctx.scope) if r.get("ip") else None
        if blocked:
            logger.warning("[!] %s answered from %s (%s): discarded, not crawled",
                           r["url"], r["ip"], blocked)
            continue
        live.append(r)
    live_urls = [r["url"] for r in live]

    # HTTP bonus for R4. This stage is the only place httpx's result is used
    # for confidence.
    source_map = {a["host"]: db.get_asset_sources(ctx.conn, scan_id, a["host"]) for a in assets}
    live_hosts = {normalize_host(u) for u in live_urls if normalize_host(u)}
    for host, score in compute_source_confidence(source_map, live_hosts).items():
        db.update_asset_confidence(ctx.conn, scan_id, host, score)

    endpoints: List[str] = []
    if live_urls and ctx.allows("full"):
        seen = {_canonical(u) for u in live_urls}
        crawled = asyncio.run(run_katana(live_urls, rate, timeout=ctx.config.tool_timeout))
        endpoints = [u for u in _scoped(ctx, crawled) if _canonical(u) not in seen]
    elif live_urls:
        logger.info("[*] Crawling skipped: katana only runs in --mode full")

    host_set = set(hosts)
    technologies: List[Technology] = []
    for r in live:
        raw_host = r.get("input")
        host = raw_host if raw_host in host_set else (normalize_host(r["url"]) or r["url"])
        db.update_asset_network(ctx.conn, scan_id, host, ip=r.get("ip"),
                                is_cdn=bool(r.get("cdn")), cdn_name=r.get("cdn_name"))
        technologies += _technologies(scan_id, host, r)
    tech_stored = db.save_many(ctx.conn, "technologies", technologies) if technologies else 0
    logger.info("[+] Stored %d technology/version record(s); %d host(s) behind a CDN",
                tech_stored, sum(1 for r in live if r.get("cdn")))

    items = [
        WebItem(scan_id=scan_id, host=normalize_host(r["url"]) or r["url"], url=r["url"],
                kind=WebItemKind.URL, source=DiscoverySource.ACTIVE,
                status_code=r["status_code"], has_params=False)
        for r in live
    ]
    items += [_endpoint_item(scan_id, u) for u in endpoints]
    stored = db.save_many(ctx.conn, "web_items", items) if items else 0
    logger.info("[+] Stored %d web item(s): %d live URL(s), %d endpoint(s)/JS file(s)",
                stored, len(live_urls), len(endpoints))

    _write_outputs(out_dir, ctx.target, {"live_urls": live_urls, "endpoints": endpoints})

    return _result(
        live_urls=live_urls,
        endpoints=endpoints,
        stored=stored,
        technologies=tech_stored,
        archived_urls=archived_urls,
        archived_stored=archived_stored,
    )
