import logging
import asyncio
from .discovery import discover_subdomains
from .resolver import filter_active_subdomains
from .coverage import log_missing_asset_hunter
from .confidence import score_hosts
from .cdn_asn import lookup_cdn_asn
from .. import db
from ..models import Asset, DiscoverySource

logger = logging.getLogger(__name__)


def _extract_api_keys(ctx) -> dict:
    """
    Pull the recon API keys out of the real pipeline Context (ctx.config has
    individual fields like virustotal_api_key, not a `.keys` dict - the old
    code checked `ctx.cfg.keys`, which never matched the real Context
    (attribute is `config`, not `cfg`) and silently returned {} every time,
    which is why VirusTotal/chaos always showed "No API Key provided" even
    after adding keys to config.toml).
    """
    cfg = getattr(ctx, "config", None)
    if cfg is not None:
        return {
            "virustotal": getattr(cfg, "virustotal_api_key", "") or None,
            "chaos": getattr(cfg, "chaos_api_key", "") or None,
            "alienvault": getattr(cfg, "otx_api_key", "") or None,
        }
    # fallback for tests/callers that pass a plain dict context
    if isinstance(ctx, dict) and "config" in ctx:
        c = ctx["config"]
        get = (lambda k: c.get(k)) if isinstance(c, dict) else (lambda k: getattr(c, k, None))
        return {
            "virustotal": get("virustotal_api_key"),
            "chaos": get("chaos_api_key"),
            "alienvault": get("otx_api_key"),
        }
    return {}


def run(ctx, *args, **kwargs) -> dict:
    if hasattr(ctx, "target"):
        target = ctx.target
    elif isinstance(ctx, dict) and "target" in ctx:
        target = ctx["target"]
    else:
        target = "example.com"

    api_keys = _extract_api_keys(ctx)

    logger.info(f"=== Starting Recon stage for target: {target} ===")

    # 1. Discover subdomains from all active tools and sources
    raw_results = discover_subdomains(target, api_keys)

    # 2. Filter out dead domains via DNS resolution
    active_results = asyncio.run(filter_active_subdomains(raw_results))

    # 3. Persist each host as an Asset, and record which sources found it as
    #    AssetSource rows (R3 wiring + R4 confidence data). Without this,
    #    nothing ever lands in the DB, so the "track" stage always sees 0
    #    assets for every scan and reports it as a fresh baseline forever.
    if hasattr(ctx, "conn") and hasattr(ctx, "scan"):
        scan_id = ctx.scan.id
        in_scope = getattr(ctx, "in_scope", None)

        # R4: real confidence score (sources + resolved + HTTP liveness when
        # the scan mode allows contacting the target) instead of a sources-only guess.
        sources_by_host = {host: info["sources"] for host, info in active_results.items()}
        confidence_scores = asyncio.run(score_hosts(ctx, sources_by_host))

        # R9: CDN/ASN - one bulk lookup for every unique IP, not one per host
        unique_ips = {info["ip"] for info in active_results.values() if info.get("ip")}
        cdn_asn_info = asyncio.run(lookup_cdn_asn(unique_ips))

        assets = []
        for host, info in active_results.items():
            host_in_scope = in_scope(host) if callable(in_scope) else True
            ip = info.get("ip")
            extra = cdn_asn_info.get(ip, {}) if ip else {}
            assets.append(Asset(
                scan_id=scan_id,
                host=host,
                ip=ip,
                in_scope=host_in_scope,
                source=DiscoverySource.PASSIVE,
                confidence_score=confidence_scores.get(host, 0),
                is_cdn=extra.get("is_cdn", False),
                cdn_name=extra.get("asn_owner") if extra.get("is_cdn") else None,
                asn=extra.get("asn"),
                asn_owner=extra.get("asn_owner"),
            ))

        saved = db.save_many(ctx.conn, "assets", assets)
        logger.info(f"[+] Saved {saved} assets for scan #{scan_id}")

        for host, info in active_results.items():
            db.save_asset_sources_many(ctx.conn, scan_id, host, info["sources"])

        # R17: Missing Asset Hunter - per-source coverage + single-source hosts
        log_missing_asset_hunter(ctx.conn, scan_id)

    return {
        "subdomains": {host: info["sources"] for host, info in active_results.items()}
    }
