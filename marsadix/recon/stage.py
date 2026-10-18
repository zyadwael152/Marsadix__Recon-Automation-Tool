import logging
import asyncio
from .discovery import discover_subdomains
from .resolver import filter_active_subdomains
from .. import db
from ..models import Asset, DiscoverySource

logger = logging.getLogger(__name__)


def _extract_api_keys(ctx) -> dict:
    cfg = getattr(ctx, "config", None)
    if cfg is not None:
        return {
            "virustotal": getattr(cfg, "virustotal_api_key", "") or None,
            "chaos": getattr(cfg, "chaos_api_key", "") or None,
            "alienvault": getattr(cfg, "otx_api_key", "") or None,
        }
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

    raw_results = discover_subdomains(target, api_keys)

    active_results = asyncio.run(filter_active_subdomains(raw_results))

    if hasattr(ctx, "conn") and hasattr(ctx, "scan"):
        scan_id = ctx.scan.id
        in_scope = getattr(ctx, "in_scope", None)

        assets = []
        for host, sources in active_results.items():
            host_in_scope = in_scope(host) if callable(in_scope) else True
            assets.append(Asset(
                scan_id=scan_id,
                host=host,
                in_scope=host_in_scope,
                source=DiscoverySource.PASSIVE,
                confidence_score=min(100, len(sources) * 20),
            ))

        saved = db.save_many(ctx.conn, "assets", assets)
        logger.info(f"[+] Saved {saved} assets for scan #{scan_id}")

        for host, sources in active_results.items():
            db.save_asset_sources_many(ctx.conn, scan_id, host, sources)

    return {
        "subdomains": active_results
    }
