import logging
import asyncio
from .discovery import discover_subdomains
from .resolver import filter_active_subdomains

logger = logging.getLogger(__name__)

def run(ctx, *args, **kwargs) -> dict:
    if hasattr(ctx, "target"):
        target = ctx.target
    elif isinstance(ctx, dict) and "target" in ctx:
        target = ctx["target"]
    else:
        target = "example.com"

    api_keys = {}
    if hasattr(ctx, "cfg") and hasattr(ctx.cfg, "keys"):
        api_keys = ctx.cfg.keys
    elif isinstance(ctx, dict) and "cfg" in ctx:
        api_keys = ctx["cfg"].get("keys", {})

    logger.info(f"=== Starting Recon stage for target: {target} ===")
    
    # 1. Discover subdomains from all active tools and sources
    raw_results = discover_subdomains(target, api_keys)
    
    # 2. Filter out dead domains via DNS resolution
    active_results = asyncio.run(filter_active_subdomains(raw_results))
    
    return {
        "subdomains": active_results
    }
