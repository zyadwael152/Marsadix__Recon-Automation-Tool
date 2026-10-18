import logging
from .discovery import discover_subdomains

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
    
    results = discover_subdomains(target, api_keys)
    
    return {
        "subdomains": results
    }
