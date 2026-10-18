import logging
import asyncio
from .probe import run_httpx

logger = logging.getLogger(__name__)

def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Web stage ===")
    
    # Try to extract subdomains that succeeded in the Recon stage
    subdomains = []
    
    # Data extraction logic based on the Pipeline architecture
    if hasattr(ctx, "data") and "recon" in ctx.data:
        recon_data = ctx.data["recon"].get("subdomains", {})
        subdomains = list(recon_data.keys()) if isinstance(recon_data, dict) else recon_data
    elif "recon" in kwargs:
        recon_data = kwargs["recon"].get("subdomains", {})
        subdomains = list(recon_data.keys()) if isinstance(recon_data, dict) else recon_data

    if not subdomains:
        logger.warning("[-] No subdomains provided to Web stage. Skipping.")
        return {"live_urls": []}

    # Run httpx to find live HTTP/HTTPS services
    live_urls = asyncio.run(run_httpx(subdomains))
    
    return {
        "live_urls": live_urls
    }
