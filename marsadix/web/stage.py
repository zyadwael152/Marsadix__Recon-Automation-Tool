import logging
import asyncio
from .probe import run_httpx

logger = logging.getLogger(__name__)

def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Web stage ===")
    
    # === سطور الاستكشاف لمعرفة مكان حفظ البيانات ===
    logger.info(f"[DEBUG] ctx attributes: {dir(ctx)}")
    logger.info(f"[DEBUG] kwargs keys: {list(kwargs.keys())}")
    if hasattr(ctx, 'results'):
        logger.info(f"[DEBUG] ctx.results keys: {list(ctx.results.keys())}")
    if hasattr(ctx, 'state'):
        logger.info(f"[DEBUG] ctx.state keys: {list(ctx.state.keys())}")
    # ===============================================

    recon_data = {}
    
    # محاولة الاستخراج الموسعة
    if "recon" in kwargs:
        recon_data = kwargs["recon"]
    elif hasattr(ctx, "results") and "recon" in ctx.results:
        recon_data = ctx.results["recon"]
    elif hasattr(ctx, "state") and "recon" in ctx.state:
        recon_data = ctx.state["recon"]
    elif hasattr(ctx, "data") and "recon" in ctx.data:
        recon_data = ctx.data["recon"]

    # لو النطاقات مبعوتة مباشرة
    if not recon_data and "subdomains" in kwargs:
        recon_data = {"subdomains": kwargs["subdomains"]}

    subdomains = []
    if isinstance(recon_data, dict):
        if "subdomains" in recon_data:
            subs = recon_data["subdomains"]
            subdomains = list(subs.keys()) if isinstance(subs, dict) else subs
        else:
            subdomains = list(recon_data.keys())

    if not subdomains:
        logger.warning("[-] No subdomains provided to Web stage. Skipping.")
        return {"live_urls": []}

    logger.info(f"[+] Successfully extracted {len(subdomains)} subdomains. Passing to httpx...")
    live_urls = asyncio.run(run_httpx(subdomains))
    
    return {
        "live_urls": live_urls
    }
