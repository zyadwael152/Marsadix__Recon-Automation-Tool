import logging
import asyncio
from .probe import run_httpx

logger = logging.getLogger(__name__)

def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Web stage ===")
    
    # محاولة استخراج النطاقات بذكاء من كل الأماكن المحتملة في ذاكرة الـ Pipeline
    recon_data = {}
    
    if hasattr(ctx, "state") and "recon" in ctx.state:
        recon_data = ctx.state["recon"].get("subdomains", {})
    elif hasattr(ctx, "data") and "recon" in ctx.data:
        recon_data = ctx.data["recon"].get("subdomains", {})
    elif "recon" in kwargs:
        recon_data = kwargs["recon"].get("subdomains", {})
        
    # تحويل البيانات لقائمة (List) سواء كانت قاموس (Dict) أو قائمة جاهزة
    subdomains = []
    if isinstance(recon_data, dict):
        subdomains = list(recon_data.keys())
    elif isinstance(recon_data, list):
        subdomains = recon_data

    if not subdomains:
        logger.warning("[-] No subdomains provided to Web stage. Skipping.")
        return {"live_urls": []}

    # تشغيل httpx لمعرفة المواقع اللي عليها Web Server شغال
    live_urls = asyncio.run(run_httpx(subdomains))
    
    return {
        "live_urls": live_urls
    }
