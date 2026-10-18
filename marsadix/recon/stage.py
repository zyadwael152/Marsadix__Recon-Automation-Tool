import logging
from .discovery import discover_subdomains

logger = logging.getLogger(__name__)

# استخدام *args و **kwargs بيحمي الكود من أي تغيير في الـ Pipeline
def run(ctx, *args, **kwargs) -> dict:
    # 1. استخراج الهدف (Target)
    if hasattr(ctx, "target"):
        target = ctx.target
    elif isinstance(ctx, dict) and "target" in ctx:
        target = ctx["target"]
    else:
        target = "example.com"

    # 2. استخراج مفاتيح الـ API (لو متسجلة في إعدادات الأداة)
    api_keys = {}
    if hasattr(ctx, "cfg") and hasattr(ctx.cfg, "keys"):
        api_keys = ctx.cfg.keys
    elif isinstance(ctx, dict) and "cfg" in ctx:
        api_keys = ctx["cfg"].get("keys", {})

    logger.info(f"=== بدء مرحلة Recon للهدف: {target} ===")
    
    # 3. تشغيل الفحص وتمرير المفاتيح
    results = discover_subdomains(target, api_keys)
    
    return {
        "subdomains": results
    }
