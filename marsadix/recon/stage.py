import logging
from .discovery import discover_subdomains

logger = logging.getLogger(__name__)

def run(target: str, cfg: dict, **kwargs) -> dict:
    """
    نقطة الدخول (Entry Point) الرسمية لمرحلة الـ Recon
    التي يبحث عنها الـ Pipeline الأساسي للمشروع.
    """
    logger.info(f"=== بدء مرحلة Recon للهدف: {target} ===")
    
    # استدعاء دالة اكتشاف النطاقات اللي جهزناها
    results = discover_subdomains(target)
    
    # إرجاع النتائج في قاموس (Dictionary) عشان باقي المراحل (Web, ASM) تستخدمها
    return {
        "subdomains": results
    }
