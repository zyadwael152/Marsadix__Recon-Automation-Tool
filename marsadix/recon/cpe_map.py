"""
R13: Technology to CPE (Common Platform Enumeration) Mapping.
Converts standard tech names (from httpx/wappalyzer) into CPE URIs.
Crucial for automating CVE lookups later.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# قاموس تحويل لأشهر التقنيات. 
# الصيغة: "tech_name_lowercase": ("vendor", "product", "part")
# part: 'a' (application), 'o' (os), 'h' (hardware)
CPE_DICTIONARY = {
    "wordpress": ("wordpress", "wordpress", "a"),
    "nginx": ("f5", "nginx", "a"),
    "apache": ("apache", "http_server", "a"),
    "php": ("php", "php", "a"),
    "mysql": ("oracle", "mysql", "a"),
    "openssh": ("openbsd", "openssh", "a"),
    "react": ("facebook", "react", "a"),
    "node.js": ("nodejs", "node.js", "a"),
    "express": ("expressjs", "express", "a"),
    "jquery": ("jquery", "jquery", "a"),
    "bootstrap": ("getbootstrap", "bootstrap", "a"),
    "cloudflare": ("cloudflare", "cloudflare", "a"),
    "ubuntu": ("canonical", "ubuntu_linux", "o"),
    "windows server": ("microsoft", "windows_server", "o"),
    "tomcat": ("apache", "tomcat", "a"),
    "drupal": ("drupal", "drupal", "a"),
    "magento": ("magento", "magento", "a")
}

def generate_cpe(tech_name: str, version: Optional[str] = None) -> Optional[str]:
    """
    يحول اسم التقنية لـ CPE 2.2 URI القياسي
    مثال: Nginx 1.18 -> cpe:/a:f5:nginx:1.18
    """
    if not tech_name:
        return None
        
    tech_lower = tech_name.strip().lower()
    
    # لو التقنية متعرفة في القاموس بتاعنا
    if tech_lower in CPE_DICTIONARY:
        vendor, product, part = CPE_DICTIONARY[tech_lower]
    else:
        # CPE identifiers must come from a curated mapping or trusted detector.
        # Guessing vendor/product from display text creates false CVE matches.
        logger.debug("No curated CPE mapping for technology %r; leaving CPE unset", tech_name)
        return None

    # In CPE, '*' means any version; '-' means not applicable, not unknown.
    ver_str = version.strip() if version and version.strip() else "*"
    
    return f"cpe:/{part}:{vendor}:{product}:{ver_str}"
