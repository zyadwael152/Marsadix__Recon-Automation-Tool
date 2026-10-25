"""
R14: Continuous CT Logs Monitoring (Certificate Transparency).
Connects to the live CertStream websocket to monitor for newly issued
SSL/TLS certificates in real-time. This is how you catch zero-days.
"""
import asyncio
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

CERTSTREAM_URL = "wss://certstream.calidog.io/"

async def monitor_ct_logs(domain: str, output_file: Optional[str] = None):
    """
    Runs continuously, listening for new certificates matching `domain`.
    Requires `websockets` library: pip install websockets
    """
    try:
        import websockets
    except ImportError:
        logger.error("[-] The 'websockets' library is required for CT Log monitoring.")
        logger.error("[-] Install it with: pip install websockets")
        return

    domain = domain.lower().strip(".")
    logger.info(f"[*] Starting continuous CT Log monitoring for: *.{domain} (R14)")
    logger.info("[*] Listening to global certificate streams... Press Ctrl+C to stop.")

    try:
        async with websockets.connect(CERTSTREAM_URL, ping_interval=20, ping_timeout=20) as ws:
            while True:
                try:
                    message = await ws.recv()
                    data = json.loads(message)
                    
                    if data.get("message_type") == "heartbeat":
                        continue
                        
                    if data.get("message_type") == "certificate_update":
                        all_domains = data["data"]["leaf_cert"]["all_domains"]
                        
                        for cert_domain in all_domains:
                            cert_domain = cert_domain.lower()
                            # فلترة الدومينات عشان نجيب التارجت بتاعنا بس
                            if cert_domain.endswith(f".{domain}") or cert_domain == domain:
                                
                                # تنبيه لحظي عند اكتشاف دومين جديد!
                                logger.info(f" [!!!] ZERO-DAY ASSET DETECTED: {cert_domain}")
                                
                                # حفظ الدومين في ملف عشان نفحصه بعدين
                                if output_file:
                                    with open(output_file, "a", encoding="utf-8") as f:
                                        f.write(f"{cert_domain}\n")
                                        
                except json.JSONDecodeError:
                    continue
                except asyncio.TimeoutError:
                    continue
                    
    except Exception as e:
        logger.error(f"[-] CertStream connection lost: {e}")
        logger.info("[*] Reconnecting in 5 seconds...")
        await asyncio.sleep(5)
        await monitor_ct_logs(domain, output_file)
