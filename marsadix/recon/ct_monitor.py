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


def _new_hosts_from_message(data, domain: str, seen: set) -> list:
    """
    In-scope host names in one CertStream message that were not seen before.

    Kept separate from the websocket loop so malformed messages (a list, a
    missing leaf_cert, a string where all_domains should be) can be tested
    without a live connection -- previously such a message raised inside the
    loop and triggered a reconnect.
    """
    if not isinstance(data, dict) or data.get("message_type") != "certificate_update":
        return []
    payload = data.get("data")
    leaf = payload.get("leaf_cert") if isinstance(payload, dict) else None
    domains = leaf.get("all_domains") if isinstance(leaf, dict) else None
    if not isinstance(domains, list):
        return []

    out = []
    for raw in domains:
        if not isinstance(raw, str):
            continue
        host = raw.lower().strip().lstrip("*.").rstrip(".")
        if host and (host == domain or host.endswith("." + domain)) and host not in seen:
            seen.add(host)
            out.append(host)
    return out


async def monitor_ct_logs(domain: str, output_file: Optional[str] = None):
    """Continuously monitor CT logs, reconnect iteratively, and write each host once."""
    try:
        import websockets
    except ImportError:
        logger.error("[-] The 'websockets' library is required for CT Log monitoring.")
        logger.error("[-] Install it with: pip install websockets")
        return

    domain = domain.lower().strip(".")
    if not domain:
        logger.error("[-] CT monitor requires a non-empty domain.")
        return
    logger.info("[*] Starting continuous CT Log monitoring for: *.%s (R14)", domain)
    logger.info("[*] Listening to global certificate streams... Press Ctrl+C to stop.")
    seen = set()
    if output_file:
        try:
            with open(output_file, "r", encoding="utf-8") as existing:
                seen.update(line.strip().lower().rstrip(".") for line in existing if line.strip())
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning("[-] Could not read prior CT results: %s", e)

    while True:
        try:
            async with websockets.connect(CERTSTREAM_URL, ping_interval=20, ping_timeout=20) as ws:
                while True:
                    try:
                        message = await ws.recv()
                        data = json.loads(message)
                    except json.JSONDecodeError:
                        continue
                    except asyncio.TimeoutError:
                        continue

                    for host in _new_hosts_from_message(data, domain, seen):
                        logger.info("[+] New CT asset: %s", host)
                        if output_file:
                            try:
                                with open(output_file, "a", encoding="utf-8") as f:
                                    f.write(f"{host}\n")
                            except OSError as e:
                                logger.warning("[-] Could not write CT result: %s", e)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("[-] CertStream connection lost (%s): %s", type(e).__name__, e)
            logger.info("[*] Reconnecting in 5 seconds...")
            await asyncio.sleep(5)
