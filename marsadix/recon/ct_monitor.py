"""
R14: Continuous CT Logs Monitoring (Certificate Transparency).
Connects to the live CertStream websocket to monitor for newly issued
SSL/TLS certificates in real-time. This is how you catch zero-days.
"""
import asyncio
import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Source is configurable from .env (CERTSTREAM_URL). Default: a local certstream-server-go.
CERTSTREAM_URL = os.environ.get("CERTSTREAM_URL", "ws://localhost:8080/")
MAX_CONNECT_FAILURES = 5   # stop after this many failed connections in a row instead of retrying forever


class BoundedSeen:
    """
    A set that remembers only the newest `maxlen` hosts. The CT monitor runs for
    days; an unbounded set of every host ever seen grows until the process dies.
    An evicted host that shows up again is simply reported again (harmless).
    """

    def __init__(self, maxlen: int = 200_000):
        from collections import OrderedDict
        self._d = OrderedDict()
        self.maxlen = maxlen

    def __contains__(self, host) -> bool:
        return host in self._d

    def __len__(self) -> int:
        return len(self._d)

    def add(self, host) -> None:
        self._d[host] = None
        self._d.move_to_end(host)
        while len(self._d) > self.maxlen:
            self._d.popitem(last=False)

    def update(self, hosts) -> None:
        for h in hosts:
            self.add(h)


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


async def _alert_new_host(host: str) -> None:
    """Instant Discord + Telegram alert. Runs in a thread so the websocket is never blocked; never raises."""
    try:
        from ..alerts.asset_alerts import notify_asset
        await asyncio.to_thread(notify_asset, "new_asset", host, "Found via Certificate Transparency logs")
    except Exception as e:
        logger.warning("[-] Could not send CT alert for %s: %s", host, e)


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
    seen = BoundedSeen()
    failures = 0
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
                failures = 0
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
                        await _alert_new_host(host)
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
            failures += 1
            if failures >= MAX_CONNECT_FAILURES:
                logger.error("[-] CT source %s unreachable after %d attempts. Stopping CT monitor. "
                             "Check the source or set CERTSTREAM_URL in .env.", CERTSTREAM_URL, failures)
                return
            logger.info("[*] Reconnecting in 5 seconds (attempt %d/%d)...", failures, MAX_CONNECT_FAILURES)
            await asyncio.sleep(5)
