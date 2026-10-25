"""
R9: CDN / ASN detection.

For each resolved IP, looks up its Autonomous System (ASN) and owner name
via Team Cymru's WHOIS service (whois.cymru.com, port 43) - one bulk TCP
query for every IP at once. Pure stdlib `socket`, no new dependency: this
project deliberately keeps pyproject.toml's `dependencies = []` empty
unless something stdlib genuinely can't do, and a single WHOIS query can.

This is a passive lookup against a third-party service (same category as
crt.sh / VirusTotal) - it never sends traffic to the target itself, so it
runs in every scan mode, including passive.

CDN detection is then a simple name match against known CDN/cloud-proxy
ASN owners (Cloudflare, Akamai, Fastly, CloudFront, Google, Azure...) -
good enough for "is this probably behind a CDN", which is what R10 will
need to exclude CDN IPs from port scanning.
"""

import asyncio
import logging
import socket
from typing import Dict, Iterable

logger = logging.getLogger(__name__)

CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
LOOKUP_TIMEOUT = 20  # seconds for the whole bulk query

# Substring match against the ASN owner / AS name (lowercase).
KNOWN_CDN_MARKERS = [
    "cloudflare", "akamai", "fastly", "amazon", "cloudfront", "incapsula",
    "imperva", "sucuri", "stackpath", "edgecast", "google", "azure",
    "microsoft", "limelight", "cdn77", "keycdn", "bunny", "maxcdn",
]


def _is_cdn(owner: str) -> bool:
    owner_lower = (owner or "").lower()
    return any(marker in owner_lower for marker in KNOWN_CDN_MARKERS)


def _bulk_cymru_query(ips: Iterable[str]) -> Dict[str, dict]:
    """Blocking socket call - run via loop.run_in_executor from async code."""
    ips = list(dict.fromkeys(ips))  # dedupe, keep order
    if not ips:
        return {}

    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    result: Dict[str, dict] = {}

    try:
        with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=LOOKUP_TIMEOUT) as sock:
            sock.sendall(query.encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        raw = b"".join(chunks).decode(errors="replace")
    except Exception as e:
        logger.warning(f"[-] CDN/ASN lookup (Team Cymru) failed: {e}")
        return {}

    # Each line: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip = parts[0], parts[1]
        as_name = parts[6]
        if asn in ("AS", "") or ip == "IP":  # header row
            continue
        result[ip] = {"asn": f"AS{asn}" if asn.isdigit() else asn, "asn_owner": as_name}

    return result


async def lookup_cdn_asn(ips: Iterable[str]) -> Dict[str, dict]:
    """
    {ip: {"asn": "AS13335", "asn_owner": "CLOUDFLARENET", "is_cdn": True}}
    An IP missing from the result means the lookup failed or returned no
    data for it - callers should treat that as "unknown", not "not a CDN".
    """
    ips = list(ips)
    if not ips:
        return {}

    logger.info(f"[*] Looking up ASN/CDN for {len(ips)} unique IP(s)...")
    loop = asyncio.get_event_loop()
    try:
        raw = await asyncio.wait_for(
            loop.run_in_executor(None, _bulk_cymru_query, ips), timeout=LOOKUP_TIMEOUT + 5)
    except asyncio.TimeoutError:
        logger.warning(f"[-] CDN/ASN lookup timed out after {LOOKUP_TIMEOUT}s.")
        return {}

    for info in raw.values():
        info["is_cdn"] = _is_cdn(info.get("asn_owner", ""))

    cdn_count = sum(1 for i in raw.values() if i["is_cdn"])
    logger.info(f"[+] ASN/CDN lookup done: {len(raw)} IP(s) resolved, {cdn_count} behind a known CDN.")
    return raw
