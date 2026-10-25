"""
Thin async wrappers around httpx and katana.

Both tools send traffic to the target. `rate_limit` (requests per second) is
passed straight to their `-rl` flag. It matters more than it looks: without it
httpx and katana both default to 150 requests/second, far more than the
config.toml / --rate value the user asked for would suggest, and enough to
knock over a small server. (Flags checked against httpx v1.12 and katana v1.8.)

What to expect from the number: it is the tools' own limiter, so it is an
AVERAGE. Measured against a local server with -rl 5, the busiest 1-second
window still saw 9-10 requests (about 2x), while without the flag the same run
peaked at 30-36 req/s. Treat --rate as "about N per second, short bursts up to
roughly 2N", and pick a lower number for fragile targets.
"""

import asyncio
import json
import logging
from typing import List, Optional, Set

logger = logging.getLogger(__name__)


def _rate_args(rate_limit: Optional[int]) -> List[str]:
    return ["-rl", str(int(rate_limit))] if rate_limit else []


async def run_httpx(domains: List[str], rate_limit: Optional[int] = None) -> List[dict]:
    """
    Probe hosts with httpx (-td technology detection, -server header; CDN
    detection is on by default). Returns one record per live web server:

        {"url": "https://a.example.com", "input": "a.example.com", "status_code": 200,
         "ip": "93.184.216.34", "webserver": "nginx/1.18.0", "tech": ["Nginx:1.18.0", "PHP"],
         "cdn": False, "cdn_name": None}

    status_code is None when httpx did not report an integer.
    """
    if not domains:
        return []

    logger.info("[*] Running httpx on %d host(s) (rate limit: %s req/s)...",
                len(domains), rate_limit or "tool default")
    input_data = "\n".join(domains).encode()
    live: List[dict] = []

    try:
        process = await asyncio.create_subprocess_exec(
            "httpx", "-silent", "-json", "-td", "-server", *_rate_args(rate_limit),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate(input=input_data)

        for line in stdout.decode(errors="replace").splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            if not isinstance(data, dict) or not data.get("url") or data.get("failed"):
                continue
            status = data.get("status_code")
            addresses = data.get("a") if isinstance(data.get("a"), list) else []
            live.append({
                "url": data["url"],
                "input": str(data.get("input") or "").strip().lower() or None,
                "status_code": status if isinstance(status, int) else None,
                "ip": data.get("host_ip") or (addresses[0] if addresses else None),
                "webserver": data.get("webserver") or None,
                "tech": [str(t) for t in data.get("tech") or []],
                "cdn": bool(data.get("cdn")),
                "cdn_name": data.get("cdn_name") or None,
            })

        logger.info("[+] httpx found %d live web servers.", len(live))
    except Exception as e:
        logger.error("[-] httpx failed: %s", e)

    return live


async def run_katana(urls: List[str], rate_limit: Optional[int] = None) -> List[str]:
    """Crawl live URLs with katana (JS parsing on, depth 2). Returns unique URLs found."""
    if not urls:
        return []

    logger.info("[*] Running katana on %d live URL(s) (rate limit: %s req/s)...",
                len(urls), rate_limit or "tool default")
    input_data = "\n".join(urls).encode()
    endpoints: Set[str] = set()

    try:
        process = await asyncio.create_subprocess_exec(
            "katana", "-silent", "-jc", "-d", "2", *_rate_args(rate_limit),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate(input=input_data)

        for line in stdout.decode(errors="replace").splitlines():
            url = line.strip()
            if url:
                endpoints.add(url)

        logger.info("[+] Katana extracted %d unique endpoints/URLs.", len(endpoints))
    except Exception as e:
        logger.error("[-] Katana failed: %s", e)

    return sorted(endpoints)
