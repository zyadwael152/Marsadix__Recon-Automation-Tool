"""
R8: HTTP liveness + technology detection (httpx).

One httpx pass answers three questions at once: is the host alive over HTTP
(feeds the R4 confidence score), what does it respond with (status/title/
server), and what technologies are running (`-tech-detect`, later used for
CPE mapping / CVE correlation). Doing it once avoids probing every host twice.

Redirects are deliberately NOT followed: a redirect can point outside the
authorized scope, and httpx would happily go there.

This sends traffic to the target - stage.py only calls it when the scan mode
allows it (ctx.allows("standard")) and only for in-scope hosts.
"""

import json
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ._proc import run_async

logger = logging.getLogger(__name__)

HTTPX_TIMEOUT = 300


def split_tech(entry: str) -> Tuple[str, Optional[str]]:
    """httpx reports technologies as "Nginx" or "PHP:7.4.3" -> (name, version)."""
    name, _, version = entry.partition(":")
    return name.strip(), (version.strip() or None)


def _clean_host(value: str) -> str:
    value = (value or "").strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    return value.split("/", 1)[0].split(":", 1)[0]


def parse_httpx_json(text: str) -> Dict[str, dict]:
    """
    {host: {"url", "status_code", "title", "webserver", "tech": [(name, version)]}}
    `input` is the host we asked about (in httpx JSON, `host` is the IP).
    Lines that aren't JSON (e.g. the pip `httpx` CLI by mistake) are ignored.
    """
    out: Dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        host = _clean_host(data.get("input") or data.get("url") or "")
        if not host:
            continue

        entry = out.setdefault(host, {"url": data.get("url"), "status_code": None,
                                      "title": None, "webserver": None, "tech": []})
        status = data.get("status_code", data.get("status-code"))
        if entry["status_code"] is None:
            entry["status_code"] = status
        entry["title"] = entry["title"] or data.get("title")
        entry["webserver"] = entry["webserver"] or data.get("webserver")
        for raw in data.get("tech") or []:
            tech = split_tech(raw)
            if tech[0] and tech not in entry["tech"]:
                entry["tech"].append(tech)
    return out


async def probe_web(hosts: List[str], rate_limit: Optional[int] = None,
                    timeout: int = HTTPX_TIMEOUT) -> Dict[str, dict]:
    """Returns {} when httpx is missing, times out, or finds nothing."""
    if not hosts:
        return {}
    logger.info(f"[*] Probing {len(hosts)} host(s) with httpx (liveness + technologies, R8)...")
    cmd = ["httpx", "-silent", "-json", "-tech-detect", "-title", "-status-code",
           "-web-server", "-timeout", "10", "-retries", "1"]
    if rate_limit:
        cmd += ["-rl", str(int(rate_limit))]
    out = await run_async(cmd, stdin_lines=hosts, timeout=timeout, name="httpx")
    if out is None:
        return {}
    results = parse_httpx_json(out)
    tech_total = sum(len(v["tech"]) for v in results.values())
    logger.info(f"[+] {len(results)} host(s) responded over HTTP, {tech_total} technology hit(s).")
    return results
