"""
R6: DNS bruteforce (puredns) with wildcard filtering.

puredns does the heavy lifting (massdns under the hood) and filters wildcard
answers itself. If puredns/massdns isn't installed, the wordlist is turned
into plain candidates (word.domain) and handed back to resolver.py (R7),
whose own wildcard filter drops generated names that only resolve to a
wildcard IP - so the feature degrades instead of disappearing.

Like R5, this sends DNS traffic, so stage.py only runs it when the scan mode
allows it. Source names: "puredns" (the real tool) or "wordlist" (fallback).
"""

import logging
import os
import re
import tempfile
from typing import List, Optional, Set, Tuple

from ._proc import run_async

logger = logging.getLogger(__name__)

PUREDNS_TIMEOUT = 900
MAX_WORDS = 100000

# Small built-in list so the feature works out of the box; point
# `bruteforce_wordlist` in the config at a real list (e.g. SecLists
# subdomains-top1million) for serious runs.
DEFAULT_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1",
    "host", "support", "dev", "web", "mx", "email", "cloud",
    "forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api", "exchange",
    "app", "vps", "news",
    "staging", "stage", "stg", "uat", "qa", "prod", "preprod", "beta", "demo",
    "sandbox", "internal", "intranet", "git", "gitlab", "jenkins", "ci", "jira",
    "wiki", "docs", "status", "monitor", "grafana", "kibana", "elastic", "db",
    "mysql", "sql", "redis", "backup", "old", "new", "static", "assets", "img",
    "images", "media", "files", "upload", "download", "auth", "login", "sso",
    "id", "accounts", "account", "billing", "pay", "payment", "crm", "erp",
    "hr", "dashboard", "panel", "cpanel", "whm", "autodiscover", "lyncdiscover",
    "sip", "meet", "chat", "video", "mobile", "ios", "android", "v1", "v2",
]

# Public resolvers - fine for a smoke test. For real bruteforce runs give
# `resolvers_file` a large, freshly validated resolver list instead.
DEFAULT_RESOLVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"]

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def load_wordlist(path: Optional[str]) -> List[str]:
    if path:
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                words = []
                seen = set()
                for line in fh:
                    w = line.strip().lower()
                    if w and w not in seen and _LABEL_RE.match(w):
                        seen.add(w)
                        words.append(w)
                        if len(words) >= MAX_WORDS:
                            break
            if words:
                return words
            logger.warning(f"[-] Wordlist {path} had no usable entries - using the built-in list.")
        except OSError as e:
            logger.warning(f"[-] Could not read wordlist {path} ({e}) - using the built-in list.")
    return list(DEFAULT_WORDLIST)


async def bruteforce_subdomains(domain: str, wordlist_path: Optional[str] = None,
                                resolvers_path: Optional[str] = None,
                                rate_limit: Optional[int] = None,
                                timeout: int = PUREDNS_TIMEOUT) -> Tuple[Set[str], str]:
    """
    Returns (hosts, engine).
      engine == "puredns": hosts are already resolved and wildcard-filtered.
      engine == "wordlist": hosts are UNRESOLVED candidates - resolver.py must
                            resolve and wildcard-filter them.
    """
    domain = domain.lower().strip(".")
    words = load_wordlist(wordlist_path)
    logger.info(f"[*] DNS bruteforce with {len(words)} word(s) (R6)...")

    with tempfile.TemporaryDirectory() as tmp:
        wl_file = os.path.join(tmp, "words.txt")
        with open(wl_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(words) + "\n")

        if resolvers_path and os.path.isfile(resolvers_path):
            res_file = resolvers_path
        else:
            res_file = os.path.join(tmp, "resolvers.txt")
            with open(res_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(DEFAULT_RESOLVERS) + "\n")
            logger.info("[-] No resolvers_file configured - using a few public resolvers (slow; "
                        "use a validated resolver list for big wordlists).")

        cmd = ["puredns", "bruteforce", wl_file, domain, "-r", res_file, "-q"]
        if rate_limit:
            cmd += ["--rate-limit", str(int(rate_limit))]
        out = await run_async(cmd, timeout=timeout, name="puredns")

    if out is None:
        logger.info("[-] puredns unavailable - falling back to resolver-based wordlist check.")
        return {f"{w}.{domain}" for w in words}, "wordlist"

    hosts = {line.strip().lower() for line in out.splitlines()
             if line.strip().lower().endswith("." + domain)}
    logger.info(f"[+] puredns found {len(hosts)} subdomain(s) (wildcards filtered).")
    return hosts, "puredns"
