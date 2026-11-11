"""
Web enumeration skills: security headers, CORS, robots.txt / sitemap.xml, directory listing.

Each skill produces BOTH:
  * findings, only where the evidence is clear (severity info / low / medium; status Detected, or
    Needs Review when the signal is partial), and
  * an inventory (client.record): what was seen, even when it is perfectly fine. The inventory is
    what lets a report say "these hosts DO send HSTS", not only "these do not".

Low traffic by design: one to a dozen GET requests per host. No payloads, no data extraction.
"""

from __future__ import annotations

import re
import secrets
from typing import List
from urllib.parse import urlsplit

from ..models import Confidence, DetectionStatus, Finding, Severity
from ..skills import registry
from .http import ProbeClient
from .skills import CANARY_DOMAIN, Target, _mk

WEB_SKILLS = {"security-headers", "cors", "robots-sitemap", "directory-listing"}


# ---------------------------------------------------------------- security headers
def _frame_protected(headers_csp: str, xfo: str) -> bool:
    return bool(xfo) or "frame-ancestors" in headers_csp.lower()


@registry.register_handler("security-headers")
def probe_security_headers(c: ProbeClient, t: Target) -> List[Finding]:
    r = c.get(t.base + "/")
    if r is None:
        return []
    https = t.base.startswith("https://")
    h = {k: (r.header(k) or "") for k in ("strict-transport-security", "content-security-policy", "x-content-type-options",
                                          "x-frame-options", "referrer-policy", "permissions-policy")}
    for name, value in h.items():
        c.record(t.host, "security_header", name, value[:160] if value else "MISSING", "security-headers")
    leaks = []
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = r.header(name) or ""
        if value:
            c.record(t.host, "banner", name, value[:160], "security-headers")
            if re.search(r"\d+\.\d+", value):
                leaks.append(f"{name}: {value[:80]}")
    out: List[Finding] = []
    if not (200 <= r.status < 400) or (r.status in (301, 302, 303, 307, 308) and not https):
        return out                                   # an error page / http->https redirect says nothing about the real policy
    missing = []
    if https and not h["strict-transport-security"]:
        missing.append("Strict-Transport-Security")
    if not h["content-security-policy"]:
        missing.append("Content-Security-Policy")
    if h["x-content-type-options"].lower() != "nosniff":
        missing.append("X-Content-Type-Options")
    if not _frame_protected(h["content-security-policy"], h["x-frame-options"]):
        missing.append("X-Frame-Options / frame-ancestors")
    if not h["referrer-policy"]:
        missing.append("Referrer-Policy")
    if missing:
        important = any(m in ("Strict-Transport-Security", "Content-Security-Policy") for m in missing)
        out.append(_mk(t, "security-headers", f"Missing security headers ({len(missing)})",
                       Severity.LOW if important else Severity.INFO, DetectionStatus.DETECTED, Confidence.CONFIRMED,
                       "The response from / did not carry: " + ", ".join(missing) + ".", "missing",
                       "response headers inspected"))
    if leaks:
        out.append(_mk(t, "security-headers", "Server software version is revealed in response headers", Severity.INFO,
                       DetectionStatus.DETECTED, Confidence.CONFIRMED, "; ".join(leaks), "version-leak",
                       "response headers inspected"))
    return out


# ------------------------------------------------------------------------- CORS
@registry.register_handler("cors")
def probe_cors(c: ProbeClient, t: Target) -> List[Finding]:
    out: List[Finding] = []
    origin = f"https://{secrets.token_hex(4)}.{CANARY_DOMAIN}"
    for label, sent in (("arbitrary origin", origin), ("null origin", "null")):
        r = c.get(t.base + "/", headers={"Origin": sent})
        if r is None:
            return out
        acao = (r.header("access-control-allow-origin") or "").strip()
        creds = (r.header("access-control-allow-credentials") or "").strip().lower() == "true"
        c.record(t.host, "cors", f"ACAO for {label}", acao or "none", "cors")
        if creds:
            c.record(t.host, "cors", f"ACAC for {label}", "true", "cors")
        if acao and acao == sent:
            out.append(_mk(t, "cors", f"CORS trusts the {label}" + (" with credentials" if creds else ""),
                           Severity.MEDIUM if creds else Severity.LOW, DetectionStatus.DETECTED, Confidence.CONFIRMED,
                           f"The server echoed the {label} in Access-Control-Allow-Origin"
                           + (" and allowed credentials." if creds else "."), label, "Origin header reflected"))
    return out


# ------------------------------------------------------------------ robots / sitemap
_SENSITIVE = re.compile(r"admin|backup|\bbak\b|private|internal|secret|config|\.git|\.env|\bdb\b|dump|staging|\btest\b|"
                        r"\bold\b|\btmp\b|passw|login|phpmyadmin|upload", re.I)
MAX_ENTRIES = 200


def _text(r) -> str:
    return r.text if r is not None and r.status == 200 and not r.is_html else ""


@registry.register_handler("robots-sitemap")
def probe_robots_sitemap(c: ProbeClient, t: Target) -> List[Finding]:
    out: List[Finding] = []
    sitemaps = []
    body = _text(c.get(t.base + "/robots.txt"))
    if body:
        paths = []
        for line in body.splitlines()[:2000]:
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if not value:
                continue
            if key in ("disallow", "allow") and len(paths) < MAX_ENTRIES:
                paths.append(value)
                c.record(t.host, "robots_path", f"{key} {value}", "", "robots-sitemap")
            elif key == "sitemap" and len(sitemaps) < 3:
                sitemaps.append(value)
        sensitive = [p for p in paths if _SENSITIVE.search(p)]
        if sensitive:
            out.append(_mk(t, "robots-sitemap", "robots.txt lists paths that look sensitive", Severity.INFO,
                           DetectionStatus.NEEDS_REVIEW, Confidence.POSSIBLE,
                           f"{len(sensitive)} of {len(paths)} rule(s), e.g. " + ", ".join(sensitive[:5])[:200]
                           + ". robots.txt is public: it advertises these paths, it does not protect them.", "robots",
                           "robots.txt read"))
    urls = []
    for candidate in sitemaps or [t.base + "/sitemap.xml"]:
        # a sitemap named by robots.txt must stay on this host
        if urlsplit(candidate).netloc not in ("", urlsplit(t.base).netloc):
            continue
        sm = _text(c.get(candidate if "://" in candidate else t.base + candidate))
        head = sm[:2000]
        if sm and ("<urlset" in head or "<sitemapindex" in head):
            found = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sm)[:MAX_ENTRIES]
            for u in found:
                urls.append(u)
                c.record(t.host, "sitemap_url", u[:300], "", "robots-sitemap")
    return out


# --------------------------------------------------------------- directory listing
LISTING_DIRS = ["/", "/images/", "/uploads/", "/files/", "/assets/", "/static/", "/backup/", "/logs/", "/tmp/", "/admin/"]
_LISTING = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /|<title>\s*Directory Listing", re.I)


def _is_listing(r) -> bool:
    return r is not None and r.status == 200 and r.is_html and bool(_LISTING.search(r.text)) \
        and len(re.findall(r"<a\s+href=", r.text, re.I)) >= 2


@registry.register_handler("directory-listing")
def probe_directory_listing(c: ProbeClient, t: Target) -> List[Finding]:
    out: List[Finding] = []
    control = c.get(t.base + f"/mx{secrets.token_hex(4)}/")
    if _is_listing(control):
        return out                                   # the server shows a listing for any path: nothing specific to report
    for path in LISTING_DIRS:
        r = c.get(t.base + path)
        if _is_listing(r):
            c.record(t.host, "directory_listing", path, "", "directory-listing")
            f = _mk(t, "directory-listing", f"Directory listing enabled at {path}", Severity.LOW, DetectionStatus.DETECTED,
                    Confidence.CONFIRMED, f"GET {path} returned an index page that lists the folder's files.", path,
                    "index page signature")
            f.url = t.base + path
            out.append(f)
    return out
