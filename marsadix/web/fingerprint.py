"""
Turn what httpx / nmap print about a technology into the fields the database
stores: name, version, CPE, category.

The CPE is what the CVE monitor matches vulnerabilities against, so a wrong one
is worse than none. cpe_for() therefore only knows a short list of products
whose NVD vendor:product pair is certain; anything else gets no CPE (nmap, for
services, supplies its own and is the authoritative source). Extend _KNOWN only
with pairs checked against the NVD CPE dictionary.
"""

import re
from typing import Optional

# lower-case product name -> (CPE vendor, CPE product, category)
_KNOWN = {
    "nginx":              ("f5", "nginx", "web-server"),
    "apache http server": ("apache", "http_server", "web-server"),
    "apache":             ("apache", "http_server", "web-server"),     # Server: Apache/2.4.58
    "iis":                ("microsoft", "internet_information_services", "web-server"),
    "microsoft-iis":      ("microsoft", "internet_information_services", "web-server"),
    "lighttpd":           ("lighttpd", "lighttpd", "web-server"),
    "apache tomcat":      ("apache", "tomcat", "web-server"),
    "tomcat":             ("apache", "tomcat", "web-server"),
    "php":                ("php", "php", "language"),
    "python":             ("python", "python", "language"),
    "node.js":            ("nodejs", "node.js", "language"),
    "openssl":            ("openssl", "openssl", "library"),
    "wordpress":          ("wordpress", "wordpress", "cms"),
    "drupal":             ("drupal", "drupal", "cms"),
    "jquery":             ("jquery", "jquery", "js-library"),
    "bootstrap":          ("getbootstrap", "bootstrap", "js-library"),
    "django":             ("djangoproject", "django", "framework"),
    "laravel":            ("laravel", "laravel", "framework"),
    "express":            ("expressjs", "express", "framework"),
    "phpmyadmin":         ("phpmyadmin", "phpmyadmin", "application"),
    "grafana":            ("grafana", "grafana", "application"),
    "jenkins":            ("jenkins", "jenkins", "application"),
    "gitlab":             ("gitlab", "gitlab", "application"),
    "varnish":            ("varnish-cache", "varnish", "cache"),
    "redis":              ("redis", "redis", "database"),
    "elasticsearch":      ("elastic", "elasticsearch", "database"),
}

# characters allowed in a CPE 2.3 version field without escaping
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9._~+-]+$")
_TECH_WITH_VERSION = re.compile(r"^(?P<name>.+):(?P<version>\d[^:\s]*)$")
_SERVER_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*)(?:/([A-Za-z0-9_.+~-]+))?")


def category_for(name: str) -> Optional[str]:
    known = _KNOWN.get(name.strip().lower())
    return known[2] if known else None


def cpe_for(name: str, version: Optional[str] = None) -> Optional[str]:
    """CPE 2.3 for a well-known product, else None. A missing version becomes '*'."""
    known = _KNOWN.get(name.strip().lower())
    if not known:
        return None
    vendor, product, _ = known
    v = (version or "").strip()
    if not v or not _SAFE_VERSION.match(v):
        v = "*"
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def parse_tech(items) -> list[tuple[str, Optional[str]]]:
    """
    httpx prints technologies as "Name" or "Name:version" ("Python:3.12.3").
    Only a part after the LAST colon that starts with a digit is a version, so
    a name that merely contains a colon is not cut in half.
    """
    out = []
    for raw in items or []:
        raw = str(raw).strip()
        if not raw:
            continue
        m = _TECH_WITH_VERSION.match(raw)
        out.append((m["name"].strip(), m["version"]) if m else (raw, None))
    return out


def parse_server_header(value: Optional[str]) -> list[tuple[str, Optional[str]]]:
    """
    "nginx/1.18.0 (Ubuntu)"           -> [("nginx", "1.18.0")]
    "SimpleHTTP/0.6 Python/3.12.3"    -> [("SimpleHTTP", "0.6"), ("Python", "3.12.3")]
    Text in parentheses (usually the OS or modules) is dropped.
    """
    if not value:
        return []
    cleaned = re.sub(r"\([^)]*\)", " ", value)
    return [(m.group(1), m.group(2)) for m in _SERVER_TOKEN.finditer(cleaned)]


def merge_technologies(*groups) -> list[tuple[str, Optional[str]]]:
    """Combine lists of (name, version), dropping repeats (name compared case-insensitively)."""
    seen, out = set(), []
    for group in groups:
        for name, version in group:
            key = (name.strip().lower(), version or "")
            if key not in seen:
                seen.add(key)
                out.append((name.strip(), version))
    return out


def normalize_cpe(cpe: Optional[str]) -> Optional[str]:
    """nmap prints CPE 2.2 URIs ("cpe:/a:python:simplehttpserver:0.6"); store CPE 2.3."""
    if not cpe:
        return None
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return None
    parts = [p or "*" for p in cpe[len("cpe:/"):].split(":")]
    parts += ["*"] * (11 - len(parts))
    return "cpe:2.3:" + ":".join(parts[:11])
