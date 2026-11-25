"""
version_detect.py — Technology Version Detection Engine
========================================================
Module مستقل يكتشف الـ technology وversion لأي target.

الاستخدام:
    from marsadix.asm.version_detect import VersionDetector, detect

    # طريقة 1: سريعة
    results = detect("https://example.com")
    for tech in results:
        print(tech.name, tech.version, tech.confidence)

    # طريقة 2: تحكم كامل
    d = VersionDetector("https://example.com")
    results = d.run()

الـ integration مع cve_verify.py:
    from marsadix.asm.version_detect import detect
    techs = detect(url)
    version = next((t.version for t in techs if t.name == "brotli"), None)
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import http.client
import json
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TechMatch:
    """تقنية واحدة اتكشفت مع كل التفاصيل."""
    name: str                        # "nodejs", "nginx", "php", ...
    version: Optional[str] = None   # "20.11.0" أو None
    confidence: int = 0             # 0-100
    method: str = ""                # "header:server", "endpoint:/version", ...
    raw: str = ""                   # القيمة الخام اللي لقيناها
    category: str = ""              # "runtime", "webserver", "framework", "library"


@dataclass
class DetectionResult:
    """نتيجة الـ detection لـ target واحد."""
    url: str
    host: str
    technologies: List[TechMatch] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def get(self, name: str) -> Optional[TechMatch]:
        """جيب أعلى confidence match لاسم معين."""
        matches = [t for t in self.technologies if t.name.lower() == name.lower()]
        return max(matches, key=lambda t: t.confidence) if matches else None

    def version_of(self, name: str) -> Optional[str]:
        m = self.get(name)
        return m.version if m else None


# ---------------------------------------------------------------------------
# Fingerprint patterns — قاموس شامل للـ patterns
# ---------------------------------------------------------------------------

# كل entry: (pattern, tech_name, version_group, confidence, category)
# version_group: رقم الـ group اللي فيه الـ version، أو None لو مفيش version
HEADER_PATTERNS: List[Tuple] = [
    # Web Servers
    (r"nginx[/\s](\d+\.\d+(?:\.\d+)?)",          "nginx",      1, 90, "webserver"),
    (r"nginx",                                      "nginx",   None, 60, "webserver"),
    (r"Apache[/\s](\d+\.\d+(?:\.\d+)?)",          "apache",     1, 90, "webserver"),
    (r"Apache",                                     "apache",  None, 60, "webserver"),
    (r"Microsoft-IIS[/\s](\d+\.\d+)",             "iis",        1, 90, "webserver"),
    (r"cloudflare",                                 "cloudflare",None,70, "cdn"),
    (r"railway-(?:edge|hikari)",                    "railway",  None, 85, "infrastructure"),
    (r"AmazonS3",                                   "s3",       None, 85, "storage"),
    (r"awselb",                                     "aws-elb",  None, 70, "infrastructure"),
    (r"Caddy[/\s](\d+\.\d+(?:\.\d+)?)",           "caddy",      1, 90, "webserver"),

    # Runtimes
    (r"[Nn]ode[./ ]v?(\d+\.\d+\.\d+)",            "nodejs",     1, 90, "runtime"),
    (r"[Pp]ython[/\s](\d+\.\d+(?:\.\d+)?)",       "python",     1, 90, "runtime"),
    (r"[Pp]HP[/\s](\d+\.\d+(?:\.\d+)?)",          "php",        1, 90, "runtime"),
    (r"[Jj]ava[/\s](\d+\.\d+(?:\.\d+)?)",         "java",       1, 85, "runtime"),
    (r"Ruby[/\s](\d+\.\d+(?:\.\d+)?)",            "ruby",       1, 90, "runtime"),
    (r"Golang[/\s](\d+\.\d+(?:\.\d+)?)",          "golang",     1, 90, "runtime"),
    (r"Go-http-client[/\s](\d+\.\d+)",            "golang",     1, 70, "runtime"),
    (r"Werkzeug[/\s](\d+\.\d+(?:\.\d+)?)",        "werkzeug",   1, 85, "framework"),
    (r"gunicorn[/\s](\d+\.\d+(?:\.\d+)?)",        "gunicorn",   1, 85, "runtime"),

    # Frameworks
    (r"Express",                                    "express",  None, 65, "framework"),
    (r"Laravel",                                    "laravel",  None, 65, "framework"),
    (r"Django[/\s](\d+\.\d+(?:\.\d+)?)",          "django",     1, 85, "framework"),
    (r"Rails[/\s](\d+\.\d+(?:\.\d+)?)",           "rails",      1, 85, "framework"),
    (r"Spring[/\s](\d+\.\d+(?:\.\d+)?)",          "spring",     1, 85, "framework"),
    (r"ASP\.NET[/\s](\d+\.\d+(?:\.\d+)?)",        "aspnet",     1, 85, "framework"),
    (r"Next\.js",                                   "nextjs",   None, 65, "framework"),
    (r"Nuxt",                                       "nuxt",     None, 65, "framework"),

    # Libraries
    (r"OpenSSL[/\s](\d+\.\d+(?:\.\d+)?)",         "openssl",    1, 90, "library"),
    (r"LibreSSL[/\s](\d+\.\d+(?:\.\d+)?)",        "libressl",   1, 90, "library"),
    (r"Brotli[/\s](\d+\.\d+(?:\.\d+)?)",          "brotli",     1, 90, "library"),
]

# Headers المهمة اللي نفحصها
TARGET_HEADERS = [
    "server", "x-powered-by", "x-runtime", "x-generator",
    "x-drupal-cache", "x-laravel-cache", "x-nextjs-page",
    "x-frame-options", "via", "x-aspnet-version",
    "x-aspnetmvc-version", "x-cf-powered-by",
]

# Endpoints للـ version discovery
VERSION_ENDPOINTS: List[Tuple[str, str]] = [
    # (path, description)
    ("/version",              "version endpoint"),
    ("/_version",             "version endpoint"),
    ("/api/version",          "API version"),
    ("/api/v1/version",       "API v1 version"),
    ("/health",               "health endpoint"),
    ("/_health",              "health endpoint"),
    ("/api/health",           "API health"),
    ("/status",               "status endpoint"),
    ("/api/status",           "API status"),
    ("/info",                 "info endpoint"),
    ("/api/info",             "API info"),
    ("/metrics",              "metrics endpoint"),
    ("/__version__",          "dunder version"),
    ("/actuator/info",        "Spring Boot actuator"),
    ("/actuator/health",      "Spring Boot health"),
    ("/debug/vars",           "Go expvar"),
    ("/debug/pprof/",         "Go pprof"),
    ("/robots.txt",           "robots.txt"),
    ("/package.json",         "package.json (should be blocked)"),
    ("/composer.json",        "composer.json (should be blocked)"),
    ("/Gemfile",              "Gemfile (should be blocked)"),
    ("/wp-login.php",         "WordPress login"),
    ("/wp-json/wp/v2/",       "WordPress REST API"),
    ("/xmlrpc.php",           "WordPress XML-RPC"),
    ("/administrator/",       "Joomla admin"),
    ("/phpmyadmin/",          "phpMyAdmin"),
    ("/adminer.php",          "Adminer"),
]

# JSON patterns للـ response body
JSON_VERSION_PATTERNS: List[Tuple[str, str, str]] = [
    # (pattern, tech_name, category)
    (r'"node(?:Version|_version)"\s*:\s*"v?(\d+\.\d+\.\d+)"',  "nodejs",  "runtime"),
    (r'"node"\s*:\s*"v?(\d+\.\d+\.\d+)"',                       "nodejs",  "runtime"),
    (r'"python"\s*:\s*"(\d+\.\d+\.\d+)"',                       "python",  "runtime"),
    (r'"php"\s*:\s*"(\d+\.\d+\.\d+)"',                          "php",     "runtime"),
    (r'"ruby"\s*:\s*"(\d+\.\d+\.\d+)"',                         "ruby",    "runtime"),
    (r'"go(?:lang)?"\s*:\s*"(\d+\.\d+\.\d+)"',                  "golang",  "runtime"),
    (r'"java"\s*:\s*"(\d+\.\d+\.\d+)"',                         "java",    "runtime"),
    (r'"brotli"\s*:\s*"(\d+\.\d+\.\d+)"',                       "brotli",  "library"),
    (r'"openssl"\s*:\s*"(\d+\.\d+\.\d+)"',                      "openssl", "library"),
    (r'"version"\s*:\s*"v?(\d+\.\d+(?:\.\d+)?)"',               "app",     "application"),
    (r'"app(?:Version|_version)"\s*:\s*"v?(\d+\.\d+(?:\.\d+)?)"',"app",   "application"),
    (r'"runtime"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"',                 "runtime", "runtime"),
    (r'"framework(?:Version)?"\s*:\s*"v?(\d+\.\d+(?:\.\d+)?)"', "framework","framework"),
    # Spring Boot
    (r'"build"\s*:\s*\{[^}]*"version"\s*:\s*"(\d+\.\d+\.\d+)"',"spring",  "framework"),
    # Django / Python
    (r'Django/(\d+\.\d+(?:\.\d+)?)',                             "django",  "framework"),
    (r'Python/(\d+\.\d+(?:\.\d+)?)',                             "python",  "runtime"),
]

# SSH banner patterns
SSH_BANNER_PATTERNS: List[Tuple[str, str, Optional[int], int, str]] = [
    # (pattern, tech_name, version_group, confidence, category)
    (r"SSH-2\.0-OpenSSH[_/](\d+\.\d+(?:p\d+)?)",  "openssh", 1, 95, "service"),
    (r"SSH-2\.0-Go\b",                               "golang",  None, 85, "runtime"),
    (r"SSH-2\.0-Go[_/](\d+\.\d+(?:\.\d+)?)",        "golang",  1, 90, "runtime"),
    (r"SSH-2\.0-libssh[_/](\d+\.\d+\.\d+)",         "libssh",  1, 90, "library"),
    (r"SSH-2\.0-Dropbear[_/](\d+\.\d+)",            "dropbear",1, 90, "service"),
    (r"SSH-2\.0-ROSSSH",                             "rosssh",  None, 80, "service"),
    (r"SSH-2\.0-PuTTY[_/](\d+\.\d+)",               "putty",   1, 85, "client"),
]

# FTP banner patterns
FTP_BANNER_PATTERNS: List[Tuple[str, str, Optional[int], int, str]] = [
    (r"vsFTPd (\d+\.\d+\.\d+)",                     "vsftpd",  1, 90, "service"),
    (r"FileZilla Server (\d+\.\d+\.\d+)",            "filezilla",1,90, "service"),
    (r"ProFTPD (\d+\.\d+\.\d+)",                     "proftpd", 1, 90, "service"),
    (r"Pure-FTPd",                                    "pureftpd",None,70,"service"),
]

# TLS/Certificate patterns
TLS_PATTERNS: List[Tuple[str, str, Optional[int], int, str]] = [
    (r"Let's Encrypt",                               "letsencrypt",None,80,"tls"),
    (r"DigiCert",                                    "digicert",None, 70, "tls"),
    (r"Cloudflare",                                  "cloudflare",None,75,"cdn"),
]

# Favicon hashes → known technology
FAVICON_HASHES: Dict[str, Tuple[str, str]] = {
    # md5(favicon) → (tech_name, version_or_None)
    "f7e3d33f4a5a21ae5b17a73e0b87c40c": ("wordpress", None),
    "1f6f2731a3c48ea60a4c5b48f0f33d02": ("drupal",    None),
    "78d05d4a24d08b8c50ad98c1c95e879d": ("joomla",    None),
    "84628b4a1ab98f9f754c0cf08e4c94f8": ("jenkins",   None),
    "116f4915e0e7ba95fb0d5b97f2bceb45": ("grafana",   None),
    "0944de58acbff73d5d3fde8f8484c5d6": ("gitlab",    None),
}

# Content-Type → technology hints
CONTENT_TYPE_HINTS: Dict[str, str] = {
    "application/json":             "api",
    "text/x-json":                  "api",
    "application/vnd.api+json":     "jsonapi",
}

# ---------------------------------------------------------------------------
# HTTP client helper
# ---------------------------------------------------------------------------

def _http_get(host: str, port: int, path: str,
              tls: bool, timeout: float = 8.0,
              accept_encoding: str = "gzip, deflate",
              extra_headers: Optional[Dict[str, str]] = None) -> Optional[Tuple]:
    """
    Returns (status, headers_dict_lowercase, body_bytes) or None.
    """
    try:
        ctx = None
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        ConnCls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
        conn_kwargs = {"timeout": timeout}
        if tls:
            conn_kwargs["context"] = ctx
        conn = ConnCls(host, port, **conn_kwargs)

        hdrs = {
            "Host": host,
            "User-Agent": "Marsadix/2.0 (authorized security assessment)",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": accept_encoding,
            "Connection": "close",
        }
        if extra_headers:
            hdrs.update(extra_headers)

        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        resp_hdrs = {k.lower().strip(): v.strip() for k, v in resp.getheaders()}
        body = resp.read(32768)   # max 32KB
        return (resp.status, resp_hdrs, body)

    except Exception as exc:
        logger.debug("HTTP GET %s:%d%s → %s", host, port, path, exc)
        return None


def _banner_grab(host: str, port: int, timeout: float = 6.0,
                  send: bytes = b"") -> Optional[bytes]:
    """Plain TCP banner grab."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if send:
            sock.sendall(send)
        data = b""
        while len(data) < 1024:
            chunk = sock.recv(256)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        sock.close()
        return data
    except Exception as exc:
        logger.debug("Banner grab %s:%d → %s", host, port, exc)
        return None


def _tls_cert_info(host: str, port: int, timeout: float = 6.0) -> Optional[Dict]:
    """جيب معلومات الـ TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {"cert": cert, "cipher": cipher, "tls_version": version}
    except Exception as exc:
        logger.debug("TLS info %s:%d → %s", host, port, exc)
        return None


# ---------------------------------------------------------------------------
# Pattern matchers
# ---------------------------------------------------------------------------

def _match_patterns(text: str,
                    patterns: List[Tuple],
                    source: str) -> List[TechMatch]:
    """
    يطبّق قايمة patterns على text ويرجع قايمة TechMatch.
    patterns format: (regex, name, version_group_or_None, confidence, category)
    """
    results = []
    seen = set()
    for pattern, name, ver_group, confidence, category in patterns:
        m = re.search(pattern, text, re.I)
        if not m:
            continue
        version = m.group(ver_group) if ver_group and ver_group <= len(m.groups()) else None
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        results.append(TechMatch(
            name=name,
            version=version,
            confidence=confidence,
            method=source,
            raw=m.group(0),
            category=category,
        ))
    return results


# ---------------------------------------------------------------------------
# Detection strategies
# ---------------------------------------------------------------------------

class VersionDetector:
    """
    الـ detector الرئيسي.
    كل strategy method بترجع List[TechMatch].
    """

    def __init__(self, url: str, timeout: float = 8.0,
                 probe_ports: bool = False):
        parsed = urlsplit(url)
        self.url = url
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.tls = parsed.scheme == "https"
        self.timeout = timeout
        self.probe_ports = probe_ports    # لو True بيفحص SSH/FTP/etc

        self._result = DetectionResult(url=url, host=self.host)
        self._fetched_cache: Dict[str, Optional[Tuple]] = {}

    def _get(self, path: str, accept_encoding: str = "gzip, deflate") -> Optional[Tuple]:
        """Cached HTTP GET."""
        key = f"{path}|{accept_encoding}"
        if key not in self._fetched_cache:
            self._fetched_cache[key] = _http_get(
                self.host, self.port, path, self.tls,
                self.timeout, accept_encoding
            )
        return self._fetched_cache[key]

    def _add(self, matches: List[TechMatch]):
        self._result.technologies.extend(matches)

    # ── Strategy 1: HTTP Response Headers ────────────────────────────────

    def detect_from_headers(self) -> List[TechMatch]:
        """أكثر strategy موثوقة — headers مباشرة من الـ server."""
        r = self._get("/")
        if not r:
            return []
        _, hdrs, _ = r
        results = []

        for hdr_name in TARGET_HEADERS:
            val = hdrs.get(hdr_name)
            if not val:
                continue
            matches = _match_patterns(val, HEADER_PATTERNS, f"header:{hdr_name}")
            # لو مفيش match بس في version رقم
            if not matches and re.search(r"\d+\.\d+", val):
                results.append(TechMatch(
                    name=hdr_name.replace("x-", "").replace("-version", ""),
                    version=re.search(r"(\d+\.\d+(?:\.\d+)?)", val).group(1),
                    confidence=50,
                    method=f"header:{hdr_name}",
                    raw=val,
                    category="unknown",
                ))
            results.extend(matches)

        # Content-Encoding: br → Brotli present
        enc = hdrs.get("content-encoding", "")
        if "br" in enc.lower():
            results.append(TechMatch(
                name="brotli",
                version=None,
                confidence=50,
                method="header:content-encoding",
                raw=enc,
                category="library",
            ))

        # Cookies → framework hints
        for hdr_name in ("set-cookie", "cookie"):
            val = hdrs.get(hdr_name, "")
            if "laravel_session" in val.lower():
                results.append(TechMatch("laravel", None, 80, f"header:{hdr_name}", val, "framework"))
            if "phpsessid" in val.lower():
                results.append(TechMatch("php", None, 65, f"header:{hdr_name}", val, "runtime"))
            if "django" in val.lower() or "csrftoken" in val.lower():
                results.append(TechMatch("django", None, 65, f"header:{hdr_name}", val, "framework"))
            if "rack.session" in val.lower():
                results.append(TechMatch("rails", None, 65, f"header:{hdr_name}", val, "framework"))
            if "jsessionid" in val.lower():
                results.append(TechMatch("java", None, 65, f"header:{hdr_name}", val, "runtime"))

        return results

    # ── Strategy 2: Version/Health Endpoints ─────────────────────────────

    def detect_from_endpoints(self) -> List[TechMatch]:
        """دور على endpoints بيعرضوا version info."""
        results = []
        for path, desc in VERSION_ENDPOINTS:
            r = self._get(path)
            if not r:
                continue
            status, hdrs, body = r
            if status not in (200, 206):
                continue

            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                continue

            source = f"endpoint:{path}"

            # JSON patterns
            for pattern, name, category in JSON_VERSION_PATTERNS:
                m = re.search(pattern, text, re.I | re.S)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                    results.append(TechMatch(
                        name=name,
                        version=version,
                        confidence=85,
                        method=source,
                        raw=m.group(0)[:120],
                        category=category,
                    ))

            # Header patterns على الـ response headers
            for hdr_name in TARGET_HEADERS:
                val = hdrs.get(hdr_name, "")
                if val:
                    matches = _match_patterns(val, HEADER_PATTERNS,
                                               f"{source}+header:{hdr_name}")
                    results.extend(matches)

            # WordPress detection
            if "wp-json" in path and status == 200:
                try:
                    data = json.loads(text)
                    ver = (data.get("namespaces") and "wp/v2" in data.get("namespaces", [])) \
                          or data.get("description")
                    gm = re.search(r'"wp_version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"', text)
                    wp_ver = gm.group(1) if gm else None
                    results.append(TechMatch("wordpress", wp_ver, 90, source,
                                             text[:80], "cms"))
                except Exception:
                    pass

            # Spring Boot actuator
            if "actuator" in path and status == 200:
                try:
                    data = json.loads(text)
                    build = data.get("build", {})
                    ver = build.get("version")
                    if ver:
                        results.append(TechMatch("spring-boot", ver, 90,
                                                   source, str(build), "framework"))
                except Exception:
                    pass

            # Go pprof/expvar → confirms Go
            if "pprof" in path or "debug/vars" in path:
                results.append(TechMatch("golang", None, 70, source, path, "runtime"))

            # package.json (should never be public)
            if path == "/package.json" and status == 200:
                try:
                    data = json.loads(text)
                    ver = data.get("version")
                    deps = data.get("dependencies", {})
                    # engine
                    engines = data.get("engines", {})
                    node_ver = engines.get("node")
                    if node_ver:
                        # مثلاً ">=18.0.0" → "18.0.0"
                        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", node_ver)
                        if m:
                            results.append(TechMatch("nodejs", m.group(1), 75,
                                                       source, node_ver, "runtime"))
                    # frameworks from dependencies
                    for pkg, pkg_ver in deps.items():
                        clean_ver = re.search(r"(\d+\.\d+(?:\.\d+)?)", str(pkg_ver))
                        cv = clean_ver.group(1) if clean_ver else None
                        if pkg in ("express",):
                            results.append(TechMatch("express", cv, 80, source, f"{pkg}@{pkg_ver}", "framework"))
                        if pkg in ("next",):
                            results.append(TechMatch("nextjs", cv, 80, source, f"{pkg}@{pkg_ver}", "framework"))
                        if pkg == "brotli" or pkg == "brotli-wasm":
                            results.append(TechMatch("brotli", cv, 75, source, f"{pkg}@{pkg_ver}", "library"))
                except Exception:
                    pass

            # robots.txt → generator hint
            if path == "/robots.txt" and status == 200:
                if "wordpress" in text.lower() or "wp-" in text.lower():
                    results.append(TechMatch("wordpress", None, 60, source, text[:80], "cms"))
                if "drupal" in text.lower():
                    results.append(TechMatch("drupal", None, 60, source, text[:80], "cms"))

        return results

    # ── Strategy 3: Response Body Patterns ───────────────────────────────

    def detect_from_body(self) -> List[TechMatch]:
        """ابحث في الـ HTML body عن version strings."""
        results = []
        for path in ("/", "/index.html", "/index.php"):
            r = self._get(path)
            if not r:
                continue
            status, hdrs, body = r
            if status not in (200, 206):
                continue
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                continue

            source = f"body:{path}"

            # Meta generator
            for m in re.finditer(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                text, re.I
            ):
                gen = m.group(1)
                ver_m = re.search(r"(\d+\.\d+(?:\.\d+)?)", gen)
                ver = ver_m.group(1) if ver_m else None

                for tech in ("WordPress", "Drupal", "Joomla", "Django",
                              "Laravel", "Gatsby", "Hugo", "Jekyll"):
                    if tech.lower() in gen.lower():
                        results.append(TechMatch(tech.lower(), ver, 85,
                                                   source + ":meta-generator",
                                                   gen, "cms"))

            # HTML comments with version
            for m in re.finditer(r"<!--.*?-->", text, re.S):
                comment = m.group(0)
                for pattern, name, ver_group, confidence, category in HEADER_PATTERNS:
                    cm = re.search(pattern, comment, re.I)
                    if cm:
                        version = cm.group(ver_group) if ver_group else None
                        results.append(TechMatch(name, version, confidence - 15,
                                                   source + ":html-comment",
                                                   comment[:80], category))

            # Script src patterns
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', text, re.I):
                src = m.group(1)
                # React
                rm = re.search(r"react[./-](\d+\.\d+\.\d+)", src, re.I)
                if rm:
                    results.append(TechMatch("react", rm.group(1), 80,
                                               source + ":script-src", src, "framework"))
                # Vue
                vm = re.search(r"vue[./-](\d+\.\d+\.\d+)", src, re.I)
                if vm:
                    results.append(TechMatch("vue", vm.group(1), 80,
                                               source + ":script-src", src, "framework"))
                # Angular
                am = re.search(r"angular[./-](\d+\.\d+\.\d+)", src, re.I)
                if am:
                    results.append(TechMatch("angular", am.group(1), 80,
                                               source + ":script-src", src, "framework"))

            # Error page patterns
            for pattern, name, ver_group, confidence, category in HEADER_PATTERNS:
                bm = re.search(pattern, text, re.I)
                if bm:
                    version = bm.group(ver_group) if ver_group else None
                    results.append(TechMatch(name, version, confidence - 10,
                                               source + ":page-body",
                                               bm.group(0)[:80], category))

        return results

    # ── Strategy 4: TLS Certificate ──────────────────────────────────────

    def detect_from_tls(self) -> List[TechMatch]:
        """معلومات من الـ TLS certificate."""
        if not self.tls:
            return []
        results = []
        info = _tls_cert_info(self.host, self.port, self.timeout)
        if not info:
            return []

        cert = info.get("cert") or {}
        tls_ver = info.get("tls_version", "")

        # TLS version
        if tls_ver:
            results.append(TechMatch(
                name="tls",
                version=tls_ver,
                confidence=95,
                method="tls:version",
                raw=tls_ver,
                category="protocol",
            ))

        # Issuer → CA hint
        issuer = dict(x[0] for x in cert.get("issuer", []))
        org = issuer.get("organizationName", "")
        for pattern, name, _, confidence, category in TLS_PATTERNS:
            if re.search(pattern, org, re.I):
                results.append(TechMatch(name, None, confidence,
                                          "tls:issuer", org, category))

        # Subject Alternative Names
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        # Cloudflare SANs غالباً بتبقى *.cloudflare.com
        if any("cloudflare" in s for s in sans):
            results.append(TechMatch("cloudflare", None, 70,
                                      "tls:san", str(sans[:3]), "cdn"))

        return results

    # ── Strategy 5: Favicon Hash ─────────────────────────────────────────

    def detect_from_favicon(self) -> List[TechMatch]:
        """Hash الـ favicon وقارنه بقاموس معروف."""
        results = []
        for path in ("/favicon.ico", "/favicon.png"):
            r = self._get(path)
            if not r:
                continue
            status, _, body = r
            if status != 200 or not body:
                continue
            fav_hash = hashlib.md5(body).hexdigest()
            if fav_hash in FAVICON_HASHES:
                name, version = FAVICON_HASHES[fav_hash]
                results.append(TechMatch(
                    name=name,
                    version=version,
                    confidence=90,
                    method=f"favicon:md5:{fav_hash[:8]}",
                    raw=f"md5={fav_hash}",
                    category="cms",
                ))
        return results

    # ── Strategy 6: Error Page Probe ─────────────────────────────────────

    def detect_from_error_page(self) -> List[TechMatch]:
        """404/500 error pages غالباً بتكشف الـ server info."""
        results = []
        for path in ("/marsadix-nonexistent-probe-12345",
                     "/marsadix-probe.php",
                     "/marsadix-probe.aspx"):
            r = self._get(path)
            if not r:
                continue
            status, hdrs, body = r
            if status not in (400, 403, 404, 405, 500, 503):
                continue
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                continue

            source = f"error-page:{path}:{status}"

            # Headers أهم من الـ body في الـ error pages
            for hdr_name in TARGET_HEADERS:
                val = hdrs.get(hdr_name, "")
                if val:
                    matches = _match_patterns(val, HEADER_PATTERNS,
                                               f"{source}+header:{hdr_name}")
                    results.extend(matches)

            # Body patterns
            for pattern, name, ver_group, confidence, category in HEADER_PATTERNS:
                m = re.search(pattern, text, re.I)
                if m:
                    version = m.group(ver_group) if ver_group else None
                    results.append(TechMatch(name, version, confidence - 15,
                                               source + ":body",
                                               m.group(0)[:80], category))

        return results

    # ── Strategy 7: Brotli Content-Encoding ──────────────────────────────

    def detect_brotli_encoding(self) -> List[TechMatch]:
        """تحقق إن السيرفر بيستخدم Brotli كـ content encoding."""
        r = self._get("/", accept_encoding="br, gzip, deflate")
        if not r:
            return []
        _, hdrs, _ = r
        enc = hdrs.get("content-encoding", "")
        if "br" in enc.lower():
            return [TechMatch(
                name="brotli",
                version=None,
                confidence=70,
                method="content-encoding:br",
                raw=enc,
                category="library",
            )]
        return []

    # ── Strategy 8: Service Banner Grab ──────────────────────────────────

    def detect_from_service_banners(self) -> List[TechMatch]:
        """Banner grab على الـ service ports. بيشتغل لو probe_ports=True."""
        if not self.probe_ports:
            return []
        results = []

        # SSH port 22
        banner = _banner_grab(self.host, 22, self.timeout)
        if banner:
            try:
                banner_str = banner.decode("utf-8", errors="replace").strip()
                matches = _match_patterns(banner_str, SSH_BANNER_PATTERNS,
                                           "banner:ssh:22")
                results.extend(matches)
            except Exception:
                pass

        # FTP port 21
        banner = _banner_grab(self.host, 21, self.timeout)
        if banner:
            try:
                banner_str = banner.decode("utf-8", errors="replace").strip()
                matches = _match_patterns(banner_str, FTP_BANNER_PATTERNS,
                                           "banner:ftp:21")
                results.extend(matches)
            except Exception:
                pass

        return results

    # ── Strategy 9: Brotli Version Inference from Node ───────────────────

    def infer_brotli_from_node(self) -> List[TechMatch]:
        """لو عرفنا Node.js version، نستنتج Brotli version."""
        node_match = None
        for t in self._result.technologies:
            if t.name == "nodejs" and t.version:
                if node_match is None or t.confidence > node_match.confidence:
                    node_match = t

        if not node_match:
            return []

        from packaging.version import Version, InvalidVersion
        try:
            node_ver = Version(node_match.version)
        except InvalidVersion:
            return []

        from marsadix.asm.version_detect import _NODE_TO_BROTLI
        for lo, hi, brotli_ver in _NODE_TO_BROTLI:
            try:
                if Version(lo) <= node_ver < Version(hi):
                    return [TechMatch(
                        name="brotli",
                        version=brotli_ver,
                        confidence=75,
                        method=f"inferred:nodejs:{node_match.version}",
                        raw=f"Node {node_match.version} → Brotli {brotli_ver}",
                        category="library",
                    )]
            except InvalidVersion:
                continue
        return []

    # ── Main runner ───────────────────────────────────────────────────────

    def run(self) -> DetectionResult:
        """
        شغّل كل الـ strategies بالترتيب وارجع النتيجة.
        """
        strategies = [
            ("headers",          self.detect_from_headers),
            ("endpoints",        self.detect_from_endpoints),
            ("body",             self.detect_from_body),
            ("tls",              self.detect_from_tls),
            ("favicon",          self.detect_from_favicon),
            ("error-page",       self.detect_from_error_page),
            ("brotli-encoding",  self.detect_brotli_encoding),
            ("service-banners",  self.detect_from_service_banners),
        ]

        for name, fn in strategies:
            try:
                matches = fn()
                if matches:
                    logger.debug("[%s] %s → %d match(es)", self.host, name, len(matches))
                self._add(matches)
            except Exception as exc:
                logger.debug("[%s] strategy %s failed: %s", self.host, name, exc)
                self._result.errors.append(f"{name}: {exc}")

        # Inference: Brotli من Node.js بعد ما جمعنا كل النتايج
        try:
            inferred = self.infer_brotli_from_node()
            self._add(inferred)
        except Exception:
            pass

        # Dedup: لو نفس (name, version) اتلقوا من strategies مختلفة،
        # سيب اللي بـ confidence أعلى
        self._result.technologies = _dedup(self._result.technologies)

        return self._result


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup(techs: List[TechMatch]) -> List[TechMatch]:
    """
    لكل (name, version) سيب اللي بـ confidence أعلى.
    لو نفس الـ name بس versions مختلفة → سيبهم كلهم.
    """
    best: Dict[Tuple[str, Optional[str]], TechMatch] = {}
    for t in techs:
        key = (t.name.lower(), t.version)
        if key not in best or t.confidence > best[key].confidence:
            best[key] = t
    return sorted(best.values(), key=lambda t: (-t.confidence, t.name))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect(url: str, timeout: float = 8.0,
           probe_ports: bool = False) -> DetectionResult:
    """
    الدالة الرئيسية — بتاخد URL وبترجع DetectionResult.

    مثال:
        from marsadix.asm.version_detect import detect
        result = detect("https://example.com")
        for tech in result.technologies:
            print(f"{tech.name:20} {tech.version or '?':15} conf={tech.confidence}")
    """
    d = VersionDetector(url, timeout=timeout, probe_ports=probe_ports)
    return d.run()


# ---------------------------------------------------------------------------
# CLI للاختبار المباشر
# ---------------------------------------------------------------------------
# python3 -m marsadix.asm.version_detect https://example.com

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.WARNING)
    if len(sys.argv) < 2:
        print("Usage: python3 version_detect.py <url> [--ports]")
        sys.exit(1)
    target_url = sys.argv[1]
    probe = "--ports" in sys.argv

    print(f"\n[*] Detecting technologies on: {target_url}\n")
    res = detect(target_url, probe_ports=probe)

    if not res.technologies:
        print("  No technologies detected.")
    else:
        print(f"  {'Technology':<22} {'Version':<18} {'Conf':>4}  Method")
        print(f"  {'-'*22} {'-'*18} {'-'*4}  {'-'*40}")
        for t in res.technologies:
            ver = t.version or "unknown"
            print(f"  {t.name:<22} {ver:<18} {t.confidence:>4}%  {t.method}")

    if res.errors:
        print(f"\n  Errors: {len(res.errors)}")
        for e in res.errors[:3]:
            print(f"    - {e}")
