"""
The only way the custom detection skills talk to a target.

Built for safe, evidence-only probing (A5/A8), so it is deliberately strict:

  * SCOPE   every request is checked against the scan scope first; anything else is refused
  * NETWORK the hostname is resolved HERE, each address goes through core/netguard (no
            loopback / private / cloud-metadata addresses unless the scope lists them), and the
            connection is made to that exact checked address. A name cannot "change its mind"
            between the check and the connection (DNS rebinding)
  * REDIRECT never followed. A redirect is evidence to read, not a place to go
  * RATE     one shared limiter (the scan's requests/second) across all worker threads
  * SIZE     response bodies are cut at max_body bytes
  * TLS      certificates are NOT verified: a scanner must also look at hosts with expired or
            self-signed certificates. Nothing secret is sent, so this only affects what we read
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlsplit

from ..core import netguard

USER_AGENT = "Marsadix/1.0 (authorized security assessment)"


@dataclass
class Response:
    status: int
    headers: List[Tuple[str, str]]
    body: bytes
    elapsed: float
    timed_out: bool = False
    truncated: bool = False
    url: str = ""
    _lower: Dict[str, List[str]] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        for k, v in self.headers:
            self._lower.setdefault(k.lower(), []).append(v)

    def header(self, name: str) -> Optional[str]:
        vals = self._lower.get(name.lower())
        return vals[0] if vals else None

    def header_all(self, name: str) -> List[str]:
        return self._lower.get(name.lower(), [])

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def is_html(self) -> bool:
        ct = (self.header("content-type") or "").lower()
        return "html" in ct or (not ct and b"<html" in self.body[:2000].lower())


class _Pinned(http.client.HTTPConnection):
    """Connect to a pre-checked IP, but keep the real hostname for Host/SNI."""

    def __init__(self, host, port, ip, timeout, tls_ctx=None):
        super().__init__(host, port, timeout=timeout)
        self._ip, self._tls_ctx = ip, tls_ctx

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        if self._tls_ctx is not None:
            sock = self._tls_ctx.wrap_socket(sock, server_hostname=self.host)
        self.sock = sock


class RateLimiter:
    def __init__(self, per_second: float):
        self._gap = 1.0 / max(per_second, 0.1)
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            at = max(now, self._next)
            self._next = at + self._gap
        if at > now:
            time.sleep(at - now)


class ProbeClient:
    def __init__(self, scope, rate_limit: float = 10, timeout: float = 10,
                 max_body: int = 256 * 1024, allow_private: bool = False):
        self.scope, self.timeout, self.max_body = scope, timeout, max_body
        self.allow_private = allow_private            # tests only
        self.limiter = RateLimiter(rate_limit)
        self.requests = 0
        self._lock = threading.Lock()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._tls = ctx

    def _pick_ip(self, host: str, port: int) -> Optional[str]:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            return None
        for info in infos:
            ip = info[4][0]
            if self.allow_private or netguard.blocked_reason(ip, self.scope) is None:
                return ip
        return None

    def request(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                timeout: Optional[float] = None) -> Optional[Response]:
        """None = refused (scope / network guard) or the connection failed."""
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        if self.scope is not None and not self.scope.is_in_scope(url):
            return None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ip = self._pick_ip(parts.hostname, port)
        if ip is None:
            return None
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
        hdrs.update(headers or {})
        t = timeout or self.timeout
        self.limiter.wait()
        with self._lock:
            self.requests += 1
        conn = _Pinned(parts.hostname, port, ip, t, self._tls if parts.scheme == "https" else None)
        start = time.monotonic()
        try:
            conn.request(method, target, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read(self.max_body + 1)
            return Response(resp.status, resp.getheaders(), body[:self.max_body],
                            time.monotonic() - start, truncated=len(body) > self.max_body, url=url)
        except socket.timeout:
            return Response(0, [], b"", time.monotonic() - start, timed_out=True, url=url)
        except (OSError, http.client.HTTPException, ssl.SSLError):
            return None
        finally:
            conn.close()

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: Optional[float] = None):
        return self.request(url, "GET", headers, timeout)


# ------------------------------------------------------------------ URL helpers
def query_pairs(url: str) -> List[Tuple[str, str]]:
    return parse_qsl(urlsplit(url).query, keep_blank_values=True)


def with_param(url: str, index: int, value: str, raw: bool = False) -> str:
    """
    `url` with the value of query parameter number `index` replaced.
    raw=False percent-encodes the value; raw=True inserts it exactly as given
    (needed to test CRLF with a literal %0d%0a).
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    out = []
    for i, (k, v) in enumerate(pairs):
        val = value if i == index else v
        out.append(f"{quote(k, safe='')}={val if (raw and i == index) else quote(val, safe='')}")
    return parts._replace(query="&".join(out)).geturl()
