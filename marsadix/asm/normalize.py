"""Conservative HTTP(S) URL normalization used by ASM scope checks."""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, urlunsplit
from .errors import ScopeViolation

@dataclass(frozen=True)
class NormalizedURL:
    url: str
    key: str
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    has_params: bool
    @property
    def origin(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return f"{self.scheme}://{host}" + (f":{self.port}" if self.port and self.port != default else "")
    @property
    def is_root(self) -> bool:
        return self.path == "/" and not self.query

def normalize_url(raw: str, base_url: Optional[str] = None, strip_tracking: bool = True) -> NormalizedURL:
    if not isinstance(raw, str):
        raise ScopeViolation("URL must be text")
    value = raw.strip()
    if not value or any(ch.isspace() or ord(ch) < 32 for ch in value) or "\\" in value:
        raise ScopeViolation("URL is empty or contains ambiguous characters")
    if base_url and value.startswith(("/", "?", "#")):
        from urllib.parse import urljoin
        value = urljoin(base_url, value)
    elif value.startswith("//"):
        value = "https:" + value
    elif "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            raise ScopeViolation("only absolute HTTP(S) URLs are accepted")
        if parts.username is not None or parts.password is not None:
            raise ScopeViolation("URLs with embedded credentials are refused")
        host = parts.hostname.lower().rstrip(".")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if len(host) > 253 or not re.fullmatch(r"[a-z0-9._-]+", host):
                host = host.encode("idna").decode("ascii").lower()
        port = parts.port
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, ScopeViolation):
            raise
        raise ScopeViolation("malformed URL") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ScopeViolation("URL port out of range")
    path = parts.path or "/"
    if re.search(r"%(?:00|0a|0d)", path, re.I):
        raise ScopeViolation("URL path contains encoded control characters")
    default = 443 if scheme == "https" else 80
    netloc = f"[{host}]" if ":" in host else host
    if port and port != default:
        netloc += f":{port}"
    query = parts.query
    if strip_tracking and query:
        from urllib.parse import parse_qsl, urlencode
        query = urlencode([(k,v) for k,v in parse_qsl(query, keep_blank_values=True)
                           if not (k.lower().startswith("utm_") or k.lower() in {"gclid","fbclid","dclid","msclkid"})])
    url = urlunsplit((scheme, netloc, path, query, ""))
    return NormalizedURL(url, url, scheme, host, port, path, query, bool(query))
