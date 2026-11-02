"""URL normalization, deduplication keys and endpoint classification.

The base Web stage only strips a trailing slash (`url.rstrip("/")`).  Archived
URLs, crawlers and JavaScript produce many spellings of the same resource:

    HTTPS://Example.com:443/a/../b?utm_source=x#frag
    https://example.com/b?utm_source=x
    https://example.com/b/

Those are one resource for inventory purposes.  The normalizer is deliberately
conservative: it never invents a host, rejects ambiguous/credentialed URLs,
keeps query values unless they are clearly tracking parameters, and produces a
stable dedup key independent of query order.
"""

from __future__ import annotations

import html
import ipaddress
import posixpath
import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

from .errors import ScopeViolation

_DEFAULT_PORTS = {"http": 80, "https": 443}
_ALLOWED_HOST = re.compile(r"^[a-z0-9._-]+$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MULTI_SLASH = re.compile(r"/{2,}")

# Clearly non-semantic marketing/analytics parameters.  Everything else is
# preserved because it may select a distinct application state.
_TRACKING_PARAMS = {
    "gclid", "dclid", "fbclid", "msclkid", "yclid", "igshid", "mc_cid", "mc_eid",
    "_ga", "_gl", "ref_src", "ref_url", "vero_conv", "vero_id", "wickedid",
}


def _is_tracking(name: str) -> bool:
    key = name.lower()
    return key.startswith("utm_") or key in _TRACKING_PARAMS


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    # Some tools emit //path; collapse repeated slashes for a stable key.
    path = _MULTI_SLASH.sub("/", path)
    had_trailing = path.endswith("/") and path != "/"
    # URL paths are POSIX-like; normpath resolves . and .. without touching the
    # query.  It also protects the stored inventory from ../../ escapes.
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if had_trailing and normalized != "/" and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host or len(host) > 253:
        raise ScopeViolation("empty or overlong URL host")
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        pass
    # IDNA for unicode hostnames, but keep ASCII/underscore hosts untouched so
    # intentionally-named internal lab hosts still work.
    if all(ord(c) < 128 for c in host):
        if not _ALLOWED_HOST.match(host):
            raise ScopeViolation(f"invalid URL host: {host!r}")
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeViolation(f"invalid internationalized host: {host!r}") from exc


def _format_netloc(host: str, port: Optional[int], scheme: str) -> str:
    if ":" in host and not host.startswith("["):  # IPv6 literal
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        return host
    return f"{host}:{port}"


@dataclass(frozen=True)
class NormalizedURL:
    url: str                 # stored/display form
    key: str                 # stable dedup key
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    has_params: bool

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{_format_netloc(self.host, self.port, self.scheme)}"

    @property
    def is_root(self) -> bool:
        return self.path == "/" and not self.query


def normalize_url(raw: str, base_url: Optional[str] = None,
                  strip_tracking: bool = True) -> NormalizedURL:
    """Return a validated, normalized HTTP(S) URL or raise ScopeViolation."""
    if not isinstance(raw, str):
        raise ScopeViolation("URL must be text")
    value = html.unescape(raw).strip()
    if not value:
        raise ScopeViolation("empty URL")
    # JavaScript strings frequently escape slashes as \/ ; undo only that,
    # then refuse any remaining backslash (URL-parser ambiguity/SSRF gadget).
    value = value.replace("\\/", "/")
    if "\\" in value or _CONTROL.search(value) or any(ch.isspace() for ch in value):
        raise ScopeViolation("URL contains whitespace, control or backslash characters")

    if base_url:
        try:
            value = urljoin(base_url, value)
        except ValueError as exc:
            raise ScopeViolation(f"cannot resolve relative URL: {raw!r}") from exc
    elif value.startswith("//"):
        value = "https:" + value
    elif "://" not in value:
        if value.startswith(("/", "./", "../", "?")):
            raise ScopeViolation(f"relative URL without a base: {raw!r}")
        value = "https://" + value

    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise ScopeViolation(f"malformed URL: {raw!r}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ScopeViolation(f"unsupported URL scheme: {scheme or '(none)'}")
    if parts.username is not None or parts.password is not None:
        raise ScopeViolation("URLs with embedded credentials are refused")
    if not parts.hostname:
        raise ScopeViolation("URL has no host")

    host = _normalize_host(parts.hostname)
    try:
        port = parts.port
    except ValueError as exc:
        raise ScopeViolation(f"invalid port in URL: {raw!r}") from exc
    if port is not None and (port < 1 or port > 65535):
        raise ScopeViolation("URL port out of range")

    path = _normalize_path(parts.path)
    # Reject encoded NUL/CR/LF and encoded dot-dot that would survive to a
    # downstream tool.  Re-encoding after validation keeps the URL printable.
    if "%" in path:
        try:
            decoded_path = unquote(path)
        except Exception:
            decoded_path = path
        if _CONTROL.search(decoded_path) or "\\" in decoded_path:
            raise ScopeViolation("URL path contains forbidden encoded characters")
    path = quote(path, safe="/:@!$&'()*+,;=-._~%")

    pairs = parse_qsl(parts.query, keep_blank_values=True) if parts.query else []
    if strip_tracking:
        pairs = [(k, v) for k, v in pairs if not _is_tracking(k)]
    query = urlencode(pairs, doseq=True)
    has_params = bool(pairs)

    netloc = _format_netloc(host, port, scheme)
    display = urlunsplit((scheme, netloc, path, query, ""))
    # Dedup key: sorted query pairs means ?a=1&b=2 == ?b=2&a=1.
    key_query = urlencode(sorted(pairs), doseq=True)
    key = urlunsplit((scheme, netloc, path, key_query, ""))
    return NormalizedURL(
        url=display, key=key, scheme=scheme, host=host, port=port,
        path=path, query=query, has_params=has_params,
    )


def url_host(raw: str) -> Optional[str]:
    try:
        return normalize_url(raw).host
    except ScopeViolation:
        return None


def is_under_domain(host: str, domain: str) -> bool:
    """True for the root domain itself or a true subdomain (not evil-example)."""
    host = (host or "").lower().rstrip(".")
    domain = (domain or "").lower().rstrip(".")
    return bool(host and domain and (host == domain or host.endswith("." + domain)))


def classify_kind(url: str, root_keys: Iterable[str] = (),
                  content_type: Optional[str] = None) -> str:
    """Return "url", "js_file" or "endpoint" matching WebItemKind values."""
    normalized = normalize_url(url)
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    path = normalized.path.lower()
    if ctype in ("application/javascript", "text/javascript", "application/x-javascript",
                 "text/ecmascript", "application/ecmascript") or path.endswith(
                     (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
        return "js_file"
    roots = set(root_keys)
    if normalized.key in roots or normalized.is_root:
        return "url"
    return "endpoint"


def dedupe_normalized(items: Iterable[NormalizedURL],
                      prefer_scheme: bool = True) -> list[NormalizedURL]:
    """Deduplicate by stable key, preferring HTTPS over HTTP when both exist."""
    chosen: dict[str, NormalizedURL] = {}
    for item in items:
        identity = item.key.split("://", 1)[-1]   # scheme-agnostic identity
        existing = chosen.get(identity)
        if existing is None:
            chosen[identity] = item
            continue
        if prefer_scheme and existing.scheme == "http" and item.scheme == "https":
            chosen[identity] = item
    return list(chosen.values())


def safe_url_for_log(url: str) -> str:
    """Strip query/fragment before logging (tokens often hide in queries)."""
    try:
        p = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))
