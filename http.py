"""HTTP transport with bounded retries, 429 handling and timeouts.

* Every request has a timeout.
* 429: wait ``Retry-After`` (header, or JSON ``retry_after`` / ``parameters.retry_after``),
  capped at ``max_retry_after`` seconds; counts as an attempt.
* 5xx and network errors/timeouts: exponential backoff ``base * 2**(n-1)`` capped
  at ``max_delay``.
* Other 4xx: fail immediately (not retryable).
* Error strings never contain URLs, tokens or response bodies.
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Protocol

from .base import DeliveryResult

__all__ = ["HttpResponse", "HttpClient", "TransportError", "TransportTimeout", "UrllibClient",
           "post_with_retry", "retry_after_seconds", "redact"]

DEFAULT_TIMEOUT = 10.0


class TransportError(Exception):
    """Network-level failure. Message must never contain URLs or secrets."""


class TransportTimeout(TransportError):
    """Raised for invalid input."""


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""

    def header(self, name: str) -> Optional[str]:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return None

    def json(self):
        return json.loads(self.body)


class HttpClient(Protocol):
    def post(self, url: str, body: bytes, headers: Dict[str, str], timeout: float) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # SSRF hardening: never follow redirects
        return None


class UrllibClient:
    """Stdlib client. Redirects are *not* followed."""

    def post(self, url: str, body: bytes, headers: Dict[str, str], timeout: float) -> HttpResponse:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=timeout) as r:
                return HttpResponse(r.status, dict(r.headers), r.read(65536).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            try:
                data = e.read(65536).decode("utf-8", "replace")
            except Exception:
                data = ""
            return HttpResponse(e.code, dict(e.headers or {}), data)
        except (socket.timeout, TimeoutError) as e:
            raise TransportTimeout("timeout") from None
        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                raise TransportTimeout("timeout") from None
            raise TransportError(f"network error ({type(e.reason).__name__})") from None
        except OSError as e:
            raise TransportError(f"network error ({type(e).__name__})") from None


def redact(text: str, *secrets: Optional[str]) -> str:
    out = text or ""
    for s in secrets:
        if s and len(s) >= 4:
            out = out.replace(s, "***")
    return out


def retry_after_seconds(resp: HttpResponse, default: float = 1.0) -> float:
    h = resp.header("Retry-After")
    if h:
        try:
            return max(0.0, float(h))
        except ValueError:
            _ = None  # non-numeric (HTTP-date) Retry-After: fall back to the JSON body / default
    try:
        data = resp.json()
        if isinstance(data, dict):
            v = data.get("retry_after")
            if v is None and isinstance(data.get("parameters"), dict):
                v = data["parameters"].get("retry_after")
            if v is not None:
                return max(0.0, float(v))
    except (ValueError, TypeError):
        return default
    return default


def post_with_retry(client: HttpClient, url: str, body: bytes, headers: Dict[str, str], *,
                    timeout: float = DEFAULT_TIMEOUT, max_attempts: int = 4, base_delay: float = 1.0,
                    max_delay: float = 30.0, max_retry_after: float = 60.0,
                    sleep: Callable[[float], None] = time.sleep,
                    validate: Optional[Callable[[HttpResponse], Optional[str]]] = None) -> DeliveryResult:
    """POST with retry policy. ``validate`` may return an error string for a 2xx response
    that is not actually a success (malformed response) - such failures are not retried."""
    last_error = "unknown error"
    last_status: Optional[int] = None
    for attempt in range(1, max_attempts + 1):
        delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
        try:
            resp = client.post(url, body, headers, timeout)
        except TransportTimeout:
            last_error, last_status = "timeout", None
        except TransportError as exc:
            last_error, last_status = str(exc) or "network error", None
        except Exception as exc:  # unexpected client failure: sanitized
            last_error, last_status = f"transport failure ({type(exc).__name__})", None
        else:
            last_status = resp.status
            if 200 <= resp.status < 300:
                bad = validate(resp) if validate else None
                if bad:
                    return DeliveryResult(False, resp.status, attempt, bad)
                return DeliveryResult(True, resp.status, attempt)
            if resp.status == 429:
                last_error = "rate limited (HTTP 429)"
                delay = min(max_retry_after, retry_after_seconds(resp, default=delay))
            elif resp.status >= 500:
                last_error = f"server error (HTTP {resp.status})"
            else:
                return DeliveryResult(False, resp.status, attempt, f"HTTP {resp.status}")
        if attempt < max_attempts:
            sleep(delay)
    return DeliveryResult(False, last_status, max_attempts, last_error)
