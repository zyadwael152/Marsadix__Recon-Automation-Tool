"""M18 - generic JSON webhook (optional HMAC-SHA256), Slack and Microsoft Teams.

SSRF protection: destinations must be http/https and must not resolve to
loopback / private / link-local / reserved / multicast addresses unless
``MARSADIX_ALLOW_PRIVATE_WEBHOOKS=1``.  Redirects are never followed.  Name
resolution happens at validation time (DNS-rebinding between check and connect
is a documented residual risk - put an egress firewall in front for hard
guarantees).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urlsplit

from .base import AlertPayload, DeliveryResult, fmt_score, truncate
from .http import DEFAULT_TIMEOUT, HttpClient, UrllibClient, post_with_retry

__all__ = ["WebhookNotifier", "SlackNotifier", "TeamsNotifier", "UnsafeDestination", "validate_destination",
           "sign_body", "generic_payload", "slack_payload", "teams_payload", "SIGNATURE_HEADER"]

SIGNATURE_HEADER = "X-Marsadix-Signature"


class UnsafeDestination(ValueError):
    """Raised when a webhook destination is invalid or blocked. Message never contains the URL."""


Resolver = Callable[[str], List[str]]


def _default_resolver(host: str) -> List[str]:
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


def _blocked(ip: str) -> bool:
    a = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
            or a.is_unspecified or (isinstance(a, ipaddress.IPv4Address) and a in ipaddress.ip_network("100.64.0.0/10")))


def validate_destination(url: str, *, allow_private: bool = False, resolver: Optional[Resolver] = None) -> None:
    try:
        parts = urlsplit(url or "")
        scheme, host = parts.scheme.lower(), parts.hostname
        parts.port  # noqa: B018 - validates port
    except ValueError:
        raise UnsafeDestination("invalid webhook URL") from None
    if scheme not in ("http", "https") or not host:
        raise UnsafeDestination("webhook URL must be http or https with a host")
    if parts.username or parts.password:
        raise UnsafeDestination("credentials in webhook URL are not allowed")
    if allow_private:
        return
    if host.lower() in ("localhost",) or host.lower().endswith(".localhost"):
        raise UnsafeDestination("webhook destination is blocked (private/loopback/link-local)")
    try:
        ips = [host] if _is_ip(host) else (resolver or _default_resolver)(host)
    except (OSError, UnicodeError):
        raise UnsafeDestination("webhook host could not be resolved") from None
    if not ips:
        raise UnsafeDestination("webhook host could not be resolved")
    for ip in ips:
        if _blocked(ip):
            raise UnsafeDestination("webhook destination is blocked (private/loopback/link-local)")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def sign_body(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


# ---- payload builders ------------------------------------------------------
def generic_payload(a: AlertPayload) -> Dict:
    return {"event": "marsadix.alert", "schema": 1, "alert": a.to_dict()}


def _esc_slack(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(a: AlertPayload) -> Dict:
    tech = " ".join(x for x in (a.technology or a.product, a.version) if x) or "-"
    rem = (a.remediation_title + ": " if a.remediation_title else "") + (a.remediation_text or "n/a")
    fields = [
        {"type": "mrkdwn", "text": truncate(f"*Host*\n{_esc_slack(a.host)}", 2000)},
        {"type": "mrkdwn", "text": truncate(f"*CVE*\n{_esc_slack(a.cve_id)}", 2000)},
        {"type": "mrkdwn", "text": truncate(f"*Technology*\n{_esc_slack(tech)}", 2000)},
        {"type": "mrkdwn", "text": f"*Priority*\n{a.priority_level.upper()} ({a.priority_score:.1f})"},
        {"type": "mrkdwn", "text": f"*CVSS / EPSS*\n{fmt_score(a.cvss)} / {fmt_score(a.epss, 3)}"},
        {"type": "mrkdwn", "text": f"*KEV / Confidence*\n{'YES' if a.kev else 'no'} / {a.confidence}"},
    ]
    return {
        "text": truncate(f"{a.title} - {a.priority_level.upper()}", 300),
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": truncate(a.title, 150)}},
            {"type": "section", "fields": fields},
            {"type": "section", "text": {"type": "mrkdwn", "text": truncate("*Remediation*\n" + _esc_slack(rem), 2900)}},
        ],
    }


def teams_payload(a: AlertPayload) -> Dict:
    tech = " ".join(x for x in (a.technology or a.product, a.version) if x) or "-"
    rem = (a.remediation_title + ": " if a.remediation_title else "") + (a.remediation_text or "n/a")
    color = {"critical": "Attention", "high": "Warning", "medium": "Accent"}.get(a.priority_level.lower(), "Default")
    facts = [("Host", a.host), ("CVE", a.cve_id), ("Technology", tech), ("CVSS", fmt_score(a.cvss)), ("EPSS", fmt_score(a.epss, 3)),
             ("KEV", "YES" if a.kev else "no"), ("Confidence", a.confidence), ("Priority", f"{a.priority_level.upper()} ({a.priority_score:.1f})")]
    return {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "color": color, "wrap": True, "text": truncate(a.title, 200)},
                        {"type": "FactSet", "facts": [{"title": k, "value": truncate(v, 200)} for k, v in facts]},
                        {"type": "TextBlock", "wrap": True, "text": truncate("**Remediation:** " + rem, 1500)}]}}]}


# ---- notifiers ---------------------------------------------------------------
class _BaseWebhook:
    name = "webhook"

    def __init__(self, url: str, *, secret: str = "", allow_private: bool = False, client: Optional[HttpClient] = None,
                 resolver: Optional[Resolver] = None, timeout: float = DEFAULT_TIMEOUT, max_attempts: int = 4,
                 sleep: Callable[[float], None] = time.sleep):
        self._url, self._secret, self._allow_private = url or "", secret or "", allow_private
        self._client = client or UrllibClient()
        self._resolver, self._timeout, self._max_attempts, self._sleep = resolver, timeout, max_attempts, sleep

    @property
    def configured(self) -> bool:
        return bool(self._url)

    builder: Callable[[AlertPayload], Dict] = staticmethod(generic_payload)

    def _payload(self, a: AlertPayload) -> Dict:
        return type(self).builder(a)

    def send(self, alert: AlertPayload) -> DeliveryResult:
        if not self.configured:
            return DeliveryResult(False, error=f"{self.name} not configured", skipped=True)
        try:
            validate_destination(self._url, allow_private=self._allow_private, resolver=self._resolver)
        except UnsafeDestination as exc:
            return DeliveryResult(False, error=str(exc))
        body = json.dumps(self._payload(alert), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "marsadix"}
        if self._secret and self.name == "webhook":
            headers[SIGNATURE_HEADER] = sign_body(self._secret, body)
        return post_with_retry(self._client, self._url, body, headers, timeout=self._timeout,
                               max_attempts=self._max_attempts, sleep=self._sleep)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(configured={self.configured})"


class WebhookNotifier(_BaseWebhook):
    name = "webhook"
    builder = staticmethod(generic_payload)


class SlackNotifier(_BaseWebhook):
    name = "slack"
    builder = staticmethod(slack_payload)


class TeamsNotifier(_BaseWebhook):
    name = "teams"
    builder = staticmethod(teams_payload)
