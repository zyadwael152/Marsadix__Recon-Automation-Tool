"""M12 - Discord webhook sender (rich embed)."""
from __future__ import annotations

import json
import time
from typing import Callable, Dict, List, Optional

from .base import AlertPayload, DeliveryResult, fmt_score, truncate
from .http import DEFAULT_TIMEOUT, HttpClient, UrllibClient, post_with_retry

__all__ = ["DiscordNotifier", "build_payload", "COLORS", "LIMITS"]

COLORS = {"critical": 0xB71C1C, "high": 0xE65100, "medium": 0xF9A825, "low": 0x1E88E5}
LIMITS = {"title": 256, "description": 2048, "field_name": 256, "field_value": 1024, "fields": 25,
          "footer": 2048, "embed_total": 6000}


def _field(name: str, value: str, inline: bool = True) -> Dict:
    return {"name": truncate(name, LIMITS["field_name"]), "value": truncate(value or "-", LIMITS["field_value"]) or "-", "inline": inline}


def build_payload(a: AlertPayload) -> Dict:
    tech = " ".join(x for x in (a.technology or a.product, a.version) if x) or "-"
    fields = [
        _field("Host", a.host), _field("CVE", a.cve_id), _field("Technology", tech),
        _field("Version", a.version or "unknown"), _field("CVSS", fmt_score(a.cvss)),
        _field("EPSS", fmt_score(a.epss, 3)), _field("KEV", "YES" if a.kev else "no"),
        _field("Confidence", a.confidence), _field("Priority", f"{a.priority_level.upper()} ({a.priority_score:.1f})"),
    ]
    if a.risk_score is not None:
        fields.append(_field("Risk", f"{a.risk_score:.1f}"))
    rem = (a.remediation_title + ": " if a.remediation_title else "") + (a.remediation_text or "No remediation available")
    fields.append(_field("Remediation", rem, inline=False))
    embed = {
        "title": truncate(a.title, LIMITS["title"]),
        "description": truncate(a.description or "No description available.", LIMITS["description"]),
        "color": COLORS.get(a.priority_level.lower(), COLORS["low"]),
        "fields": fields[: LIMITS["fields"]],
        "footer": {"text": truncate("Marsadix CVE monitor" + (" - " + a.kind.replace("_", " ") if a.kind != "new" else ""), LIMITS["footer"])},
    }
    # enforce the 6000 character embed total by shrinking the description, then remediation
    def total(e: Dict) -> int:
        return (len(e["title"]) + len(e["description"]) + len(e["footer"]["text"]) +
                sum(len(f["name"]) + len(f["value"]) for f in e["fields"]))
    while total(embed) > LIMITS["embed_total"] and len(embed["description"]) > 50:
        embed["description"] = truncate(embed["description"], len(embed["description"]) - 200)
    return {"username": "Marsadix", "allowed_mentions": {"parse": []}, "embeds": [embed]}


_DISCORD_HOSTS = ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")


def is_discord_webhook_url(url: str) -> bool:
    """Alerts carry CVE / host details, so only ever send them to a real Discord webhook."""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url.strip())
        return (u.scheme == "https" and (u.hostname or "").lower() in _DISCORD_HOSTS
                and u.path.startswith("/api/webhooks/") and not u.username and u.port in (None, 443))
    except ValueError:
        return False


class DiscordNotifier:
    name = "discord"

    def __init__(self, webhook_url: str, *, client: Optional[HttpClient] = None, timeout: float = DEFAULT_TIMEOUT,
                 max_attempts: int = 4, sleep: Callable[[float], None] = time.sleep):
        self._url = webhook_url or ""
        self._client = client or UrllibClient()
        self._timeout, self._max_attempts, self._sleep = timeout, max_attempts, sleep

    @property
    def configured(self) -> bool:
        return bool(self._url)

    def send(self, alert: AlertPayload) -> DeliveryResult:
        if not self.configured:
            return DeliveryResult(False, error="discord not configured", skipped=True)
        if not is_discord_webhook_url(self._url):
            return DeliveryResult(False, error="DISCORD_WEBHOOK_URL is not a https://discord.com/api/webhooks/... URL; "
                                                "refusing to send alert data anywhere else")
        body = json.dumps(build_payload(alert), ensure_ascii=False).encode("utf-8")
        return post_with_retry(self._client, self._url, body, {"Content-Type": "application/json", "User-Agent": "marsadix"},
                               timeout=self._timeout, max_attempts=self._max_attempts, sleep=self._sleep)

    def __repr__(self) -> str:
        return "DiscordNotifier(configured=%s)" % self.configured
