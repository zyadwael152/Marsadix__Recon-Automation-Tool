"""Alert channel settings (env first, then the repository config object).

Environment variables (all optional):
  DISCORD_WEBHOOK_URL | DISCORD_WEBHOOK
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TO (comma list),
  SMTP_STARTTLS (true)
  WEBHOOK_URL, WEBHOOK_SECRET, SLACK_WEBHOOK_URL, TEAMS_WEBHOOK_URL
  MARSADIX_ALLOW_PRIVATE_WEBHOOKS=1   (opt in to private/loopback destinations)
  MARSADIX_ALERT_MIN_CONFIDENCE (low|medium|high; default medium)
  MARSADIX_ALERT_MIN_PRIORITY   (low|medium|high|critical; default high; KEV always alerts)

``config`` may be the existing ``marsadix.core.config`` settings object; attributes
``discord_webhook``, ``telegram_bot_token``, ``telegram_chat_id``, ``webhook_url`` and the
new ones (``smtp_host`` ... ``teams_webhook_url``) are read when the env var is unset.
Secrets are never included in ``describe()`` or ``repr``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .base import CHANNELS

__all__ = ["AlertSettings"]


def _bool(v: Any, default: bool) -> bool:
    if v is None or v == "":
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class AlertSettings:
    discord_webhook: str = field(default="", repr=False)
    telegram_bot_token: str = field(default="", repr=False)
    telegram_chat_id: str = field(default="", repr=False)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = field(default="", repr=False)
    smtp_password: str = field(default="", repr=False)
    smtp_from: str = ""
    smtp_to: List[str] = field(default_factory=list, repr=False)
    smtp_starttls: bool = True
    webhook_url: str = field(default="", repr=False)
    webhook_secret: str = field(default="", repr=False)
    slack_webhook_url: str = field(default="", repr=False)
    teams_webhook_url: str = field(default="", repr=False)
    allow_private_webhooks: bool = False
    min_confidence: str = "medium"
    min_priority: str = "high"

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, config: Any = None) -> "AlertSettings":
        env = os.environ if env is None else env

        def pick(env_names, attr, default=""):
            for n in env_names:
                if env.get(n):
                    return env[n]
            v = getattr(config, attr, None) if config is not None else None
            return default if v in (None, "") else v

        to_raw = pick(("SMTP_TO",), "smtp_to", "")
        to = [t.strip() for t in (to_raw if isinstance(to_raw, (list, tuple)) else str(to_raw).split(",")) if str(t).strip()]
        try:
            port = int(pick(("SMTP_PORT",), "smtp_port", 587))
        except (TypeError, ValueError):
            port = 587
        return cls(
            discord_webhook=str(pick(("DISCORD_WEBHOOK_URL", "DISCORD_WEBHOOK"), "discord_webhook")),
            telegram_bot_token=str(pick(("TELEGRAM_BOT_TOKEN",), "telegram_bot_token")),
            telegram_chat_id=str(pick(("TELEGRAM_CHAT_ID",), "telegram_chat_id")),
            smtp_host=str(pick(("SMTP_HOST",), "smtp_host")), smtp_port=port,
            smtp_user=str(pick(("SMTP_USER",), "smtp_user")), smtp_password=str(pick(("SMTP_PASSWORD",), "smtp_password")),
            smtp_from=str(pick(("SMTP_FROM",), "smtp_from")), smtp_to=to,
            smtp_starttls=_bool(pick(("SMTP_STARTTLS",), "smtp_starttls", None), True),
            webhook_url=str(pick(("WEBHOOK_URL",), "webhook_url")), webhook_secret=str(pick(("WEBHOOK_SECRET",), "webhook_secret")),
            slack_webhook_url=str(pick(("SLACK_WEBHOOK_URL",), "slack_webhook_url")),
            teams_webhook_url=str(pick(("TEAMS_WEBHOOK_URL",), "teams_webhook_url")),
            allow_private_webhooks=_bool(env.get("MARSADIX_ALLOW_PRIVATE_WEBHOOKS"), False),
            min_confidence=str(env.get("MARSADIX_ALERT_MIN_CONFIDENCE", "medium")).lower(),
            min_priority=str(env.get("MARSADIX_ALERT_MIN_PRIORITY", "high")).lower(),
        )

    def configured_channels(self) -> List[str]:
        ok = {
            "discord": bool(self.discord_webhook),
            "telegram": bool(self.telegram_bot_token and self.telegram_chat_id),
            "email": bool(self.smtp_host and self.smtp_from and self.smtp_to),
            "webhook": bool(self.webhook_url),
            "slack": bool(self.slack_webhook_url),
            "teams": bool(self.teams_webhook_url),
        }
        return [c for c in CHANNELS if ok[c]]

    def describe(self) -> Dict[str, str]:
        """Channel -> 'configured' / 'not configured' (never any secret value)."""
        on = set(self.configured_channels())
        return {c: ("configured" if c in on else "not configured") for c in CHANNELS}
