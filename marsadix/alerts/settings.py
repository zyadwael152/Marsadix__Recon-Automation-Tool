"""Alert channel settings (env first, then the repository config object).

Environment variables (all optional):
  DISCORD_WEBHOOK_URL | DISCORD_WEBHOOK
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  MARSADIX_ALERT_MIN_CONFIDENCE (low|medium|high; default medium)
  MARSADIX_ALERT_MIN_PRIORITY   (low|medium|high|critical; default high; KEV always alerts)

``config`` may be the existing ``marsadix.core.config`` settings object; attributes
``discord_webhook``, ``telegram_bot_token`` and ``telegram_chat_id`` are read when the env var is unset.
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

        return cls(
            discord_webhook=str(pick(("DISCORD_WEBHOOK_URL", "DISCORD_WEBHOOK"), "discord_webhook")),
            telegram_bot_token=str(pick(("TELEGRAM_BOT_TOKEN",), "telegram_bot_token")),
            telegram_chat_id=str(pick(("TELEGRAM_CHAT_ID",), "telegram_chat_id")),
            min_confidence=str(env.get("MARSADIX_ALERT_MIN_CONFIDENCE", "medium")).lower(),
            min_priority=str(env.get("MARSADIX_ALERT_MIN_PRIORITY", "high")).lower(),
        )

    def configured_channels(self) -> List[str]:
        ok = {
            "discord": bool(self.discord_webhook),
            "telegram": bool(self.telegram_bot_token and self.telegram_chat_id),
        }
        return [c for c in CHANNELS if ok[c]]

    def describe(self) -> Dict[str, str]:
        """Channel -> 'configured' / 'not configured' (never any secret value)."""
        on = set(self.configured_channels())
        return {c: ("configured" if c in on else "not configured") for c in CHANNELS}
