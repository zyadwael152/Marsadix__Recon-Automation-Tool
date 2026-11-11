"""Build notifiers from settings."""
from __future__ import annotations

import time
from typing import Callable, Dict, Iterable, List, Optional

from .base import CHANNELS, Notifier
from .discord import DiscordNotifier
from .email import EmailNotifier
from .http import HttpClient
from .settings import AlertSettings
from .telegram import TelegramNotifier
from .webhook import SlackNotifier, TeamsNotifier, WebhookNotifier

__all__ = ["build_notifiers", "UnknownChannel"]


class UnknownChannel(ValueError):
    """Raised for invalid input."""


def build_notifiers(settings: AlertSettings, channels: Optional[Iterable[str]] = None, *,
                    client: Optional[HttpClient] = None, smtp_factory: Optional[Callable] = None,
                    resolver: Optional[Callable] = None, sleep: Callable[[float], None] = time.sleep) -> Dict[str, Notifier]:
    """Return ``{channel: notifier}`` for the requested channels (default: every configured one).

    Requesting a channel that is not configured raises nothing - it is simply omitted,
    callers report it via ``AlertSettings.describe()``.
    """
    wanted: List[str]
    if channels:
        wanted = []
        for c in channels:
            c = c.strip().lower()
            if c not in CHANNELS:
                raise UnknownChannel(f"unknown channel {c!r}; expected one of {', '.join(CHANNELS)}")
            if c not in wanted:
                wanted.append(c)
    else:
        wanted = settings.configured_channels()
    common = dict(client=client, sleep=sleep)
    hook = dict(allow_private=settings.allow_private_webhooks, resolver=resolver, **common)
    make = {
        "discord": lambda: DiscordNotifier(settings.discord_webhook, **common),
        "telegram": lambda: TelegramNotifier(settings.telegram_bot_token, settings.telegram_chat_id, **common),
        "email": lambda: EmailNotifier(settings.smtp_host, settings.smtp_port, settings.smtp_from, settings.smtp_to,
                                       user=settings.smtp_user, password=settings.smtp_password,
                                       starttls=settings.smtp_starttls, smtp_factory=smtp_factory),
        "webhook": lambda: WebhookNotifier(settings.webhook_url, secret=settings.webhook_secret, **hook),
        "slack": lambda: SlackNotifier(settings.slack_webhook_url, **hook),
        "teams": lambda: TeamsNotifier(settings.teams_webhook_url, **hook),
    }
    out: Dict[str, Notifier] = {}
    for c in wanted:
        n = make[c]()
        if n.configured:
            out[c] = n
    return out
