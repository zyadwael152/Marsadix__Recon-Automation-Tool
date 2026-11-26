"""Instant Discord + Telegram messages for asset changes (new / removed subdomain, new open port).

The CVE notifiers expect a CVE-shaped AlertPayload, so asset changes use this small sender instead. It reads
the same settings (DISCORD_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID) and the same retrying HTTP
helper. It never raises: a failed send must not break a scan.
"""
import html
import json
import logging
import time
from datetime import datetime, timezone

from .discord import is_discord_webhook_url
from .http import UrllibClient, post_with_retry
from .settings import AlertSettings

log = logging.getLogger(__name__)

_TITLES = {
    "new_asset": "🆕 New asset",
    "removed_asset": "⚠️ Asset no longer seen",
    "new_port": "🔓 New open port",
}


def notify_asset(kind, host, details="", settings=None):
    """Send one asset message to every configured channel. True if at least one channel accepted it."""
    settings = settings or AlertSettings.from_env()
    client = UrllibClient()
    head = _TITLES.get(kind, "Asset change")
    text = f"{head}: {host}\n{details}".strip()
    sent = False
    if settings.discord_webhook and is_discord_webhook_url(settings.discord_webhook):
        body = json.dumps({"content": text[:1900]}, ensure_ascii=False).encode("utf-8")
        r = post_with_retry(client, settings.discord_webhook, body,
                            {"Content-Type": "application/json", "User-Agent": "marsadix"},
                            timeout=10, max_attempts=3, sleep=time.sleep)
        sent = sent or r.ok
        if not r.ok:
            log.warning("asset alert: discord failed (%s)", r.error)
    if settings.telegram_bot_token and settings.telegram_chat_id:
        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
        body = json.dumps({"chat_id": str(settings.telegram_chat_id), "text": html.escape(text)[:3900],
                           "disable_web_page_preview": True}).encode("utf-8")
        r = post_with_retry(client, url, body, {"Content-Type": "application/json"},
                            timeout=10, max_attempts=3, sleep=time.sleep)
        sent = sent or r.ok
        if not r.ok:
            log.warning("asset alert: telegram failed (%s)", r.error)
    return sent


def push(conn, alert, kind):
    """Send a just-saved alert right away and mark it delivered in the database on success."""
    try:
        if notify_asset(kind, alert.host, alert.details):
            conn.execute("UPDATE alerts SET delivered=1, sent_at=? WHERE dedup_key=?",
                         (datetime.now(timezone.utc).isoformat(), alert.dedup_key))
            conn.commit()
    except Exception:
        log.warning("asset alert for %s could not be sent", getattr(alert, "host", "?"), exc_info=True)
