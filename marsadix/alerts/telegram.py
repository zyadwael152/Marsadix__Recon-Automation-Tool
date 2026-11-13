"""M14 - Telegram Bot API sender (HTML parse mode, all dynamic text escaped)."""
from __future__ import annotations

import html
import json
import time
from typing import Callable, List, Optional

from .base import AlertPayload, DeliveryResult, fmt_score, truncate
from .http import DEFAULT_TIMEOUT, HttpClient, HttpResponse, UrllibClient, post_with_retry

__all__ = ["TelegramNotifier", "build_lines", "split_message", "MAX_LEN"]

MAX_LEN = 4096
_SAFE = 3900  # headroom below the hard limit


def esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=False)


def build_lines(a: AlertPayload) -> List[str]:
    tech = " ".join(x for x in (a.technology or a.product, a.version) if x) or "-"
    rem = (a.remediation_title + ": " if a.remediation_title else "") + (a.remediation_text or "n/a")
    return [
        f"<b>{esc(truncate(a.title, 300))}</b>",
        f"<b>Priority:</b> {esc(a.priority_level.upper())} ({a.priority_score:.1f})" + ("  🔥 <b>KEV</b>" if a.kev else ""),
        f"<b>Technology:</b> {esc(truncate(tech, 200))}",
        f"<b>CVSS:</b> {esc(fmt_score(a.cvss))}  <b>EPSS:</b> {esc(fmt_score(a.epss, 3))}  <b>Confidence:</b> {esc(a.confidence)}",
        f"<b>Description:</b> {esc(truncate(a.description, 600))}",
        f"<b>Remediation:</b> {esc(truncate(rem, 900))}",
    ]


def split_message(lines: List[str], limit: int = _SAFE) -> List[str]:
    """Join already-escaped, self-contained HTML lines into chunks <= limit characters."""
    chunks, cur = [], ""
    for line in lines:
        if len(line) > limit:  # should not happen (values are truncated) - hard cut on a tag-free boundary
            line = html.escape(html.unescape(re_strip_tags(line))[: limit // 2], quote=False)
        if cur and len(cur) + 1 + len(line) > limit:
            chunks.append(cur)
            cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur:
        chunks.append(cur)
    return chunks


def re_strip_tags(s: str) -> str:
    import re
    return re.sub(r"</?[a-z]+>", "", s)


def _validate(resp: HttpResponse) -> Optional[str]:
    try:
        data = resp.json()
    except ValueError:
        return "malformed response"
    if not isinstance(data, dict) or data.get("ok") is not True:
        return "telegram reported failure"
    return None


class TelegramNotifier:
    name = "telegram"

    def __init__(self, bot_token: str, chat_id: str, *, client: Optional[HttpClient] = None,
                 timeout: float = DEFAULT_TIMEOUT, max_attempts: int = 4, sleep: Callable[[float], None] = time.sleep):
        self._token, self._chat = bot_token or "", str(chat_id or "")
        self._client = client or UrllibClient()
        self._timeout, self._max_attempts, self._sleep = timeout, max_attempts, sleep

    @property
    def configured(self) -> bool:
        return bool(self._token and self._chat)

    def send(self, alert: AlertPayload) -> DeliveryResult:
        if not self.configured:
            return DeliveryResult(False, error="telegram not configured", skipped=True)
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        last = DeliveryResult(False, error="nothing sent")
        attempts = 0
        for chunk in split_message(build_lines(alert)):
            body = json.dumps({"chat_id": self._chat, "text": chunk, "parse_mode": "HTML",
                               "disable_web_page_preview": True}).encode("utf-8")
            last = post_with_retry(self._client, url, body, {"Content-Type": "application/json"}, timeout=self._timeout,
                                   max_attempts=self._max_attempts, sleep=self._sleep, validate=_validate)
            attempts += last.attempts
            if not last.ok:
                break
        last.attempts = attempts
        return last

    def __repr__(self) -> str:
        return "TelegramNotifier(configured=%s)" % self.configured
