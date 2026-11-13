"""M11 - alert deduplication and delivery bookkeeping.

Policy (one row per dedup key in ``alerts``; ``dedup_key`` is UNIQUE)
---------------------------------------------------------------------
group key : ``cve:<cve_id>|host:<host>|product:<product>|channel:<channel>``

1. First time a (CVE, host, product, channel) is seen  -> alert with key = group key (``new``).
2. Same group already *delivered*                       -> never sent again.
3. Same group exists but delivery failed (delivered=0)  -> retried on the next run
   (``retry``) until ``MAX_ATTEMPTS`` total attempts, then left for manual review.
4. KEV transition: the group was alerted while the CVE was NOT in KEV and the CVE is
   now in KEV -> exactly one extra alert, key = group key + ``|event:kev``.
5. Priority escalation: the current priority level is *strictly higher* than the highest
   level ever recorded for the group AND is >= HIGH -> one alert per newly reached level,
   key = group key + ``|escalation:<level>``.  A level can fire only once per group, so
   flapping scores never spam.  When a KEV transition fires in the same run, the
   escalation to CRITICAL is folded into it (no second message).
6. ``delivered=1`` is written only after the channel reports success; failures keep
   ``delivered=0``, increment ``attempts`` and store a sanitized ``last_error``.
7. dry-run: ``plan`` is pure (reads only); nothing is written and nothing is sent.

``INSERT OR IGNORE`` on the UNIQUE ``dedup_key`` is the race-safe equivalent of the
repository's ``save_alert_if_new``.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from ..dbutil import fetch_all, fetch_one, insert_row, update_row
from .base import AlertPayload, DeliveryResult, Notifier

__all__ = ["MAX_ATTEMPTS", "group_key", "AlertAction", "plan_alert", "deliver", "process_alert", "LEVEL_RANK"]

MAX_ATTEMPTS = 10
LEVEL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _seg(v: Any) -> str:
    return re.sub(r"[|\s]+", "_", str(v or "").strip().lower())


def group_key(cve_id: str, host: str, product: str, channel: str) -> str:
    return f"cve:{str(cve_id).strip().upper()}|host:{_seg(host)}|product:{_seg(product)}|channel:{_seg(channel)}"


@dataclass
class AlertAction:
    channel: str
    dedup_key: str
    group: str
    kind: str                # new | kev_transition | escalation | retry
    exists: bool = False     # row already in DB (retry)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def plan_alert(conn: sqlite3.Connection, payload: AlertPayload, channel: str) -> Optional[AlertAction]:
    """Decide whether (and under which key) this alert should be sent. Read-only."""
    gk = group_key(payload.cve_id, payload.host, payload.product, channel)
    rows = fetch_all(conn, "SELECT dedup_key, delivered, kev, priority_level, attempts FROM alerts WHERE group_key=? OR dedup_key=?", (gk, gk))
    if not rows:
        return AlertAction(channel, gk, gk, "new")
    # 3. retries of undelivered rows (oldest key first = the base alert)
    for r in sorted(rows, key=lambda r: len(r["dedup_key"])):
        if not r["delivered"] and int(r["attempts"] or 0) < MAX_ATTEMPTS:
            return AlertAction(channel, r["dedup_key"], gk, "retry", exists=True)
    keys = {r["dedup_key"] for r in rows}
    # 4. KEV transition
    if payload.kev and not any(int(r["kev"] or 0) for r in rows):
        k = gk + "|event:kev"
        if k not in keys:
            return AlertAction(channel, k, gk, "kev_transition")
        return None
    # 5. escalation
    cur = LEVEL_RANK.get(payload.priority_level.lower(), 1)
    seen = max((LEVEL_RANK.get(str(r["priority_level"] or "low").lower(), 1) for r in rows), default=1)
    if cur >= LEVEL_RANK["high"] and cur > seen:
        k = f"{gk}|escalation:{payload.priority_level.lower()}"
        if k not in keys:
            return AlertAction(channel, k, gk, "escalation")
    return None


def _record(conn: sqlite3.Connection, action: AlertAction, payload: AlertPayload) -> bool:
    """Insert the alert row if the key is new (race-safe). Returns True if inserted."""
    row = {
        "dedup_key": action.dedup_key, "group_key": action.group, "channel": action.channel,
        "cve_id": payload.cve_id, "host": payload.host, "product": payload.product, "kind": action.kind,
        "kev": int(payload.kev), "priority_level": payload.priority_level.lower(), "priority_score": payload.priority_score,
        "delivered": 0, "attempts": 0, "created_at": _now(), "alert_type": "cve", "message": payload.title,
        "payload_json": json.dumps(payload.to_dict(), sort_keys=True),
    }
    before = conn.total_changes
    probe = fetch_one(conn, "SELECT id FROM alerts WHERE dedup_key=?", (action.dedup_key,))
    if probe:
        return False
    try:
        insert_row(conn, "alerts", row)
    except sqlite3.IntegrityError:
        return False
    return conn.total_changes > before


def deliver(conn: sqlite3.Connection, action: AlertAction, payload: AlertPayload, notifier: Notifier) -> DeliveryResult:
    """Send and update bookkeeping. ``delivered=1`` only on success."""
    if not action.exists:
        _record(conn, action, payload)
    payload.kind = action.kind
    try:
        result = notifier.send(payload)
    except Exception as exc:  # a notifier must never crash the monitor run
        result = DeliveryResult(False, error=f"notifier failure ({type(exc).__name__})")
    row = fetch_one(conn, "SELECT attempts FROM alerts WHERE dedup_key=?", (action.dedup_key,)) or {"attempts": 0}
    if result.ok:
        update_row(conn, "alerts", "dedup_key", action.dedup_key,
                   {"delivered": 1, "attempts": int(row["attempts"] or 0) + 1, "last_error": None,
                    "last_attempt_at": _now(), "sent_at": _now()})
    else:
        update_row(conn, "alerts", "dedup_key", action.dedup_key,
                   {"delivered": 0, "attempts": int(row["attempts"] or 0) + 1,
                    "last_error": (result.error or "send failed")[:200], "last_attempt_at": _now()})
    conn.commit()
    return result


def process_alert(conn: sqlite3.Connection, payload: AlertPayload, channel: str, notifier: Notifier, *,
                  dry_run: bool = False) -> Optional[Dict[str, Any]]:
    """Plan + (unless dry-run) deliver one alert on one channel.

    Returns ``None`` when deduplicated; otherwise ``{"action", "result"}`` (result is None in dry-run).
    """
    action = plan_alert(conn, payload, channel)
    if action is None:
        return None
    if dry_run:
        return {"action": action, "result": None}
    return {"action": action, "result": deliver(conn, action, payload, notifier)}
