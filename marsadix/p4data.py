"""Read/write helpers over the stored recon data for the Person 4 modules.

Reads only already-stored data (no network, no probes).  For every host the rows
of the *latest scan that observed that host* are used so stale scans do not
produce stale findings.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .dbutil import columns, fetch_all, fetch_one, has_table, insert_row, update_row

__all__ = ["latest_per_host", "load_assets", "load_technologies", "load_services", "load_web_items",
           "load_findings", "load_cves", "asset_context", "upsert_finding", "latest_scan_id", "now_iso"]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _table(conn: sqlite3.Connection, table: str, where: str = "", params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    if not has_table(conn, table):
        return []
    order = " ORDER BY id" if "id" in columns(conn, table) else ""
    return fetch_all(conn, f'SELECT * FROM "{table}"{(" WHERE " + where) if where else ""}{order}', params)


def latest_per_host(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep only rows from the highest ``scan_id`` seen for each host (rows without scan_id are kept)."""
    best: Dict[str, int] = {}
    for r in rows:
        if r.get("scan_id") is not None:
            h = str(r.get("host", ""))
            best[h] = max(best.get(h, -1), int(r["scan_id"]))
    return [r for r in rows if r.get("scan_id") is None or int(r["scan_id"]) == best.get(str(r.get("host", "")), -1)]


def load_assets(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    return latest_per_host(_table(conn, "assets"))


def load_technologies(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    return latest_per_host(_table(conn, "technologies"))


def load_services(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    return latest_per_host(_table(conn, "services"))


def load_web_items(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    rows = latest_per_host(_table(conn, "web_items"))
    for r in rows:
        h = r.get("headers")
        if isinstance(h, str):
            try:
                h = json.loads(h)
            except ValueError:
                h = {}
        r["headers"] = {str(k).lower(): str(v) for k, v in (h or {}).items()} if isinstance(h, dict) else {}
    return rows


def load_findings(conn: sqlite3.Connection, *, source: Optional[str] = None, open_only: bool = False) -> List[Dict[str, Any]]:
    rows = _table(conn, "findings")
    if source and rows and "source" in rows[0]:
        rows = [r for r in rows if r.get("source") == source]
    if open_only:
        rows = [r for r in rows if str(r.get("status") or "open").lower() not in ("fixed", "resolved", "closed", "false_positive", "accepted")]
    return rows


def load_cves(conn: sqlite3.Connection, ids: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    if not has_table(conn, "cves"):
        return []
    if ids is None:
        return fetch_all(conn, "SELECT * FROM cves")
    ids = sorted({i.upper() for i in ids})
    out: List[Dict[str, Any]] = []
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        out.extend(fetch_all(conn, f"SELECT * FROM cves WHERE upper(cve_id) IN ({','.join('?' * len(chunk))})", chunk))
    return out


def asset_context(conn: sqlite3.Connection) -> Dict[str, Dict[str, Any]]:
    """host -> asset row (internet_facing / behind_cdn / criticality / cdn)."""
    return {str(r["host"]): r for r in load_assets(conn) if r.get("host")}


def latest_scan_id(conn: sqlite3.Connection) -> Optional[int]:
    if not has_table(conn, "scans"):
        return None
    r = fetch_one(conn, "SELECT max(id) AS m FROM scans")
    return int(r["m"]) if r and r["m"] is not None else None


def upsert_finding(conn: sqlite3.Connection, dedup_key: str, values: Dict[str, Any]) -> Dict[str, Any]:
    """Insert or refresh a finding keyed by ``dedup_key``.

    Existing rows keep their ``status`` (so a human-triaged finding is not re-opened) and
    ``first_seen``; scores/evidence are refreshed.  Returns ``{"id", "created"}``.
    """
    ts = now_iso()
    existing = fetch_one(conn, "SELECT id FROM findings WHERE dedup_key=?", (dedup_key,))
    if existing:
        refresh = {k: v for k, v in values.items() if k not in ("status", "first_seen", "created_at", "scan_id")}
        refresh["last_seen"] = ts
        update_row(conn, "findings", "id", existing["id"], refresh)
        return {"id": existing["id"], "created": False}
    row = dict(values)
    row.update(dedup_key=dedup_key, first_seen=ts, last_seen=ts)
    row.setdefault("created_at", ts)
    row.setdefault("status", "open")
    return {"id": insert_row(conn, "findings", row), "created": True}
