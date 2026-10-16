"""
Marsadix database layer  (WHERE and HOW the data is stored).

models.py  = the shape of the data (Python classes).
db.py      = the SQLite tables + functions that save / load those classes.
marsadix.db= the actual file created when you run init_db(). Never commit it.

Other modules should call the helpers here instead of writing SQL by hand.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Iterable, Optional

from .models import (
    Alert, Asset, CVE, Finding, MonitorState, Scan, Service, Technology,
    TrackedAsset, WebItem, Email, utcnow,
)

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',
    is_baseline   INTEGER NOT NULL DEFAULT 0,
    max_depth     INTEGER NOT NULL DEFAULT 2,
    scope_file    TEXT,
    rate_limit    INTEGER
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL, ip TEXT,
    in_scope INTEGER NOT NULL DEFAULT 0,
    is_cdn INTEGER NOT NULL DEFAULT 0,
    cdn_name TEXT, asn TEXT, asn_owner TEXT,
    depth INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL, parent_host TEXT, first_seen TEXT NOT NULL,
    UNIQUE (scan_id, host)
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL, ip TEXT, port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    name TEXT, product TEXT, version TEXT, banner TEXT, cpe TEXT,
    UNIQUE (scan_id, host, port, protocol)
);

CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL, name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    cpe TEXT, category TEXT, source TEXT,
    confidence TEXT NOT NULL DEFAULT 'possible',
    UNIQUE (scan_id, host, name, version)
);

CREATE TABLE IF NOT EXISTS web_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL, url TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'url',
    source TEXT, status_code INTEGER, parent_url TEXT,
    has_params INTEGER NOT NULL DEFAULT 0,
    UNIQUE (scan_id, url, kind)
);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address TEXT NOT NULL, source TEXT,
    UNIQUE (scan_id, address)
);

-- memory across scans (new-subdomain monitoring)
CREATE TABLE IF NOT EXISTS tracked_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL, host TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    last_scan_id INTEGER,
    UNIQUE (target, host)
);

CREATE TABLE IF NOT EXISTS monitor_state (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY, description TEXT, cvss_score REAL,
    severity TEXT NOT NULL DEFAULT 'info',
    published TEXT, modified TEXT,
    cpe_matches TEXT,            -- JSON
    in_kev INTEGER NOT NULL DEFAULT 0,
    refs TEXT                    -- JSON
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'nuclei',
    cve_id TEXT, title TEXT, template_id TEXT, url TEXT,
    technology TEXT, port INTEGER,
    severity TEXT NOT NULL DEFAULT 'info',
    confidence TEXT NOT NULL DEFAULT 'possible',
    evidence TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    verification_method TEXT,
    in_kev INTEGER NOT NULL DEFAULT 0,
    found_at TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    UNIQUE (scan_id, dedup_key)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    host TEXT NOT NULL,
    cve_id TEXT, technology TEXT, version TEXT,
    title TEXT, details TEXT,
    confidence TEXT NOT NULL DEFAULT 'possible',
    priority TEXT NOT NULL DEFAULT 'low',
    channel TEXT NOT NULL,
    created_at TEXT NOT NULL, sent_at TEXT,
    delivered INTEGER NOT NULL DEFAULT 0,
    dedup_key TEXT NOT NULL UNIQUE      -- never alert twice
);

CREATE INDEX IF NOT EXISTS idx_assets_scan   ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_tech_name     ON technologies(name, version);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target  ON scans(target, started_at);
"""

# model field name -> DB column name (when they differ)
_COLMAP = {"cves": {"references": "refs"}}


def connect(path: str = "marsadix.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()


# ---------------------------------------------------------------- generic save

def _save(conn, table: str, model, replace: bool = False) -> Optional[int]:
    """Insert a model. Duplicates are silently skipped (returns None)."""
    d = model.to_dict()
    if d.get("id") is None:
        d.pop("id", None)
    cmap = _COLMAP.get(table, {})
    row = {}
    for k, v in d.items():
        if isinstance(v, (list, dict)):
            v = json.dumps(v)
        if table == "technologies" and k == "version" and v is None:
            v = ""                      # so UNIQUE works for "no version"
        row[cmap.get(k, k)] = v
    cols = ", ".join(row)
    qs = ", ".join("?" for _ in row)
    verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
    cur = conn.execute(f"{verb} INTO {table} ({cols}) VALUES ({qs})", list(row.values()))
    return cur.lastrowid if cur.rowcount else None


def save_scan(conn, scan: Scan) -> int:
    scan.id = _save(conn, "scans", scan)
    conn.commit()
    return scan.id


def finish_scan(conn, scan_id: int, status: str = "completed") -> None:
    conn.execute("UPDATE scans SET status=?, finished_at=? WHERE id=?",
                 (status, utcnow(), scan_id))
    conn.commit()


def save_many(conn, table: str, models: Iterable) -> int:
    """Bulk save (assets, services, technologies, web_items, emails, findings)."""
    n = 0
    for m in models:
        if _save(conn, table, m) is not None:
            n += 1
    conn.commit()
    return n


def save_cve(conn, cve: CVE) -> None:
    _save(conn, "cves", cve, replace=True)      # CVEs get updated by NVD
    conn.commit()


# ------------------------------------------------------------------ monitor state

def get_state(conn, key: str) -> Optional[str]:
    r = conn.execute("SELECT value FROM monitor_state WHERE key=?", (key,)).fetchone()
    return r["value"] if r else None


def set_state(conn, key: str, value: str) -> None:
    _save(conn, "monitor_state", MonitorState(key=key, value=value), replace=True)
    conn.commit()


# ------------------------------------------------------------------------ alerts

def save_alert_if_new(conn, alert: Alert) -> bool:
    """True if this alert is new (send it). False if already alerted before."""
    new = _save(conn, "alerts", alert) is not None
    conn.commit()
    return new


def mark_alert_sent(conn, dedup_key: str) -> None:
    conn.execute("UPDATE alerts SET delivered=1, sent_at=? WHERE dedup_key=?",
                 (utcnow(), dedup_key))
    conn.commit()


# ------------------------------------------------- new-subdomain tracking (diff)

def update_tracked_assets(conn, target: str, hosts: Iterable[str], scan_id: int):
    """
    Call after each scan with the hosts found (resolved + in scope).
    Returns (new_hosts, disappeared_hosts, is_baseline).
    First ever scan of a target = baseline: nothing is reported as 'new'.
    """
    hosts = set(hosts)
    now = utcnow()
    known = {r["host"] for r in conn.execute(
        "SELECT host FROM tracked_assets WHERE target=?", (target,))}
    is_baseline = len(known) == 0

    new_hosts = sorted(hosts - known)
    for h in new_hosts:
        _save(conn, "tracked_assets",
              TrackedAsset(target=target, host=h, first_seen=now,
                           last_seen=now, last_scan_id=scan_id))
    for h in hosts & known:
        conn.execute("UPDATE tracked_assets SET last_seen=?, is_active=1, last_scan_id=? "
                     "WHERE target=? AND host=?", (now, scan_id, target, h))
    gone = sorted(known - hosts)
    for h in gone:
        conn.execute("UPDATE tracked_assets SET is_active=0 WHERE target=? AND host=?",
                     (target, h))
    conn.commit()
    return ([] if is_baseline else new_hosts), gone, is_baseline


# ------------------------------------------------------------------------- reads

def get_technologies(conn, scan_id: Optional[int] = None) -> list[sqlite3.Row]:
    """All stored technologies (latest data per host/name) - what the CVE monitor watches."""
    if scan_id is not None:
        return conn.execute("SELECT * FROM technologies WHERE scan_id=?", (scan_id,)).fetchall()
    return conn.execute(
        "SELECT t.* FROM technologies t JOIN (SELECT host, name, MAX(scan_id) s "
        "FROM technologies GROUP BY host, name) m "
        "ON t.host=m.host AND t.name=m.name AND t.scan_id=m.s").fetchall()


def get_assets(conn, scan_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM assets WHERE scan_id=?", (scan_id,)).fetchall()
