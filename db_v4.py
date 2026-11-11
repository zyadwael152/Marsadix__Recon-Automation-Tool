"""Schema v3 -> v4 migration for the Person 4 scope (M11-M19).

``migrate_v3_to_v4`` is idempotent and data preserving (only CREATE IF NOT
EXISTS / ADD COLUMN).  Call it from the repository's migration chain and bump
``SCHEMA_VERSION`` to 4 in ``marsadix/db.py`` (see INTEGRATION.md).

v4 additions
------------
* ``remediation``           - M19 store (id, match_type, match_value, title, fix_text,
                              references JSON, effort, priority, created_at)
* ``attack_surface_scores`` - M17 history, one row per scan / monitor run
* ``monitor_runs``          - metadata for each ``marsadix monitor`` matching run
                              (also the documented answer to ``findings.scan_id``:
                              CVE findings keep the *latest scan that observed the
                              technology* in ``scan_id`` and additionally reference
                              ``monitor_run_id`` - no synthetic scan rows, FKs intact)
* ``alerts``  + columns     - group_key, channel, cve_id, host, product, kind, kev,
                              priority_level, priority_score, attempts, last_error,
                              last_attempt_at, sent_at, payload_json
* ``findings`` + columns    - dedup_key (partial UNIQUE index), source, cve_id, product,
                              version, cvss, epss, kev, confidence, priority_score,
                              risk_score, rule_id, owasp, remediation_key, evidence,
                              monitor_run_id, first_seen, last_seen
* ``assets`` + ``criticality`` (low|medium|high|critical, default medium)
"""
from __future__ import annotations

import sqlite3
from typing import Dict, List

from .dbutil import columns, has_table

__all__ = ["SCHEMA_VERSION", "migrate_v3_to_v4", "ensure_v4", "get_user_version"]

SCHEMA_VERSION = 4

_NEW_TABLES = [
    """CREATE TABLE IF NOT EXISTS remediation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_type TEXT NOT NULL CHECK (match_type IN ('skill','template','keyword','cve','cwe','owasp','product')),
        match_value TEXT NOT NULL,
        title TEXT NOT NULL,
        fix_text TEXT NOT NULL,
        "references" TEXT NOT NULL DEFAULT '[]',
        effort TEXT NOT NULL DEFAULT 'medium' CHECK (effort IN ('low','medium','high')),
        priority INTEGER NOT NULL DEFAULT 50,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_remediation_match ON remediation(match_type, match_value)",
    """CREATE TABLE IF NOT EXISTS attack_surface_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL DEFAULT '*',
        run_type TEXT NOT NULL DEFAULT 'monitor',
        run_ref INTEGER,
        score REAL NOT NULL,
        previous_score REAL,
        delta REAL,
        trend TEXT NOT NULL DEFAULT 'stable',
        reasons TEXT NOT NULL DEFAULT '[]',
        inputs TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    )""",
    "CREATE INDEX IF NOT EXISTS ix_asm_target ON attack_surface_scores(target, id)",
    """CREATE TABLE IF NOT EXISTS monitor_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
        finished_at TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        flags TEXT NOT NULL DEFAULT '{}',
        synced INTEGER NOT NULL DEFAULT 0,
        technologies INTEGER NOT NULL DEFAULT 0,
        cves_evaluated INTEGER NOT NULL DEFAULT 0,
        matches INTEGER NOT NULL DEFAULT 0,
        alerts_sent INTEGER NOT NULL DEFAULT 0,
        failures INTEGER NOT NULL DEFAULT 0,
        max_tech_id INTEGER NOT NULL DEFAULT 0
    )""",
]

_ALERT_COLS: Dict[str, str] = {
    "delivered": "INTEGER NOT NULL DEFAULT 0",
    "group_key": "TEXT", "channel": "TEXT", "cve_id": "TEXT", "host": "TEXT", "product": "TEXT",
    "kind": "TEXT", "kev": "INTEGER NOT NULL DEFAULT 0", "priority_level": "TEXT",
    "priority_score": "REAL", "attempts": "INTEGER NOT NULL DEFAULT 0", "last_error": "TEXT",
    "last_attempt_at": "TEXT", "sent_at": "TEXT", "payload_json": "TEXT",
}
_FINDING_COLS: Dict[str, str] = {
    "dedup_key": "TEXT", "source": "TEXT", "cve_id": "TEXT", "product": "TEXT", "version": "TEXT",
    "cvss": "REAL", "epss": "REAL", "kev": "INTEGER NOT NULL DEFAULT 0", "confidence": "TEXT",
    "priority_score": "REAL", "risk_score": "REAL", "rule_id": "TEXT", "owasp": "TEXT",
    "remediation_key": "TEXT", "evidence": "TEXT", "monitor_run_id": "INTEGER",
    "first_seen": "TEXT", "last_seen": "TEXT",
}


def get_user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _add_missing(conn: sqlite3.Connection, table: str, wanted: Dict[str, str]) -> List[str]:
    if not has_table(conn, table):
        return []
    have = columns(conn, table)
    added = []
    for name, ddl in wanted.items():
        if name not in have:
            conn.execute(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {ddl}')
            added.append(name)
    return added


def migrate_v3_to_v4(conn: sqlite3.Connection) -> None:
    """Idempotent, data-preserving migration. Commits on success, rolls back on error."""
    own_tx = not conn.in_transaction
    try:
        if own_tx:
            conn.execute("BEGIN")
        for ddl in _NEW_TABLES:
            conn.execute(ddl)
        _add_missing(conn, "alerts", _ALERT_COLS)
        _add_missing(conn, "findings", _FINDING_COLS)
        _add_missing(conn, "assets", {"criticality": "TEXT NOT NULL DEFAULT 'medium'"})
        if has_table(conn, "alerts"):
            conn.execute("CREATE INDEX IF NOT EXISTS ix_alerts_group ON alerts(group_key)")
        if has_table(conn, "findings"):
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_dedup ON findings(dedup_key) WHERE dedup_key IS NOT NULL")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_findings_cve ON findings(cve_id)")
        # keep any repo-level version bookkeeping in sync
        for table, col in (("schema_version", "version"), ("schema_meta", "version")):
            if has_table(conn, table) and col in columns(conn, table):
                conn.execute(f'UPDATE "{table}" SET "{col}"=?', (SCHEMA_VERSION,))
        if has_table(conn, "meta") and {"key", "value"} <= set(columns(conn, "meta")):
            conn.execute("UPDATE meta SET value=? WHERE key='schema_version'", (str(SCHEMA_VERSION),))
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        if own_tx:
            conn.commit()
    except Exception:
        if own_tx and conn.in_transaction:
            conn.rollback()
        raise


def ensure_v4(conn: sqlite3.Connection) -> None:
    """Run the migration when the database is older than v4 (or columns are missing)."""
    migrate_v3_to_v4(conn)
