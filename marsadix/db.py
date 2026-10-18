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
    Alert, Asset, AssetSource, CVE, Finding, MonitorState, Scan, Service,
    Technology, TrackedAsset, WebItem, Email, utcnow,
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
    rate_limit    INTEGER,
    mode          TEXT NOT NULL DEFAULT 'passive'
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
    confidence_score INTEGER NOT NULL DEFAULT 0,
    UNIQUE (scan_id, host)
);

-- Which tool/API found each host. Many rows per (scan_id, host) = higher
-- confidence the subdomain really exists. (R3 / R4)
CREATE TABLE IF NOT EXISTS asset_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    source_name TEXT NOT NULL,
    found_at TEXT NOT NULL,
    UNIQUE (scan_id, host, source_name)
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
    epss_score REAL,
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
    owasp_category TEXT,
    source_reference TEXT,
    status TEXT NOT NULL DEFAULT 'no_indicators',
    exploited INTEGER NOT NULL DEFAULT 0,
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

-- Knowledge Graph (G1): generic nodes/edges so any entity type can be linked
-- without a schema change per relationship kind.
CREATE TABLE IF NOT EXISTS graph_nodes (
    id TEXT PRIMARY KEY,              -- e.g. "subdomain:api.example.com", "cve:CVE-2024-1234"
    node_type TEXT NOT NULL,          -- subdomain | ip | asn | cdn | port | service |
                                       -- technology | cpe | cve | finding | email | js_file |
                                       -- endpoint | certificate | org
    label TEXT NOT NULL,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    attrs TEXT                        -- JSON blob of extra attributes
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_id TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    dst_id TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    relation TEXT NOT NULL,           -- resolves_to | belongs_to | behind | exposes |
                                       -- runs | has_cpe | affected_by | uses | serves |
                                       -- contains | shares_cert_with | found_on | listed_in
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    UNIQUE (src_id, dst_id, relation, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_assets_scan   ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_asset_sources ON asset_sources(scan_id, host);
CREATE INDEX IF NOT EXISTS idx_tech_name     ON technologies(name, version);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_owasp ON findings(owasp_category);
CREATE INDEX IF NOT EXISTS idx_scans_target  ON scans(target, started_at);
CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(src_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(dst_id);

-- One row, tracks which SCHEMA_VERSION this file was created/migrated at.
CREATE TABLE IF NOT EXISTS schema_info (version INTEGER NOT NULL);
"""

# model field name -> DB column name (when they differ)
_COLMAP = {"cves": {"references": "refs"}}

# schema version: bump this whenever SCHEMA_SQL changes, and tell the team
# to delete their local marsadix.db (see TEAM_GUIDE.md step 15).
SCHEMA_VERSION = 2

# A column that was added in SCHEMA_VERSION 2. If a db file already has a
# `findings` table but THIS column is missing, it predates the schema_info
# table itself -- the only way to tell "genuinely brand new db" apart from
# "old db created before versioning existed".
_V2_MARKER_COLUMN = ("findings", "owasp_category")


class SchemaVersionError(RuntimeError):
    """Raised when marsadix.db was created by an older/newer code version."""


def connect(path: str = "marsadix.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return any(r["name"] == column for r in conn.execute(f"PRAGMA table_info({table})"))


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


_OUT_OF_DATE_MSG = (
    "Delete the local database file and re-run your scans:\n"
    "  Remove-Item marsadix.db      (PowerShell)\n"
    "  rm marsadix.db               (Linux / macOS)"
)


def init_db(conn: sqlite3.Connection) -> None:
    """
    Create any missing tables, then make sure this file's schema actually
    matches SCHEMA_VERSION. CREATE TABLE IF NOT EXISTS never alters an
    existing table, so a db created by older code would otherwise fail much
    later with a confusing `sqlite3.OperationalError: no such column` deep
    inside some unrelated save/read call -- or even inside this function's
    own executescript(), since SCHEMA_SQL also creates an index on that
    column. So the compatibility check below runs BEFORE executescript(),
    not after, to fail fast with an actionable message instead of a raw
    sqlite3 traceback.
    """
    table, column = _V2_MARKER_COLUMN
    if _table_exists(conn, table) and not _has_column(conn, table, column):
        raise SchemaVersionError(
            f"This database predates schema v{SCHEMA_VERSION} "
            f"(missing column '{table}.{column}').\n{_OUT_OF_DATE_MSG}")

    conn.executescript(SCHEMA_SQL)
    conn.commit()

    row = conn.execute("SELECT version FROM schema_info").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_info (version) VALUES (?)", (SCHEMA_VERSION,))
        conn.commit()
    elif row["version"] != SCHEMA_VERSION:
        raise SchemaVersionError(
            f"This database is schema v{row['version']}, but the installed code "
            f"expects v{SCHEMA_VERSION}.\n{_OUT_OF_DATE_MSG}")


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


# ------------------------------------------------------------- asset sources (R3/R4)

def save_asset_source(conn, scan_id: int, host: str, source_name: str) -> None:
    """Record that `source_name` found `host`. Call once per source per host."""
    _save(conn, "asset_sources",
          AssetSource(scan_id=scan_id, host=host, source_name=source_name))
    conn.commit()


def save_asset_sources_many(conn, scan_id: int, host: str, source_names: Iterable[str]) -> None:
    for name in source_names:
        _save(conn, "asset_sources",
              AssetSource(scan_id=scan_id, host=host, source_name=name))
    conn.commit()


def get_asset_sources(conn, scan_id: int, host: str) -> list[str]:
    """Every source name that found this host in this scan. (R4)"""
    rows = conn.execute(
        "SELECT source_name FROM asset_sources WHERE scan_id=? AND host=?",
        (scan_id, host)).fetchall()
    return [r["source_name"] for r in rows]


def get_asset_confidence(conn, scan_id: int, host: str) -> dict:
    """{'sources': [...], 'count': n} for a host. (R4)"""
    sources = get_asset_sources(conn, scan_id, host)
    return {"sources": sources, "count": len(sources)}


def get_source_coverage(conn, scan_id: int) -> dict:
    """
    How many hosts each source found, and how many hosts were found by only
    ONE source (useful for the Missing Asset Hunter, R17/R20).
    """
    rows = conn.execute(
        "SELECT source_name, COUNT(DISTINCT host) AS n "
        "FROM asset_sources WHERE scan_id=? GROUP BY source_name", (scan_id,)).fetchall()
    per_source = {r["source_name"]: r["n"] for r in rows}

    single = conn.execute(
        "SELECT host FROM asset_sources WHERE scan_id=? "
        "GROUP BY host HAVING COUNT(DISTINCT source_name) = 1", (scan_id,)).fetchall()
    return {"per_source": per_source, "single_source_hosts": [r["host"] for r in single]}


# -------------------------------------------------------------- OWASP coverage (M20)

def get_owasp_coverage(conn, scan_id: int) -> dict:
    """Coverage % + per-category finding counts for one scan. (M20)"""
    from .owasp import ALL_CATEGORIES

    rows = conn.execute(
        "SELECT owasp_category, COUNT(*) AS n FROM findings "
        "WHERE scan_id=? AND owasp_category IS NOT NULL "
        "GROUP BY owasp_category", (scan_id,)).fetchall()
    breakdown = {r["owasp_category"]: r["n"] for r in rows}
    covered = len(breakdown)
    total = len(ALL_CATEGORIES)
    return {
        "coverage_pct": round(covered / total * 100, 1) if total else 0.0,
        "covered_categories": covered,
        "total_categories": total,
        "breakdown": breakdown,
    }


# ------------------------------------------------------------- graph storage (G1)

def upsert_graph_node(conn, node_id: str, node_type: str, label: str,
                       scan_id: Optional[int] = None, attrs: Optional[dict] = None) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO graph_nodes (id, node_type, label, scan_id, attrs) "
        "VALUES (?, ?, ?, ?, ?)",
        (node_id, node_type, label, scan_id, json.dumps(attrs or {})))
    conn.commit()


def add_graph_edge(conn, src_id: str, dst_id: str, relation: str,
                    scan_id: Optional[int] = None) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO graph_edges (src_id, dst_id, relation, scan_id) "
        "VALUES (?, ?, ?, ?)",
        (src_id, dst_id, relation, scan_id))
    conn.commit()


def get_graph(conn, scan_id: int) -> dict:
    """All nodes and edges for one scan, ready to hand to a visualizer."""
    nodes = conn.execute(
        "SELECT id, node_type, label, attrs FROM graph_nodes WHERE scan_id=?",
        (scan_id,)).fetchall()
    edges = conn.execute(
        "SELECT src_id, dst_id, relation FROM graph_edges WHERE scan_id=?",
        (scan_id,)).fetchall()
    return {
        "nodes": [dict(n) for n in nodes],
        "edges": [dict(e) for e in edges],
    }


def get_neighbors(conn, node_id: str, scan_id: Optional[int] = None) -> list[dict]:
    """Direct neighbors of one node, for blast-radius / attack-path queries (G3/G4)."""
    q = ("SELECT dst_id AS id, relation, 'out' AS direction FROM graph_edges "
         "WHERE src_id=?" + (" AND scan_id=?" if scan_id else "") +
         " UNION ALL "
         "SELECT src_id AS id, relation, 'in' AS direction FROM graph_edges "
         "WHERE dst_id=?" + (" AND scan_id=?" if scan_id else ""))
    params = ([node_id, scan_id, node_id, scan_id] if scan_id
              else [node_id, node_id])
    rows = conn.execute(q, params).fetchall()
    return [dict(r) for r in rows]


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


def get_services(conn, scan_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM services WHERE scan_id=?", (scan_id,)).fetchall()


def get_web_items(conn, scan_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM web_items WHERE scan_id=?", (scan_id,)).fetchall()


def get_findings(conn, scan_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()


def get_cves(conn) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM cves").fetchall()


def get_pending_alerts(conn) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM alerts WHERE delivered=0").fetchall()


def get_latest_scans(conn, target: str, limit: int = 2) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM scans WHERE target=? ORDER BY started_at DESC LIMIT ?",
        (target, limit)).fetchall()
