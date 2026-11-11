"""Scaffold v3 schema used by the tests.

This mirrors the tables named in the task description (scans, assets, services,
technologies, web_items, findings, alerts, cves, monitor_state).  The exact
columns of the real repository may differ - the Person 4 modules introspect
columns, so only the columns listed in INTEGRATION.md are required.
"""
import json
import sqlite3

import pytest

V3_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, started_at TEXT, finished_at TEXT, status TEXT);
CREATE TABLE assets (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id), host TEXT NOT NULL,
    ip TEXT, internet_facing INTEGER DEFAULT 1, behind_cdn INTEGER DEFAULT 0, cdn TEXT);
CREATE TABLE services (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id), host TEXT NOT NULL,
    port INTEGER, protocol TEXT DEFAULT 'tcp', service TEXT, banner TEXT, state TEXT DEFAULT 'open',
    tls_version TEXT, tls_not_after TEXT, tls_expired INTEGER);
CREATE TABLE technologies (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id), host TEXT NOT NULL,
    name TEXT, version TEXT, cpe TEXT, source TEXT, confidence TEXT);
CREATE TABLE web_items (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id), host TEXT NOT NULL,
    url TEXT, status_code INTEGER, title TEXT, headers TEXT, body TEXT, content_type TEXT, origin TEXT);
CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id), host TEXT,
    title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info', status TEXT NOT NULL DEFAULT 'open', category TEXT,
    description TEXT, template_id TEXT, created_at TEXT);
CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, dedup_key TEXT NOT NULL UNIQUE, alert_type TEXT NOT NULL DEFAULT 'cve',
    message TEXT NOT NULL DEFAULT '', created_at TEXT);
CREATE TABLE cves (cve_id TEXT PRIMARY KEY, cvss_score REAL, epss_score REAL, in_kev INTEGER DEFAULT 0, cpe_matches TEXT,
    description TEXT, published TEXT, modified TEXT);
CREATE TABLE monitor_state (key TEXT PRIMARY KEY, value TEXT);
"""


def make_v3(conn):
    conn.executescript(V3_SCHEMA)
    conn.execute("PRAGMA user_version = 3")
    conn.commit()
    return conn


@pytest.fixture()
def v3db():
    conn = sqlite3.connect(":memory:")
    make_v3(conn)
    yield conn
    conn.close()


@pytest.fixture()
def db(v3db):
    from marsadix.db_v4 import migrate_v3_to_v4
    migrate_v3_to_v4(v3db)
    return v3db


APACHE_CPE = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
APACHE_CVE_CFG = [{"nodes": [{"operator": "OR", "cpeMatch": [
    {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.4.51"}]}]}]


def seed_basic(conn, host="www.example.com", version="2.4.49", kev=0, internet_facing=1, behind_cdn=0, cvss=9.8, epss=0.9):
    sid = conn.execute("INSERT INTO scans(target,status) VALUES (?,?)", ("example.com", "completed")).lastrowid
    conn.execute("INSERT INTO assets(scan_id,host,internet_facing,behind_cdn) VALUES (?,?,?,?)", (sid, host, internet_facing, behind_cdn))
    conn.execute("INSERT INTO technologies(scan_id,host,name,version,cpe,source,confidence) VALUES (?,?,?,?,?,?,?)",
                 (sid, host, "Apache", version, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "nmap", "high"))
    conn.execute("INSERT OR REPLACE INTO cves(cve_id,cvss_score,epss_score,in_kev,cpe_matches,description) VALUES (?,?,?,?,?,?)",
                 ("CVE-2021-41773", cvss, epss, kev, json.dumps(APACHE_CVE_CFG), "Path traversal in Apache 2.4.49"))
    conn.commit()
    return sid


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Tests must never touch the network: any socket connection attempt fails the test."""
    import socket

    def blocked(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
