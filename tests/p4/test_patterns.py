import json
from datetime import datetime, timezone
import pytest
from marsadix import patterns as P
from marsadix.patterns import PatternData, hunt, load_pattern_data, persist_findings, run_patterns

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def W(url, status=200, body="", headers=None, ct="text/html", host="www.example.com", **kw):
    d = {"host": host, "url": url, "status_code": status, "body": body, "headers": headers or {}, "content_type": ct, "scan_id": 1, "title": "", "origin": ""}
    d.update(kw)
    return d


def run(**kw):
    kw.setdefault("now", NOW)
    return hunt(PatternData(**kw))


def one(findings, rule):
    got = [f for f in findings if f.rule_id == rule]
    assert got, f"{rule} not found in {[f.rule_id for f in findings]}"
    return got


def none(findings, rule):
    assert not [f for f in findings if f.rule_id == rule]


# ---- exposed files ---------------------------------------------------------
def test_env_file_confirmed_by_signature():
    f = one(run(web_items=[W("https://www.example.com/.env", body="APP_KEY=base64:abc\nDB_PASSWORD=hunter2", ct="text/plain")]), "exposed-sensitive-file")[0]
    assert f.status == "confirmed" and f.severity == "critical" and f.confidence == "high" and f.owasp == "A05:2021"
    assert f.remediation_key == "exposed-sensitive-file"


def test_git_head_and_backup_and_soft404():
    fs = run(web_items=[W("https://www.example.com/.git/HEAD", body="ref: refs/heads/main\n", ct="text/plain"),
                        W("https://www.example.com/db.sql", body="x", ct="application/sql"),
                        W("https://www.example.com/.env.bak", body="<html>Not found</html>")])
    got = {f.target: f for f in one(fs, "exposed-sensitive-file")}
    assert got["/.git/head"].status == "confirmed"
    assert got["/db.sql"].status == "needs-review" and got["/db.sql"].severity == "high"
    assert got["/.env.bak"].status == "possible"


def test_exposed_file_requires_2xx():
    none(run(web_items=[W("https://www.example.com/.env", status=404, body="APP=1")]), "exposed-sensitive-file")
    none(run(web_items=[W("https://www.example.com/index.html", body="x")]), "exposed-sensitive-file")


# ---- directory listing -----------------------------------------------------
def test_directory_listing():
    f = one(run(web_items=[W("https://www.example.com/files/", body="<html><title>Index of /files</title><a href='?C=N;O=D'>")]), "directory-listing")[0]
    assert f.status == "confirmed"
    none(run(web_items=[W("https://www.example.com/", body="<html>welcome</html>")]), "directory-listing")


# ---- headers ---------------------------------------------------------------
def test_missing_security_headers_per_host_aggregated():
    fs = run(web_items=[W("https://www.example.com/", headers={"server": "nginx"}), W("https://www.example.com/a", headers={"server": "nginx"})])
    f = one(fs, "missing-security-headers")
    assert len(f) == 1 and "Content-Security-Policy" in f[0].evidence[0] and "Strict-Transport-Security" in f[0].evidence[0]
    assert f[0].status == "needs-review" and f[0].severity == "medium"


def test_headers_complete_or_uncaptured_no_finding():
    full = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer", "strict-transport-security": "max-age=1"}
    none(run(web_items=[W("https://www.example.com/", headers=full)]), "missing-security-headers")
    none(run(web_items=[W("https://www.example.com/", headers={})]), "missing-security-headers")
    none(run(web_items=[W("https://www.example.com/x.json", headers={"server": "x"}, ct="application/json", body="{}")]), "missing-security-headers")


def test_hsts_not_required_over_http():
    h = {"content-security-policy": "frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "x"}
    none(run(web_items=[W("http://www.example.com/", headers=h)]), "missing-security-headers")


# ---- cors ------------------------------------------------------------------
def test_cors_variants():
    fs = run(web_items=[
        W("https://a.example.com/api", host="a", headers={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}),
        W("https://b.example.com/api", host="b", headers={"access-control-allow-origin": "*"}),
        W("https://c.example.com/api", host="c", headers={"access-control-allow-origin": "https://evil.test", "access-control-allow-credentials": "true"}, origin="https://evil.test"),
        W("https://d.example.com/api", host="d", headers={"access-control-allow-origin": "https://d.example.com"}, origin="https://d.example.com"),
    ])
    sev = {f.host: f.severity for f in one(fs, "cors-misconfiguration")}
    assert sev == {"a": "high", "b": "low", "c": "high"}


# ---- admin / default login --------------------------------------------------
def test_admin_panels():
    fs = run(web_items=[W("https://www.example.com/phpmyadmin/", body="x"), W("https://www.example.com/wp-admin/", status=401),
                        W("https://www.example.com/admin", status=404)])
    got = {f.target: f.severity for f in one(fs, "exposed-admin-panel")}
    assert got == {"/phpmyadmin/": "medium", "/wp-admin/": "low"}


def test_default_login_panel_is_never_confirmed():
    f = one(run(web_items=[W("https://www.example.com/login", body="<p>Default password is admin/admin</p>")]), "default-login-panel")[0]
    assert f.status == "possible" and f.severity == "high" and f.owasp == "A07:2021"
    none(run(web_items=[W("https://www.example.com/login", body="<p>Sign in</p>")]), "default-login-panel")


# ---- debug -----------------------------------------------------------------
def test_debug_endpoints():
    fs = run(web_items=[W("https://www.example.com/actuator/env", body='{"activeProfiles":[],"propertySources":[]}', ct="application/json"),
                        W("https://www.example.com/phpinfo.php", body="<title>phpinfo()</title>PHP Version 8"),
                        W("https://www.example.com/server-status", body="x"),
                        W("https://www.example.com/actuator/health", body="{}", ct="application/json")])
    got = {f.target: f for f in one(fs, "debug-endpoint")}
    assert got["/actuator/env"].status == "confirmed" and got["/actuator/env"].severity == "high"
    assert got["/phpinfo.php"].status == "confirmed" and got["/server-status"].status == "needs-review"
    assert "/actuator/health" not in got


# ---- tls -------------------------------------------------------------------
def test_weak_and_expired_tls():
    fs = run(services=[{"host": "h", "port": 443, "tls_version": "TLSv1.0", "tls_not_after": "2026-01-01T00:00:00Z", "scan_id": 1},
                       {"host": "h2", "port": 443, "tls_version": "TLSv1.3", "tls_not_after": "2027-01-01T00:00:00Z", "scan_id": 1},
                       {"host": "h3", "port": 8443, "tls_version": "SSLv3", "tls_expired": 1, "scan_id": 1}])
    got = {(f.host, f.target): f for f in one(fs, "weak-tls")}
    assert set(got) == {("h", "port:443:version"), ("h", "port:443:expired"), ("h3", "port:8443:version"), ("h3", "port:8443:expired")}
    assert got[("h3", "port:8443:version")].severity == "high"


# ---- outdated components -----------------------------------------------------
def test_outdated_components_from_findings():
    fs = run(findings=[
        {"id": 1, "host": "h", "cve_id": "CVE-1", "product": "http_server", "version": "2.4.49", "cvss": 9.8, "kev": 1, "confidence": "high", "status": "open", "scan_id": 1},
        {"id": 2, "host": "h", "cve_id": "CVE-2", "product": "http_server", "cvss": 7.5, "kev": 0, "status": "open"},
        {"id": 3, "host": "h", "cve_id": "CVE-3", "product": "nginx", "cvss": 4.0, "kev": 0, "status": "open"},
        {"id": 4, "host": "h", "cve_id": "CVE-4", "product": "openssl", "cvss": 9.0, "kev": 0, "status": "fixed"},
    ])
    f = one(fs, "outdated-component")
    assert len(f) == 1 and f[0].severity == "critical" and "CVE-1" in f[0].evidence[0] and "CVE-2" in f[0].evidence[0]
    assert f[0].status == "needs-review"


# ---- ports -----------------------------------------------------------------
def test_open_ports():
    fs = run(services=[{"host": "h", "port": 6379, "state": "open", "scan_id": 1}, {"host": "h", "port": 443, "state": "open"},
                       {"host": "h", "port": 3306, "state": "closed"}, {"host": "int", "port": 5432, "state": "open"}],
             assets=[{"host": "h", "internet_facing": 1}, {"host": "int", "internet_facing": 0}])
    f = one(fs, "exposed-service-port")
    assert [(x.host, x.target, x.severity) for x in f] == [("h", "port:6379", "critical")]


# ---- verbose errors ---------------------------------------------------------
@pytest.mark.parametrize("body", ["Traceback (most recent call last):\n  File", "java.lang.NullPointerException\n at com.a.B(B.java:12)",
                                  "You have an error in your SQL syntax near", "Whitelabel Error Page", "Fatal error: Uncaught x in /var/www/a.php on line 4"])
def test_verbose_errors(body):
    f = one(run(web_items=[W("https://www.example.com/x", status=500, body=body)]), "verbose-error")[0]
    assert f.status == "needs-review"


def test_verbose_error_negative():
    none(run(web_items=[W("https://www.example.com/x", status=500, body="Internal Server Error")]), "verbose-error")


# ---- cloud -----------------------------------------------------------------
def test_public_cloud_storage():
    f = one(run(web_items=[W("https://bucket.s3.amazonaws.com/", host="bucket.s3.amazonaws.com", body="<?xml version='1.0'?><ListBucketResult xmlns=...>", ct="application/xml")]), "public-cloud-storage")[0]
    assert f.status == "confirmed"
    g = one(run(findings=[{"id": 9, "host": "h", "title": "Public S3 bucket referenced in JS", "description": ""}]), "public-cloud-storage")[0]
    assert g.status == "possible"
    none(run(web_items=[W("https://b.s3.amazonaws.com/", body="<Error><Code>AccessDenied</Code></Error>")]), "public-cloud-storage")


# ---- meta: rule contract, dedup, persistence ---------------------------------
def test_every_rule_has_full_contract_and_is_covered():
    ids = {r.id for r in P.RULES}
    assert len(ids) == len(P.RULES) == 12
    for r in P.RULES:
        assert r.id and r.title and r.severity in P.SEVERITY_ORDER and callable(r.predicate)
        assert r.confidence in ("low", "medium", "high") and r.owasp.startswith("A") and r.remediation_key
    import inspect, sys
    src = inspect.getsource(sys.modules[__name__])
    for i in ids:
        assert f'"{i}"' in src, f"rule {i} has no test"


def test_no_false_confirmed_without_definitive_evidence():
    data = PatternData(web_items=[W("https://www.example.com/backup.zip", body="PK", ct="application/zip"),
                                  W("https://www.example.com/phpmyadmin/")], now=NOW)
    for f in hunt(data):
        assert f.status in ("needs-review", "possible")


def test_in_run_dedup_merges_evidence():
    items = [W("https://www.example.com/.env", body="A_KEY=1", ct="text/plain"), W("http://www.example.com/.env", body="A_KEY=1", ct="text/plain")]
    f = one(run(web_items=items), "exposed-sensitive-file")
    assert len(f) == 1 and len(f[0].evidence) == 2


def test_hunter_is_deterministic_and_sorted():
    items = [W("https://www.example.com/.env", body="A_KEY=1", ct="text/plain"), W("https://www.example.com/x", status=500, body="Whitelabel Error Page")]
    a, b = run(web_items=items), run(web_items=list(reversed(items)))
    assert [f.dedup_key for f in a] == [f.dedup_key for f in b]
    sev = [P.SEVERITY_ORDER[f.severity] for f in a]
    assert sev == sorted(sev, reverse=True)


def test_db_roundtrip_dedup_and_status_preserved(db):
    sid = db.execute("INSERT INTO scans(target,status) VALUES ('example.com','completed')").lastrowid
    db.execute("INSERT INTO assets(scan_id,host,internet_facing) VALUES (?,?,1)", (sid, "www.example.com"))
    db.execute("INSERT INTO web_items(scan_id,host,url,status_code,body,headers,content_type) VALUES (?,?,?,?,?,?,?)",
               (sid, "www.example.com", "https://www.example.com/.env", 200, "APP_KEY=abc", json.dumps({}), "text/plain"))
    db.execute("INSERT INTO services(scan_id,host,port,state) VALUES (?,?,?, 'open')", (sid, "www.example.com", 6379))
    db.commit()
    first = run_patterns(db, now=NOW)
    assert {f.rule_id for f in first} == {"exposed-sensitive-file", "exposed-service-port"}
    n = db.execute("SELECT count(*) FROM findings WHERE source='pattern'").fetchone()[0]
    assert n == 2
    db.execute("UPDATE findings SET status='accepted' WHERE rule_id='exposed-service-port'")
    run_patterns(db, now=NOW)
    assert db.execute("SELECT count(*) FROM findings WHERE source='pattern'").fetchone()[0] == 2
    assert db.execute("SELECT status FROM findings WHERE rule_id='exposed-service-port'").fetchone()[0] == "accepted"
    row = db.execute("SELECT category, source, owasp, remediation_key, first_seen, last_seen FROM findings WHERE rule_id='exposed-sensitive-file'").fetchone()
    assert row[0] == "pattern" and row[1] == "pattern" and row[2] == "A05:2021" and row[4] and row[5]
    assert persist_findings(db, []) == {"created": 0, "updated": 0, "skipped": 0}


def test_loader_uses_only_latest_scan_per_host(db):
    s1 = db.execute("INSERT INTO scans(target) VALUES ('x')").lastrowid
    s2 = db.execute("INSERT INTO scans(target) VALUES ('x')").lastrowid
    for s in (s1, s2):
        db.execute("INSERT INTO web_items(scan_id,host,url,status_code,body) VALUES (?,?,?,?,?)", (s, "h", f"https://h/.env?{s}", 200, "A_KEY=1"))
    db.commit()
    data = load_pattern_data(db)
    assert [w["scan_id"] for w in data.web_items] == [s2]
