"""A finding without its own scan must be attached to a scan that saw the host, never to 'the newest scan'."""
import dataclasses
import json

from marsadix import db, p4data
from marsadix.alerts.settings import AlertSettings
from marsadix.monitor import matching_run
from marsadix.monitor.matching_run import run_matching
from marsadix.patterns import PatternFinding, persist_findings

CFG = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{
    "vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}]}]}]


def _two_targets():
    c = db.connect(":memory:"); db.init_db(c)
    for t in ("a.example", "b.example"):            # scan 1 = a.example, scan 2 (newest) = b.example
        c.execute("insert into scans(target,started_at,status) values(?, '2025-01-01', 'completed')", (t,))
    c.execute("insert into assets(scan_id,host,in_scope,source,first_seen) values(1,'www.a.example',1,'subfinder','2025-01-01')")
    c.execute("insert into technologies(scan_id,host,name,version,cpe,source,confidence) values(1,'www.a.example','Apache','2.4.49','cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*','nmap','high')")
    c.execute("insert into cves(cve_id,description,cvss_score,severity,cpe_matches,in_kev,epss_score,refs) values('CVE-2021-41773','x',7.5,'high',?,1,0.9,'[]')", (json.dumps(CFG),))
    c.commit(); return c


def test_scan_for_host_returns_the_scan_that_saw_the_host():
    c = _two_targets()
    assert p4data.scan_for_host(c, "WWW.A.EXAMPLE") == 1
    assert p4data.scan_for_host(c, "ghost.example") is None and p4data.scan_for_host(c, "") is None


def test_cve_finding_without_a_scan_goes_to_the_hosts_scan_not_the_newest(monkeypatch):
    c = _two_targets(); orig = matching_run.build_assets
    monkeypatch.setattr(matching_run, "build_assets", lambda *a, **k: [dataclasses.replace(x, scan_id=None) for x in orig(*a, **k)])
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    assert c.execute("select scan_id from findings where cve_id='CVE-2021-41773'").fetchone()[0] == 1


def test_finding_for_an_unknown_host_is_not_stored_and_is_reported(monkeypatch):
    c = _two_targets(); orig = matching_run.build_assets
    monkeypatch.setattr(matching_run, "build_assets",
                        lambda *a, **k: [dataclasses.replace(x, scan_id=None, host="ghost.example") for x in orig(*a, **k)])
    s = run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    assert c.execute("select count(*) from findings").fetchone()[0] == 0
    assert any("no scan has observed this host" in f for f in s.failures)


def test_pattern_finding_without_a_scan_is_attached_correctly_or_skipped():
    c = _two_targets()
    mk = lambda host, key: PatternFinding("exposed-sensitive-file", "t", "high", host, "x", ["e"], "medium", "likely",
                                          "A05:2021", "exposed-sensitive-file", key, None)
    res = persist_findings(c, [mk("www.a.example", "k1"), mk("ghost.example", "k2")])
    assert (res["created"], res["skipped"]) == (1, 1)
    assert c.execute("select scan_id from findings where dedup_key='k1'").fetchone()[0] == 1
