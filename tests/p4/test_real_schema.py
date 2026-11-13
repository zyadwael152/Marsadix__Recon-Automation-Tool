"""Run the matcher against the REAL schema from marsadix.db.init_db (not the scaffold in conftest.py)."""
import json

from marsadix import db
from marsadix.alerts.settings import AlertSettings
from marsadix.matching.adapter import to_p4_asset
from marsadix.monitor.matching_run import run_matching

CFG = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{
    "vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}]}]}]
CPE = "cpe:2.3:a:apache:http_server:%s:*:*:*:*:*:*:*"


def _seed(version="2.4.49"):
    c = db.connect(":memory:"); db.init_db(c)
    c.execute("insert into scans(target,started_at) values('example.com','2025-01-01')")
    c.execute("insert into assets(scan_id,host,in_scope,is_cdn,source,first_seen) values(1,'a.example.com',1,1,'subfinder','2025-01-01')")
    c.execute("insert into technologies(scan_id,host,name,version,cpe,source,confidence) values(1,'a.example.com','Apache',?,?, 'nmap','high')",
              (version, CPE % version))
    c.execute("insert into cves(cve_id,description,cvss_score,severity,cpe_matches,in_kev,epss_score,refs) values('CVE-2021-41773','x',7.5,'high',?,1,0.9,'[]')",
              (json.dumps(CFG),))
    c.commit(); return c


def test_is_cdn_column_is_honoured():
    assert to_p4_asset({"host": "h", "cpe": CPE % "1"}, {"is_cdn": 1}).behind_cdn is True


def test_cve_finding_is_tagged_owasp_a06_and_kev():
    c = _seed(); run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    row = c.execute("select owasp_category,in_kev from findings where cve_id='CVE-2021-41773'").fetchone()
    assert (row["owasp_category"], row["in_kev"]) == ("A06:2021", 1)


def test_finding_is_resolved_after_the_asset_is_patched():
    c = _seed(); run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    c.execute("update technologies set version='2.4.50', cpe=?", (CPE % "2.4.50",)); c.commit()
    s = run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    assert s.findings_resolved == 1
    assert c.execute("select status from findings where cve_id='CVE-2021-41773'").fetchone()[0] == "resolved"
