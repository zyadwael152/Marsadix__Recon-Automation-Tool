"""Second review round: distro versions, canonical OWASP names, no double counting (real schema)."""
import json

from marsadix import db, p4data
from marsadix import patterns as pat
from marsadix.alerts.settings import AlertSettings
from marsadix.attack_surface import collect_inputs
from marsadix.matching.version import compare_versions, is_distro_packaged
from marsadix.monitor.matching_run import run_matching

CFG = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{
    "vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}]}]}]
A06 = "A06:2021-Vulnerable_and_Outdated_Components"


def _seed(version="2.4.49"):
    c = db.connect(":memory:"); db.init_db(c)
    c.execute("insert into scans(target,started_at) values('example.com','2025-01-01')")
    c.execute("insert into assets(scan_id,host,in_scope,source,first_seen) values(1,'a.example.com',1,'subfinder','2025-01-01')")
    c.execute("insert into technologies(scan_id,host,name,version,cpe,source,confidence) values(1,'a.example.com','Apache',?,?, 'nmap','high')",
              (version, f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"))
    c.execute("insert into cves(cve_id,description,cvss_score,severity,cpe_matches,in_kev,epss_score,refs) values('CVE-2021-41773','x',7.5,'high',?,1,0.9,'[]')",
              (json.dumps(CFG),))
    c.commit(); return c


def test_distro_packaging_does_not_change_the_upstream_version():
    for raw, upstream in [("1:2.4.7-1ubuntu4", "2.4.7"), ("2.4.7-1+deb10u2", "2.4.7"), ("2.4.7+dfsg", "2.4.7"),
                          ("2.4.6-97.el7.centos.5", "2.4.6"), ("7.6p1-4ubuntu0.7", "7.6p1")]:
        assert compare_versions(raw, upstream) == 0, raw
    assert compare_versions("9.9.1-P2", "9.9.1") == 1          # BIND patch level is a real upstream suffix
    assert compare_versions("3.0.0-beta1", "3.0.0") == -1
    assert is_distro_packaged("1:2.4.7-1ubuntu4") and not is_distro_packaged("2.4.49")


def test_vulnerable_ubuntu_build_is_not_hidden_by_versionEndIncluding():
    from marsadix.matching.version import version_in_range
    assert version_in_range("2.4.7-1ubuntu4", end_incl="2.4.7") is True


def test_distro_packaged_asset_is_capped_at_medium_confidence():
    c = _seed("2.4.49-1ubuntu0.1")
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    row = c.execute("select confidence from findings where cve_id='CVE-2021-41773'").fetchone()
    assert row is not None and str(row[0]).lower() in ("medium", "low")


def test_cve_and_pattern_findings_use_the_canonical_owasp_name_and_count_once():
    c = _seed()
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    pat.run_patterns(c, persist=True)
    cats = {r[0] for r in c.execute("select owasp_category from findings where owasp_category is not null")}
    assert cats == {A06}, cats                                    # never the short 'A06:2021'
    assert db.get_owasp_coverage(c, 1)["breakdown"] == {A06: 2}


def test_attack_surface_does_not_double_count_the_outdated_component_rollup():
    c = _seed()
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    before = len(collect_inputs(c).findings)
    pat.run_patterns(c, persist=True)
    assert c.execute("select count(*) from findings where source='pattern' and template_id='outdated-component'").fetchone()[0] == 1
    assert len(collect_inputs(c).findings) == before == 1
