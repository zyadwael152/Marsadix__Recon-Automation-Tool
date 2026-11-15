"""Unverified CVE matches (no version -> low confidence) must not sink the attack-surface score."""
import json

from marsadix import db
from marsadix.alerts.settings import AlertSettings
from marsadix.attack_surface import AttackSurfaceInputs, collect_inputs, compute_score
from marsadix.monitor.matching_run import run_matching


def _finding(**kw):
    d = {"key": "k", "severity": "critical", "risk": 80.0, "kev": True, "internet_facing": True, "open": True}
    d.update(kw); return d


def _score(*fs):
    return compute_score(AttackSurfaceInputs(findings=list(fs), technologies=1, versioned_technologies=1)).score


def test_weights_default_to_full_for_findings_without_a_confidence_weight():
    assert _score(_finding()) == _score(_finding(confidence_weight=1.0))


def test_lower_confidence_costs_less_and_never_more_than_full_confidence():
    full, med, low = (_score(_finding(confidence_weight=w)) for w in (1.0, 0.6, 0.2))
    assert full < med < low <= 100.0


def test_score_explains_the_discount():
    r = compute_score(AttackSurfaceInputs(findings=[_finding(confidence_weight=0.2)], technologies=1, versioned_technologies=1))
    assert any("reduced weight" in x for x in r.reasons)
    assert not any("reduced weight" in x for x in compute_score(AttackSurfaceInputs(findings=[_finding()])).reasons)


def test_versionless_technologies_with_kev_cves_no_longer_collapse_the_score():
    c = db.connect(":memory:"); db.init_db(c)
    c.execute("insert into scans(target,started_at,status) values('a.example','2026-11-14','completed')")
    for i, (v, p) in enumerate([("apache", "http_server"), ("nginx", "nginx"), ("php", "php")]):
        host = f"h{i}.a.example"
        c.execute("insert into assets(scan_id,host,in_scope,source,first_seen) values(1,?,1,'subfinder','2026-11-14')", (host,))
        c.execute("insert into technologies(scan_id,host,name,version,cpe,source,confidence) values(1,?,?,'',?,'httpx','medium')",
                  (host, p, f"cpe:2.3:a:{v}:{p}:*:*:*:*:*:*:*:*"))
        cfg = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": True,
                "criteria": f"cpe:2.3:a:{v}:{p}:*:*:*:*:*:*:*:*", "versionEndExcluding": "99.0"}]}]}]
        c.execute("insert into cves(cve_id,description,cvss_score,severity,cpe_matches,in_kev,epss_score,refs) values(?,'x',9.8,'critical',?,1,0.9,'[]')",
                  (f"CVE-2024-{1000 + i}", json.dumps(cfg)))
    c.commit()
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    rows = c.execute("select confidence from findings where source='monitor'").fetchall()
    assert rows and {r[0] for r in rows} == {"low"}                       # no version -> low confidence
    inputs = collect_inputs(c)
    assert {f["confidence_weight"] for f in inputs.findings} == {0.2}
    unweighted = compute_score(AttackSurfaceInputs(findings=[{**f, "confidence_weight": 1.0} for f in inputs.findings],
                                                   technologies=3, versioned_technologies=0)).score
    weighted = compute_score(inputs).score
    assert unweighted < 40 <= weighted                                     # was a grade F, now a sensible score


def test_scanner_findings_keep_full_weight():
    c = db.connect(":memory:"); db.init_db(c)
    c.execute("insert into scans(target,started_at,status) values('a.example','2026-11-14','completed')")
    c.execute("insert into findings(scan_id,host,source,severity,confidence,found_at,dedup_key) values(1,'h','nuclei','high','possible','2026-11-14','x')")
    c.commit()
    assert [f["confidence_weight"] for f in collect_inputs(c).findings] == [1.0]
