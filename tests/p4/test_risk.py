import pytest
from marsadix.matching.models import CVE, Asset, Confidence, PriorityLevel
from marsadix.matching.priority import compute_priority
from marsadix.remediation_db import RemediationEntry
from marsadix.risk import RiskedFinding, assess, compute_risk, finding_from_row, top_fixes

P = compute_priority(8.0, 0.2, False, Confidence.HIGH)
PK = compute_priority(8.0, 0.2, True, Confidence.HIGH)


def rf(cve="CVE-1", host="h", cvss=8.0, epss=0.2, kev=False, facing=True, cdn=False, crit="medium", conf=Confidence.HIGH, product="nginx", effort="medium"):
    pr = compute_priority(cvss, epss, kev, conf)
    r = compute_risk(pr, internet_facing=facing, behind_cdn=cdn, criticality=crit, kev=kev)
    rem = RemediationEntry(1, "product", product, f"Fix {product}", f"Upgrade {product}", [], effort, 50)
    return RiskedFinding(cve, host, product, "1.0", cvss, epss, kev, conf, pr, r, internet_facing=facing, behind_cdn=cdn,
                         criticality=crit, remediation=rem)


def test_formula_and_reasons():
    r = compute_risk(P, internet_facing=True, behind_cdn=False, criticality="high", kev=False)
    assert r.score == round(P.score * 0.7 + 15 + 4, 1)
    assert any("internet-facing" in x for x in r.reasons) and any("criticality high" in x for x in r.reasons) and len(r.reasons) >= 3


def test_context_ordering():
    internal = compute_risk(P, internet_facing=False).score
    cdn = compute_risk(P, internet_facing=True, behind_cdn=True).score
    direct = compute_risk(P, internet_facing=True).score
    assert internal < cdn < direct


def test_criticality_monotonic():
    s = [compute_risk(P, criticality=c).score for c in ("low", "medium", "high", "critical")]
    assert s == sorted(s) and len(set(s)) == 4


def test_kev_internet_facing_bonus_and_context_differs_from_priority():
    kev = compute_risk(PK, internet_facing=True, kev=True)
    assert any("known-exploited" in x for x in kev.reasons)
    assert compute_risk(PK, internet_facing=False, kev=True).score < kev.score
    assert compute_risk(P).score != P.score


def test_clamped_0_100():
    top = compute_priority(10, 1, True, Confidence.HIGH)
    assert compute_risk(top, internet_facing=True, criticality="critical", kev=True).score == 100.0
    low = compute_priority(0, 0, False, Confidence.LOW)
    assert compute_risk(low, internet_facing=False, criticality="low").score == 0.0


def test_invalid_criticality_defaults_medium():
    assert compute_risk(P, criticality="weird").score == compute_risk(P, criticality="medium").score


def test_assess_uses_asset_context():
    a = Asset(host="h", cpe="cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", internet_facing=False, criticality="low")
    pr, r = assess(CVE(id="X", cvss=9, kev=False), a, Confidence.HIGH)
    assert r.score < pr.score


def test_top10_internet_kev_ranks_above_internal_non_kev():
    findings = [rf("CVE-A", "internal", kev=False, facing=False, product="a"), rf("CVE-B", "public", kev=True, facing=True, product="b"),
                rf("CVE-C", "cdn", kev=False, facing=True, cdn=True, product="c")]
    out = top_fixes(findings)
    assert [t.cve_id for t in out] == ["CVE-B", "CVE-C", "CVE-A"]


def test_equivalent_findings_internet_facing_beats_internal_and_kev_beats_non_kev():
    base = dict(cvss=7.5, epss=0.3)
    out = top_fixes([rf("I", "int", facing=False, product="p1", **base), rf("E", "ext", facing=True, product="p2", **base)])
    assert out[0].cve_id == "E"
    out = top_fixes([rf("N", "h1", kev=False, product="p1", **base), rf("K", "h2", kev=True, product="p2", **base)])
    assert out[0].cve_id == "K"


def test_top_limit_fields_and_grouping():
    fs = [rf(f"CVE-{i}", f"h{i}", cvss=5 + i * 0.3, product=f"p{i}") for i in range(15)]
    fs += [rf("CVE-X", "h14", cvss=6.0, product="p14")]  # same host+product -> grouped
    out = top_fixes(fs, limit=10)
    assert len(out) == 10
    t = next(x for x in top_fixes(fs, limit=50) if x.host == "h14")
    assert t.fixes_count == 2 and set(t.cve_ids) == {"CVE-14", "CVE-X"} and "also resolves 1" in t.reason
    for k in ("cve_id", "host", "risk_score", "reason", "action", "effort"):
        assert getattr(t, k)
    assert top_fixes(fs, limit=0) == []


def test_effort_breaks_near_ties_but_risk_dominates():
    easy = rf("EASY", "h1", cvss=8.0, product="a", effort="low")
    hard = rf("HARD", "h2", cvss=8.0, product="b", effort="high")
    assert [t.cve_id for t in top_fixes([hard, easy])] == ["EASY", "HARD"]
    big = rf("BIG", "h3", cvss=10, kev=True, product="c", effort="high")
    assert top_fixes([easy, big])[0].cve_id == "BIG"


def test_deterministic_order():
    fs = [rf(f"CVE-{i}", "h", product=f"p{i}") for i in range(5)]
    assert [t.cve_id for t in top_fixes(fs)] == [t.cve_id for t in top_fixes(list(reversed(fs)))]


def test_finding_from_row_roundtrip():
    row = {"id": 4, "cve_id": "CVE-9", "host": "h", "product": "nginx", "cvss": 9.0, "epss": 0.5, "kev": 1, "confidence": "high"}
    f = finding_from_row(row, {"internet_facing": 0, "criticality": "high"})
    assert f.kev and not f.internet_facing and f.risk.score > 0 and f.finding_id == 4 and "risk_score" in f.to_dict()
