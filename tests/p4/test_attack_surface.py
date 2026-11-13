import json
import pytest
from marsadix.attack_surface import (AttackSurfaceInputs, collect_inputs, compute_score, history, latest_score,
                                     posture_for_report, record_score)


def F(sev="high", risk=60, kev=False, facing=True, open_=True, key=None):
    return {"key": key or f"{sev}-{risk}-{kev}", "severity": sev, "risk": risk, "kev": kev, "internet_facing": facing, "open": open_}


def inp(findings=(), **kw):
    kw.setdefault("technologies", 4); kw.setdefault("versioned_technologies", 4)
    return AttackSurfaceInputs(findings=list(findings), **kw)


def test_clean_environment_scores_100():
    r = compute_score(inp())
    assert r.score == 100.0 and r.grade == "A" and r.trend == "stable" and r.previous_score is None and r.delta is None


def test_documented_direction_more_problems_lower_score():
    base = compute_score(inp([F("low", 20)])).score
    for worse in ([F("low", 20), F("low", 20, key="b")], [F("medium", 20)], [F("low", 80)], [F("low", 20, kev=True)]):
        assert compute_score(inp(worse)).score < base


def test_monotonic_in_each_input():
    prev = 101
    for n in range(0, 40, 4):
        s = compute_score(inp([F("high", 60, key=str(i)) for i in range(n)])).score
        assert s <= prev
        prev = s
    prev = 101
    for sev in ("info", "low", "medium", "high", "critical"):
        s = compute_score(inp([F(sev, 50)])).score
        assert s <= prev
        prev = s
    prev = 101
    for risk in (0, 25, 50, 75, 100):
        s = compute_score(inp([F("high", risk)])).score
        assert s <= prev
        prev = s
    assert compute_score(inp(internet_assets=20)).score < compute_score(inp(internet_assets=1)).score
    assert compute_score(inp(versioned_technologies=0)).score < compute_score(inp()).score


def test_kev_exposure_internet_worse_than_internal():
    ext = compute_score(inp([F("critical", 90, True, True)])).score
    internal = compute_score(inp([F("critical", 90, True, False)])).score
    assert ext < internal


def test_closed_findings_ignored_and_bounds():
    assert compute_score(inp([F("critical", 100, True, open_=False)])).score == 100.0
    worst = compute_score(inp([F("critical", 100, True, key=str(i)) for i in range(200)], internet_assets=100, technologies=10, versioned_technologies=0))
    assert 0.0 <= worst.score <= 10.0


def test_saturation_does_not_go_below_zero():
    assert compute_score(inp([F("critical", 100, True, key=str(i)) for i in range(5000)], internet_assets=1000, technologies=1)).score >= 0.0


def test_deterministic_and_reasons_explain_penalties():
    a = compute_score(inp([F("critical", 90, True)], internet_assets=3))
    b = compute_score(inp([F("critical", 90, True)], internet_assets=3))
    assert a == b
    text = " ".join(a.reasons)
    assert "KEV" in text and "open finding" in text and "internet-facing asset" in text
    assert abs(100 - sum(a.penalties.values()) - a.score) < 0.2


def test_trend_direction():
    assert compute_score(inp(), None, 80.0).trend == "improving"
    assert compute_score(inp([F("critical", 90, True)]), None, 100.0).trend == "worsening"
    assert compute_score(inp(), None, 99.0).trend == "stable"   # delta +1 < threshold
    r = compute_score(inp(), None, 90.0)
    assert (r.previous_score, r.delta) == (90.0, 10.0)
    assert compute_score(inp(), None, 98.0).trend == "improving" and compute_score(inp(), None, 102.0).trend == "worsening"


def test_drift_penalty_uses_previous_snapshot():
    prev = {"finding_keys": ["a"], "hosts": ["h1"], "ports": ["h1:80"]}
    cur = inp([F(key="a"), F(key="b")], finding_keys=["a", "b"], hosts=["h1", "h2"], ports=["h1:80", "h1:22"])
    r = compute_score(cur, prev)
    assert r.penalties["drift"] == 1.5 and any("new finding/host/port" in x for x in r.reasons)
    assert compute_score(cur, None).penalties["drift"] == 0.0


# ---- DB -------------------------------------------------------------------
def seed(db, sev_findings=()):
    sid = db.execute("INSERT INTO scans(target,status) VALUES ('example.com','completed')").lastrowid
    db.execute("INSERT INTO assets(scan_id,host,internet_facing) VALUES (?,?,1)", (sid, "a.example.com"))
    db.execute("INSERT INTO assets(scan_id,host,internet_facing) VALUES (?,?,0)", (sid, "int.example.com"))
    db.execute("INSERT INTO technologies(scan_id,host,name,version) VALUES (?,?,?,?)", (sid, "a.example.com", "nginx", "1.2"))
    db.execute("INSERT INTO technologies(scan_id,host,name,version) VALUES (?,?,?,?)", (sid, "a.example.com", "php", None))
    db.execute("INSERT INTO services(scan_id,host,port,state) VALUES (?,?,?,'open')", (sid, "a.example.com", 443))
    for i, (sev, risk, kev) in enumerate(sev_findings):
        db.execute("INSERT INTO findings(scan_id,host,title,severity,risk_score,kev,dedup_key,status) VALUES (?,?,?,?,?,?,?,'open')",
                   (sid, "a.example.com", f"f{i}", sev, risk, kev, f"k{i}"))
    db.commit()
    return sid


def test_collect_inputs(db):
    seed(db, [("high", 80, 1)])
    i = collect_inputs(db)
    assert (i.total_assets, i.internet_assets, i.technologies, i.versioned_technologies) == (2, 1, 2, 1)
    assert i.ports == ["a.example.com:443"] and i.findings[0]["kev"] is True and i.finding_keys == ["k0"]


def test_record_one_row_per_run_and_trend(db):
    seed(db, [("high", 80, 1), ("medium", 40, 0)])
    r1 = record_score(db, run_type="monitor", run_ref=1)
    assert r1.previous_score is None and r1.trend == "stable"
    db.execute("UPDATE findings SET status='fixed'")
    db.commit()
    r2 = record_score(db, run_type="monitor", run_ref=2)
    assert r2.previous_score == r1.score and r2.delta > 0 and r2.trend == "improving"
    db.execute("INSERT INTO findings(scan_id,host,title,severity,risk_score,kev,dedup_key,status) VALUES (1,'a.example.com','new','critical',95,1,'knew','open')")
    db.commit()
    r3 = record_score(db, run_type="scan", run_ref=3)
    assert r3.trend == "worsening" and r3.previous_score == r2.score
    rows = history(db)
    assert [r["run_ref"] for r in rows] == [3, 2, 1] and db.execute("SELECT count(*) FROM attack_surface_scores").fetchone()[0] == 3
    assert latest_score(db)["inputs"]["open_findings"] == 1 and "KEV" in " ".join(latest_score(db)["reasons"])


def test_no_persist_writes_nothing(db):
    seed(db, [("high", 80, 0)])
    record_score(db, persist=False)
    assert db.execute("SELECT count(*) FROM attack_surface_scores").fetchone()[0] == 0
    d = posture_for_report(db)
    assert d["direction"].startswith("100 = healthiest") and db.execute("SELECT count(*) FROM attack_surface_scores").fetchone()[0] == 0


def test_target_scoping(db):
    seed(db, [("critical", 90, 1)])
    s2 = db.execute("INSERT INTO scans(target,status) VALUES ('other.org','completed')").lastrowid
    db.execute("INSERT INTO assets(scan_id,host) VALUES (?,?)", (s2, "x.other.org"))
    db.commit()
    assert collect_inputs(db, "other.org").findings == [] and collect_inputs(db, "other.org").total_assets == 1
    assert len(collect_inputs(db, "example.com").findings) == 1
