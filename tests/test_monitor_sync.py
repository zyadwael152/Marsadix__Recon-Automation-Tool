"""M1-M6: NVD/KEV/EPSS sync (network mocked)."""
import json
from datetime import datetime, timezone

from marsadix import db
from marsadix.monitor import runner, sources

CFG = type("C", (), {"nvd_api_key": ""})()
ITEM = dict(cve_id="CVE-2024-0001", description="d", cvss_score=9.8, severity="critical",
            published="2024-01-01T00:00:00.000", modified="2024-01-02T00:00:00.000",
            cpe_matches=[{"nodes": []}], references=["http://x"])


def _conn():
    c = db.connect(":memory:"); db.init_db(c); return c


def _patch(monkeypatch, nvd, kev, epss):
    monkeypatch.setattr(runner, "fetch_nvd", lambda s, e, k="": iter(nvd))
    monkeypatch.setattr(runner, "fetch_kev", lambda: kev)
    monkeypatch.setattr(runner, "fetch_epss", lambda ids: epss)


def test_dry_run_writes_nothing(monkeypatch):
    c = _conn(); _patch(monkeypatch, [ITEM], {"CVE-2024-0001"}, {"CVE-2024-0001": .5})
    out = runner.synchronize(c, CFG, dry_run=True, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
    assert out["dry_run"] and c.execute("select count(*) from cves").fetchone()[0] == 0
    assert db.get_state(c, runner.STATE) is None


def test_summary_exposes_changed_ids_for_matcher(monkeypatch):
    c = _conn(); _patch(monkeypatch, [ITEM], {"CVE-2023-9999"}, {})
    out = runner.synchronize(c, CFG, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
    assert out["changed_cve_ids"] == ["CVE-2024-0001"] and out["total"] == 1


def test_kev_membership_is_replaced_and_new_kev_reported(monkeypatch):
    c = _conn(); now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    _patch(monkeypatch, [ITEM], {"CVE-2024-0001", "CVE-2023-9999"}, {"CVE-2024-0001": .5})
    assert runner.synchronize(c, CFG, now=now)["new_kev"] == ["CVE-2023-9999", "CVE-2024-0001"]
    _patch(monkeypatch, [], {"CVE-2023-9999"}, {})
    out = runner.synchronize(c, CFG, now=datetime(2025, 1, 2, tzinfo=timezone.utc))
    assert out["new_kev"] == []
    assert c.execute("select in_kev from cves where cve_id='CVE-2024-0001'").fetchone()[0] == 0


def test_failure_does_not_advance_watermark(monkeypatch):
    c = _conn(); _patch(monkeypatch, [ITEM], {"CVE-2023-9999"}, {})
    runner.synchronize(c, CFG, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
    before = db.get_state(c, runner.STATE)
    monkeypatch.setattr(runner, "fetch_epss", lambda ids: (_ for _ in ()).throw(RuntimeError("down")))
    assert runner.run(c, CFG) == 1
    assert db.get_state(c, runner.STATE) == before


def test_rejected_cve_loses_its_configurations():
    rec = {"cve": {"id": "CVE-2020-1", "vulnStatus": "Rejected", "metrics": {},
                   "descriptions": [{"lang": "en", "value": "** REJECT ** dup"}],
                   "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", "vulnerable": True}]}]}]}}
    assert sources.parse_nvd(rec)["cpe_matches"] == []


def test_lock_blocks_a_second_run_and_expires(monkeypatch):
    from datetime import timedelta
    c = _conn(); t0 = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert runner.acquire_lock(c, "A", t0) is True
    assert runner.acquire_lock(c, "B", t0 + timedelta(minutes=5)) is False
    assert runner.acquire_lock(c, "B", t0 + runner.LOCK_TTL + timedelta(minutes=1)) is True  # stale -> taken over
    runner.release_lock(c, "A")                      # not the owner: must not free B's lock
    assert runner.acquire_lock(c, "C", t0 + runner.LOCK_TTL + timedelta(minutes=2)) is False


def test_run_skips_when_locked_and_releases_after_success(monkeypatch):
    c = _conn(); _patch(monkeypatch, [], {"CVE-2023-9999"}, {})
    assert runner.acquire_lock(c, "other") is True
    assert runner.run(c, CFG) == 2                   # skipped, nothing fetched
    runner.release_lock(c, "other")
    assert runner.run(c, CFG) == 0
    assert c.execute("select count(*) from monitor_state where key=?", (runner.LOCK,)).fetchone()[0] == 0


def test_epss_is_refreshed_for_cves_with_open_findings(monkeypatch):
    c = _conn(); _patch(monkeypatch, [], {"CVE-2023-9999"}, {})
    c.execute("insert into scans(target,started_at) values('x','2025-01-01')")
    c.execute("insert into cves(cve_id,severity,in_kev) values('CVE-2020-5555','high',0)")
    c.execute("insert into findings(scan_id,host,source,title,severity,status,cve_id,dedup_key,found_at) "
              "values(1,'h','monitor','t','high','open','CVE-2020-5555','k','2025-01-01')")
    c.commit()
    asked = {}
    def fake_epss(ids): asked["ids"] = set(ids); return {"CVE-2020-5555": 0.42}
    monkeypatch.setattr(runner, "fetch_epss", fake_epss)
    runner.synchronize(c, CFG, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
    assert "CVE-2020-5555" in asked["ids"]
    assert c.execute("select epss_score from cves where cve_id='CVE-2020-5555'").fetchone()[0] == 0.42


def test_nvd_403_is_retried_but_other_403_is_not(monkeypatch):
    import io, urllib.error
    calls = {"n": 0}
    def fake_urlopen(req, timeout=0):
        calls["n"] += 1
        raise urllib.error.HTTPError("u", 403, "Forbidden", {}, io.BytesIO(b""))
    monkeypatch.setattr(sources, "urlopen", fake_urlopen)
    monkeypatch.setattr(sources.time, "sleep", lambda s: None)
    try: sources.request_json("http://x", retries=2); raise AssertionError("should raise")
    except urllib.error.HTTPError: pass
    assert calls["n"] == 1                           # KEV/EPSS style call: 403 is final
    calls["n"] = 0
    try: sources.request_json("http://x", retries=2, extra_retry=(403,)); raise AssertionError("should raise")
    except urllib.error.HTTPError: pass
    assert calls["n"] == 3                           # NVD style call: retried
