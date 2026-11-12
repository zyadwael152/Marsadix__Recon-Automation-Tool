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


def _item(i):
    d = dict(ITEM); d["cve_id"] = f"CVE-2024-{i:05d}"; return d


def test_large_backfill_is_streamed_not_listed(monkeypatch):
    """fetch_nvd must be consumed lazily (one record at a time), never materialised with list()."""
    c = _conn(); produced = {"n": 0}

    def gen():
        for i in range(3000):
            produced["n"] += 1
            yield _item(i)

    monkeypatch.setattr(runner, "fetch_nvd", lambda s, e, k="": gen())
    monkeypatch.setattr(runner, "fetch_kev", lambda: {"CVE-2023-9999"})
    seen_at_epss = {}
    monkeypatch.setattr(runner, "fetch_epss", lambda ids: seen_at_epss.update(n=len(ids)) or {})
    out = runner.synchronize(c, CFG, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
    assert produced["n"] == 3000 and out["nvd_records"] == 3000 and len(out["changed_cve_ids"]) == 3000
    assert c.execute("select count(*) from cves").fetchone()[0] == 3001      # 3000 NVD + 1 KEV-only
    assert seen_at_epss["n"] == 3001


def test_failure_in_the_middle_of_the_stream_leaves_db_untouched(monkeypatch):
    c = _conn()

    def gen():
        for i in range(5): yield _item(i)
        raise RuntimeError("NVD died mid-way")

    monkeypatch.setattr(runner, "fetch_nvd", lambda s, e, k="": gen())
    assert runner.run(c, CFG) == 1
    assert c.execute("select count(*) from cves").fetchone()[0] == 0
    assert db.get_state(c, runner.STATE) is None
    assert c.execute("select count(*) from temp.sqlite_master where name='nvd_stage'").fetchone()[0] == 0
    assert c.execute("select count(*) from monitor_state where key=?", (runner.LOCK,)).fetchone()[0] == 0


def test_dry_run_leaves_no_staging_table_and_no_rows(monkeypatch):
    c = _conn(); _patch(monkeypatch, [_item(1)], {"CVE-2023-9999"}, {})
    out = runner.synchronize(c, CFG, dry_run=True, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
    assert out["nvd_records"] == 1
    assert c.execute("select count(*) from cves").fetchone()[0] == 0
    assert c.execute("select count(*) from temp.sqlite_master where name='nvd_stage'").fetchone()[0] == 0


def test_resync_keeps_kev_and_epss_of_updated_cves(monkeypatch):
    c = _conn(); now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    _patch(monkeypatch, [_item(1)], {"CVE-2024-00001"}, {"CVE-2024-00001": 0.7})
    runner.synchronize(c, CFG, now=now)
    changed = _item(1); changed["description"] = "updated"
    _patch(monkeypatch, [changed], {"CVE-2024-00001"}, {})
    runner.synchronize(c, CFG, now=datetime(2025, 1, 2, tzinfo=timezone.utc))
    row = c.execute("select description,in_kev,epss_score from cves where cve_id='CVE-2024-00001'").fetchone()
    assert (row[0], row[1], row[2]) == ("updated", 1, 0.7)
