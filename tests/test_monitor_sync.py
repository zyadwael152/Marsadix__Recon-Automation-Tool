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
