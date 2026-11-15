"""The console summary stays short even when 1800 CVEs are new in KEV."""
import json

import pytest

runner = pytest.importorskip("marsadix.monitor.runner")
CFG = type("C", (), {"nvd_api_key": ""})()


def test_summary_prints_counts_and_a_sample_but_returns_the_full_list(monkeypatch, capsys):
    from marsadix import db
    c = db.connect(":memory:"); db.init_db(c)
    kev = {f"CVE-2020-{i:05d}" for i in range(1800)}
    monkeypatch.setattr(runner, "fetch_nvd", lambda s, e, k="": iter([]))
    monkeypatch.setattr(runner, "fetch_kev", lambda: kev)
    monkeypatch.setattr(runner, "fetch_epss", lambda ids: {})
    rc, summary = runner.run(c, CFG, return_summary=True)
    shown = json.loads(capsys.readouterr().out)
    assert rc == 0 and len(summary["new_kev"]) == 1800                       # matcher still gets everything
    assert shown["new_kev_count"] == 1800 and len(shown["new_kev_sample"]) == 10 and "new_kev" not in shown
