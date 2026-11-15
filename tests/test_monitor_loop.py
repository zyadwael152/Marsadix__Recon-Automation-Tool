"""`marsadix monitor` = sync + match + alert, repeated every N hours (one command, nothing else to run)."""
import types

import pytest

scheduler = pytest.importorskip("marsadix.monitor.scheduler")
CFG = types.SimpleNamespace(db_path=":memory:", nvd_api_key="")


def _stop_after(n, sleeps):
    def sleep(s):
        sleeps.append(s)
        if len(sleeps) == n:
            raise KeyboardInterrupt
    return sleep


def test_runs_now_then_every_interval_with_alerts_on_and_stops_cleanly_on_ctrl_c(monkeypatch):
    seen, sleeps = [], []
    monkeypatch.setattr(scheduler, "cycle", lambda config, **kw: seen.append(kw) or 0)
    assert scheduler.watch(CFG, interval_hours=5, sleep=_stop_after(2, sleeps)) == 0
    assert sleeps == [5 * 3600, 5 * 3600] and len(seen) == 2 and all(k["send_alerts"] for k in seen)


def test_since_and_all_apply_to_the_first_cycle_only(monkeypatch):
    seen, sleeps = [], []
    monkeypatch.setattr(scheduler, "cycle", lambda config, **kw: seen.append(kw) or 0)
    scheduler.watch(CFG, since="2026-01-01", all_cves=True, channels=["discord"], sleep=_stop_after(2, sleeps))
    assert (seen[0]["since"], seen[0]["all_cves"]) == ("2026-01-01", True)
    assert (seen[1]["since"], seen[1]["all_cves"]) == (None, False)          # later cycles are incremental
    assert seen[0]["channels"] == seen[1]["channels"] == ["discord"]


def test_a_failing_cycle_never_stops_the_monitor(monkeypatch):
    calls, sleeps = [], []

    def cycle(config, **kw):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("NVD is down")
        return 0

    monkeypatch.setattr(scheduler, "cycle", cycle)
    assert scheduler.watch(CFG, sleep=_stop_after(2, sleeps)) == 0
    assert len(calls) == 2 and len(sleeps) == 2                               # cycle 1 failed, cycle 2 still ran


def test_once_runs_a_single_cycle_and_returns_its_exit_code(monkeypatch):
    monkeypatch.setattr(scheduler, "cycle", lambda config, **kw: 7)
    assert scheduler.watch(CFG, once=True, sleep=lambda s: (_ for _ in ()).throw(AssertionError("must not sleep"))) == 7


def test_interval_must_be_positive():
    with pytest.raises(ValueError):
        scheduler.watch(CFG, interval_hours=0)


def _cycle_with(monkeypatch, tmp_path, run_result, **kw):
    posted, run_kw = [], {}

    def fake_run(conn, config, dry_run=False, since=None, return_summary=False):
        run_kw.update(dry_run=dry_run, since=since)
        return run_result

    monkeypatch.setattr(scheduler, "run", fake_run)
    monkeypatch.setattr(scheduler, "_post_sync", lambda: lambda conn, args, summary, config=None: posted.append(args))
    rc = scheduler.cycle(types.SimpleNamespace(db_path=str(tmp_path / "t.db")), **kw)
    return rc, posted, run_kw


def test_cycle_matches_and_alerts_after_a_good_sync(monkeypatch, tmp_path):
    rc, posted, _ = _cycle_with(monkeypatch, tmp_path, (0, {"changed_cve_ids": ["CVE-1"], "new_kev": []}))
    assert rc == 0 and len(posted) == 1 and posted[0].no_alerts is False and posted[0].all_cves is False


def test_cycle_passes_the_flags_through(monkeypatch, tmp_path):
    _, posted, run_kw = _cycle_with(monkeypatch, tmp_path, (0, {}), dry_run=True, send_alerts=False, since="2026-02-01",
                                    all_cves=True, channels=["telegram"])
    assert run_kw == {"dry_run": True, "since": "2026-02-01"}
    a = posted[0]
    assert (a.dry_run, a.no_alerts, a.all_cves, a.channel) == (True, True, True, ["telegram"])


def test_cycle_does_not_match_after_a_failed_or_skipped_sync(monkeypatch, tmp_path):
    for bad in (1, 2):
        rc, posted, _ = _cycle_with(monkeypatch, tmp_path, (bad, None))
        assert rc == bad and posted == []


def test_without_the_matching_package_the_cycle_still_syncs(monkeypatch, tmp_path):
    monkeypatch.setattr(scheduler, "run", lambda conn, config, dry_run=False, since=None, return_summary=False: 0)
    monkeypatch.setattr(scheduler, "_post_sync", lambda: None)
    assert scheduler.cycle(types.SimpleNamespace(db_path=str(tmp_path / "t.db"))) == 0


# ---- the one command -------------------------------------------------------------------------------------
def _fake_watch(monkeypatch, seen):
    monkeypatch.setattr("marsadix.cli.load_callable",
                        lambda p: (lambda cfg, **kw: seen.update(kw) or 0) if p.endswith("scheduler:watch") else None)


def test_plain_monitor_is_continuous_every_5_hours_and_alerts(monkeypatch, tmp_path):
    from marsadix.cli import main
    seen = {}
    _fake_watch(monkeypatch, seen)
    assert main(["--no-banner", "--db", str(tmp_path / "t.db"), "monitor"]) == 0
    assert seen == {"interval_hours": 5.0, "once": False, "dry_run": False, "send_alerts": True,
                    "since": None, "all_cves": False, "channels": None}


def test_monitor_flags_reach_the_scheduler(monkeypatch, tmp_path):
    from marsadix.cli import main
    seen = {}
    _fake_watch(monkeypatch, seen)
    assert main(["--no-banner", "--db", str(tmp_path / "t.db"), "monitor", "--interval-hours", "2", "--once", "--no-alerts",
                 "--since", "2026-11-01", "--all", "--channel", "discord"]) == 0
    assert seen["interval_hours"] == 2.0 and seen["once"] is True and seen["send_alerts"] is False
    assert seen["since"] == "2026-11-01" and seen["all_cves"] is True and seen["channels"] == ["discord"]


def test_a_dry_run_is_always_a_single_cycle(monkeypatch, tmp_path):
    from marsadix.cli import main
    seen = {}
    _fake_watch(monkeypatch, seen)
    assert main(["--no-banner", "--db", str(tmp_path / "t.db"), "monitor", "--dry-run"]) == 0
    assert seen["dry_run"] is True and seen["once"] is True


def test_a_non_positive_interval_is_rejected(tmp_path, capsys):
    from marsadix.cli import main
    assert main(["--no-banner", "--db", str(tmp_path / "t.db"), "monitor", "--interval-hours", "0"]) == 2
    assert "positive" in capsys.readouterr().err


def test_there_is_no_separate_watch_command(tmp_path):
    from marsadix.cli import main
    with pytest.raises(SystemExit):
        main(["--no-banner", "--db", str(tmp_path / "t.db"), "watch"])
