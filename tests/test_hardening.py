"""Regression tests for the review fixes: child environment, process lifecycle,
tool status, tracking integrity, alert keys, report/diff scan selection."""

import asyncio
import json
import os
import sqlite3
import sys
import time
from types import SimpleNamespace

import pytest

from marsadix import db
from marsadix.core import childenv, limits, toolstatus
from marsadix.core.aproc import run_exec
from marsadix.core.config import load_config
from marsadix.core.diff import compute_diff, run_stage
from marsadix.core.pipeline import StageResult
from marsadix.models import Asset, Scan, ScanStatus
from marsadix.recon import _proc
from marsadix.recon.ct_monitor import BoundedSeen
from marsadix.recon.resolver import parse_dnsx_json


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


# ------------------------------------------------------------------ secrets
def test_child_env_never_contains_marsadix_secrets_or_unrelated_shell_secrets(monkeypatch):
    for k in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "NVD_API_KEY", "DISCORD_WEBHOOK_URL",
              "TELEGRAM_BOT_TOKEN", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"):
        monkeypatch.setenv(k, "s3cret")
    env = childenv.child_env()
    assert not set(env) & {"SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "NVD_API_KEY",
                           "DISCORD_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN",
                           "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"}
    assert "PATH" in env                              # tools must still be found


def test_child_env_passes_only_the_explicit_extra_key():
    env = childenv.child_env({"PDCP_API_KEY": "k", "UNSET": None})
    assert env["PDCP_API_KEY"] == "k" and "UNSET" not in env


def test_dotenv_keys_stay_in_config_and_do_not_enter_os_environ(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    open(".env", "w").write("SHODAN_API_KEY=abc\n")
    assert load_config(None).shodan_api_key == "abc"
    assert "SHODAN_API_KEY" not in os.environ        # so no child process can inherit it


def test_a_real_child_process_does_not_receive_api_keys(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "s3cret")
    code = "import os,sys;sys.stdout.write(os.environ.get('SHODAN_API_KEY','-')+'|'+os.environ.get('X_EXTRA','-'))"
    res = asyncio.run(run_exec([sys.executable, "-c", code], timeout=20, env_extra={"X_EXTRA": "1"}))
    assert res.stdout.decode() == "-|1"


# --------------------------------------------------------- process lifecycle
def test_timeout_keeps_partial_output_and_kills_the_child():
    code = "import sys,time;print('partial.example.com',flush=True);time.sleep(60)"
    t0 = time.monotonic()
    res = asyncio.run(run_exec([sys.executable, "-c", code], timeout=2))
    assert res.timed_out and b"partial.example.com" in res.stdout
    assert time.monotonic() - t0 < 15


def test_cancelling_the_task_kills_the_child_process(tmp_path):
    pidfile = tmp_path / "pid"
    code = f"import os,time;open(r'{pidfile}','w').write(str(os.getpid()));time.sleep(60)"

    async def main():
        task = asyncio.create_task(run_exec([sys.executable, "-c", code], timeout=60))
        for _ in range(100):
            if pidfile.exists() and pidfile.read_text():
                break
            await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return int(pidfile.read_text())

    pid = asyncio.run(main())
    time.sleep(0.5)
    try:
        os.kill(pid, 0)
        alive = True
    except (ProcessLookupError, PermissionError, OSError):
        alive = False
    assert not alive, "the child outlived the cancelled task"


def test_output_limit_stops_the_tool_and_marks_truncated():
    code = "import sys\nwhile True: sys.stdout.write('a.example.com\\n'*1000); sys.stdout.flush()"
    res = asyncio.run(run_exec([sys.executable, "-c", code], timeout=30, max_bytes=100_000))
    assert res.truncated and len(res.stdout) <= 100_000


def test_run_async_returns_partial_output_on_timeout_and_records_it():
    toolstatus.reset()
    limits.configure()
    code = "import sys,time;print('a.example.com',flush=True);time.sleep(60)"
    out = asyncio.run(_proc.run_async([sys.executable, "-c", code], timeout=1, name="fake"))
    assert "a.example.com" in out
    assert [(r.tool, r.status) for r in toolstatus.degraded()] == [("fake", "timeout")]


def test_a_missing_tool_is_recorded_as_missing_not_as_found_nothing():
    toolstatus.reset()
    assert asyncio.run(_proc.run_async(["definitely-not-a-tool-xyz"], name="ghost")) is None
    assert [(r.tool, r.status) for r in toolstatus.runs()] == [("ghost", "missing")]
    assert toolstatus.degraded() == []                # not installed is stable, not an incident


def test_user_tool_timeout_caps_every_tool_but_never_lengthens_one():
    limits.configure(tool_timeout=30)
    assert limits.cap_timeout(900) == 30 and limits.cap_timeout(10) == 10
    limits.configure()
    assert limits.cap_timeout(900) == 900


def test_concurrency_limit_is_enforced():
    limits.configure(max_concurrency=2)
    state = {"now": 0, "peak": 0}

    async def job():
        async with limits.slot():
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
            await asyncio.sleep(0.02)
            state["now"] -= 1

    async def main():
        await asyncio.gather(*[job() for _ in range(12)])

    asyncio.run(main())
    limits.configure()
    assert state["peak"] == 2


# ---------------------------------------------------------- dnsx / CT / memory
def test_dnsx_record_with_unexpected_types_is_skipped_not_fatal():
    text = "\n".join([
        json.dumps({"host": "ok.example.com", "a": ["1.2.3.4"], "cname": ["c.example.net."]}),
        json.dumps({"host": "str.example.com", "a": "5.6.7.8"}),         # a string, not a list
        json.dumps({"host": 5, "a": ["9.9.9.9"]}),                         # host not a string
        json.dumps({"host": "weird.example.com", "a": [1, None, "2.2.2.2"], "cname": [None, 3]}),
        json.dumps(["not", "a", "dict"]),
        "not json at all",
    ])
    out = parse_dnsx_json(text)
    assert out["ok.example.com"] == {"ips": ["1.2.3.4"], "cname": ["c.example.net"]}
    assert out["str.example.com"]["ips"] == ["5.6.7.8"]
    assert out["weird.example.com"] == {"ips": ["2.2.2.2"], "cname": []}
    assert "5" not in out


def test_ct_seen_set_is_bounded():
    seen = BoundedSeen(maxlen=100)
    for i in range(1000):
        seen.add(f"h{i}.example.com")
    assert len(seen) == 100 and "h999.example.com" in seen and "h0.example.com" not in seen


# ----------------------------------------------------- tracking integrity (2)
def _scan(conn, target="example.com", status=ScanStatus.COMPLETED):
    s = Scan(target=target, status=status)
    db.save_scan(conn, s)
    db.finish_scan(conn, s.id, status.value)
    return s


def _ctx(conn, scan, stages=(), degraded=()):
    return SimpleNamespace(conn=conn, scan=scan, target=scan.target, stage_results=list(stages),
                           degraded_tools=list(degraded))


def _assets(conn, scan, hosts):
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host=h, in_scope=True) for h in hosts])


def test_failed_recon_does_not_report_every_asset_as_removed(conn):
    base = _scan(conn)
    _assets(conn, base, ["a.example.com", "b.example.com"])
    run_stage(_ctx(conn, base))
    bad = _scan(conn, status=ScanStatus.FAILED)                    # recon crashed: no assets saved
    res = run_stage(_ctx(conn, bad, stages=[StageResult("recon", "failed", "boom")]))
    assert res and "skipped" in res
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_type='removed_asset'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM tracked_assets WHERE is_active=1").fetchone()[0] == 2


def test_incomplete_scan_records_new_assets_but_not_disappearances(conn):
    base = _scan(conn)
    _assets(conn, base, ["a.example.com", "b.example.com"])
    run_stage(_ctx(conn, base))
    second = _scan(conn)
    _assets(conn, second, ["a.example.com", "new.example.com"])    # b is missing: subfinder timed out
    run_stage(_ctx(conn, second, degraded=[toolstatus.ToolRun("subfinder", "timeout")]))
    kinds = {r["alert_type"] for r in conn.execute("SELECT alert_type FROM alerts")}
    assert "new_asset" in kinds and "removed_asset" not in kinds
    assert conn.execute("SELECT is_active FROM tracked_assets WHERE host='b.example.com'").fetchone()[0] == 1


def test_complete_scan_still_reports_a_real_disappearance(conn):
    base = _scan(conn)
    _assets(conn, base, ["a.example.com", "b.example.com"])
    run_stage(_ctx(conn, base))
    second = _scan(conn)
    _assets(conn, second, ["a.example.com"])
    run_stage(_ctx(conn, second))
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_type='removed_asset'").fetchone()[0] == 1


# ------------------------------------------------------------- alert keys (15)
def test_every_new_port_on_a_host_gets_its_own_alert(conn):
    from marsadix.models import Service
    old, new = _scan(conn), _scan(conn)
    db.save_many(conn, "services", [Service(scan_id=old.id, host="a.example.com", port=80)])
    db.save_many(conn, "services", [Service(scan_id=new.id, host="a.example.com", port=80),
                                    Service(scan_id=new.id, host="a.example.com", port=8080),
                                    Service(scan_id=new.id, host="a.example.com", port=9200)])
    run_stage(_ctx(conn, new))
    n = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_type='new_port'").fetchone()[0]
    assert n == 2
    run_stage(_ctx(conn, new))                                    # re-run: still no duplicates
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_type='new_port'").fetchone()[0] == 2


# ------------------------------------------- scan selection for diff/report (11)
def test_latest_completed_scan_skips_failed_and_interrupted(conn):
    good = _scan(conn)
    _scan(conn, status=ScanStatus.FAILED)
    _scan(conn, status=ScanStatus.INTERRUPTED)
    assert [r["id"] for r in db.get_latest_scans(conn, "example.com", 5, completed_only=True)] == [good.id]
    assert len(db.get_latest_scans(conn, "example.com", 5)) == 3


def test_report_defaults_to_the_latest_completed_scan_and_rejects_a_foreign_scan_id(conn):
    from marsadix.reports.generate import _gather
    good = _scan(conn)
    _scan(conn, status=ScanStatus.FAILED)
    other = _scan(conn, target="other.org")
    assert _gather(conn, "example.com", None)["scan"]["id"] == good.id
    assert _gather(conn, "example.com", other.id) is None          # id belongs to another target
    assert _gather(conn, "EXAMPLE.com", good.id) is not None


# ------------------------------------------------------------------- sqlite
def test_connect_enables_busy_timeout_and_wal(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 30000
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    conn.close()


# --------------------------------------------------------------- katana scope
def test_katana_is_limited_to_each_seed_host(monkeypatch):
    from marsadix.web import probe
    seen = {}

    class R:
        def __init__(self):
            self._d = [b"https://a.example.com/x\n", b""]
        async def read(self, n=-1):
            return self._d.pop(0)

    class Proc:
        returncode = 0
        stdout, stderr = R(), R()
        stdin = None
        async def wait(self): return 0
        def kill(self): pass

    async def fake_exec(*argv, **kw):
        seen["argv"], seen["env"] = list(argv), kw.get("env")
        return Proc()

    monkeypatch.setattr(probe.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setenv("SHODAN_API_KEY", "s3cret")
    asyncio.run(probe.run_katana(["https://a.example.com"], 5))
    argv = seen["argv"]
    assert argv[argv.index("-fs") + 1] == "fqdn"
    assert "SHODAN_API_KEY" not in seen["env"]


# ------------------------------------------------- keys must not live in .env.example
def test_real_keys_in_env_example_trigger_a_warning_without_printing_them(tmp_path, monkeypatch, caplog):
    from marsadix.core.config import warn_if_secrets_in_example
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env.example").write_text("SHODAN_API_KEY=sup3rs3cretvalue\nVIRUSTOTAL_API_KEY=\n# note\nMARSADIX_RATE_LIMIT=20\n")
    with caplog.at_level("WARNING"):
        assert warn_if_secrets_in_example() == ["SHODAN_API_KEY"]
    assert "SHODAN_API_KEY" in caplog.text and "sup3rs3cretvalue" not in caplog.text


def test_the_shipped_env_example_holds_no_values_for_secrets():
    from pathlib import Path
    from marsadix.core.config import warn_if_secrets_in_example
    assert warn_if_secrets_in_example(str(Path(__file__).resolve().parents[1] / ".env.example")) == []
