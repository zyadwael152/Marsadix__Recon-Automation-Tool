import os
import pytest
from marsadix import db
from marsadix.cli import main
from marsadix.core.config import ConfigError, load_config


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)          # no stray config.toml / .env
    for k in ("NVD_API_KEY", "DISCORD_WEBHOOK_URL", "MARSADIX_DB", "MARSADIX_OUTPUT_DIR"):
        monkeypatch.delenv(k, raising=False)


def test_scan_runs_and_stores_scan(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    assert main(["--db", dbp, "scan", "example.com"]) == 0
    out = capsys.readouterr().out
    assert "completed" in out and "(baseline)" in out
    assert "skipped" in out                       # stages not written yet
    conn = db.connect(dbp)
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_second_scan_is_not_baseline(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    main(["--db", dbp, "scan", "example.com"])
    capsys.readouterr()
    main(["--db", dbp, "scan", "example.com"])
    assert "(baseline)" not in capsys.readouterr().out


def test_target_outside_scope_is_refused(tmp_path, capsys):
    scope = tmp_path / "scope.txt"
    scope.write_text("*.example.com\n")           # apex NOT included
    rc = main(["--db", str(tmp_path / "t.db"), "scan", "example.com", "--scope", str(scope)])
    assert rc == 1 and "not in scope" in capsys.readouterr().err


def test_unimplemented_commands_exit_3(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    assert main(["--db", dbp, "monitor"]) == 3
    assert "not implemented yet" in capsys.readouterr().err


def test_report_needs_a_scan(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    assert main(["--db", dbp, "report", "example.com"]) == 1
    assert "no completed scans found" in capsys.readouterr().err


def test_report_writes_html_and_json(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    out = str(tmp_path / "out")
    main(["--db", dbp, "scan", "example.com"])
    capsys.readouterr()
    assert main(["--db", dbp, "report", "example.com", "--out", out]) == 0
    files = list((tmp_path / "out").glob("*"))
    names = {f.name for f in files}
    assert any(n.endswith("_report.html") for n in names)
    assert any(n.endswith("_report.json") for n in names)


def test_scan_default_mode_is_passive(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    main(["--db", dbp, "scan", "example.com"])
    out = capsys.readouterr().out
    assert "[mode=passive]" in out


def _scope_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("example.com\n*.example.com\n")
    return str(f)


def test_scan_accepts_explicit_mode(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    main(["--db", dbp, "scan", "example.com", "--mode", "full", "--scope", _scope_file(tmp_path)])
    out = capsys.readouterr().out
    assert "[mode=full]" in out


@pytest.mark.parametrize("mode", ["standard", "full"])
def test_scan_active_mode_without_scope_is_refused(tmp_path, capsys, mode):
    dbp = tmp_path / "t.db"
    rc = main(["--db", str(dbp), "scan", "example.com", "--mode", mode])
    err = capsys.readouterr().err
    assert rc == 1
    assert "explicit scope" in err and "--scope" in err
    assert not dbp.exists()


def test_scan_rate_below_one_is_refused(tmp_path, capsys):
    rc = main(["--db", str(tmp_path / "t.db"), "scan", "example.com", "--rate", "0"])
    assert rc == 1 and "rate limit" in capsys.readouterr().err


def test_scan_rejects_invalid_mode(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    with pytest.raises(SystemExit) as exc:
        main(["--db", dbp, "scan", "example.com", "--mode", "bogus"])
    assert exc.value.code == 2  # argparse's own validation


def test_graph_needs_a_scan(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    assert main(["--db", dbp, "graph", "example.com"]) == 1
    assert "no scans found" in capsys.readouterr().err


def test_graph_runs_after_a_scan(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    main(["--db", dbp, "scan", "example.com"])
    capsys.readouterr()
    assert main(["--db", dbp, "graph", "example.com"]) == 0
    out = capsys.readouterr().out
    assert "Knowledge Graph for example.com" in out


def test_diff_needs_two_scans(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    assert main(["--db", dbp, "diff", "example.com"]) == 1
    assert "need at least 2 scans" in capsys.readouterr().err


def test_diff_runs_after_two_scans(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    main(["--db", dbp, "scan", "example.com"])
    capsys.readouterr()
    main(["--db", dbp, "scan", "example.com"])
    capsys.readouterr()
    assert main(["--db", dbp, "diff", "example.com"]) == 0
    out = capsys.readouterr().out
    assert "Diff for example.com" in out
    assert "New assets" in out


def test_scope_command(tmp_path, capsys):
    scope = tmp_path / "scope.txt"
    scope.write_text("*.example.com\n!mail.example.com\n")
    main(["scope", str(scope), "dev.example.com", "mail.example.com", "evil.com"])
    out = capsys.readouterr().out
    assert "IN   dev.example.com" in out
    assert "OUT  mail.example.com" in out and "OUT  evil.com" in out


def test_doctor_runs(capsys):
    assert main(["doctor"]) == 0
    assert "External tools" in capsys.readouterr().out


def test_config_toml_and_env(tmp_path, monkeypatch):
    (tmp_path / "config.toml").write_text('max_depth = 5\nrate_limit = 10\n')
    monkeypatch.setenv("NVD_API_KEY", "secret")
    cfg = load_config()
    assert cfg.max_depth == 5 and cfg.nvd_api_key == "secret"
    assert "secret" not in repr(cfg)              # secrets never printed


def test_config_rejects_unknown_key(tmp_path):
    (tmp_path / "config.toml").write_text('bogus = 1\n')
    with pytest.raises(ConfigError):
        load_config()


def test_failing_stage_marks_scan_failed(tmp_path, monkeypatch, capsys):
    from marsadix.core import pipeline
    def boom(ctx): raise RuntimeError("kaboom")
    monkeypatch.setattr(pipeline, "load_callable", lambda p: boom if "recon" in p else None)
    assert main(["--db", str(tmp_path / "t.db"), "scan", "example.com"]) == 1
    out = capsys.readouterr().out
    assert "failed" in out and "kaboom" in out


def test_snapshots_needs_a_scan(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    assert main(["--db", dbp, "snapshots", "example.com"]) == 1
    assert "no scans found" in capsys.readouterr().err


def test_snapshots_lists_scans(tmp_path, capsys):
    dbp = str(tmp_path / "t.db")
    main(["--db", dbp, "scan", "example.com"])
    capsys.readouterr()
    main(["--db", dbp, "scan", "example.com"])
    capsys.readouterr()
    assert main(["--db", dbp, "snapshots", "example.com"]) == 0
    out = capsys.readouterr().out
    assert "Snapshots for example.com (2 scan(s))" in out



# ---------------------------------------------------------------------------
# ct-monitor output path, Windows-written scope files, unreadable files
# ---------------------------------------------------------------------------

@pytest.fixture
def ct_calls(monkeypatch):
    calls = []

    async def fake_monitor(target, output_file=None):
        calls.append({"target": target, "out": output_file})
    monkeypatch.setattr("marsadix.recon.ct_monitor.monitor_ct_logs", fake_monitor)
    return calls


def test_ct_monitor_writes_into_the_configured_output_folder(tmp_path, ct_calls):
    rc = main(["--no-banner", "--db", str(tmp_path / "t.db"), "ct-monitor", "Example.COM"])
    assert rc == 0
    assert ct_calls == [{"target": "example.com", "out": os.path.join("output", "example.com_ct_assets.txt")}]
    assert (tmp_path / "output").is_dir() and not (tmp_path / "outputs").exists()


def test_ct_monitor_honours_output_dir_from_the_environment(tmp_path, ct_calls, monkeypatch):
    monkeypatch.setenv("MARSADIX_OUTPUT_DIR", "results")
    main(["--no-banner", "ct-monitor", "example.com"])
    assert ct_calls[0]["out"] == os.path.join("results", "example.com_ct_assets.txt")


@pytest.mark.parametrize("target", ["../../escape", "..\\..\\escape", "/etc/cron.d/x", "1.2.3.4", "a b.com", ".."])
def test_ct_monitor_rejects_targets_that_are_not_clean_domain_names(tmp_path, capsys, ct_calls, target):
    rc = main(["--no-banner", "ct-monitor", target])
    assert rc == 1 and "invalid target for ct-monitor" in capsys.readouterr().err
    assert ct_calls == []
    assert list(tmp_path.iterdir()) == []                          # nothing was created anywhere


def test_an_unusable_output_folder_is_an_error_message_not_a_traceback(tmp_path, capsys, ct_calls, monkeypatch):
    (tmp_path / "taken").write_text("i am a file, not a folder")
    monkeypatch.setenv("MARSADIX_OUTPUT_DIR", "taken")
    rc = main(["--no-banner", "ct-monitor", "example.com"])
    assert rc == 1 and capsys.readouterr().err.startswith("error:")


def test_scan_accepts_a_scope_file_saved_as_utf16_by_powershell(tmp_path, capsys):
    f = tmp_path / "scope.txt"
    f.write_bytes("example.com\r\n*.example.com\r\n".encode("utf-16"))
    rc = main(["--no-banner", "--db", str(tmp_path / "t.db"), "scan", "example.com", "--mode", "standard", "--scope", str(f)])
    assert rc == 0 and "[mode=standard]" in capsys.readouterr().out


def test_a_garbage_scope_file_is_a_one_line_error(tmp_path, capsys):
    f = tmp_path / "scope.txt"
    f.write_bytes(b"example.com\n\xff\xfe\xfa\n")
    rc = main(["--no-banner", "--db", str(tmp_path / "t.db"), "scan", "example.com", "--mode", "standard", "--scope", str(f)])
    err = capsys.readouterr().err
    assert rc == 1 and err.startswith("error: cannot read scope file") and "Traceback" not in err


class _TrackingConn:
    def __init__(self, conn):
        self._conn = conn
        self.closed = False

    def close(self):
        self.closed = True
        self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def test_db_commands_close_their_connection(tmp_path, monkeypatch, capsys):
    """An unclosed SQLite handle keeps the file locked (notably on Windows)."""
    real_connect = db.connect
    opened = []

    def tracking_connect(path):
        conn = _TrackingConn(real_connect(path))
        opened.append(conn)
        return conn

    monkeypatch.setattr("marsadix.cli.db.connect", tracking_connect)

    # `graph` with no scans: opens the DB, reports the error, returns 1.
    assert main(["--no-banner", "--db", str(tmp_path / "t.db"), "graph", "example.com"]) == 1
    assert "no scans found" in capsys.readouterr().err
    assert opened and all(c.closed for c in opened)
