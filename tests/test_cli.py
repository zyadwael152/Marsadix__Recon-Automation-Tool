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
    for cmd in (["monitor"], ["diff", "example.com"], ["report", "example.com"]):
        assert main(["--db", dbp] + cmd) == 3
    assert "not implemented yet" in capsys.readouterr().err


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
