import pytest

from marsadix.core.config import Config, ConfigError
from marsadix.core.pipeline import run_scan
from marsadix.core.scope import Scope, ScopeError


def test_run_scan_defaults_to_config_mode(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), scan_mode="standard")
    scan, _ = run_scan("example.com", cfg, scope=Scope.from_target("example.com"))
    assert scan.mode.value == "standard"


def test_run_scan_explicit_mode_overrides_config(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), scan_mode="passive")
    scan, _ = run_scan("example.com", cfg, mode="full", scope=Scope.from_target("example.com"))
    assert scan.mode.value == "full"


def test_run_scan_rejects_invalid_mode(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"))
    with pytest.raises(ConfigError):
        run_scan("example.com", cfg, mode="bogus")


def test_run_scan_allow_injection_does_not_mutate_shared_config(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), allow_injection=False)
    run_scan("example.com", cfg, allow_injection=True)
    assert cfg.allow_injection is False  # the original Config object is untouched


# ---------------------------------------------------------------------------
# Scope is mandatory before any active scan (C15)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["standard", "full"])
def test_active_modes_refuse_to_run_without_an_explicit_scope(tmp_path, mode):
    dbp = tmp_path / "t.db"
    cfg = Config(db_path=str(dbp))
    with pytest.raises(ScopeError, match="explicit scope"):
        run_scan("example.com", cfg, mode=mode)
    assert not dbp.exists()          # refused up front: no scan row, no traffic


def test_config_default_mode_is_also_checked(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), scan_mode="standard")
    with pytest.raises(ScopeError):
        run_scan("example.com", cfg)         # mode comes from config.toml, not the flag


def test_passive_mode_still_works_without_a_scope(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"))
    scan, _ = run_scan("example.com", cfg)
    assert scan.mode.value == "passive"


def test_scope_file_path_is_stored_on_the_scan(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"))
    scan, _ = run_scan("example.com", cfg, mode="standard",
                       scope=Scope.from_target("example.com"), scope_file="scope.txt")
    assert scan.scope_file == "scope.txt"


# ---------------------------------------------------------------------------
# Rate limit (C6)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [0, -5])
def test_rate_limit_below_one_is_rejected(tmp_path, bad):
    # httpx/katana read "-rl 0" as "no limit at all": never let a typo mean that
    cfg = Config(db_path=str(tmp_path / "t.db"))
    with pytest.raises(ConfigError, match="rate limit"):
        run_scan("example.com", cfg, rate_limit=bad)


def test_negative_depth_is_rejected(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"))
    with pytest.raises(ConfigError, match="depth"):
        run_scan("example.com", cfg, max_depth=-1)


def test_cli_rate_and_depth_reach_the_scan_and_ctx_config(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr("marsadix.recon.stage.run", lambda ctx: seen.update(
        scan_rate=ctx.scan.rate_limit, cfg_rate=ctx.config.rate_limit,
        scan_depth=ctx.scan.max_depth, cfg_depth=ctx.config.max_depth))
    cfg = Config(db_path=str(tmp_path / "t.db"), rate_limit=50, max_depth=3)
    run_scan("example.com", cfg, rate_limit=7, max_depth=1)

    assert seen == {"scan_rate": 7, "cfg_rate": 7, "scan_depth": 1, "cfg_depth": 1}
    assert cfg.rate_limit == 50      # the caller's Config is not mutated



# ---------------------------------------------------------------------------
# Scan lifecycle: a crash or Ctrl+C must never leave a scan "running" forever
# ---------------------------------------------------------------------------

import importlib
import sqlite3

from marsadix import db
from marsadix.core import pipeline
from marsadix.models import ScanStatus


@pytest.fixture
def stage_modules(tmp_path, monkeypatch):
    """write_stage(name, source) creates an importable stage module; use_stages([...]) selects the stages."""
    monkeypatch.syspath_prepend(str(tmp_path))

    def write(name, source):
        (tmp_path / f"{name}.py").write_text(source)
        importlib.invalidate_caches()

    def use(*names_and_modules):
        monkeypatch.setattr(pipeline, "STAGES", [(n, f"{m}:run") for n, m in names_and_modules])
    return write, use


def _scan_rows(db_path):
    c = sqlite3.connect(db_path)
    c.row_factory = sqlite3.Row
    rows = [(r["id"], r["status"], r["is_baseline"], r["finished_at"] is not None) for r in c.execute("SELECT * FROM scans")]
    c.close()
    return rows


def test_a_stage_whose_own_import_is_broken_fails_that_stage_not_the_whole_cli(tmp_path, stage_modules):
    write, use = stage_modules
    write("lc_broken", "from marsadix.recon.no_such_module import x\ndef run(ctx): pass\n")
    write("lc_ok", "def run(ctx): return {}\n")
    use(("recon", "lc_broken"), ("web", "lc_ok"))
    cfg = Config(db_path=str(tmp_path / "t.db"))

    scan, results = run_scan("example.com", cfg)                    # used to raise ModuleNotFoundError out of run_scan

    assert [(r.name, r.status) for r in results] == [("recon", "failed"), ("web", "ok")]     # the next stage still ran
    assert "no_such_module" in results[0].detail and "could not load" in results[0].detail
    assert scan.status == ScanStatus.FAILED
    assert _scan_rows(cfg.db_path) == [(1, "failed", 1, True)]


def test_ctrl_c_marks_the_scan_interrupted_and_still_propagates(tmp_path, stage_modules):
    write, use = stage_modules
    write("lc_ctrlc", "def run(ctx): raise KeyboardInterrupt()\n")
    use(("recon", "lc_ctrlc"))
    cfg = Config(db_path=str(tmp_path / "t.db"))

    with pytest.raises(KeyboardInterrupt):
        run_scan("example.com", cfg)

    assert _scan_rows(cfg.db_path) == [(1, "interrupted", 1, True)]         # not "running" forever


def test_an_unexpected_error_outside_the_stages_marks_the_scan_failed(tmp_path, stage_modules, monkeypatch):
    write, use = stage_modules
    write("lc_ok2", "def run(ctx): return {}\n")
    use(("recon", "lc_ok2"))
    monkeypatch.setattr(db, "finish_scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full")))
    cfg = Config(db_path=str(tmp_path / "t.db"))
    with pytest.raises(RuntimeError, match="disk full"):
        run_scan("example.com", cfg)                                # finish_scan itself failed; the error is not hidden


def test_the_database_connection_is_closed_on_success_and_on_interrupt(tmp_path, stage_modules, monkeypatch):
    write, use = stage_modules
    write("lc_ok3", "def run(ctx): return {}\n")
    write("lc_ctrlc3", "def run(ctx): raise KeyboardInterrupt()\n")
    opened = []
    real_connect = db.connect
    monkeypatch.setattr(db, "connect", lambda path: opened.append(real_connect(path)) or opened[-1])
    cfg = Config(db_path=str(tmp_path / "t.db"))

    use(("recon", "lc_ok3"))
    run_scan("example.com", cfg)
    use(("recon", "lc_ctrlc3"))
    with pytest.raises(KeyboardInterrupt):
        run_scan("example.com", cfg)

    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):               # "Cannot operate on a closed database"
            conn.execute("SELECT 1")


def test_a_scan_after_a_crashed_first_scan_is_still_the_baseline(tmp_path, stage_modules):
    """is_baseline used to count every scan row: one Ctrl+C'd scan meant no scan was ever the baseline."""
    write, use = stage_modules
    write("lc_ctrlc4", "def run(ctx): raise KeyboardInterrupt()\n")
    write("lc_ok4", "def run(ctx): return {}\n")
    cfg = Config(db_path=str(tmp_path / "t.db"))

    use(("recon", "lc_ctrlc4"))
    with pytest.raises(KeyboardInterrupt):
        run_scan("example.com", cfg)
    use(("recon", "lc_ok4"))
    second, _ = run_scan("example.com", cfg)
    third, _ = run_scan("example.com", cfg)

    assert second.is_baseline is True                               # nothing had COMPLETED before it
    assert third.is_baseline is False                               # a completed scan exists now
    assert [(r[1], r[2]) for r in _scan_rows(cfg.db_path)] == [("interrupted", 1), ("completed", 1), ("completed", 0)]


def test_a_failed_first_scan_does_not_stop_the_next_one_being_the_baseline(tmp_path, stage_modules):
    write, use = stage_modules
    write("lc_boom", "def run(ctx): raise RuntimeError('boom')\n")
    write("lc_ok5", "def run(ctx): return {}\n")
    cfg = Config(db_path=str(tmp_path / "t.db"))
    use(("recon", "lc_boom"))
    first, _ = run_scan("example.com", cfg)
    use(("recon", "lc_ok5"))
    second, _ = run_scan("example.com", cfg)
    assert first.status == ScanStatus.FAILED and second.is_baseline is True
