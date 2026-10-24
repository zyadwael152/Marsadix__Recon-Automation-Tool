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
