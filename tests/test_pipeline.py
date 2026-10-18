import pytest

from marsadix.core.config import Config, ConfigError
from marsadix.core.pipeline import run_scan


def test_run_scan_defaults_to_config_mode(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), scan_mode="standard")
    scan, _ = run_scan("example.com", cfg)
    assert scan.mode.value == "standard"


def test_run_scan_explicit_mode_overrides_config(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), scan_mode="passive")
    scan, _ = run_scan("example.com", cfg, mode="full")
    assert scan.mode.value == "full"


def test_run_scan_rejects_invalid_mode(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"))
    with pytest.raises(ConfigError):
        run_scan("example.com", cfg, mode="bogus")


def test_run_scan_allow_injection_does_not_mutate_shared_config(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), allow_injection=False)
    run_scan("example.com", cfg, allow_injection=True)
    assert cfg.allow_injection is False  # the original Config object is untouched
