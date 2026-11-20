import pytest

from marsadix.core.config import Config, ConfigError, normalize_mode
from marsadix.models import ScanMode
from marsadix.skills import registry


@pytest.mark.parametrize("old", ["standard", "full", "STANDARD", " Full "])
def test_old_mode_names_mean_active(old):
    assert normalize_mode(old) == "active"
    assert ScanMode(old) is ScanMode.ACTIVE


def test_passive_and_active_are_unchanged():
    assert normalize_mode("passive") == "passive"
    assert normalize_mode("active") == "active"


def test_config_accepts_old_names():
    cfg = Config(scan_mode="full")
    cfg.validate()
    assert cfg.scan_mode == "active"


def test_unknown_mode_is_rejected():
    with pytest.raises(ConfigError):
        Config(scan_mode="bogus").validate()


def test_registry_treats_old_names_as_active():
    old = {s.name for s in registry.active_skills("full", True)}
    new = {s.name for s in registry.active_skills("active", True)}
    assert old == new
