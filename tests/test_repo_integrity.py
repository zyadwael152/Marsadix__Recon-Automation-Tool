"""The repository must hang together: every module imports, every pipeline stage loads, the shared
config file serves both loaders, and the safety defaults of the ASM stage stay in place.

These tests exist because a partial merge once left a syntax error in web/probe.py, a stage module that
was missing, and four 'shared' modules that nobody imported and that could not even be imported."""

import asyncio
import importlib
import pkgutil
from pathlib import Path

import pytest

import marsadix
from marsadix.core import pipeline
from marsadix.core.config import load_config
from marsadix.core.loader import load_callable

ROOT = Path(__file__).resolve().parents[1]


def test_every_module_in_the_package_can_be_imported():
    broken = []
    for mod in pkgutil.walk_packages(marsadix.__path__, "marsadix."):
        if mod.name.endswith("__main__"):
            continue
        try:
            importlib.import_module(mod.name)
        except Exception as e:                                  # noqa: BLE001 - any failure is the finding
            broken.append(f"{mod.name}: {type(e).__name__}: {e}")
    assert not broken, "modules that cannot be imported:\n  " + "\n  ".join(broken)


@pytest.mark.parametrize("name,path", pipeline.STAGES)
def test_every_pipeline_stage_that_exists_loads(name, path):
    module = path.partition(":")[0]
    if name == "monitor":
        pytest.skip("monitor is not part of the pipeline stages")
    importlib.import_module(module)
    assert callable(load_callable(path))


def test_the_duplicated_copies_are_gone():
    gone = ["core/http_client.py", "core/rate_limit.py", "core/security.py", "core/verify.py",
            "web/js.py", "web/discovery.py", "web/errors.py", "web/normalize.py", "web/config.py",
            "web/tools.py", "web/crawl.py", "coverage.py"]
    assert [g for g in gone if (ROOT / "marsadix" / g).exists()] == []
    assert (ROOT / "marsadix" / "web_recon" / "http_client.py").exists()     # the one real implementation


# ------------------------------------------------------------- one config file
def test_shared_config_file_is_accepted_by_both_loaders(tmp_path):
    from marsadix.web_recon.config import Member2Config
    p = tmp_path / "config.toml"
    p.write_text("rate_limit = 20\n[web_recon]\nrate_limit = 5\nretries = 1\n")
    assert load_config(str(p)).rate_limit == 20                   # base settings: the extension table is not an error
    cfg = Member2Config.from_toml(str(p))
    assert cfg.rate_limit == 5 and cfg.retries == 1               # extension settings come from its own table


def test_the_old_member2_table_name_still_works(tmp_path):
    from marsadix.web_recon.config import Member2Config
    p = tmp_path / "config.toml"
    p.write_text("[member2]\nrate_limit = 7\n")
    assert load_config(str(p)).rate_limit == Config_default_rate()
    assert Member2Config.from_toml(str(p)).rate_limit == 7


def Config_default_rate():
    from marsadix.core.config import Config
    return Config().rate_limit


def test_the_shipped_example_config_loads_in_both_loaders():
    from marsadix.web_recon.config import Member2Config
    path = str(ROOT / "config.example.toml")
    assert load_config(path) is not None
    assert Member2Config.from_toml(path) is not None
    assert not (ROOT / "marsadix" / "config").exists()            # no second config folder


def test_an_unknown_table_is_still_rejected(tmp_path):
    from marsadix.core.config import ConfigError
    p = tmp_path / "c.toml"
    p.write_text("[surprise]\nx = 1\n")
    with pytest.raises(ConfigError):
        load_config(str(p))


# ------------------------------------------------------------- ASM safety + registry
def test_nuclei_never_runs_dos_fuzz_or_intrusive_templates(monkeypatch):
    from marsadix.asm import nuclei as nuclei_module
    from marsadix.asm.config import ASMConfig
    from marsadix.asm.runtime import ToolExecution
    from marsadix.core.scope import Scope

    seen = {}

    async def fake_run_tool(name, executable, argv, *, input_text=None, timeout=300):
        seen["argv"] = argv
        return ToolExecution(name=name, argv=[executable, *argv], stdout="", returncode=0)

    async def no_dns(self, normalized):
        return ()

    class Resolver:
        def path(self, name):
            return "/bin/nuclei"

    monkeypatch.setattr(nuclei_module, "run_tool", fake_run_tool)
    monkeypatch.setattr(nuclei_module.ScopeEnforcer, "ensure_safe_url", no_dns)
    enforcer = nuclei_module.ScopeEnforcer(scope=Scope.from_target("example.com"), target="example.com")
    asyncio.run(nuclei_module.run_nuclei(["https://a.example.com/"], 1, "example.com", ASMConfig(), Resolver(), enforcer))
    argv = seen["argv"]
    assert argv[argv.index("-etags") + 1] == "dos,fuzz,intrusive"
    assert "-dr" in argv and "-ni" in argv and "-duc" in argv       # no redirects, no out-of-band, no self-update


def test_the_registry_lists_the_nuclei_groups_as_active_now():
    from marsadix.skills import registry
    names = {s.name for s in registry.active_skills("standard", True)}
    assert {"nuclei-takeover", "nuclei-exposures", "nuclei-tech-cve"} <= names
    assert registry.active_skills("passive", True) == []
    planned = {s.name for s in registry.all_skills() if not registry.is_implemented(s.name)}
    assert {"xss", "sqli", "ssti", "open-redirect", "crlf", "host-header", "jwt", "git-env-exposure"} <= planned
