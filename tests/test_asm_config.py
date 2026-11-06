from marsadix.asm.config import ASMConfig


def test_asm_config_inherits_shared_runtime_limits():
    class Runtime:
        db_path = "runtime.db"
        output_dir = "runtime-output"
        rate_limit = 17
        tool_timeout = 91

    cfg = ASMConfig.from_runtime(Runtime())
    assert cfg.db_path == "runtime.db"
    assert cfg.output_dir == "runtime-output"
    assert cfg.rate_limit == 17
    assert cfg.tool_timeout == 91
    assert cfg.write_outputs is False


def test_asm_config_reads_its_own_environment(monkeypatch):
    monkeypatch.setenv("MARSADIX_ASM_NUCLEI_ENABLED", "false")
    monkeypatch.setenv("MARSADIX_ASM_NUCLEI_TAGS", "cve, exposure")
    monkeypatch.setenv("MARSADIX_ASM_NUCLEI_HEADLESS", "1")
    cfg = ASMConfig.from_runtime()
    assert cfg.nuclei_enabled is False
    assert cfg.nuclei_tags == ("cve", "exposure")
    assert cfg.nuclei_headless is True


def test_asm_config_rejects_invalid_limits():
    cfg = ASMConfig(rate_limit=0)
    try:
        cfg.validate()
    except ValueError:
        pass
    else:
        raise AssertionError("invalid ASM limits must be rejected")
