import logging
import os

import pytest

from marsadix.core.config import Config, ConfigError, load_config, load_dotenv

KNOWN = ["SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "MARSADIX_DNS_RATE_LIMIT", "MARSADIX_MAX_PERMUTATIONS",
         "MARSADIX_BRUTEFORCE_WORDLIST", "MARSADIX_RESOLVERS_FILE", "MARSADIX_DB"]
DANGEROUS = ["LD_PRELOAD", "HTTPS_PROXY", "PYTHONSTARTUP", "PATH_EVIL", "SSL_CERT_FILE"]


@pytest.fixture(autouse=True)
def clean_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                                     # no stray .env / config.toml
    for k in KNOWN + DANGEROUS:
        monkeypatch.delenv(k, raising=False)


def test_dotenv_only_reads_marsadixs_own_settings():
    open(".env", "w").write("LD_PRELOAD=/tmp/evil.so\nHTTPS_PROXY=http://attacker:8080\nPYTHONSTARTUP=/tmp/x.py\n"
                            "SHODAN_API_KEY=abc\n")
    cfg = load_config(None)
    assert cfg.shodan_api_key == "abc"
    for k in DANGEROUS:
        assert k not in os.environ, f"{k} leaked into the environment inherited by every scan tool"


def test_dotenv_names_ignored_variables_but_never_prints_their_values(caplog):
    open(".env", "w").write("LD_PRELOAD=/tmp/very-secret-path.so\n")
    with caplog.at_level(logging.WARNING):
        load_dotenv()
    assert "LD_PRELOAD" in caplog.text and "very-secret-path" not in caplog.text


def test_real_environment_variables_win_over_the_dotenv_file(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "from-real-env")
    open(".env", "w").write("SHODAN_API_KEY=from-file\n")
    assert load_config(None).shodan_api_key == "from-real-env"


def test_dotenv_accepts_export_prefix_quotes_and_crlf():
    open(".env", "wb").write(b'export SHODAN_API_KEY="abc123"\r\nVIRUSTOTAL_API_KEY=\'vt456\'\r\n')
    cfg = load_config(None)
    assert (cfg.shodan_api_key, cfg.virustotal_api_key) == ("abc123", "vt456")


@pytest.mark.parametrize("label,data", [
    ("utf-8 BOM", b"\xef\xbb\xbf" + b"SHODAN_API_KEY=abc\r\n"),
    ("utf-16 (PowerShell redirect)", "SHODAN_API_KEY=abc\r\n".encode("utf-16")),
])
def test_dotenv_written_by_windows_tools_is_readable(label, data):
    open(".env", "wb").write(data)
    assert load_config(None).shodan_api_key == "abc", label


def test_an_undecodable_dotenv_is_a_clear_config_error_not_a_traceback():
    open(".env", "wb").write(b"SHODAN_API_KEY=\xff\xfe\xfa broken")
    with pytest.raises(ConfigError, match="cannot read .env"):
        load_config(None)


# ------------------------------------------------------------------ recon tuning knobs

def test_the_recon_knobs_exist_with_safe_defaults():
    cfg = Config()
    assert (cfg.dns_rate_limit, cfg.max_permutations, cfg.bruteforce_wordlist, cfg.resolvers_file) == (0, 20000, "", "")


def test_recon_knobs_can_be_set_from_the_environment_as_numbers(monkeypatch):
    monkeypatch.setenv("MARSADIX_DNS_RATE_LIMIT", "40")
    monkeypatch.setenv("MARSADIX_MAX_PERMUTATIONS", "500")
    monkeypatch.setenv("MARSADIX_BRUTEFORCE_WORDLIST", "words.txt")
    monkeypatch.setenv("MARSADIX_RESOLVERS_FILE", "resolvers.txt")
    cfg = load_config(None)
    assert cfg.dns_rate_limit == 40 and cfg.max_permutations == 500          # ints, not the strings "40"/"500"
    assert (cfg.bruteforce_wordlist, cfg.resolvers_file) == ("words.txt", "resolvers.txt")


def test_a_non_numeric_value_for_a_numeric_setting_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("MARSADIX_DNS_RATE_LIMIT", "fast")
    with pytest.raises(ConfigError, match="MARSADIX_DNS_RATE_LIMIT must be a whole number"):
        load_config(None)


@pytest.mark.parametrize("field,value", [("dns_rate_limit", -1), ("max_permutations", 0)])
def test_recon_knobs_are_validated(field, value):
    cfg = Config()
    setattr(cfg, field, value)
    with pytest.raises(ConfigError, match=field):
        cfg.validate()


def test_recon_knobs_from_config_toml():
    pytest.importorskip("tomllib")
    open("config.toml", "w").write('dns_rate_limit = 25\nmax_permutations = 100\nbruteforce_wordlist = "w.txt"\n')
    cfg = load_config(None)
    assert (cfg.dns_rate_limit, cfg.max_permutations, cfg.bruteforce_wordlist) == (25, 100, "w.txt")


def test_config_toml_saved_as_utf16_by_powershell_is_readable():
    pytest.importorskip("tomllib")
    open("config.toml", "wb").write('rate_limit = 7\r\n'.encode("utf-16"))
    assert load_config(None).rate_limit == 7


def test_a_secret_in_config_toml_triggers_a_warning_that_never_shows_the_secret(caplog):
    pytest.importorskip("tomllib")
    open("config.toml", "w").write('shodan_api_key = "TOPSECRETVALUE"\n')
    with caplog.at_level(logging.WARNING):
        cfg = load_config(None)
    assert cfg.shodan_api_key == "TOPSECRETVALUE"                      # still honoured...
    assert "shodan_api_key" in caplog.text and "TOPSECRETVALUE" not in caplog.text   # ...but flagged
