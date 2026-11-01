import pytest

from marsadix.web_recon.config import Member2Config, parse_status_ranges
from marsadix.web_recon.errors import ConfigError, ScopeViolation
from marsadix.web_recon.normalize import (
    classify_kind, dedupe_normalized, is_under_domain, normalize_url,
)


def test_normalization_removes_default_port_fragment_and_tracking():
    n = normalize_url("HTTPS://Example.com:443/a/../b?utm_source=x&b=2&a=1#frag")
    assert n.url == "https://example.com/b?b=2&a=1"
    assert n.key == "https://example.com/b?a=1&b=2"
    assert n.host == "example.com"
    assert n.has_params is True


def test_query_order_does_not_change_the_dedup_key():
    a = normalize_url("https://e.test/x?a=1&b=2")
    b = normalize_url("https://e.test/x?b=2&a=1")
    assert a.key == b.key


def test_relative_urls_are_resolved_against_a_base():
    n = normalize_url("../api/v1?q=1", base_url="https://e.test/static/app.js")
    assert n.url == "https://e.test/api/v1?q=1"


def test_scheme_relative_urls_use_https():
    assert normalize_url("//e.test/a").url == "https://e.test/a"


@pytest.mark.parametrize("bad", [
    "ftp://e.test/a",
    "https://user:pass@e.test/a",
    "https://e.test/a\\@evil.test/",
    "https://e.test/a b",
    "javascript:alert(1)",
    "/relative/without/base",
])
def test_ambiguous_or_unsafe_urls_are_rejected(bad):
    with pytest.raises(ScopeViolation):
        normalize_url(bad)


def test_https_is_preferred_when_deduplicating_schemes():
    http = normalize_url("http://e.test/a")
    https = normalize_url("https://e.test/a")
    out = dedupe_normalized([http, https])
    assert [n.url for n in out] == ["https://e.test/a"]


def test_kind_classification():
    assert classify_kind("https://e.test/") == "url"
    assert classify_kind("https://e.test/static/app.js") == "js_file"
    assert classify_kind("https://e.test/thing", content_type="text/javascript") == "js_file"
    assert classify_kind("https://e.test/api/v1") == "endpoint"


def test_domain_boundary():
    assert is_under_domain("a.example.com", "example.com")
    assert is_under_domain("example.com", "example.com")
    assert not is_under_domain("evil-example.com", "example.com")
    assert not is_under_domain("example.com.evil.test", "example.com")


def test_status_spec_parser():
    ranges = parse_status_ranges("200-299, 301,403,403")
    assert ranges == ((200, 299), (301, 301), (403, 403))
    with pytest.raises(ConfigError):
        parse_status_ranges("600")
    with pytest.raises(ConfigError):
        parse_status_ranges("")


def test_toml_section_accepts_booleans_and_tuples(tmp_path):
    from marsadix.web_recon.config import load_member2_config
    path = tmp_path / "config.toml"
    path.write_text(
        "db_path = 'custom.db'\nrate_limit = 7\n\n[member2]\n"
        "write_outputs = false\nextract_js = false\n"
        "archive_sources = ['wayback']\nstatus_allow = '200-204'\n",
        encoding="utf-8")
    cfg = load_member2_config(str(path))
    assert cfg.db_path == "custom.db"
    assert cfg.rate_limit == 7
    assert cfg.write_outputs is False
    assert cfg.extract_js is False
    assert cfg.archive_sources == ("wayback",)


def test_config_rejects_unlimited_rate_and_unknown_archive():
    with pytest.raises(ConfigError):
        Member2Config(rate_limit=0)
    with pytest.raises(ConfigError):
        Member2Config(archive_sources=("gau", "unknown"))
    cfg = Member2Config(status_allow="200-204")
    assert cfg.status_allowed(204) and not cfg.status_allowed(404)
