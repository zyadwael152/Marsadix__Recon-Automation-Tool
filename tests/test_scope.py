import pytest
from marsadix.core.scope import Scope, ScopeError, normalize_host

RULES = """
# comment
example.com
*.example.com        # inline comment
203.0.113.0/24
!mail.example.com
!*.internal.example.com
!203.0.113.50
"""


@pytest.fixture
def scope():
    return Scope.from_lines(RULES.splitlines())


@pytest.mark.parametrize("value,expected", [
    ("example.com", True),
    ("EXAMPLE.com.", True),                       # case + trailing dot
    ("dev.example.com", True),
    ("a.b.c.example.com", True),                  # any depth
    ("https://dev.example.com:8443/login?x=1", True),   # URL
    ("dev.example.com:8080", True),               # host:port
    ("mail.example.com", False),                  # excluded exactly
    ("x.mail.example.com", True),                 # exact exclusion only
    ("db.internal.example.com", False),           # wildcard exclusion
    ("internal.example.com", True),               # wildcard excl. not the apex
    ("example.org", False),
    ("notexample.com", False),                    # suffix trap
    ("example.com.evil.com", False),
    ("203.0.113.7", True),
    ("203.0.113.50", False),                      # excluded IP
    ("198.51.100.1", False),
    ("", False),
])
def test_check(scope, value, expected):
    assert scope.is_in_scope(value) is expected


def test_apex_not_matched_by_wildcard_only():
    s = Scope.from_lines(["*.example.com"])
    assert not s.is_in_scope("example.com")
    assert s.is_in_scope("www.example.com")


def test_ipv6():
    s = Scope.from_lines(["2001:db8::/32"])
    assert s.is_in_scope("2001:db8::1")
    assert not s.is_in_scope("203.0.113.1")


def test_from_target():
    s = Scope.from_target("https://Example.com/")
    assert s.is_in_scope("example.com") and s.is_in_scope("x.example.com")
    assert not s.is_in_scope("other.com")


def test_filter(scope):
    assert scope.filter(["a.example.com", "evil.com", "mail.example.com"]) == ["a.example.com"]


@pytest.mark.parametrize("bad", ["!", "ex ample.com", "-bad-.com", "http://x.com/a b"])
def test_invalid_rules(bad):
    with pytest.raises(ScopeError):
        Scope.from_lines(["example.com", bad])


def test_only_exclusions_rejected():
    with pytest.raises(ScopeError):
        Scope.from_lines(["!a.example.com"])


def test_missing_file():
    with pytest.raises(ScopeError):
        Scope.from_file("nope.txt")


def test_normalize_host():
    assert normalize_host("http://[::1]:80/x") == "::1"
    assert normalize_host("  ") is None


def test_wildcard_over_a_whole_tld_is_rejected():
    # "*.com" used to be accepted and put every .com site in scope
    with pytest.raises(ScopeError, match="top-level domain"):
        Scope.from_lines(["*.com"])


def test_normal_wildcards_and_tld_exclusions_still_work():
    sc = Scope.from_lines(["example.com", "*.example.com", "!*.internal"])
    assert sc.is_in_scope("api.example.com")
    assert not sc.is_in_scope("evil.com")


# ---------------------------------------------------------------------------
# Ambiguous URLs, and scope files saved by Windows tools
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "https://evil.com\\@www.example.com/",        # Python: www.example.com ; a browser: evil.com
    "https://www.example.com\\@evil.com/",
    "www.example.com\\evil.com",
    "www.exam\tple.com", "www.example.com\nevil.com", "www.exa mple.com", "www.example.com\x00.evil.com",
    "..\\..\\escape", "../../escape", "a b.com",
])
def test_ambiguous_urls_are_refused_not_guessed(value):
    assert normalize_host(value) is None
    sc = Scope.from_lines(["example.com", "*.example.com"])
    assert sc.is_in_scope(value) is False


def test_surrounding_whitespace_is_still_tolerated():
    # tool output lines carry a trailing newline; only whitespace INSIDE a value is suspicious
    assert normalize_host("  www.example.com\n") == "www.example.com"


def test_normal_urls_and_hosts_are_unchanged():
    assert normalize_host("https://WWW.Example.com:8443/a?b=c") == "www.example.com"
    assert normalize_host("http://[::1]:8080/x") == "::1"
    assert normalize_host("Example.COM.") == "example.com"
    assert normalize_host("http://user@www.example.com/") == "www.example.com"     # RFC: host is after the @


def test_valid_hostname_only_accepts_clean_dns_names():
    from marsadix.core.scope import valid_hostname
    assert valid_hostname("https://Sub.Example.com/x") == "sub.example.com"
    assert valid_hostname("1.2.3.4") is None and valid_hostname("::1") is None
    assert valid_hostname("../../x") is None and valid_hostname("a..b") is None


@pytest.mark.parametrize("label,data", [
    ("utf-8", "example.com\n*.example.com\n".encode("utf-8")),
    ("utf-8 with BOM (older Notepad)", b"\xef\xbb\xbf" + b"example.com\n*.example.com\n"),
    ("utf-16 (PowerShell > / echo)", "example.com\r\n*.example.com\r\n".encode("utf-16")),
    ("utf-16 big endian", b"\xfe\xff" + "example.com\n*.example.com\n".encode("utf-16-be")),
    ("CRLF line endings", b"example.com\r\n*.example.com\r\n"),
])
def test_scope_files_written_by_windows_tools_load(tmp_path, label, data):
    f = tmp_path / "scope.txt"
    f.write_bytes(data)
    sc = Scope.from_file(str(f))
    assert sc.is_in_scope("example.com") and sc.is_in_scope("www.example.com"), label


def test_from_target_accepts_ip_targets_without_inventing_a_wildcard():
    for target in ("1.2.3.4", "::1"):
        sc = Scope.from_target(target)
        assert sc.is_in_scope(target)
        assert sc.wildcards == set()


def test_an_undecodable_scope_file_is_a_scope_error_not_a_traceback(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_bytes(b"example.com\n\xff\xfe\xfa\n")
    with pytest.raises(ScopeError, match="cannot read scope file"):
        Scope.from_file(str(f))
