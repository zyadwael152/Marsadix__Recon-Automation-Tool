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
