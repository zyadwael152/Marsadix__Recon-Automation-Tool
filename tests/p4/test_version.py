import pytest
from marsadix.matching.version import VersionParseError, compare_versions as cmp, parse_version, version_in_range


@pytest.mark.parametrize("a,b", [
    ("1.0.2", "1.0.2a"), ("1.0.2a", "1.0.2f"), ("1.0.2f", "1.0.2k"), ("1.0.2k", "1.0.3"),
    ("1.0.2-alpha", "1.0.2-beta"), ("1.0.2-beta1", "1.0.2-beta2"), ("1.0.2beta", "1.0.2rc1"),
    ("1.0.2rc1", "1.0.2"), ("1.0.2-rc1", "1.0.2-rc2"), ("1.0a1", "1.0b1"), ("1.0b1", "1.0"),
    ("8.2", "8.2p1"), ("8.2p1", "8.2p2"), ("8.2p2", "8.3"), ("9.3p1", "9.3p2"), ("9.3p2", "9.4"),
    ("2.4.9", "2.4.10"), ("1.9", "1.10"), ("1.0.0-dev", "1.0.0-alpha"), ("0.9.8zh", "1.0.0"),
])
def test_ordering(a, b):
    assert cmp(a, b) < 0 and cmp(b, a) > 0


@pytest.mark.parametrize("a,b", [("1.0", "1.0.0"), ("v2.1", "2.1"), ("1.0.2", "1.0.2"), ("1.0-final", "1.0")])
def test_equal(a, b):
    assert cmp(a, b) == 0
    assert hash(parse_version(a)) == hash(parse_version(b))


def test_openssl_letters_higher_than_base():
    for letter in "abcdef":
        assert cmp(f"1.0.2{letter}", "1.0.2") > 0


def test_openssl_range():
    kw = dict(start_incl="1.0.2", end_excl="1.0.2h")
    assert version_in_range("1.0.2", **kw)
    assert version_in_range("1.0.2a", **kw)
    assert version_in_range("1.0.2g", **kw)
    assert not version_in_range("1.0.2h", **kw)
    assert not version_in_range("1.0.1u", **kw)


def test_range_bounds():
    assert version_in_range("2.0", start_excl="1.0", end_incl="2.0")
    assert not version_in_range("1.0", start_excl="1.0")
    assert not version_in_range("2.0.1", end_incl="2.0")


@pytest.mark.parametrize("bad", ["", "latest", None, "abc", "x" * 300])
def test_unparseable(bad):
    with pytest.raises(VersionParseError):
        parse_version(bad)
