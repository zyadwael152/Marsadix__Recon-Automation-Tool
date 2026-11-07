import pytest
from marsadix.matching.confidence import assess
from marsadix.matching.models import CVE, Asset, Confidence, MatchResult, VersionSource

CPE = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"


def mr(source, version="2.4.49", compared=True, unverified=False):
    a = Asset(host="h", cpe=CPE, version=version, version_source=source)
    return MatchResult(cve=CVE(id="x"), asset=a, version_compared=compared, platform_unverified=unverified)


@pytest.mark.parametrize("source,expected", [
    (VersionSource.VERIFIED, Confidence.HIGH), (VersionSource.NMAP, Confidence.HIGH),
    (VersionSource.BANNER, Confidence.HIGH), (VersionSource.HTTPX, Confidence.MEDIUM),
    (VersionSource.FINGERPRINT, Confidence.MEDIUM), (VersionSource.INFERRED, Confidence.LOW),
    (VersionSource.UNKNOWN, Confidence.LOW),
])
def test_every_source(source, expected):
    assert assess(mr(source)).level == expected


@pytest.mark.parametrize("source,expected", [
    (VersionSource.NMAP, Confidence.MEDIUM),
    (VersionSource.HTTPX, Confidence.LOW), (VersionSource.INFERRED, Confidence.LOW),
    (VersionSource.VERIFIED, Confidence.MEDIUM),
])
def test_unverified_platform_downgrades_one_level(source, expected):
    assert assess(mr(source, unverified=True)).level == expected


def test_never_high_when_version_not_compared():
    r = assess(mr(VersionSource.NMAP, compared=False))
    assert r.level == Confidence.MEDIUM and any("not compared" in x for x in r.reasons)


def test_unknown_version_is_low_even_with_high_source():
    assert assess(mr(VersionSource.NMAP, version=None, compared=False)).level == Confidence.LOW


def test_cpe_version_counts_as_known():
    a = Asset(host="h", cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", version=None, version_source=VersionSource.NMAP)
    m = MatchResult(cve=CVE(id="x"), asset=a, version_compared=True)
    assert assess(m).level == Confidence.HIGH


def test_floor_is_low():
    assert assess(mr(VersionSource.UNKNOWN, version=None, compared=False, unverified=True)).level == Confidence.LOW
