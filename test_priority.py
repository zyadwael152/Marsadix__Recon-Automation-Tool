import itertools
import pytest
from marsadix.matching.models import CVE, Confidence, PriorityLevel
from marsadix.matching.priority import DEFAULT_CVSS, compute_priority, priority_for


def test_formula():
    p = compute_priority(9.8, 0.5, False, Confidence.HIGH)
    assert p.score == round(9.8 * 6 + 0.5 * 20 + 5, 1) == 73.8
    assert p.level == PriorityLevel.HIGH and p.reasons


def test_missing_cvss_default_and_reason():
    p = compute_priority(None, None, False, Confidence.MEDIUM)
    assert p.score == DEFAULT_CVSS * 6
    assert any("CVSS missing" in r for r in p.reasons) and any("EPSS missing" in r for r in p.reasons)


@pytest.mark.parametrize("cvss", [None, 0.0, 1.0, 5.0, 10.0])
@pytest.mark.parametrize("conf", list(Confidence))
def test_kev_forces_critical(cvss, conf):
    p = compute_priority(cvss, 0.0, True, conf)
    assert p.level == PriorityLevel.CRITICAL and p.score >= 80


def test_clamped():
    assert compute_priority(99, 5, True, Confidence.HIGH).score == 100.0
    assert compute_priority(-5, -1, False, Confidence.LOW).score == 0.0


def test_levels():
    assert compute_priority(2, 0, False, Confidence.MEDIUM).level == PriorityLevel.LOW
    assert compute_priority(6, 0, False, Confidence.MEDIUM).level == PriorityLevel.MEDIUM
    assert compute_priority(10, 0, False, Confidence.MEDIUM).level == PriorityLevel.HIGH
    assert compute_priority(10, 1, False, Confidence.HIGH).level == PriorityLevel.CRITICAL


def test_monotonic():
    for kev, conf in itertools.product([False, True], Confidence):
        prev = -1
        for cvss in [x / 2 for x in range(0, 21)]:
            s = compute_priority(cvss, 0.3, kev, conf).score
            assert s >= prev
            prev = s
        prev = -1
        for epss in [x / 20 for x in range(0, 21)]:
            s = compute_priority(7.0, epss, kev, conf).score
            assert s >= prev
            prev = s
    for cvss, epss, kev in itertools.product([0, 5, 9.8], [0, .5, 1], [False, True]):
        s = [compute_priority(cvss, epss, kev, c).score for c in (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)]
        assert s == sorted(s)
    for cvss, epss, c in itertools.product([0, 5, 9.8], [0, .5, 1], Confidence):
        assert compute_priority(cvss, epss, True, c).score >= compute_priority(cvss, epss, False, c).score


def test_deterministic():
    assert compute_priority(7.5, 0.1, False, Confidence.MEDIUM) == compute_priority(7.5, 0.1, False, Confidence.MEDIUM)


def test_priority_for_cve():
    assert priority_for(CVE(id="x", cvss=9.0, kev=True), Confidence.LOW).level == PriorityLevel.CRITICAL
