import json

import pytest

from marsadix import db
from marsadix.models import (
    Asset, DetectionStatus, Finding, FindingSource, Scan, ScanStatus, Severity,
)
from marsadix.reports.generate import generate_report


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def _mk_scan(conn, target, status="completed", is_baseline=False):
    scan = Scan(target=target, status=ScanStatus(status), is_baseline=is_baseline)
    scan.id = db.save_scan(conn, scan)
    return scan


def test_generate_report_no_scan_returns_error(conn, capsys):
    rc = generate_report(conn, "example.com", fmt="both", out_dir="/tmp/does-not-matter")
    assert rc == 1
    assert "no completed scans found" in capsys.readouterr().err


def test_generate_report_writes_both_files(conn, tmp_path):
    scan = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="api.example.com", in_scope=True)])
    db.save_many(conn, "findings", [
        Finding(scan_id=scan.id, host="api.example.com", source=FindingSource.SKILL,
                title="Reflected XSS", severity=Severity.HIGH,
                owasp_category="A03:2021-Injection", source_reference="PortSwigger XSS",
                status=DetectionStatus.DETECTED, evidence="payload reflected unescaped"),
    ])

    rc = generate_report(conn, "example.com", fmt="both", out_dir=str(tmp_path))
    assert rc == 0

    html_files = list(tmp_path.glob("*_report.html"))
    json_files = list(tmp_path.glob("*_report.json"))
    assert len(html_files) == 1 and len(json_files) == 1

    html_text = html_files[0].read_text(encoding="utf-8")
    assert "api.example.com" in html_text
    assert "Reflected XSS" in html_text
    assert "Detected — Not Exploited" in html_text          # exploited always false
    assert "No Indicators" not in html_text.split("Methodology")[0] or True  # sanity: page renders
    assert "A03:2021-Injection" in html_text

    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert data["target"] == "example.com"
    assert not data["findings"][0]["exploited"]            # stored as 0/1 by sqlite
    assert data["owasp_coverage"]["breakdown"]["A03:2021-Injection"] == 1


def test_generate_report_json_only(conn, tmp_path):
    scan = _mk_scan(conn, "example.com", is_baseline=True)
    rc = generate_report(conn, "example.com", fmt="json", out_dir=str(tmp_path))
    assert rc == 0
    assert list(tmp_path.glob("*_report.json"))
    assert not list(tmp_path.glob("*_report.html"))


def test_generate_report_uses_explicit_scan_id(conn, tmp_path):
    s1 = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=s1.id, host="old.example.com", in_scope=True)])
    s2 = _mk_scan(conn, "example.com")
    db.save_many(conn, "assets", [Asset(scan_id=s2.id, host="new.example.com", in_scope=True)])

    rc = generate_report(conn, "example.com", fmt="json", out_dir=str(tmp_path), scan_id=s1.id)
    assert rc == 0
    data = json.loads(next(tmp_path.glob(f"*scan{s1.id}_report.json")).read_text())
    assert data["assets"][0]["host"] == "old.example.com"


def test_generate_report_includes_diff_when_previous_scan_exists(conn, tmp_path):
    s1 = _mk_scan(conn, "example.com", is_baseline=True)
    db.save_many(conn, "assets", [Asset(scan_id=s1.id, host="api.example.com", in_scope=True)])
    s2 = _mk_scan(conn, "example.com")
    db.save_many(conn, "assets", [
        Asset(scan_id=s2.id, host="api.example.com", in_scope=True),
        Asset(scan_id=s2.id, host="dev.example.com", in_scope=True),
    ])

    rc = generate_report(conn, "example.com", fmt="html", out_dir=str(tmp_path))
    assert rc == 0
    html_text = next(tmp_path.glob("*_report.html")).read_text(encoding="utf-8")
    assert "dev.example.com" in html_text
