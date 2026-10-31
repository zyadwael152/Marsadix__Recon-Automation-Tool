import asyncio
import json

import pytest

from marsadix.core.scope import Scope
from marsadix.models import FindingSource, Severity
from marsadix_member2 import nuclei as nuclei_module
from marsadix_member2.config import Member2Config
from marsadix_member2.errors import TOOL_SKIPPED
from marsadix_member2.nuclei import run_nuclei
from marsadix_member2.scope_filter import ScopeEnforcer
from marsadix_member2.security import (
    SecurityScanner, detect_waf, missing_security_headers, scan_js_secrets,
)
from marsadix_member2.tools import ToolExecution


class _FakeResponse:
    error = ""
    status = 200
    headers = {"server": "cloudflare", "cf-ray": "abc123"}


class _FakeClient:
    async def fetch(self, url, max_bytes=0):
        return None, _FakeResponse()


def _enforcer(*hosts):
    scope = Scope.from_lines(hosts)
    return ScopeEnforcer(scope, hosts[0])


@pytest.fixture
def no_dns(monkeypatch):
    async def _noop(self, normalized):
        return ()
    monkeypatch.setattr(ScopeEnforcer, "ensure_safe_url", _noop)


def test_header_gap_and_waf_fingerprint():
    headers = {"server": "cloudflare", "cf-ray": "abc123"}
    assert detect_waf(headers) == "cloudflare"
    missing = dict(missing_security_headers("https://example.com/", headers))
    assert "hsts" in missing
    assert "csp" in missing
    assert "x-frame-options" in missing
    assert "permissions-policy" in missing


def test_security_scanner_records_header_findings(no_dns):
    cfg = Member2Config(archive_sources=(), tls_check=False)
    scanner = SecurityScanner(_enforcer("example.com"), cfg, _FakeClient())
    batch = asyncio.run(scanner.check_headers(["https://example.com/"], scan_id=9))
    ids = {f.template_id for f in batch.findings}
    assert "waf-detected" in ids
    assert "missing-security-header:hsts" in ids
    assert batch.waf == {"example.com": "cloudflare"}
    assert all(f.scan_id == 9 for f in batch.findings)
    assert all(f.source is FindingSource.SKILL for f in batch.findings)


def test_js_secret_scan_redacts_values():
    secret = "AKIA" + "A" * 16
    findings = scan_js_secrets(
        f"const key = '{secret}'; fetch('/api');", "https://example.com/app.js", 4)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.scan_id == 4
    assert finding.template_id == "js-secret-aws-access-key"
    assert finding.host == "example.com"
    assert secret not in finding.evidence
    evidence = json.loads(finding.evidence)
    assert evidence["redacted"] == "AKIA...AA"


def test_tls_without_https_is_skipped(no_dns):
    cfg = Member2Config(archive_sources=())
    scanner = SecurityScanner(_enforcer("example.com"), cfg, _FakeClient())
    batch = asyncio.run(scanner.check_tls(["http://example.com/"], scan_id=1))
    assert batch.findings == []
    assert batch.outcomes[0].status == TOOL_SKIPPED


def test_tls_findings_cover_expiry_trust_and_protocol():
    cfg = Member2Config(archive_sources=())
    scanner = SecurityScanner(_enforcer("example.com"), cfg, _FakeClient())
    normalized = _enforcer("example.com").check("https://example.com/")
    findings = scanner._tls_findings(3, normalized, {
        "trusted": False, "days_left": -1, "version": "TLSv1",
        "not_after": "Jan  1 00:00:00 2020 GMT"})
    ids = {f.template_id for f in findings}
    assert {"tls-expired", "tls-weak-protocol"} <= ids
    untrusted = scanner._tls_findings(3, normalized, {
        "trusted": False, "days_left": 365, "version": "TLSv1.3"})
    assert {f.template_id for f in untrusted} == {"tls-untrusted"}
    assert all(f.scan_id == 3 for f in findings + untrusted)


def test_nuclei_parses_groups_and_drops_out_of_scope(monkeypatch, no_dns):
    cfg = Member2Config(archive_sources=(), nuclei_tags=("takeover", "exposure"))
    resolver = type("Resolver", (), {"path": lambda self, name: "/bin/nuclei"})()
    payload = "\n".join([
        json.dumps({
            "template-id": "takeover-check",
            "info": {"name": "Takeover", "severity": "high",
                     "tags": ["takeover"], "classification": {"cve-id": []}},
            "matched-at": "https://example.com/",
            "host": "https://example.com/",
        }),
        json.dumps({
            "template-id": "leak",
            "info": {"name": "Leak", "severity": "medium", "tags": ["exposure"]},
            "matched-at": "https://evil.test/leak",
        }),
    ])

    async def fake_run_tool(name, executable, argv, *, input_text=None, timeout=300):
        return ToolExecution(name="nuclei", argv=[executable, *argv],
                             stdout=payload, returncode=0)

    monkeypatch.setattr(nuclei_module, "run_tool", fake_run_tool)
    batch = asyncio.run(run_nuclei(
        ["https://example.com", "https://out.test/"],
        scan_id=11, target="example.com", config=cfg,
        resolver=resolver, enforcer=_enforcer("example.com"),
    ))
    assert len(batch.findings) == 1
    finding = batch.findings[0]
    assert finding.source is FindingSource.NUCLEI
    assert finding.scan_id == 11
    assert finding.severity is Severity.HIGH
    assert finding.owasp_category
    assert batch.groups == {"takeover": 1}
    command = batch.outcome.command
    assert "-tags" in command
    assert command[command.index("-tags") + 1] == "takeover,exposure"
    assert command[command.index("-timeout") + 1] == "10"
    assert "-ni" in command and "-dr" in command


def test_nuclei_disabled_is_a_skip(no_dns):
    cfg = Member2Config(archive_sources=(), nuclei_enabled=False)
    resolver = type("Resolver", (), {"path": lambda self, name: "/bin/nuclei"})()
    batch = asyncio.run(run_nuclei(
        ["https://example.com"], 1, "example.com",
        cfg, resolver, _enforcer("example.com")))
    assert batch.outcome.status == "skipped"
    assert batch.findings == []
