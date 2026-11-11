"""W7/W9/W10 security inspection for Member 2.

The checks here are evidence collectors, not exploiters:

* W7: HTTP security headers and conservative WAF fingerprinting;
* W9: high-confidence secret patterns in downloaded JavaScript;
* W10: certificate expiry/trust and TLS protocol inspection.

They reuse the extension's scope enforcement, rate limiter and safe HTTP client,
and write only the shared `Finding` model, so `marsadix.db` schema v3 stays
unchanged. Secret values are never stored or logged in full.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import ssl
import tempfile
from dataclasses import dataclass, field
from typing import Iterable, Optional

from marsadix.models import (
    Confidence, DetectionStatus, Finding, FindingSource, Severity,
)
from marsadix.owasp import get_owasp_category

from .config import Member2Config
from .errors import (TOOL_FAILED, TOOL_OK, TOOL_PARTIAL, TOOL_SKIPPED,
                     ToolOutcome, elapsed_ms)
from .http_client import SafeHTTPClient
from .scope_filter import ScopeEnforcer

logger = logging.getLogger(__name__)

_HEADER_SEVERITY = {
    "hsts": Severity.MEDIUM,
    "csp": Severity.MEDIUM,
    "x-content-type-options": Severity.LOW,
    "x-frame-options": Severity.LOW,
    "referrer-policy": Severity.LOW,
    "permissions-policy": Severity.LOW,
}

_WAF_SIGNATURES = {
    "cloudflare": ("cloudflare", "cf-ray", "cf-cache-status"),
    "akamai": ("akamai", "akamai-ghost", "x-akamai"),
    "imperva": ("imperva", "incapsula", "x-iinfo"),
    "sucuri": ("sucuri", "x-sucuri"),
    "aws-waf": ("awswaf", "x-amzn-waf"),
    "fastly": ("fastly", "x-fastly"),
    "f5": ("big-ip", "f5", "x-wa-info"),
    "barracuda": ("barracuda", "x-barracuda"),
}

_SECRET_RULES = (
    ("aws-access-key", "AWS access key", Severity.HIGH,
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key", "Private key material", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("google-api-key", "Google API key", Severity.HIGH,
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack-token", "Slack token", Severity.HIGH,
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    ("github-token", "GitHub token", Severity.HIGH,
     re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b")),
    ("stripe-secret", "Stripe secret key", Severity.CRITICAL,
     re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{20,}\b")),
    ("jwt", "JSON Web Token", Severity.MEDIUM,
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("generic-api-key", "High-entropy API token", Severity.MEDIUM,
     re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']"
                r"(?P<value>[A-Za-z0-9_\-+/=]{20,})[\"']")),
)


@dataclass
class SecurityBatch:
    findings: list[Finding] = field(default_factory=list)
    outcomes: list[ToolOutcome] = field(default_factory=list)
    waf: dict[str, str] = field(default_factory=dict)


def _finding(*, scan_id: int, host: str, url: str, template_id: str,
             title: str, severity: Severity, evidence: dict,
             confidence: Confidence = Confidence.CONFIRMED,
             finding_type: str = "missing_security_headers",
             verified: bool = True,
             source_reference: str = "OWASP WSTG; OWASP Secure Headers Project"
             ) -> Finding:
    return Finding(
        scan_id=scan_id,
        host=host,
        source=FindingSource.SKILL,
        title=title,
        template_id=template_id,
        url=url,
        severity=severity,
        confidence=confidence,
        evidence=json.dumps(evidence, sort_keys=True, default=str)[:4000],
        verified=verified,
        verification_method="http-response-headers",
        status=DetectionStatus.DETECTED,
        owasp_category=get_owasp_category(finding_type),
        source_reference=source_reference,
    )


def _redact_secret(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-2:]}"


def _looks_random(value: str) -> bool:
    if len(set(value)) < 8:
        return False
    digits = sum(ch.isdigit() for ch in value)
    upper = sum(ch.isupper() for ch in value)
    lower = sum(ch.islower() for ch in value)
    return digits >= 2 and upper >= 2 and lower >= 2


def _secret_finding(scan_id: int, js_url: str, host: str, rule_name: str,
                    title: str, severity: Severity,
                    match: re.Match) -> Optional[Finding]:
    value = match.group(0)
    if rule_name == "generic-api-key":
        value = match.groupdict().get("value") or value
        if not _looks_random(value):
            return None
    return Finding(
        scan_id=scan_id,
        host=host,
        source=FindingSource.SKILL,
        title=f"JavaScript secret exposure: {title}",
        template_id=f"js-secret-{rule_name}",
        url=js_url,
        severity=severity,
        confidence=Confidence.LIKELY,
        evidence=json.dumps({
            "match_type": rule_name,
            "redacted": _redact_secret(value),
            "offset": match.start(),
            "source": "javascript",
        }, sort_keys=True),
        verified=False,
        verification_method="javascript-secret-pattern",
        status=DetectionStatus.DETECTED,
        owasp_category=get_owasp_category("git_env_exposure"),
        source_reference="OWASP WSTG; secret-scanning pattern catalogue",
    )


def scan_js_secrets(text: str, js_url: str, scan_id: int) -> list[Finding]:
    """Return high-confidence secret findings from one downloaded JS body.

    Values are redacted before they reach the model; the full secret is never
    logged or persisted. Endpoint extraction remains in `js_extract`.
    """
    if not text:
        return []
    host = ""
    try:
        from marsadix.core.scope import normalize_host
        host = normalize_host(js_url) or ""
    except Exception:
        host = ""
    found: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for rule_name, title, severity, pattern in _SECRET_RULES:
        for match in pattern.finditer(text):
            key = (rule_name, match.start())
            if key in seen:
                continue
            seen.add(key)
            finding = _secret_finding(scan_id, js_url, host, rule_name, title,
                                      severity, match)
            if finding is not None:
                found.append(finding)
    return found


def detect_waf(headers: dict[str, str], cookies: Iterable[str] = ()) -> Optional[str]:
    """Conservative WAF fingerprint from response headers, never a claim of proof."""
    haystack = " ".join(
        [f"{k}:{v}" for k, v in headers.items()] + [str(c) for c in cookies]
    ).lower()
    for vendor, needles in _WAF_SIGNATURES.items():
        if any(needle in haystack for needle in needles):
            return vendor
    return None


def _header_name_map(headers: dict[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v or "") for k, v in headers.items()}


def missing_security_headers(url: str, headers: dict[str, str]) -> list[tuple[str, str]]:
    """Return (template-suffix, title) pairs for headers absent or ineffective."""
    lower = _header_name_map(headers)
    missing: list[tuple[str, str]] = []
    scheme = url.split(":", 1)[0].lower()
    csp = lower.get("content-security-policy", "") + " " + lower.get(
        "content-security-policy-report-only", "")
    if scheme == "https" and "strict-transport-security" not in lower:
        missing.append(("hsts", "Strict-Transport-Security"))
    if not csp.strip():
        missing.append(("csp", "Content-Security-Policy"))
    if "x-content-type-options" not in lower:
        missing.append(("x-content-type-options", "X-Content-Type-Options"))
    if "x-frame-options" not in lower and "frame-ancestors" not in csp.lower():
        missing.append(("x-frame-options", "X-Frame-Options or CSP frame-ancestors"))
    if "referrer-policy" not in lower:
        missing.append(("referrer-policy", "Referrer-Policy"))
    if "permissions-policy" not in lower:
        missing.append(("permissions-policy", "Permissions-Policy"))
    return missing


def _decode_der_certificate(der: bytes) -> dict:
    if not der:
        return {}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        try:
            return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            try:
                import os
                os.unlink(path)
            except OSError:
                pass
    except Exception:
        return {}


def _probe_tls(host: str, port: int, timeout: float) -> dict:
    """Small stdlib TLS probe; returns data only, never secrets."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    result: dict = {"trusted": False, "error": ""}
    der = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True) or b""
                result["version"] = tls.version() or ""
    except Exception as exc:
        result["error"] = type(exc).__name__
        return result

    cert = _decode_der_certificate(der)
    not_after = cert.get("notAfter") if isinstance(cert, dict) else None
    if not_after:
        result["not_after"] = not_after
        try:
            expires = ssl.cert_time_to_seconds(not_after)
            import time
            result["days_left"] = int((expires - time.time()) // 86400)
        except Exception:
            pass
    verified_context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with verified_context.wrap_socket(raw, server_hostname=host):
                result["trusted"] = True
    except ssl.SSLCertVerificationError:
        result["trusted"] = False
    except Exception as exc:
        result["error"] = result.get("error") or type(exc).__name__
    return result


class SecurityScanner:
    def __init__(self, enforcer: ScopeEnforcer, config: Member2Config,
                 client: SafeHTTPClient) -> None:
        self.enforcer = enforcer
        self.config = config
        self.client = client

    async def check_headers(self, urls: Iterable[str], scan_id: int = 0) -> SecurityBatch:
        start = asyncio.get_running_loop().time()
        batch = SecurityBatch()
        checked = 0
        failed = 0
        seen: set[str] = set()
        for raw in urls:
            if checked >= self.config.security_max_targets:
                break
            try:
                normalized = self.enforcer.check(raw)
                if normalized.key in seen:
                    continue
                seen.add(normalized.key)
                await self.enforcer.ensure_safe_url(normalized)
            except Exception:
                continue
            _, response = await self.client.fetch(normalized.url, max_bytes=64 * 1024)
            if response.error or response.status is None:
                failed += 1
                continue
            checked += 1
            waf = detect_waf(response.headers)
            if waf:
                batch.waf[normalized.host] = waf
                batch.findings.append(_finding(
                    scan_id=scan_id, host=normalized.host, url=normalized.url,
                    template_id="waf-detected",
                    title=f"WAF detected: {waf}",
                    severity=Severity.INFO,
                    confidence=Confidence.POSSIBLE,
                    evidence={"vendor": waf},
                    finding_type="missing_security_headers",
                    source_reference="WAF response-header fingerprint"))
            for suffix, title in missing_security_headers(normalized.url, response.headers):
                batch.findings.append(_finding(
                    scan_id=scan_id, host=normalized.host, url=normalized.url,
                    template_id=f"missing-security-header:{suffix}",
                    title=f"Missing security header: {title}",
                    severity=_HEADER_SEVERITY.get(suffix, Severity.LOW),
                    evidence={"header": title, "url": normalized.url},
                    finding_type="missing_security_headers"))
        if not checked and not failed:
            status = TOOL_SKIPPED
        elif failed:
            status = TOOL_PARTIAL if checked else TOOL_FAILED
        else:
            status = TOOL_OK
        batch.outcomes.append(ToolOutcome(
            "security-headers", status, discovered=len(batch.findings),
            kept=len(batch.findings), duration_ms=elapsed_ms(start),
            error=f"{failed} header check(s) failed" if failed else "",
            details={"checked": checked, "waf": dict(batch.waf),
                     "reason": "" if checked or failed else "no HTTP targets in scope"}))
        return batch

    async def check_tls(self, urls: Iterable[str], scan_id: int = 0) -> SecurityBatch:
        start = asyncio.get_running_loop().time()
        batch = SecurityBatch()
        checked = 0
        seen: set[str] = set()
        for raw in urls:
            if checked >= self.config.security_max_targets:
                break
            try:
                normalized = self.enforcer.check(raw)
                if normalized.scheme != "https" or normalized.host in seen:
                    continue
                seen.add(normalized.host)
                await self.enforcer.ensure_safe_url(normalized)
            except Exception:
                continue
            try:
                result = await asyncio.to_thread(
                    _probe_tls, normalized.host,
                    normalized.port or 443, self.config.request_timeout)
            except Exception as exc:
                logger.debug("TLS probe failed for %s: %s", normalized.host, type(exc).__name__)
                continue
            checked += 1
            batch.findings.extend(self._tls_findings(scan_id, normalized, result))
        batch.outcomes.append(ToolOutcome(
            "tls-check", TOOL_OK if checked else TOOL_SKIPPED,
            discovered=len(batch.findings), kept=len(batch.findings),
            duration_ms=elapsed_ms(start),
            details={"checked": checked,
                     "reason": "" if checked else "no HTTPS targets in scope"}))
        return batch

    def _tls_findings(self, scan_id: int, normalized, result: dict) -> list[Finding]:
        if result.get("error") and not result.get("version"):
            return [_finding(
                scan_id=scan_id, host=normalized.host, url=normalized.url,
                template_id="tls-handshake-failed",
                title="TLS handshake failed or certificate unavailable",
                severity=Severity.MEDIUM,
                evidence={"error": result.get("error", "")},
                finding_type="weak_tls",
                source_reference="OWASP WSTG-CRYP-01")]
        findings: list[Finding] = []
        days = result.get("days_left")
        if isinstance(days, int) and days < 0:
            findings.append(_finding(
                scan_id=scan_id, host=normalized.host, url=normalized.url,
                template_id="tls-expired", title="TLS certificate has expired",
                severity=Severity.HIGH,
                evidence={"not_after": result.get("not_after", ""), "days_left": days},
                finding_type="weak_tls", source_reference="OWASP WSTG-CRYP-01"))
        elif isinstance(days, int) and days <= 30:
            findings.append(_finding(
                scan_id=scan_id, host=normalized.host, url=normalized.url,
                template_id="tls-expiring", title="TLS certificate expires within 30 days",
                severity=Severity.MEDIUM,
                evidence={"not_after": result.get("not_after", ""), "days_left": days},
                finding_type="weak_tls", source_reference="OWASP WSTG-CRYP-01"))
        if result.get("trusted") is False and not (isinstance(days, int) and days < 0):
            findings.append(_finding(
                scan_id=scan_id, host=normalized.host, url=normalized.url,
                template_id="tls-untrusted", title="TLS certificate is not trusted",
                severity=Severity.MEDIUM,
                evidence={"not_after": result.get("not_after", "")},
                finding_type="weak_tls", source_reference="OWASP WSTG-CRYP-01"))
        if result.get("version") in ("TLSv1", "TLSv1.1"):
            findings.append(_finding(
                scan_id=scan_id, host=normalized.host, url=normalized.url,
                template_id="tls-weak-protocol", title="Weak TLS protocol negotiated",
                severity=Severity.HIGH,
                evidence={"version": result.get("version")},
                finding_type="weak_tls", source_reference="OWASP WSTG-CRYP-01"))
        return findings


def attach_scan_id(findings: Iterable[Finding], scan_id: int) -> list[Finding]:
    """Set scan id on findings created before the scanner knew the scan id."""
    out = []
    for finding in findings:
        finding.scan_id = scan_id
        out.append(finding)
    return out
