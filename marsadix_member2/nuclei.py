"""Nuclei wrapper for Member 2 ASM groups A1-A4.

A1 subdomain takeover, A2 exposures/misconfigurations and A3 technology/CVE
templates are one bounded Nuclei invocation with explicit tags, severities,
rate limit, timeout and scope/network-safety checks (A4).

This module deliberately returns `Finding` models instead of writing SQL; the
pipeline persists them through `marsadix.db.save_many`, preserving schema v3.
Nuclei is active reconnaissance and must be called only for standard/full
scans; the caller enforces that gate as well.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urlsplit

from marsadix.core.scope import normalize_host
from marsadix.models import (
    Confidence, DetectionStatus, Finding, FindingSource, Severity,
)
from marsadix.owasp import get_owasp_category
from marsadix.skills import get_skill

from .config import Member2Config
from .errors import TOOL_FAILED, TOOL_MISSING, TOOL_SKIPPED, ToolOutcome, elapsed_ms
from .scope_filter import ScopeEnforcer
from .tools import ToolResolver, run_tool

logger = logging.getLogger(__name__)

_TAKEOVER_TAGS = {"takeover", "subdomain-takeover", "takeovers"}
_EXPOSURE_TAGS = {"exposure", "exposures", "misconfig", "misconfiguration",
                  "config", "git", "env", "backup", "disclosure"}
_CVE_TAGS = {"cve", "cves", "tech", "technology", "technologies", "cve-match"}

_GROUPS = {
    "takeover": ("nuclei-takeover", "subdomain_takeover"),
    "exposures": ("nuclei-exposures", "git_env_exposure"),
    "tech-cve": ("nuclei-tech-cve", "cve_match"),
}

_SEVERITIES = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW,
    "info": Severity.INFO, "unknown": Severity.INFO,
}


@dataclass
class NucleiBatch:
    findings: list[Finding] = field(default_factory=list)
    outcome: Optional[ToolOutcome] = None
    groups: dict[str, int] = field(default_factory=dict)


def _tags(info: dict, template_id: str) -> set[str]:
    raw = info.get("tags") if isinstance(info, dict) else None
    if isinstance(raw, str):
        values = raw.replace(";", ",").split(",")
    elif isinstance(raw, (list, tuple, set)):
        values = list(raw)
    else:
        values = []
    values.append(template_id)
    return {str(v).strip().lower() for v in values if str(v).strip()}


def _classify(tags: set[str]) -> tuple[str, str, str]:
    """Return (group key, skill name, finding type)."""
    parts = set()
    for tag in tags:
        parts.update(tag.replace("/", "-").replace("_", "-").split("-"))
    if tags & _TAKEOVER_TAGS or "takeover" in parts:
        return "takeover", *_GROUPS["takeover"]
    if tags & _EXPOSURE_TAGS or parts & {"exposure", "exposures", "misconfig", "git", "env"}:
        return "exposures", *_GROUPS["exposures"]
    return "tech-cve", *_GROUPS["tech-cve"]


def _cve_id(value) -> Optional[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        return None
    for item in values:
        text = str(item).strip().upper()
        if text.startswith("CVE-"):
            return text
    return None


def _record_to_finding(record: dict, scan_id: int, target: str,
                       enforcer: ScopeEnforcer) -> tuple[Optional[Finding], str]:
    info = record.get("info") if isinstance(record.get("info"), dict) else {}
    template_id = str(record.get("template-id") or record.get("templateID")
                      or record.get("template") or "unknown").strip()
    matched = str(record.get("matched-at") or record.get("matched")
                  or record.get("host") or record.get("url") or "").strip()
    if not matched:
        return None, ""
    if "://" not in matched:
        matched = "https://" + matched
    try:
        normalized = enforcer.check(matched)
    except Exception:
        logger.debug("discarding out-of-scope Nuclei match for %s", template_id)
        return None, ""
    tags = _tags(info, template_id)
    group, skill_name, finding_type = _classify(tags)
    skill = get_skill(skill_name)
    classification = info.get("classification")
    cve = None
    if isinstance(classification, dict):
        cve = _cve_id(classification.get("cve-id") or classification.get("cve_id"))
    if cve is None:
        cve = _cve_id(tags)
    severity = _SEVERITIES.get(str(info.get("severity", "info")).lower(), Severity.INFO)
    title = str(info.get("name") or template_id)
    evidence = {
        "template_id": template_id,
        "matcher": record.get("matcher-name") or record.get("matcher_name"),
        "type": record.get("type"),
        "tags": sorted(tags)[:30],
        "matched_at": normalized.url,
        "ip": record.get("ip"),
        "group": group,
    }
    try:
        port = normalized.port
    except Exception:
        port = None
    finding = Finding(
        scan_id=scan_id,
        host=normalized.host or normalize_host(target) or target,
        source=FindingSource.NUCLEI,
        cve_id=cve,
        title=title,
        template_id=template_id,
        url=normalized.url,
        port=port,
        severity=severity,
        confidence=Confidence.LIKELY,
        evidence=json.dumps(evidence, sort_keys=True, default=str)[:4000],
        verified=False,
        verification_method="nuclei-template",
        status=DetectionStatus.DETECTED,
        owasp_category=get_owasp_category(finding_type),
        source_reference=(skill.source_reference if skill else
                          "ProjectDiscovery nuclei-templates"),
    )
    return finding, group


def _parse_targets(targets: Iterable[str], enforcer: ScopeEnforcer,
                   limit: int) -> list[str]:
    selected: dict[str, str] = {}
    for raw in targets:
        if len(selected) >= limit:
            break
        value = str(raw or "").strip()
        if not value:
            continue
        if "://" not in value:
            value = "https://" + value
        try:
            normalized = enforcer.check(value)
        except Exception:
            continue
        # One scan per origin; Nuclei templates normally match at host level.
        if normalized.origin in selected:
            continue
        selected[normalized.origin] = normalized.host
    return list(selected)


async def run_nuclei(targets: Iterable[str], scan_id: int, target: str,
                     config: Member2Config, resolver: ToolResolver,
                     enforcer: ScopeEnforcer) -> NucleiBatch:
    """Run one bounded A1-A4 Nuclei pass over in-scope origins."""
    batch = NucleiBatch()
    if not config.nuclei_enabled:
        batch.outcome = ToolOutcome("nuclei", TOOL_SKIPPED, details={"reason": "disabled"})
        return batch
    executable = resolver.path("nuclei")
    if not executable:
        batch.outcome = ToolOutcome("nuclei", TOOL_MISSING,
                                    error="nuclei is not installed or not in PATH")
        return batch

    selected = _parse_targets(targets, enforcer, config.nuclei_max_targets)
    if not selected:
        batch.outcome = ToolOutcome("nuclei", TOOL_SKIPPED,
                                    details={"reason": "no in-scope targets"})
        return batch

    safe: list[str] = []
    for origin in selected:
        try:
            normalized = enforcer.check(origin)
            await enforcer.ensure_safe_url(normalized)
            safe.append(origin)
        except Exception as exc:
            logger.debug("nuclei target rejected by scope/DNS safety: %s", type(exc).__name__)
    if not safe:
        batch.outcome = ToolOutcome("nuclei", TOOL_FAILED,
                                    error="all Nuclei targets failed scope/DNS checks")
        return batch

    rate = config.nuclei_rate_limit or config.rate_limit
    request_timeout = max(1, int(config.request_timeout))
    argv = [
        "-silent", "-jsonl", "-no-color", "-duc", "-ni", "-dr",
        "-rate-limit", str(max(1, int(rate))),
        "-timeout", str(request_timeout),
        "-retries", str(min(2, max(0, config.retries))),
        "-tags", ",".join(config.nuclei_tags),
    ]
    if config.nuclei_severities:
        argv.extend(["-severity", ",".join(config.nuclei_severities)])

    start = time.monotonic()
    execution = await run_tool(
        "nuclei", executable, argv, input_text="\n".join(safe),
        timeout=config.nuclei_timeout)
    seen: set[str] = set()
    groups: dict[str, int] = {}
    for line in execution.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        finding, group = _record_to_finding(record, scan_id, target, enforcer)
        if finding is None:
            continue
        key = finding.dedup_key
        if key in seen:
            continue
        seen.add(key)
        batch.findings.append(finding)
        if group:
            groups[group] = groups.get(group, 0) + 1
    batch.groups = groups
    batch.outcome = ToolOutcome(
        "nuclei", execution.status, discovered=len(batch.findings),
        kept=len(batch.findings),
        returncode=execution.returncode, duration_ms=elapsed_ms(start),
        command=["nuclei", *argv], error=execution.error,
        details={"targets": len(safe), "groups": dict(groups),
                 "tags": list(config.nuclei_tags),
                 "severities": list(config.nuclei_severities),
                 "rate_limit": rate, "request_timeout": request_timeout,
                 "timeout": config.nuclei_timeout},
    )
    return batch
