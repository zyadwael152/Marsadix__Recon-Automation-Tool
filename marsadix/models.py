"""
Marsadix data models  (WHAT the data looks like).

This file only describes the SHAPE of the data as Python classes.
It does NOT talk to any database. Storage lives in db.py.

Contract between modules:
  Recon        -> produces Asset, Service, Technology, WebItem, Email
  ASM (Nuclei) -> produces Finding (source=nuclei)
  CVE Monitor  -> produces CVE, Finding (source=cve_match), Alert
  Asset Monitor-> produces TrackedAsset updates, Alert (new_asset / takeover)
  Core         -> stores everything (db.py), computes ScanDiff

Rule: do NOT rename a field or change a type without telling the whole team.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def utcnow() -> str:
    """ISO-8601 UTC timestamp, used everywhere so formats never differ."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _v(x) -> str:
    """Enum or plain value -> string (safe for dedup keys)."""
    return "" if x is None else str(getattr(x, "value", x))


# --------------------------------------------------------------------------
# Enums (fixed vocabularies, so nobody writes "High" while another writes "high")
# --------------------------------------------------------------------------

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Confidence(str, Enum):
    POSSIBLE = "possible"    # version match only          -> Low
    LIKELY = "likely"        # template/banner-specific    -> Medium
    CONFIRMED = "confirmed"  # safe check demonstrated it  -> High


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DiscoverySource(str, Enum):
    PASSIVE = "passive"      # subfinder, amass, crt.sh, wayback...
    ACTIVE = "active"        # dnsx, httpx, katana...
    JS = "js"                # found inside a JavaScript file
    REDIRECT = "redirect"
    CT_LOG = "ct_log"        # Certificate Transparency monitoring
    MANUAL = "manual"        # seed target given by the user


class WebItemKind(str, Enum):
    URL = "url"
    JS_FILE = "js_file"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"


class FindingSource(str, Enum):
    NUCLEI = "nuclei"        # ASM: a template actually matched on the asset
    CVE_MATCH = "cve_match"  # version/CPE matched a known CVE


class AlertType(str, Enum):
    CVE = "cve"              # new CVE matches a stored technology
    NEW_ASSET = "new_asset"  # new subdomain discovered
    NEW_PORT = "new_port"
    TAKEOVER = "takeover"    # possible subdomain takeover


class AlertChannel(str, Enum):
    DISCORD = "discord"
    TELEGRAM = "telegram"
    EMAIL = "email"
    WEBHOOK = "webhook"


class AlertPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


# --------------------------------------------------------------------------
# Base helper
# --------------------------------------------------------------------------

class _Model:
    def to_dict(self) -> dict:
        """Plain dict (enums become strings) for JSON / DB."""
        d = asdict(self)  # type: ignore[arg-type]
        for k, v in d.items():
            if isinstance(v, Enum):
                d[k] = v.value
        return d


# --------------------------------------------------------------------------
# Scan + discovered entities (per-scan snapshot)
# --------------------------------------------------------------------------

@dataclass
class Scan(_Model):
    target: str                                   # authorized root domain
    id: Optional[int] = None
    started_at: str = field(default_factory=utcnow)
    finished_at: Optional[str] = None
    status: ScanStatus = ScanStatus.PENDING
    is_baseline: bool = False                     # first scan: no "new asset" alerts
    max_depth: int = 2
    scope_file: Optional[str] = None
    rate_limit: Optional[int] = None              # requests/second


@dataclass
class Asset(_Model):
    """A host (subdomain / IP) discovered in ONE scan."""
    scan_id: int
    host: str                                     # e.g. dev.example.com
    ip: Optional[str] = None
    id: Optional[int] = None
    in_scope: bool = False
    is_cdn: bool = False
    cdn_name: Optional[str] = None
    asn: Optional[str] = None
    asn_owner: Optional[str] = None
    depth: int = 0                                # 0 = seed
    source: DiscoverySource = DiscoverySource.PASSIVE
    parent_host: Optional[str] = None
    first_seen: str = field(default_factory=utcnow)


@dataclass
class Service(_Model):
    """An open port + the service running on it."""
    scan_id: int
    host: str
    port: int
    ip: Optional[str] = None
    id: Optional[int] = None
    protocol: str = "tcp"
    name: Optional[str] = None                    # http, ssh
    product: Optional[str] = None                 # OpenSSH
    version: Optional[str] = None                 # 8.9p1
    banner: Optional[str] = None
    cpe: Optional[str] = None                     # Nmap -sV gives this


@dataclass
class Technology(_Model):
    """A technology detected on a host. This is what the CVE monitor watches."""
    scan_id: int
    host: str
    name: str                                     # nginx, react, WordPress
    id: Optional[int] = None
    version: Optional[str] = None                 # None if undetectable
    cpe: Optional[str] = None                     # REQUIRED for CVE matching
    category: Optional[str] = None                # web-server, cms, js-library
    source: Optional[str] = None                  # httpx, nmap, retire.js
    confidence: Confidence = Confidence.POSSIBLE


@dataclass
class WebItem(_Model):
    """URL, JS file, endpoint or parameter."""
    scan_id: int
    host: str
    url: str
    kind: WebItemKind = WebItemKind.URL
    id: Optional[int] = None
    source: DiscoverySource = DiscoverySource.ACTIVE
    status_code: Optional[int] = None
    parent_url: Optional[str] = None
    has_params: bool = False                      # only these go to injection templates


@dataclass
class Email(_Model):
    """Public email only. Personal data: store the minimum, never publish."""
    scan_id: int
    address: str
    id: Optional[int] = None
    source: Optional[str] = None


# --------------------------------------------------------------------------
# Memory ACROSS scans (needed for "new subdomain" monitoring)
# --------------------------------------------------------------------------

@dataclass
class TrackedAsset(_Model):
    """
    One row per (target, host) for ever, updated after every scan.
    Answers: 'have we ever seen this subdomain before?'
    New host -> first_seen = now -> new_asset alert.
    """
    target: str
    host: str
    id: Optional[int] = None
    first_seen: str = field(default_factory=utcnow)
    last_seen: str = field(default_factory=utcnow)
    is_active: bool = True                        # False = missing in latest scan
    last_scan_id: Optional[int] = None


@dataclass
class MonitorState(_Model):
    """Small key/value store, e.g. key='nvd_last_sync'."""
    key: str
    value: str
    updated_at: str = field(default_factory=utcnow)


# --------------------------------------------------------------------------
# Vulnerabilities
# --------------------------------------------------------------------------

@dataclass
class CVE(_Model):
    """A CVE record cached from NVD / CISA KEV (global, not tied to a scan)."""
    cve_id: str
    description: str = ""
    cvss_score: Optional[float] = None
    severity: Severity = Severity.INFO
    published: Optional[str] = None
    modified: Optional[str] = None
    cpe_matches: list[dict] = field(default_factory=list)  # criteria + version ranges
    in_kev: bool = False
    references: list[str] = field(default_factory=list)


@dataclass
class Finding(_Model):
    """
    Something wrong found on an asset. Two sources:
      - nuclei    : template matched (takeover, exposure, injection...) - cve_id may be empty
      - cve_match : technology version matched a CVE
    """
    scan_id: int
    host: str
    id: Optional[int] = None
    source: FindingSource = FindingSource.NUCLEI
    cve_id: Optional[str] = None
    title: str = ""
    template_id: Optional[str] = None             # nuclei template id
    url: Optional[str] = None
    technology: Optional[str] = None
    port: Optional[int] = None
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.POSSIBLE
    evidence: str = ""
    verified: bool = False
    verification_method: Optional[str] = None
    in_kev: bool = False
    found_at: str = field(default_factory=utcnow)
    dedup_key: str = ""

    def __post_init__(self):
        if not self.dedup_key:
            self.dedup_key = "|".join(_v(x) for x in (
                self.source, self.cve_id, self.template_id,
                self.host, self.url, self.technology))


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

@dataclass
class Alert(_Model):
    """Any notification: new CVE match, new subdomain, takeover, new port."""
    alert_type: AlertType
    host: str
    id: Optional[int] = None
    cve_id: Optional[str] = None                  # only for alert_type=cve
    technology: Optional[str] = None
    version: Optional[str] = None
    title: str = ""
    details: str = ""
    confidence: Confidence = Confidence.POSSIBLE
    priority: AlertPriority = AlertPriority.LOW
    channel: AlertChannel = AlertChannel.DISCORD
    created_at: str = field(default_factory=utcnow)
    sent_at: Optional[str] = None
    delivered: bool = False
    dedup_key: str = ""                           # same key -> never alert twice

    def __post_init__(self):
        if not self.dedup_key:
            self.dedup_key = "|".join(_v(x) for x in (
                self.alert_type, self.cve_id, self.host,
                self.technology, self.channel))


def compute_alert_priority(
    severity: Severity, in_kev: bool, confidence: Confidence
) -> AlertPriority:
    """CVE alerts: severity + known exploitation + how sure we are."""
    base = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
            Severity.HIGH: 3, Severity.CRITICAL: 4}[severity]
    if in_kev:
        base += 2
    base += {Confidence.POSSIBLE: -1, Confidence.LIKELY: 0, Confidence.CONFIRMED: 1}[confidence]
    if base >= 6:
        return AlertPriority.URGENT
    if base >= 4:
        return AlertPriority.HIGH
    if base >= 2:
        return AlertPriority.MEDIUM
    return AlertPriority.LOW


def default_priority(alert_type: AlertType) -> AlertPriority:
    """Non-CVE alerts have a fixed default priority."""
    return {
        AlertType.NEW_ASSET: AlertPriority.MEDIUM,
        AlertType.NEW_PORT: AlertPriority.MEDIUM,
        AlertType.TAKEOVER: AlertPriority.HIGH,
        AlertType.CVE: AlertPriority.LOW,
    }[alert_type]


# --------------------------------------------------------------------------
# Scan diff (computed, not stored)
# --------------------------------------------------------------------------

@dataclass
class ScanDiff(_Model):
    old_scan_id: int
    new_scan_id: int
    new_assets: list[str] = field(default_factory=list)
    removed_assets: list[str] = field(default_factory=list)
    new_ports: list[str] = field(default_factory=list)            # "host:port"
    closed_ports: list[str] = field(default_factory=list)
    changed_technologies: list[str] = field(default_factory=list)  # "host: nginx 1.18 -> 1.24"
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)
