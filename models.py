"""Person 4 matching data model (M7-M10)."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .cpe import CPEParseError, parse_cpe_cached

__all__ = ["VersionSource", "Confidence", "PriorityLevel", "Priority", "Asset", "CVE",
           "MatchResult", "CRITICALITY_LEVELS"]

CRITICALITY_LEVELS = ("low", "medium", "high", "critical")


class VersionSource(str, enum.Enum):
    VERIFIED = "verified"
    NMAP = "nmap"
    BANNER = "banner"
    HTTPX = "httpx"
    FINGERPRINT = "fingerprint"
    INFERRED = "inferred"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, value: Any) -> "VersionSource":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.UNKNOWN


class Confidence(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def coerce(cls, value: Any) -> "Confidence":
        if isinstance(value, cls):
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return cls.HIGH if value >= 0.8 else cls.MEDIUM if value >= 0.5 else cls.LOW
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            return cls.LOW


class PriorityLevel(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Priority:
    level: PriorityLevel
    score: float
    reasons: Tuple[str, ...] = ()


@dataclass
class Asset:
    """A host + technology observation to be matched against CVEs."""
    host: str
    cpe: str
    version: Optional[str] = None
    version_source: VersionSource = VersionSource.UNKNOWN
    internet_facing: bool = True
    behind_cdn: bool = False
    criticality: str = "medium"          # one of CRITICALITY_LEVELS
    platform_cpes: List[str] = field(default_factory=list)  # other CPEs seen on the host
    name: str = ""                        # human technology name, display only
    scan_id: Optional[int] = None
    technology_id: Optional[int] = None

    @property
    def product(self) -> str:
        try:
            return parse_cpe_cached(self.cpe).product
        except CPEParseError:
            return self.name or ""


@dataclass
class CVE:
    id: str
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: bool = False
    configurations: List[Dict[str, Any]] = field(default_factory=list)
    description: str = ""
    cwe: List[str] = field(default_factory=list)


@dataclass
class MatchResult:
    cve: CVE
    asset: Asset
    matched_criteria: Tuple[str, ...] = ()
    version_compared: bool = False
    platform_unverified: bool = False
    notes: Tuple[str, ...] = ()
