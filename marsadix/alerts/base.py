"""Shared alert types and text helpers."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Protocol

__all__ = ["AlertPayload", "DeliveryResult", "Notifier", "truncate", "ELLIPSIS", "CHANNELS"]

CHANNELS = ("discord", "telegram", "email", "webhook", "slack", "teams")
ELLIPSIS = "…"


def truncate(text: Any, limit: int) -> str:
    s = "" if text is None else str(text)
    if limit <= 0:
        return ""
    if len(s) <= limit:
        return s
    return s[: max(0, limit - len(ELLIPSIS))] + ELLIPSIS


@dataclass
class AlertPayload:
    cve_id: str
    host: str
    product: str = ""
    technology: str = ""
    version: str = ""
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: bool = False
    confidence: str = "low"
    priority_level: str = "low"
    priority_score: float = 0.0
    risk_score: Optional[float] = None
    remediation_title: str = ""
    remediation_text: str = ""
    description: str = ""
    reasons: List[str] = field(default_factory=list)
    kind: str = "new"          # new | kev_transition | escalation | retry

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def title(self) -> str:
        prefix = {"kev_transition": "[KEV] ", "escalation": "[ESCALATED] "}.get(self.kind, "")
        return f"{prefix}{self.cve_id} on {self.host}"


@dataclass
class DeliveryResult:
    ok: bool
    status: Optional[int] = None
    attempts: int = 0
    error: str = ""
    skipped: bool = False


class Notifier(Protocol):
    name: str

    @property
    def configured(self) -> bool: ...

    def send(self, alert: AlertPayload) -> DeliveryResult: ...


def fmt_score(v: Optional[float], digits: int = 1) -> str:
    return "n/a" if v is None else f"{v:.{digits}f}"
