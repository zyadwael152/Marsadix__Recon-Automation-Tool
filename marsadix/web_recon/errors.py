"""Exception types and structured tool outcomes for Member 2.

Every external tool failure is data, not control flow: a scan must never stop
because one source is missing or slow.  The pipeline collects `ToolOutcome`
objects and presents them in the final report/log summary.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional


class Member2Error(RuntimeError):
    """Base class for all extension errors."""


class ConfigError(Member2Error, ValueError):
    """Invalid Member 2 configuration."""


class ScopeViolation(Member2Error):
    """A URL/host failed scope or network-safety validation."""


class UnsafeTarget(Member2Error):
    """A target resolves to a private/loopback/link-local address."""


class ToolUnavailable(Member2Error):
    """The external binary could not be found."""


class ToolFailed(Member2Error):
    """The external binary ran but did not complete successfully."""


class ArchiveError(Member2Error):
    """An archive API returned an unusable response."""


class VerificationError(Member2Error):
    """A URL could not be verified safely."""


# Tool states used in reports.  Keep these stable: tests and the Markdown
# report document them.
TOOL_OK = "ok"
TOOL_PARTIAL = "partial"
TOOL_TIMEOUT = "timeout"
TOOL_MISSING = "missing"
TOOL_FAILED = "failed"
TOOL_SKIPPED = "skipped"


_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|apikey|token|secret|authorization)\s*[:=]\s*[^\s,;&]+"),
    re.compile(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@"),
]


def redact(text: Any) -> str:
    """Remove credentials from a message before it reaches a log/report."""
    if text is None:
        return ""
    out = str(text)
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(lambda m: (m.group(1) + "=<redacted>") if not m.group(0).startswith("http") else (m.group(1) + "<redacted>@"), out)
    return out


@dataclass
class ToolOutcome:
    """Result of one external tool/API invocation.

    `status` is one of the TOOL_* constants.  `error` is always redacted.
    """

    name: str
    status: str
    discovered: int = 0
    kept: int = 0
    returncode: Optional[int] = None
    duration_ms: int = 0
    command: list[str] = field(default_factory=list)
    error: str = ""
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.error = redact(self.error)

    @property
    def ok(self) -> bool:
        return self.status in (TOOL_OK, TOOL_PARTIAL)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "discovered": self.discovered,
            "kept": self.kept,
            "returncode": self.returncode,
            "duration_ms": self.duration_ms,
            "command": list(self.command),
            "error": self.error,
            "details": dict(self.details),
        }


def elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
