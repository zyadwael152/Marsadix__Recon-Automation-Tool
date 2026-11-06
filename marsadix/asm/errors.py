"""ASM-local errors and structured external-tool outcomes."""
from __future__ import annotations
import re, time
from dataclasses import dataclass, field
from typing import Any, Optional

class ScopeViolation(RuntimeError):
    """A URL or host is outside the authorized scope."""

class UnsafeTarget(RuntimeError):
    """A URL resolves to a blocked or unsafe network address."""

TOOL_OK = "ok"
TOOL_PARTIAL = "partial"
TOOL_TIMEOUT = "timeout"
TOOL_MISSING = "missing"
TOOL_FAILED = "failed"
TOOL_SKIPPED = "skipped"

_SECRET_PATTERNS = [re.compile(r"(?i)(api[_-]?key|apikey|token|secret|authorization)\s*[:=]\s*[^\s,;&]+"), re.compile(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@" )]
def redact(value: Any) -> str:
    out = str(value or "")
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(lambda m: (m.group(1)+"=<redacted>") if not m.group(0).startswith("http") else m.group(1)+"<redacted>@", out)
    return out

def elapsed_ms(start: float) -> int:
    return int((time.monotonic()-start)*1000)

@dataclass
class ToolOutcome:
    name: str
    status: str
    discovered: int = 0
    kept: int = 0
    returncode: Optional[int] = None
    duration_ms: int = 0
    command: list[str] = field(default_factory=list)
    error: str = ""
    details: dict = field(default_factory=dict)
    def __post_init__(self): self.error = redact(self.error)
    @property
    def ok(self) -> bool: return self.status in (TOOL_OK, TOOL_PARTIAL)
    def to_dict(self) -> dict:
        return {"name":self.name,"status":self.status,"discovered":self.discovered,"kept":self.kept,"returncode":self.returncode,"duration_ms":self.duration_ms,"command":list(self.command),"error":self.error,"details":dict(self.details)}
