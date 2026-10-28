"""
Per-scan record of how every external tool / data source actually went.

Before this, a tool that crashed, timed out or was missing looked exactly like
a tool that ran fine and found nothing: both gave an empty list. That is
dangerous downstream -- the diff stage would read "no results" as "the asset
is gone" and raise a false REMOVED_ASSET alert.

    toolstatus.reset()                       # pipeline: once per scan
    toolstatus.record("subfinder", "timeout", "kept 120 partial lines")
    toolstatus.degraded()                    # tools whose output may be INCOMPLETE

Statuses: ok | failed | timeout | truncated | missing | skipped
`degraded()` returns failed / timeout / truncated. A tool that is simply not
installed ("missing") is reported, but is a stable property of the machine and
does not by itself make a scan untrustworthy.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

STATUSES = ("ok", "failed", "timeout", "truncated", "missing", "skipped")
INCOMPLETE = ("failed", "timeout", "truncated")


@dataclass
class ToolRun:
    tool: str
    status: str
    detail: str = ""


_runs: List[ToolRun] = []


def reset() -> None:
    _runs.clear()


def record(tool: str, status: str, detail: str = "") -> None:
    if status not in STATUSES:
        raise ValueError(f"unknown tool status {status!r}")
    _runs.append(ToolRun(tool, status, detail))


def runs() -> List[ToolRun]:
    return list(_runs)


def degraded() -> List[ToolRun]:
    """Tools whose output may be incomplete (a later scan must not read the gap as 'gone')."""
    return [r for r in _runs if r.status in INCOMPLETE]


def summary(runs_: List[ToolRun] | None = None) -> str:
    rs = degraded() if runs_ is None else runs_
    return "; ".join(f"{r.tool} {r.status}" + (f" ({r.detail})" if r.detail else "") for r in rs)


def write_json(path) -> None:
    """Keep the tool log next to the scan outputs (never fatal)."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps([asdict(r) for r in _runs], indent=2), encoding="utf-8")
    except OSError as e:
        log.warning("could not write tool status file %s: %s", path, e)
