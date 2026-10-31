"""
Per-scan record of how every external tool / data source actually went.

Before this, a tool that crashed, timed out or was missing looked exactly like
a tool that ran fine and found nothing: both gave an empty list. That is
dangerous downstream -- the diff stage would read "no results" as "the asset
is gone" and raise a false REMOVED_ASSET alert.

    toolstatus.reset()                       # pipeline: once per scan
    toolstatus.record("subfinder", "timeout", "kept 120 partial lines")
    toolstatus.degraded()                    # tools whose output may be INCOMPLETE

Statuses: ok | failed | timeout | truncated | missing | denied | skipped
`degraded()` returns failed / timeout / truncated: something went wrong THIS time, so
the result may be incomplete. "missing" (tool not installed) and "denied" (the provider
rejected the key / plan: HTTP 401-403) are reported but are stable facts about the setup,
not an incident: they would otherwise disable disappearance alerts forever.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

STATUSES = ("ok", "failed", "timeout", "truncated", "missing", "denied", "skipped")
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
    """One short line, repeated runs grouped: "alienvault failed x4 (HTTP 429); crt.sh failed (HTTP 502)"."""
    rs = degraded() if runs_ is None else runs_
    groups: dict = {}
    for r in rs:
        g = groups.setdefault((r.tool, r.status), {"n": 0, "details": []})
        g["n"] += 1
        if r.detail and r.detail not in g["details"]:
            g["details"].append(r.detail)
    out = []
    for (tool, status), g in groups.items():
        text = f"{tool} {status}" + (f" x{g['n']}" if g["n"] > 1 else "")
        if g["details"]:
            text += " (" + ", ".join(g["details"][:2]) + ")"
        out.append(text)
    return "; ".join(out)


def write_json(path) -> None:
    """Keep the tool log next to the scan outputs (never fatal)."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps([asdict(r) for r in _runs], indent=2), encoding="utf-8")
    except OSError as e:
        log.warning("could not write tool status file %s: %s", path, e)
