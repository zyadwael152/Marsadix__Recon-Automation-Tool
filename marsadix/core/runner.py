"""
Safe way to run external tools (subfinder, httpx, nmap, nuclei ...).

    res = run_tool(["subfinder", "-d", "example.com", "-silent"], timeout=300)
    domains = res.stdout.splitlines()

Rules: no shell, always a timeout, never crash the pipeline because a tool
is missing/slow: the caller decides what to do with the ToolResult.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Sequence

log = logging.getLogger(__name__)


class ToolNotFound(RuntimeError):
    pass


class ToolError(RuntimeError):
    pass


@dataclass
class ToolResult:
    cmd: list
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


# tool name -> what Marsadix uses it for
KNOWN_TOOLS = {
    "subfinder": "passive subdomain discovery",
    "dnsx": "DNS resolution",
    "httpx": "probing + technology detection (ProjectDiscovery httpx)",
    "naabu": "port scanning",
    "nmap": "service/version detection + CPE",
    "katana": "crawling (URLs, JS files)",
    "gau": "archived URLs",
    "nuclei": "template scanning (ASM)",
    "ffuf": "fuzzing (optional)",
}


def find_tool(name: str) -> Optional[str]:
    return shutil.which(name)


def run_tool(
    cmd: Sequence[str],
    timeout: int = 600,
    input_text: Optional[str] = None,
    check: bool = False,
    cwd: Optional[str] = None,
) -> ToolResult:
    cmd = [str(c) for c in cmd]
    if not cmd:
        raise ValueError("empty command")
    if find_tool(cmd[0]) is None:
        raise ToolNotFound(
            f"'{cmd[0]}' is not installed or not in PATH. Run `marsadix doctor`.")

    log.debug("run: %s", " ".join(cmd))
    start = time.monotonic()
    try:
        p = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, cwd=cwd,
            shell=False,
        )
        res = ToolResult(cmd, p.returncode, p.stdout or "", p.stderr or "",
                         time.monotonic() - start)
    except subprocess.TimeoutExpired as e:
        def _s(x):
            return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")
        log.warning("%s timed out after %ss", cmd[0], timeout)
        res = ToolResult(cmd, -1, _s(e.stdout), _s(e.stderr),
                         time.monotonic() - start, timed_out=True)

    if check and not res.ok:
        reason = "timed out" if res.timed_out else f"exit code {res.returncode}"
        raise ToolError(f"{cmd[0]} failed ({reason}): {res.stderr.strip()[:300]}")
    return res


def parse_json_lines(text: str) -> list:
    """Many tools (httpx, nuclei, katana, naabu) print one JSON object per line."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            log.debug("skipping bad JSON line: %.80s", line)
    return out


def tool_status() -> list:
    """[(name, path_or_None, purpose)] for `marsadix doctor`."""
    return [(n, find_tool(n), purpose) for n, purpose in KNOWN_TOOLS.items()]


def httpx_is_projectdiscovery() -> Optional[bool]:
    """
    The Python package 'httpx' ALSO installs a command called 'httpx' and can
    shadow ProjectDiscovery's. Heuristic check; None if httpx is not found.
    """
    if find_tool("httpx") is None:
        return None
    try:
        res = run_tool(["httpx", "-version"], timeout=15)
    except (ToolNotFound, OSError):
        return None
    return "projectdiscovery" in (res.stdout + res.stderr).lower()
