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
# subprocess is only used with shell=False and an argv list.
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from . import toolstatus
from .childenv import child_env

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
    "amass": "active/passive subdomain enumeration",
    "assetfinder": "subdomain discovery via API sources",
    "chaos": "subdomain discovery via ProjectDiscovery Chaos dataset",
    "findomain": "fast subdomain discovery (Rust)",
    "alterx": "subdomain permutations (R5; skipped when missing)",
    "puredns": "DNS bruteforce with wildcard filtering (R6; needs massdns; falls back when missing)",
    "massdns": "DNS engine used by puredns (C program: Linux/macOS/WSL/Docker, no native Windows build)",
}


def find_tool(name: str) -> Optional[str]:
    return shutil.which(name)


def run_tool(
    cmd: Sequence[str],
    timeout: int = 600,
    input_text: Optional[str] = None,
    check: bool = False,
    cwd: Optional[str] = None,
    env_extra: Optional[Mapping[str, Optional[str]]] = None,
) -> ToolResult:
    cmd = [str(c) for c in cmd]
    if not cmd:
        raise ValueError("empty command")
    if find_tool(cmd[0]) is None:
        toolstatus.record(cmd[0], "missing")
        raise ToolNotFound(
            f"'{cmd[0]}' is not installed or not in PATH. Run `marsadix doctor`.")

    log.debug("run: %s", " ".join(cmd))
    start = time.monotonic()
    try:
        p = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, cwd=cwd,
            # minimal environment: the child never sees Marsadix's API keys
            env=child_env(env_extra),
            # argv list, never a shell string
            shell=False,  # nosec B603
        )
        res = ToolResult(cmd, p.returncode, p.stdout or "", p.stderr or "",
                         time.monotonic() - start)
    except subprocess.TimeoutExpired as e:
        def _s(x):
            return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")
        log.warning("%s timed out after %ss", cmd[0], timeout)
        res = ToolResult(cmd, -1, _s(e.stdout), _s(e.stderr),
                         time.monotonic() - start, timed_out=True)

    if res.timed_out:
        toolstatus.record(cmd[0], "timeout", f"after {timeout}s, {len(res.stdout)} bytes kept")
    elif res.returncode != 0 and not res.stdout.strip():
        toolstatus.record(cmd[0], "failed", f"exit {res.returncode}")
    else:
        toolstatus.record(cmd[0], "ok")

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


def httpx_check() -> tuple:
    """
    (is_projectdiscovery, first line `httpx -version` printed).
    is_projectdiscovery is None when httpx is not found or cannot be started. The first line is
    returned so `marsadix doctor` can show WHAT the command on PATH answered: a broken launcher
    (for example "did not find executable at '/usr/bin\\python.exe'") looks nothing like a version banner.
    """
    if find_tool("httpx") is None:
        return None, ""
    try:
        res = run_tool(["httpx", "-version"], timeout=15)
    except (ToolNotFound, OSError):
        return None, ""
    out = (res.stdout + res.stderr).strip()
    return "projectdiscovery" in out.lower(), (out.splitlines()[0] if out else "")


def httpx_is_projectdiscovery() -> Optional[bool]:
    """
    The Python package 'httpx' ALSO installs a command called 'httpx' and can
    shadow ProjectDiscovery's. Heuristic check; None if httpx is not found.
    """
    return httpx_check()[0]
