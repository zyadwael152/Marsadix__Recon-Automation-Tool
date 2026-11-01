"""Resolve and run external Member 2 tools safely.

Tools are launched with an argv list (never a shell), a hard timeout, a kill +
reap on expiry, and partial-output preservation.  Every wrapper returns a
`ToolOutcome` plus parsed records; missing tools are a normal, reported state.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

from marsadix.core import limits, toolstatus
from marsadix.core.aproc import run_exec
from marsadix.core.runner import find_tool as base_find_tool
from marsadix.core.runner import parse_json_lines as base_parse_json_lines

from .config import Member2Config
from .errors import (
    TOOL_FAILED, TOOL_MISSING, TOOL_OK, TOOL_PARTIAL, TOOL_SKIPPED, TOOL_TIMEOUT,
    ToolOutcome, elapsed_ms, redact,
)

logger = logging.getLogger(__name__)

_TOOL_NAMES = ("httpx", "katana", "gau", "subfinder", "dnsx", "nuclei", "waybackurls")


@dataclass
class ToolExecution:
    name: str
    argv: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    timed_out: bool = False
    truncated: bool = False
    missing: bool = False
    duration_ms: int = 0

    @property
    def status(self) -> str:
        if self.missing:
            return TOOL_MISSING
        if self.timed_out:
            return TOOL_PARTIAL if self.stdout.strip() else TOOL_TIMEOUT
        if self.truncated:
            return TOOL_PARTIAL if self.stdout.strip() else TOOL_FAILED
        if self.returncode == 0:
            return TOOL_OK
        return TOOL_PARTIAL if self.stdout.strip() else TOOL_FAILED

    @property
    def error(self) -> str:
        if self.missing:
            return f"{self.name} is not installed or not in PATH"
        if self.timed_out:
            return f"{self.name} timed out"
        if self.truncated:
            return f"{self.name} output limit reached"
        if self.returncode not in (0, None):
            return redact((self.stderr or "").strip()[:400]) or f"exit code {self.returncode}"
        return ""


@dataclass
class CrawlRecord:
    url: str
    status_code: Optional[int] = None
    content_type: str = ""
    parent_url: Optional[str] = None
    source: str = "katana"


@dataclass
class VerifyRecord:
    url: str
    status_code: Optional[int] = None
    content_type: str = ""
    location: str = ""
    final_url: str = ""
    ip: Optional[str] = None
    title: str = ""


@dataclass
class ArchiveRecord:
    url: str
    source: str
    status_code: Optional[int] = None
    mime_type: str = ""


def _candidate_dirs(config: Member2Config) -> list[Path]:
    dirs: list[Path] = []
    if config.tools_dir:
        dirs.append(Path(config.tools_dir))
    dirs.append(Path(__file__).resolve().parent.parent.parent / ".tools" / "bin")
    return [d for d in dirs if d.is_dir()]


def which_tool(name: str, config: Member2Config,
               explicit: str = "") -> Optional[str]:
    if explicit:
        p = Path(explicit)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        return None
    for directory in _candidate_dirs(config):
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return base_find_tool(name)


class ToolResolver:
    """Resolve each tool once, preferring the locally installed project tools."""

    def __init__(self, config: Member2Config) -> None:
        self.config = config
        self._cache: dict[str, Optional[str]] = {}
        self._pd_checked = False
        self._pd_httpx: Optional[str] = None

    def path(self, name: str) -> Optional[str]:
        if name in self._cache:
            return self._cache[name]
        overrides = {
            "httpx": self.config.httpx_bin,
            "katana": self.config.katana_bin,
            "gau": self.config.gau_bin,
            "subfinder": self.config.subfinder_bin,
            "dnsx": self.config.dnsx_bin,
            "nuclei": self.config.nuclei_bin,
        }
        found = which_tool(name, self.config, overrides.get(name, ""))
        if name == "httpx":
            found = self.projectdiscovery_httpx(found)
        self._cache[name] = found
        return found

    def projectdiscovery_httpx(self, candidate: Optional[str] = None) -> Optional[str]:
        """`httpx` is also a Python package command; verify the flavour."""
        if self._pd_checked:
            return self._pd_httpx
        self._pd_checked = True
        candidates = [candidate] if candidate else []
        candidates += [which_tool("httpx-pd", self.config), which_tool("httpx", self.config)]
        for path in candidates:
            if not path:
                continue
            try:
                proc = subprocess.run(
                    [path, "-version"], capture_output=True, text=True,
                    timeout=10, encoding="utf-8", errors="replace", shell=False,
                )
                banner = ((proc.stdout or "") + (proc.stderr or "")).lower()
                if "projectdiscovery" in banner or "current version" in banner:
                    self._pd_httpx = path
                    return path
            except (OSError, subprocess.SubprocessError):
                continue
        logger.warning("ProjectDiscovery httpx not found; status checks will use the "
                       "built-in HTTP client (the Python 'httpx' command is not used).")
        return None

    def status(self) -> list[dict]:
        rows = []
        for name in _TOOL_NAMES:
            path = self.path(name)
            rows.append({"name": name, "path": path or "", "available": bool(path)})
        return rows


async def run_tool(name: str, executable: Optional[str], argv: Sequence[str],
                   *, input_text: Optional[str] = None,
                   timeout: int = 300) -> ToolExecution:
    """Run one tool through the base repo's hardened async process layer.

    `core.aproc.run_exec` owns the no-shell argv contract, minimal child
    environment, process-group kill, partial-output retention and output cap.
    This wrapper only maps its result to the extension's ToolOutcome model.
    """
    if not executable:
        return ToolExecution(name=name, argv=list(argv), missing=True)
    start = time.monotonic()
    command = [executable] + [str(a) for a in argv]
    try:
        async with limits.slot():
            result = await run_exec(
                command,
                input_data=(input_text.encode("utf-8")
                            if input_text is not None else None),
                timeout=limits.cap_timeout(timeout),
            )
    except FileNotFoundError:
        toolstatus.record(name, "missing")
        return ToolExecution(name=name, argv=list(argv), missing=True,
                             duration_ms=elapsed_ms(start))
    except Exception as exc:  # tool launch failure must never abort the scan
        logger.warning("%s could not be started: %s", name, type(exc).__name__)
        toolstatus.record(name, "failed", type(exc).__name__)
        return ToolExecution(name=name, argv=list(argv), returncode=-1,
                             stderr=f"{type(exc).__name__}: {exc}",
                             duration_ms=elapsed_ms(start))

    execution = ToolExecution(
        name=name,
        argv=command,
        stdout=result.stdout.decode("utf-8", errors="replace"),
        stderr=result.stderr.decode("utf-8", errors="replace"),
        returncode=result.returncode,
        timed_out=result.timed_out,
        truncated=result.truncated,
        duration_ms=elapsed_ms(start),
    )
    if execution.timed_out:
        logger.warning("%s timed out; partial output retained", name)
        toolstatus.record(name, "timeout", f"kept {len(execution.stdout)} bytes")
    elif execution.truncated:
        logger.warning("%s output was capped; partial output retained", name)
        toolstatus.record(name, "truncated", f"kept {len(execution.stdout)} bytes")
    elif result.returncode not in (0, None) and not execution.stdout.strip():
        toolstatus.record(name, "failed", f"exit {result.returncode}")
    else:
        toolstatus.record(name, "ok")
    return execution


def parse_json_lines(text: str) -> list[dict]:
    """Use the base JSON-lines parser, keeping only object records."""
    return [record for record in base_parse_json_lines(text or "")
            if isinstance(record, dict)]


def _int_or_none(value) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _clean_url(value) -> str:
    return str(value or "").strip()


# --------------------------------------------------------------------------- katana

def _katana_record(data: dict) -> Optional[CrawlRecord]:
    request = data.get("request") if isinstance(data.get("request"), dict) else {}
    response = data.get("response") if isinstance(data.get("response"), dict) else {}
    url = (_clean_url(request.get("endpoint")) or _clean_url(data.get("url"))
           or _clean_url(data.get("endpoint")) or _clean_url(data.get("request", {}).get("url")
                                                             if isinstance(data.get("request"), dict) else ""))
    if not url:
        return None
    headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
    ctype = ""
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            ctype = str(value).split(";", 1)[0].strip().lower()
            break
    ctype = ctype or str(response.get("content_type") or data.get("content_type") or "").split(";", 1)[0].lower()
    parent = request.get("source") or data.get("source") or None
    return CrawlRecord(
        url=url,
        status_code=_int_or_none(response.get("status_code") or data.get("status_code")),
        content_type=ctype,
        parent_url=_clean_url(parent) or None,
        source="katana",
    )


async def run_katana(urls: Iterable[str], config: Member2Config,
                     resolver: ToolResolver) -> tuple[list[CrawlRecord], ToolOutcome]:
    urls = list(dict.fromkeys(u for u in urls if u))
    if not urls:
        return [], ToolOutcome("katana", TOOL_SKIPPED)
    exe = resolver.path("katana")
    if not exe:
        return [], ToolOutcome("katana", TOOL_MISSING,
                               error="katana is not installed or not in PATH")
    argv = [
        "-silent", "-jsonl", "-jc", "-no-color",
        "-d", str(config.crawl_depth),
        "-rl", str(config.rate_limit),
        "-timeout", str(max(1, int(config.request_timeout))),
        "-retry", str(min(2, max(0, config.retries))),
    ]
    execution = await run_tool("katana", exe, argv, input_text="\n".join(urls),
                               timeout=config.tool_timeout)
    records: list[CrawlRecord] = []
    for line in execution.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec = _katana_record(data) if isinstance(data, dict) else None
            if rec:
                records.append(rec)
        elif line.startswith(("http://", "https://")):
            records.append(CrawlRecord(url=line, source="katana"))
    # dedupe while preserving the richest record
    merged: dict[str, CrawlRecord] = {}
    for rec in records:
        old = merged.get(rec.url)
        if old is None or (old.status_code is None and rec.status_code is not None):
            merged[rec.url] = rec
    records = list(merged.values())
    return records, ToolOutcome(
        "katana", execution.status, discovered=len(records), kept=len(records),
        returncode=execution.returncode, duration_ms=execution.duration_ms,
        command=["katana", *argv], error=execution.error,
        details={"input_urls": len(urls)},
    )


# --------------------------------------------------------------------------- httpx

def _httpx_record(data: dict) -> Optional[VerifyRecord]:
    url = _clean_url(data.get("url") or data.get("input"))
    if not url:
        return None
    return VerifyRecord(
        url=url,
        status_code=_int_or_none(data.get("status_code")),
        content_type=str(data.get("content_type") or "").split(";", 1)[0].strip().lower(),
        location=_clean_url(data.get("location")),
        final_url=_clean_url(data.get("url")),
        ip=_clean_url(data.get("host_ip") or data.get("ip")) or None,
        title=_clean_url(data.get("title")),
    )


async def run_httpx_verify(urls: Iterable[str], config: Member2Config,
                           resolver: ToolResolver) -> tuple[list[VerifyRecord], ToolOutcome]:
    urls = list(dict.fromkeys(u for u in urls if u))
    if not urls:
        return [], ToolOutcome("httpx", TOOL_SKIPPED)
    exe = resolver.path("httpx")
    if not exe:
        return [], ToolOutcome("httpx", TOOL_MISSING,
                               error="ProjectDiscovery httpx is not installed")
    argv = [
        "-silent", "-json", "-no-color",
        "-sc", "-cl", "-ct", "-location", "-td", "-server",
        "-rl", str(config.rate_limit),
        "-timeout", str(max(1, int(config.request_timeout))),
        "-retries", str(min(2, max(0, config.retries))),
    ]
    execution = await run_tool("httpx", exe, argv, input_text="\n".join(urls),
                               timeout=config.tool_timeout)
    records = [r for r in (_httpx_record(d) for d in parse_json_lines(execution.stdout)) if r]
    return records, ToolOutcome(
        "httpx", execution.status, discovered=len(records), kept=len(records),
        returncode=execution.returncode, duration_ms=execution.duration_ms,
        command=["httpx", *argv], error=execution.error,
        details={"input_urls": len(urls)},
    )


# --------------------------------------------------------------------------- gau

def _gau_record(line: str) -> Optional[ArchiveRecord]:
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        url = _clean_url(data.get("url") or data.get("original") or data.get("endpoint"))
        if not url:
            return None
        provider = str(data.get("provider") or data.get("source") or "gau").lower()
        return ArchiveRecord(
            url=url, source=f"gau:{provider}" if provider and provider != "gau" else "gau",
            status_code=_int_or_none(data.get("status") or data.get("status_code")),
            mime_type=str(data.get("mime") or data.get("mimetype") or "").split(";", 1)[0].lower(),
        )
    if line.startswith(("http://", "https://")):
        return ArchiveRecord(url=line, source="gau")
    return None


async def run_gau(targets: Iterable[str], config: Member2Config,
                  resolver: ToolResolver,
                  providers: Sequence[str] = ("wayback", "commoncrawl")
                  ) -> tuple[list[ArchiveRecord], ToolOutcome]:
    targets = [t for t in dict.fromkeys(targets) if t]
    if not targets or "gau" not in config.archive_sources:
        return [], ToolOutcome("gau", TOOL_SKIPPED)
    exe = resolver.path("gau")
    if not exe:
        return [], ToolOutcome("gau", TOOL_MISSING,
                               error="gau is not installed or not in PATH")
    provider_arg = ",".join(providers) if providers else "wayback,commoncrawl"
    argv = [
        "--subs", "--json",
        "--threads", str(max(1, config.tool_threads)),
        "--timeout", str(max(1, int(config.tool_timeout))),
        "--retries", str(min(3, max(0, config.retries))),
        "--providers", provider_arg,
    ]
    # gau reads one domain per positional argument; keep argv explicit rather
    # than relying on stdin support differences between releases.
    execution = await run_tool("gau", exe, [*argv, *targets], timeout=config.tool_timeout)
    records = [r for r in (_gau_record(line) for line in execution.stdout.splitlines()) if r]
    deduped = list({r.url: r for r in records}.values())
    return deduped, ToolOutcome(
        "gau", execution.status, discovered=len(deduped), kept=len(deduped),
        returncode=execution.returncode, duration_ms=execution.duration_ms,
        command=["gau", *argv, *targets], error=execution.error,
        details={"targets": len(targets), "providers": provider_arg},
    )


# ----------------------------------------------------------------------- subfinder

def _host_line(line: str) -> Optional[str]:
    value = line.strip().lower().rstrip(".")
    if not value or " " in value or "/" in value or ":" in value:
        return None
    if not all(ch.isalnum() or ch in ".-_" for ch in value):
        return None
    if "." not in value and value != "localhost":
        return None
    return value


async def run_subfinder(domain: str, config: Member2Config,
                        resolver: ToolResolver) -> tuple[list[str], ToolOutcome]:
    exe = resolver.path("subfinder")
    if not exe:
        return [], ToolOutcome("subfinder", TOOL_MISSING,
                               error="subfinder is not installed or not in PATH")
    argv = ["-d", domain, "-silent", "-no-color"]
    execution = await run_tool("subfinder", exe, argv, timeout=config.tool_timeout)
    hosts = sorted({h for h in (_host_line(line) for line in execution.stdout.splitlines()) if h})
    return hosts, ToolOutcome(
        "subfinder", execution.status, discovered=len(hosts), kept=len(hosts),
        returncode=execution.returncode, duration_ms=execution.duration_ms,
        command=["subfinder", *argv], error=execution.error,
    )


def tool_doctor(config: Member2Config) -> list[dict]:
    resolver = ToolResolver(config)
    return resolver.status()
