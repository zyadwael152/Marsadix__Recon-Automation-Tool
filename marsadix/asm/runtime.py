"""ASM-local hardened Nuclei process runtime."""
from __future__ import annotations
import asyncio, logging, os, shutil, subprocess, time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence
from marsadix.core import limits, toolstatus
from marsadix.core.aproc import run_exec
from .config import ASMConfig
from .errors import TOOL_FAILED, TOOL_MISSING, TOOL_OK, TOOL_PARTIAL, TOOL_TIMEOUT, elapsed_ms, redact
log=logging.getLogger(__name__)
@dataclass
class ToolExecution:
    name: str
    argv: list[str]
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    timed_out: bool = False
    truncated: bool = False
    missing: bool = False
    duration_ms: int = 0
    @property
    def status(self):
        if self.missing: return TOOL_MISSING
        if self.timed_out: return TOOL_PARTIAL if self.stdout.strip() else TOOL_TIMEOUT
        if self.truncated: return TOOL_PARTIAL if self.stdout.strip() else TOOL_FAILED
        if self.returncode == 0: return TOOL_OK
        return TOOL_PARTIAL if self.stdout.strip() else TOOL_FAILED
    @property
    def error(self):
        if self.missing: return f"{self.name} is not installed or not in PATH"
        if self.timed_out: return f"{self.name} timed out"
        if self.truncated: return f"{self.name} output limit reached"
        if self.returncode not in (0,None): return redact((self.stderr or "").strip()[:400]) or f"exit code {self.returncode}"
        return ""
class ToolResolver:
    def __init__(self, config: ASMConfig): self.config=config; self._cache={}
    def _which(self,name,explicit=""):
        if explicit and Path(explicit).is_file() and os.access(explicit,os.X_OK): return explicit
        if explicit: return None
        local=Path(self.config.tools_dir)/name if self.config.tools_dir else None
        if local and local.is_file() and os.access(local,os.X_OK): return str(local)
        return shutil.which(name)
    def path(self,name):
        if name in self._cache: return self._cache[name]
        explicit=self.config.nuclei_bin if name=="nuclei" else ""
        found=self._which(name,explicit)
        self._cache[name]=found
        return found
    def status(self):
        names=("nuclei",)
        return [{"name":n,"path":self.path(n) or "","available":bool(self.path(n))} for n in names]
async def run_tool(name: str, executable: Optional[str], argv: Sequence[str], *, input_text: Optional[str]=None, timeout: int=300) -> ToolExecution:
    if not executable: return ToolExecution(name=name,argv=list(argv),missing=True)
    start=time.monotonic(); command=[executable,*[str(a) for a in argv]]
    try:
        async with limits.slot():
            result=await run_exec(command,input_data=input_text.encode("utf-8") if input_text is not None else None,timeout=limits.cap_timeout(timeout))
    except FileNotFoundError:
        toolstatus.record(name,"missing"); return ToolExecution(name=name,argv=command,missing=True,duration_ms=elapsed_ms(start))
    except Exception as exc:
        log.warning("%s could not be started: %s",name,type(exc).__name__); toolstatus.record(name,"failed",type(exc).__name__)
        return ToolExecution(name=name,argv=command,returncode=-1,stderr=f"{type(exc).__name__}: {exc}",duration_ms=elapsed_ms(start))
    execution=ToolExecution(name=name,argv=command,stdout=result.stdout.decode("utf-8",errors="replace"),stderr=result.stderr.decode("utf-8",errors="replace"),returncode=result.returncode,timed_out=result.timed_out,truncated=result.truncated,duration_ms=elapsed_ms(start))
    if execution.timed_out: log.warning("%s timed out; partial output retained",name); toolstatus.record(name,"timeout",f"kept {len(execution.stdout)} bytes")
    elif execution.truncated: log.warning("%s output was capped; partial output retained",name); toolstatus.record(name,"truncated",f"kept {len(execution.stdout)} bytes")
    elif result.returncode not in (0,None) and not execution.stdout.strip(): toolstatus.record(name,"failed",f"exit {result.returncode}")
    else: toolstatus.record(name,"ok")
    return execution
