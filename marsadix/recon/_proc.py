"""
Tiny shared async subprocess helper for the recon tools added in R5-R8
(alterx, puredns, dnsx, httpx). Built on core/aproc.run_exec: no shell, a
minimal child environment, a hard timeout (never longer than the user's
tool_timeout), bounded output, and the child is killed on timeout/cancel.

Returns the tool's stdout as text, or None when the tool is missing, or failed
without producing output. If a tool times out AFTER printing something, that
partial output is returned (and the run is recorded as "timeout" in
core/toolstatus so later stages know the result may be incomplete). Callers
treat None as "skip / use the fallback" - one missing tool must never stop the
whole recon stage.
"""

import logging
from typing import List, Mapping, Optional

from ..core import limits, toolstatus
from ..core.aproc import run_exec

logger = logging.getLogger(__name__)
_HINT = " Installed it in WSL or another shell? Install it where Marsadix runs, or add its folder to PATH; `marsadix doctor` shows what is found."


async def run_async(cmd: List[str], stdin_lines: Optional[List[str]] = None,
                    timeout: int = 300, name: Optional[str] = None,
                    env_extra: Optional[Mapping[str, Optional[str]]] = None) -> Optional[str]:
    name = name or cmd[0]
    timeout = limits.cap_timeout(timeout)
    data = ("\n".join(stdin_lines) + "\n").encode() if stdin_lines is not None else None
    try:
        async with limits.slot():
            res = await run_exec(cmd, input_data=data, timeout=timeout, env_extra=env_extra)
    except FileNotFoundError:
        logger.info(f"[-] {name} was not found on PATH - skipped.{_HINT}")
        toolstatus.record(name, "missing")
        return None
    except OSError as e:
        logger.warning(f"[-] Could not start {name}: {e}")
        toolstatus.record(name, "failed", f"could not start: {type(e).__name__}")
        return None

    text = res.stdout.decode(errors="replace")
    if res.timed_out:
        logger.warning(f"[-] {name} timed out after {timeout:g}s - "
                       f"{'keeping partial output' if text else 'no output'}.")
        toolstatus.record(name, "timeout", f"after {timeout:g}s, {len(res.stdout)} bytes kept")
        return text or None
    if res.truncated:
        logger.warning(f"[-] {name} produced more than the output limit - stopped, keeping what it printed.")
        toolstatus.record(name, "truncated", f"{len(res.stdout)} bytes kept")
        return text
    if res.returncode not in (0, None) and not res.stdout:
        err = res.stderr.decode(errors="replace").strip().splitlines()
        logger.warning(f"[-] {name} failed (exit {res.returncode}): {err[-1] if err else 'no output'}")
        toolstatus.record(name, "failed", f"exit {res.returncode}")
        return None
    toolstatus.record(name, "ok")
    return text
