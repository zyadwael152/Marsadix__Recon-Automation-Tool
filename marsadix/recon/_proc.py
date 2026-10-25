"""
Tiny shared async subprocess helper for the recon tools added in R5-R8
(alterx, puredns, dnsx, httpx). Same pattern the rest of recon/ already uses
(create_subprocess_exec, no shell, hard timeout), in one place.

Returns the tool's stdout as text, or None when the tool is missing, timed
out, or failed without producing output. Callers treat None as "skip / use
the fallback" - one missing tool must never stop the whole recon stage.
"""

import asyncio
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


async def run_async(cmd: List[str], stdin_lines: Optional[List[str]] = None,
                    timeout: int = 300, name: Optional[str] = None) -> Optional[str]:
    name = name or cmd[0]
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_lines is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.info(f"[-] {name} is not installed - skipped.")
        return None
    except Exception as e:
        logger.warning(f"[-] Could not start {name}: {e}")
        return None

    data = ("\n".join(stdin_lines) + "\n").encode() if stdin_lines is not None else None
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(input=data), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        logger.warning(f"[-] {name} timed out after {timeout}s - skipped.")
        return None

    if process.returncode not in (0, None) and not stdout:
        err = (stderr or b"").decode(errors="replace").strip().splitlines()
        logger.warning(f"[-] {name} failed (exit {process.returncode}): {err[-1] if err else 'no output'}")
        return None
    return stdout.decode(errors="replace")
