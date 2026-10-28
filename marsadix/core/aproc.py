"""
One safe way to run an external tool asynchronously.

Guarantees (these were each missing in at least one of the old code paths):
  * no shell, argv list only, minimal environment (core/childenv.py)
  * hard timeout; partial output is KEPT, not thrown away
  * the child (and, on POSIX, its whole process group) is killed on timeout,
    on cancellation and on Ctrl+C -- it can no longer outlive the scan
  * stdout is bounded (max_bytes) so a runaway tool cannot eat all memory;
    when the cap is hit the tool is stopped and the result is marked truncated
"""

from __future__ import annotations

import asyncio
import os
import signal
from contextlib import suppress
from dataclasses import dataclass
from typing import List, Mapping, Optional

from .childenv import child_env

MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_MAX_STDERR_BYTES = 1024 * 1024


@dataclass
class ExecResult:
    stdout: bytes
    stderr: bytes
    returncode: Optional[int]
    timed_out: bool = False
    truncated: bool = False


def kill_process(process) -> None:
    """Kill the tool and, where possible, everything it spawned."""
    pid = getattr(process, "pid", None)
    if os.name == "posix" and isinstance(pid, int) and pid > 1:
        with suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(pid, signal.SIGKILL)
            return
    with suppress(ProcessLookupError):
        process.kill()


async def run_exec(cmd: List[str], *, input_data: Optional[bytes] = None, timeout: float = 300,
                   env_extra: Optional[Mapping[str, Optional[str]]] = None,
                   max_bytes: int = MAX_OUTPUT_BYTES) -> ExecResult:
    """Raises FileNotFoundError / OSError if the tool cannot be started."""
    extra = {"start_new_session": True} if os.name == "posix" else {}
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=child_env(env_extra), limit=1024 * 1024, **extra)

    out, err = bytearray(), bytearray()
    state = {"truncated": False}

    async def pump(stream, buf: bytearray, cap: int, kill_on_cap: bool) -> None:
        if stream is None:
            return
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return
            room = cap - len(buf)
            if room > 0:
                buf += chunk[:room]
            if len(chunk) > room and kill_on_cap and not state["truncated"]:
                state["truncated"] = True
                kill_process(process)          # stdout is full: stop the tool, keep what we have

    async def feed() -> None:
        stdin = process.stdin
        try:
            if input_data:
                stdin.write(input_data)
                await stdin.drain()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with suppress(Exception):
                stdin.close()

    tasks = [asyncio.create_task(pump(process.stdout, out, max_bytes, True)),
             asyncio.create_task(pump(process.stderr, err, _MAX_STDERR_BYTES, False))]
    if input_data is not None and getattr(process, "stdin", None) is not None:
        tasks.append(asyncio.create_task(feed()))

    timed_out = False
    try:
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            timed_out = True
            kill_process(process)
            await process.wait()
    except BaseException:
        # Cancelled (Ctrl+C, parent task failed ...): never leave the tool running.
        kill_process(process)
        with suppress(BaseException):
            await asyncio.wait_for(process.wait(), timeout=5)
        for t in tasks:
            t.cancel()
        raise
    # A killed child closes its pipes at once; bound the wait anyway (a grandchild
    # can inherit the pipe and keep it open).
    try:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=5)
    except asyncio.TimeoutError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return ExecResult(bytes(out), bytes(err), process.returncode, timed_out, state["truncated"])
