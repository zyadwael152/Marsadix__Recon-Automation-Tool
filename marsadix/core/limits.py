"""
Run-wide limits for external tools, set once per scan from the config.

  tool_timeout     hard upper bound (seconds) on any single external tool. A
                   tool's own default may be SHORTER, never longer. Before this
                   most recon tools ignored the user's tool_timeout.
  max_concurrency  how many external tool processes may run at the same time.
                   Recursive recon used to start every tool for every target at
                   once (hundreds of processes).
"""

from __future__ import annotations

import asyncio
import weakref
from contextlib import asynccontextmanager
from typing import Optional

DEFAULT_MAX_CONCURRENCY = 8

_tool_timeout: Optional[float] = None
_max_concurrency: int = DEFAULT_MAX_CONCURRENCY
_semaphores: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def configure(tool_timeout: Optional[int] = None, max_concurrency: Optional[int] = None) -> None:
    global _tool_timeout, _max_concurrency
    _tool_timeout = float(tool_timeout) if tool_timeout else None
    _max_concurrency = max(1, int(max_concurrency)) if max_concurrency else DEFAULT_MAX_CONCURRENCY
    _semaphores.clear()


def cap_timeout(own_timeout: float) -> float:
    """The shorter of the tool's own timeout and the user's tool_timeout."""
    return min(own_timeout, _tool_timeout) if _tool_timeout else own_timeout


@asynccontextmanager
async def slot():
    """Hold one process slot (one semaphore per event loop)."""
    loop = asyncio.get_running_loop()
    sem = _semaphores.get(loop)
    if sem is None:
        sem = _semaphores[loop] = asyncio.Semaphore(_max_concurrency)
    async with sem:
        yield
