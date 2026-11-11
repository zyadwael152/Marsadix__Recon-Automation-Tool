"""Async token bucket and retry helpers.

A global limiter is shared by every internal HTTP request (archive APIs, status
checks, JS fetching, the built-in crawler).  External tools receive the same
number through their own `-rl`/`--threads` flags; this module cannot throttle a
subprocess directly, but the pipeline keeps tool concurrency low and passes the
configured value to every tool that supports it.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Optional


class AsyncRateLimiter:
    """Simple monotonic-clock token bucket shared across tasks."""

    def __init__(self, rate: float, burst: Optional[float] = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = float(burst if burst is not None else max(1.0, min(10.0, rate)))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def tokens(self) -> float:
        return self._tokens

    async def acquire(self, tokens: float = 1.0) -> None:
        if tokens <= 0:
            return
        if tokens > self.capacity:
            tokens = self.capacity
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                if elapsed > 0:
                    self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                    self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self.rate
                # Tiny jitter avoids lockstep bursts when many tasks wake at once.
                await asyncio.sleep(max(wait, 0.001) + random.uniform(0, 0.01))


async def backoff_delay(attempt: int, base: float = 0.5, cap: float = 20.0,
                        retry_after: Optional[float] = None) -> None:
    """Sleep before retry `attempt` (0-based). Honour Retry-After when given."""
    if retry_after is not None:
        await asyncio.sleep(max(0.0, min(float(retry_after), cap)))
        return
    delay = min(cap, base * (2 ** max(0, attempt)))
    await asyncio.sleep(delay + random.uniform(0, 0.25))
