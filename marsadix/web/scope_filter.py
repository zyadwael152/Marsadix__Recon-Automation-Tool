"""Scope + network-safety enforcement for every URL the extension touches.

Scope is re-checked at output time, not merely trusted from an earlier stage:
crawlers follow links, archives return URLs for sibling domains, and a hostname
can be made to resolve to loopback/private space.  This is the same policy as
`marsadix.core.scope` / `marsadix.core.netguard`, wrapped for URL-shaped input.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Iterable, Optional

from marsadix.core import netguard
from marsadix.core.scope import Decision, Scope

from .errors import ScopeViolation, UnsafeTarget
from .normalize import NormalizedURL, normalize_url


@dataclass
class ScopeEnforcer:
    scope: Scope
    target: str
    allow_private: bool = False
    dns_timeout: float = 5.0
    _ip_cache: dict[str, tuple[str, ...]] = field(default_factory=dict)
    _locks: dict[str, asyncio.Lock] = field(default_factory=dict)

    def decision(self, value: str) -> Decision:
        return self.scope.check(value)

    def in_scope(self, value: str) -> bool:
        return self.scope.check(value).in_scope

    def check(self, raw: str, base_url: Optional[str] = None,
              strip_tracking: bool = True) -> NormalizedURL:
        normalized = normalize_url(raw, base_url=base_url, strip_tracking=strip_tracking)
        decision = self.scope.check(normalized.host)
        if not decision:
            raise ScopeViolation(
                f"out of scope: {normalized.host} ({decision.reason})")
        return normalized

    def filter(self, values: Iterable[str], base_url: Optional[str] = None) -> list[NormalizedURL]:
        out = []
        for value in values:
            try:
                out.append(self.check(value, base_url=base_url))
            except ScopeViolation:
                continue
        return out

    # ------------------------------------------------------------- DNS safety
    async def _resolve(self, host: str) -> tuple[str, ...]:
        try:
            ipaddress.ip_address(host)
            return (host,)
        except ValueError:
            pass
        if host in self._ip_cache:
            return self._ip_cache[host]
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            if host in self._ip_cache:
                return self._ip_cache[host]
            loop = asyncio.get_running_loop()
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
                    timeout=self.dns_timeout)
            except (asyncio.TimeoutError, socket.gaierror, OSError) as exc:
                raise UnsafeTarget(f"cannot resolve {host}: {type(exc).__name__}") from exc
            addresses = tuple(sorted({str(info[4][0]) for info in infos}))
            if not addresses:
                raise UnsafeTarget(f"{host} has no A/AAAA records")
            self._ip_cache[host] = addresses
            return addresses

    async def public_addresses(self, host: str) -> tuple[str, ...]:
        """Addresses safe to contact. Internal addresses need explicit scope."""
        addresses = await self._resolve(host)
        if self.allow_private:
            return addresses
        safe = tuple(a for a in addresses
                     if netguard.blocked_reason(a, self.scope) is None)
        if not safe:
            reasons = ", ".join(sorted({netguard.blocked_reason(a, self.scope) or "blocked"
                                        for a in addresses}))
            raise UnsafeTarget(f"{host} resolves only to blocked address(es): {reasons}")
        return safe

    async def ensure_safe_url(self, normalized: NormalizedURL) -> tuple[str, ...]:
        decision = self.scope.check(normalized.host)
        if not decision:
            raise ScopeViolation(f"out of scope: {normalized.host} ({decision.reason})")
        return await self.public_addresses(normalized.host)

    def assert_in_scope(self, normalized: NormalizedURL) -> None:
        decision = self.scope.check(normalized.host)
        if not decision:
            raise ScopeViolation(f"out of scope: {normalized.host} ({decision.reason})")
