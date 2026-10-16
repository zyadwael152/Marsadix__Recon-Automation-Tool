"""
Scope manager: decides whether a host / IP / URL is allowed to be tested.

scope.txt format (one rule per line, '#' starts a comment):

    example.com              exactly this host
    *.example.com            any subdomain, any depth (NOT example.com itself)
    203.0.113.0/24           an IP range (also a single IP: 203.0.113.7)
    !mail.example.com        EXCLUDE exactly this host
    !*.internal.example.com  EXCLUDE all subdomains under it

Exclusions always win over inclusions. Anything that matches no rule is OUT.
Every new asset found by recon must pass `scope.is_in_scope()` before it
reaches an active tool.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlsplit


class ScopeError(ValueError):
    pass


_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$")


@dataclass
class Decision:
    in_scope: bool
    reason: str

    def __bool__(self) -> bool:
        return self.in_scope


def normalize_host(value: str) -> Optional[str]:
    """URL / host:port / IP / 'Example.COM.' -> lowercase bare host (or None)."""
    v = (value or "").strip()
    if not v:
        return None
    try:                                   # bare IP (incl. IPv6 without brackets)
        return str(ipaddress.ip_address(v.strip("[]")))
    except ValueError:
        pass
    if "://" not in v:
        v = "//" + v
    try:
        host = urlsplit(v).hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.rstrip(".").lower() or None


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


@dataclass
class Scope:
    domains: set = field(default_factory=set)
    wildcards: set = field(default_factory=set)      # stored without '*.'
    nets: list = field(default_factory=list)
    ex_domains: set = field(default_factory=set)
    ex_wildcards: set = field(default_factory=set)
    ex_nets: list = field(default_factory=list)

    # ---------------------------------------------------------------- build
    @classmethod
    def from_lines(cls, lines: Iterable[str], source: str = "scope") -> "Scope":
        s = cls()
        for no, raw in enumerate(lines, start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            exclude = line.startswith("!")
            rule = line[1:].strip() if exclude else line
            where = f"{source}:{no}"
            if not rule:
                raise ScopeError(f"{where}: empty rule after '!'")

            # IP or CIDR?
            try:
                net = ipaddress.ip_network(rule, strict=False)
                (s.ex_nets if exclude else s.nets).append(net)
                continue
            except ValueError:
                pass

            wildcard = rule.startswith("*.")
            name = (rule[2:] if wildcard else rule).lower().rstrip(".")
            if not _DOMAIN_RE.match(name):
                raise ScopeError(f"{where}: invalid rule '{rule}'")
            if wildcard:
                (s.ex_wildcards if exclude else s.wildcards).add(name)
            else:
                (s.ex_domains if exclude else s.domains).add(name)

        if not (s.domains or s.wildcards or s.nets):
            raise ScopeError(f"{source}: no include rules (only exclusions or empty)")
        return s

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        p = Path(path)
        if not p.is_file():
            raise ScopeError(f"scope file not found: {path}")
        return cls.from_lines(p.read_text(encoding="utf-8").splitlines(), source=p.name)

    @classmethod
    def from_target(cls, target: str) -> "Scope":
        """No scope file: the target itself + all its subdomains."""
        t = normalize_host(target)
        if not t:
            raise ScopeError(f"invalid target: {target!r}")
        return cls.from_lines([t, f"*.{t}"], source="target")

    # ---------------------------------------------------------------- check
    def check(self, value: str) -> Decision:
        host = normalize_host(value)
        if host is None:
            return Decision(False, "empty or invalid value")

        ip = _as_ip(host)
        if ip is not None:
            for n in self.ex_nets:
                if ip.version == n.version and ip in n:
                    return Decision(False, f"excluded by !{n}")
            for n in self.nets:
                if ip.version == n.version and ip in n:
                    return Decision(True, f"matches {n}")
            return Decision(False, "IP not in any included range")

        if host in self.ex_domains:
            return Decision(False, f"excluded by !{host}")
        for w in self.ex_wildcards:
            if host.endswith("." + w):
                return Decision(False, f"excluded by !*.{w}")
        if host in self.domains:
            return Decision(True, f"matches {host}")
        for w in self.wildcards:
            if host.endswith("." + w):
                return Decision(True, f"matches *.{w}")
        return Decision(False, "no matching rule")

    def is_in_scope(self, value: str) -> bool:
        return self.check(value).in_scope

    def filter(self, values: Iterable[str]) -> list:
        return [v for v in values if self.is_in_scope(v)]
