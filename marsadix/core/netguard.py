"""
Which IP addresses an active tool may be pointed at.

A hostname that is IN SCOPE says nothing about where it points: whoever controls
that name's DNS can make it resolve to 127.0.0.1, a 10.x address or the cloud
metadata service (169.254.169.254), and the scanner would then port-scan the
tester's own machine or network. So before a port scan or a probe, the address
must be public, unless the scope file lists that address or range explicitly
(a deliberate internal test: `10.0.0.0/8` in scope.txt).
"""

import ipaddress
from typing import Optional


def _addr(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped is not None:      # ::ffff:127.0.0.1 is 127.0.0.1
        a = a.ipv4_mapped
    return a


def is_ip(value) -> bool:
    return _addr(value) is not None


def asset_ip(row) -> Optional[str]:
    """The IP of an asset row: its resolved ip, or the host itself when that is an IP literal."""
    if row["ip"] and _addr(row["ip"]):
        return str(_addr(row["ip"]))
    return str(_addr(row["host"])) if _addr(row["host"]) else None


def blocked_reason(ip, scope=None) -> Optional[str]:
    """Why no tool may be pointed at `ip`, or None when it is fine."""
    a = _addr(ip)
    if a is None:
        return "not a valid IP address"
    if scope is not None and scope.check(str(a)).in_scope:
        return None                                        # listed explicitly in the scope file
    if a.is_loopback:
        return "loopback address"
    if a.is_link_local:
        return "link-local address (cloud metadata lives here)"
    if a.is_private:
        return "private/internal address"
    if a.is_multicast or a.is_unspecified or a.is_reserved:
        return "reserved address"
    if not a.is_global:
        return "non-public address"                       # e.g. carrier-grade NAT 100.64.0.0/10
    return None
