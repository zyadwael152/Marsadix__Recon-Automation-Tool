import pytest

from marsadix.core import netguard
from marsadix.core.scope import Scope


@pytest.mark.parametrize("ip,why", [
    ("127.0.0.1", "loopback"), ("::1", "loopback"), ("::ffff:127.0.0.1", "loopback"),
    ("169.254.169.254", "link-local"), ("fe80::1", "link-local"),
    ("10.1.2.3", "private"), ("172.16.0.1", "private"), ("192.168.0.1", "private"), ("fc00::1", "private"),
    ("0.0.0.0", "private"), ("100.64.0.1", "non-public"), ("224.0.0.1", "reserved"), ("240.0.0.1", "private"),
    ("not-an-ip", "not a valid"),
])
def test_internal_and_reserved_addresses_are_blocked(ip, why):
    assert why in netguard.blocked_reason(ip)


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "151.101.1.5", "104.21.5.9", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip):
    assert netguard.blocked_reason(ip) is None


def test_an_internal_address_is_allowed_only_when_the_scope_lists_it():
    sc = Scope.from_lines(["example.com", "10.0.0.0/8", "!10.9.9.9", "192.168.1.7"])
    assert netguard.blocked_reason("10.1.2.3", sc) is None
    assert netguard.blocked_reason("192.168.1.7", sc) is None
    assert netguard.blocked_reason("10.9.9.9", sc) is not None                # excluded wins
    assert netguard.blocked_reason("192.168.1.8", sc) is not None             # not listed
    assert netguard.blocked_reason("127.0.0.1", sc) is not None
    assert netguard.blocked_reason("10.1.2.3", Scope.from_lines(["example.com"])) is not None   # names alone never allow it


def test_asset_ip_uses_the_resolved_ip_or_the_host_when_it_is_an_ip():
    assert netguard.asset_ip({"host": "a.example.com", "ip": "93.184.216.34"}) == "93.184.216.34"
    assert netguard.asset_ip({"host": "93.184.216.9", "ip": None}) == "93.184.216.9"
    assert netguard.asset_ip({"host": "a.example.com", "ip": None}) is None
    assert netguard.asset_ip({"host": "a.example.com", "ip": "garbage"}) is None
    assert netguard.asset_ip({"host": "x.example.com", "ip": "::ffff:10.0.0.1"}) == "10.0.0.1"   # unwrapped
