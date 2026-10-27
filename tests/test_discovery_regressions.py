import asyncio

from marsadix.recon import discovery
from marsadix.recon.cpe_map import generate_cpe
from marsadix.recon.resolver import parse_dnsx_json


def test_depth_zero_discovers_root_once_without_recursing(monkeypatch):
    calls = []

    async def fake_single(domain, api_keys):
        calls.append(domain)
        return {
            "api.example.com": ["subfinder"],
            "cdn-20231.example.com": ["crt.sh"],
            "web12345.example.com": ["amass"],
            "evilexample.com": ["crt.sh"],
        }

    monkeypatch.setattr(discovery, "_async_discover_single", fake_single)
    result = asyncio.run(discovery._async_discover_recursive("example.com", {}, 0))

    assert calls == ["example.com"]
    assert "cdn-20231.example.com" in result
    assert "web12345.example.com" in result
    assert "evilexample.com" in result  # retained as source data, but never recursively queried


def test_recursion_requires_a_domain_label_boundary(monkeypatch):
    calls = []

    async def fake_single(domain, api_keys):
        calls.append(domain)
        if domain == "example.com":
            return {"api.example.com": ["subfinder"], "evilexample.com": ["crt.sh"]}
        return {}

    monkeypatch.setattr(discovery, "_async_discover_single", fake_single)
    asyncio.run(discovery._async_discover_recursive("example.com", {}, 2))

    assert calls == ["example.com", "api.example.com"]
    assert "evilexample.com" not in calls


def test_unknown_technology_does_not_get_an_invented_cpe():
    assert generate_cpe("HSTS") is None
    assert generate_cpe("Apache HTTP Server") is None


def test_known_technology_without_version_uses_wildcard_not_not_applicable():
    assert generate_cpe("nginx") == "cpe:/a:f5:nginx:*"


def test_dnsx_parser_keeps_ipv4_and_ipv6_addresses():
    parsed = parse_dnsx_json(
        '{"host":"dual.example.com","a":["192.0.2.10"],"aaaa":["2001:db8::10"],"cname":[]}\n'
    )
    assert parsed["dual.example.com"]["ips"] == ["192.0.2.10", "2001:db8::10"]
