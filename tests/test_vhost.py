"""ffuf VHost output parsing (R16).

The important bit: ffuf reports the request target (the IP) in "host" and the
discovered virtual-host name in input.FUZZ. Reading "host" produced IPs, which
the recon stage's scope check threw away, so VHost discovery never stored
anything.
"""

import asyncio
import json

from marsadix.recon import vhost


def _ffuf(results):
    return json.dumps({"results": results})


def test_fuzz_payload_becomes_a_hostname_under_the_target(monkeypatch):
    out = _ffuf([
        {"host": "http://1.2.3.4", "input": {"FUZZ": "admin"}, "status": 200},
        {"host": "http://1.2.3.4", "input": {"FUZZ": "staging"}, "status": 403},
    ])
    monkeypatch.setattr(vhost, "run_async", _returning(out))

    found = asyncio.run(vhost.discover_vhosts("1.2.3.4", "example.com", "words.txt"))

    assert found == {"admin.example.com", "staging.example.com"}


def test_entries_without_a_fuzz_payload_are_ignored(monkeypatch):
    out = _ffuf([
        {"host": "http://1.2.3.4", "status": 200},
        {"host": "http://1.2.3.4", "input": "not-a-dict"},
        {"host": "http://1.2.3.4", "input": {"FUZZ": "  "}},
        {"host": "http://1.2.3.4", "input": {"FUZZ": "api"}},
    ])
    monkeypatch.setattr(vhost, "run_async", _returning(out))

    assert asyncio.run(vhost.discover_vhosts("1.2.3.4", "example.com", "words.txt")) == {
        "api.example.com"}


def test_invalid_json_is_logged_not_raised(monkeypatch):
    monkeypatch.setattr(vhost, "run_async", _returning("not json"))
    assert asyncio.run(vhost.discover_vhosts("1.2.3.4", "example.com", "words.txt")) == set()


def test_missing_inputs_skip_the_tool(monkeypatch):
    async def boom(*a, **k):
        raise AssertionError("must not run without an ip, domain and wordlist")

    monkeypatch.setattr(vhost, "run_async", boom)
    assert asyncio.run(vhost.discover_vhosts("", "example.com", "words.txt")) == set()
    assert asyncio.run(vhost.discover_vhosts("1.2.3.4", "", "words.txt")) == set()
    assert asyncio.run(vhost.discover_vhosts("1.2.3.4", "example.com", "")) == set()


def _returning(value):
    async def fake(*a, **k):
        return value
    return fake
