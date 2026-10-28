"""
The command lines httpx / katana are started with. The rate limit is the only
thing standing between `--rate 10` and the tools' own default of 150 req/s.
(No real tools needed: the subprocess call is replaced by a recorder.)
"""

import asyncio

import pytest

from marsadix.web import probe


class _FakeProc:
    def __init__(self, out: bytes):
        self._out = out

    async def communicate(self, input=None):
        return self._out, b""


@pytest.fixture
def spawned(monkeypatch):
    rec = {"argv": None, "stdin": None, "out": b""}

    async def fake_exec(*argv, **kwargs):
        rec["argv"] = list(argv)
        proc = _FakeProc(rec["out"])
        orig = proc.communicate

        async def communicate(input=None):
            rec["stdin"] = input
            return await orig(input)
        proc.communicate = communicate
        return proc

    monkeypatch.setattr(probe.asyncio, "create_subprocess_exec", fake_exec)
    return rec


def test_httpx_gets_the_rate_limit_flag(spawned):
    asyncio.run(probe.run_httpx(["a.example.com"], rate_limit=10))
    assert spawned["argv"][0] == "httpx"
    i = spawned["argv"].index("-rl")
    assert spawned["argv"][i + 1] == "10"


def test_katana_gets_the_rate_limit_flag(spawned):
    asyncio.run(probe.run_katana(["https://a.example.com"], rate_limit=4))
    assert spawned["argv"][0] == "katana"
    i = spawned["argv"].index("-rl")
    assert spawned["argv"][i + 1] == "4"


def test_no_rate_limit_means_no_flag(spawned):
    asyncio.run(probe.run_httpx(["a.example.com"]))
    assert "-rl" not in spawned["argv"]


def test_httpx_output_is_parsed_into_records(spawned):
    spawned["out"] = (
        b'{"url":"https://a.example.com","input":"A.example.com","status_code":200,"host_ip":"1.2.3.4",'
        b'"webserver":"nginx/1.18.0","tech":["Nginx:1.18.0","PHP"],"cdn":true,"cdn_name":"cloudflare"}\n'
        b'{"url":"http://b.example.com","status_code":"oops","a":["5.6.7.8"]}\n'   # odd status -> None; IP from "a"
        b'{"url":"https://c.example.com","failed":true}\n'                          # failed probe: dropped
        b'not json at all\n'
        b'{"no_url_here":1}\n')
    out = asyncio.run(probe.run_httpx(["a", "b", "c"], rate_limit=5))

    assert out[0] == {"url": "https://a.example.com", "input": "a.example.com", "status_code": 200,
                      "ip": "1.2.3.4", "webserver": "nginx/1.18.0", "tech": ["Nginx:1.18.0", "PHP"],
                      "cdn": True, "cdn_name": "cloudflare"}
    assert out[1] == {"url": "http://b.example.com", "input": None, "status_code": None, "ip": "5.6.7.8",
                      "webserver": None, "tech": [], "cdn": False, "cdn_name": None}
    assert len(out) == 2


def test_httpx_asks_for_technology_detection_and_the_server_header(spawned):
    asyncio.run(probe.run_httpx(["a.example.com"], rate_limit=5))
    assert "-td" in spawned["argv"] and "-server" in spawned["argv"]


def test_katana_output_is_deduplicated_and_sorted(spawned):
    spawned["out"] = b"https://a.example.com/b\nhttps://a.example.com/a\n\nhttps://a.example.com/b\n"
    out = asyncio.run(probe.run_katana(["https://a.example.com"]))
    assert out == ["https://a.example.com/a", "https://a.example.com/b"]


def test_a_missing_tool_is_logged_not_raised(monkeypatch):
    async def boom(*a, **k):
        raise FileNotFoundError("httpx")
    monkeypatch.setattr(probe.asyncio, "create_subprocess_exec", boom)
    assert asyncio.run(probe.run_httpx(["a.example.com"])) == []
    assert asyncio.run(probe.run_katana(["https://a.example.com"])) == []


class _HangingProc:
    """Never finishes on its own; records whether it was killed and reaped."""

    def __init__(self):
        self.killed = False
        self.waited = False

    async def communicate(self, input=None):
        await asyncio.sleep(3600)

    def kill(self):
        self.killed = True

    async def wait(self):
        self.waited = True
        return -9


@pytest.mark.parametrize("runner,args", [
    (probe.run_httpx, ["a.example.com"]),
    (probe.run_katana, ["https://a.example.com"]),
])
def test_a_hung_tool_times_out_and_is_killed(monkeypatch, runner, args):
    proc = _HangingProc()

    async def fake_exec(*a, **k):
        return proc

    monkeypatch.setattr(probe.asyncio, "create_subprocess_exec", fake_exec)
    assert asyncio.run(runner(args, timeout=0.01)) == []
    assert proc.killed and proc.waited
