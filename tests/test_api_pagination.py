import asyncio
from urllib.parse import parse_qs, urlsplit

from marsadix.recon import api_sources


def test_virustotal_follows_same_host_next_link_and_filters_domain_boundary(monkeypatch):
    calls = []

    def fake_request(url, headers=None):
        calls.append((url, headers))
        if len(calls) == 1:
            return {
                "data": [{"id": "a.example.com"}, {"id": "evil-example.com"}],
                "links": {"next": "https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=next"},
            }
        return {"data": [{"id": "b.example.com"}], "links": {}}

    monkeypatch.setattr(api_sources, "_request_json", fake_request)
    source, names = asyncio.run(api_sources.fetch_virustotal("example.com", "secret"))

    assert source == "virustotal"
    assert names == {"a.example.com", "b.example.com"}
    assert len(calls) == 2
    assert all(headers["x-apikey"] == "secret" for _, headers in calls)


def test_virustotal_does_not_send_api_key_to_untrusted_next_host(monkeypatch):
    calls = []

    def fake_request(url, headers=None):
        calls.append(url)
        return {"data": [{"id": "a.example.com"}], "links": {"next": "https://attacker.invalid/steal"}}

    monkeypatch.setattr(api_sources, "_request_json", fake_request)
    _, names = asyncio.run(api_sources.fetch_virustotal("example.com", "secret"))

    assert names == {"a.example.com"}
    assert len(calls) == 1


def test_shodan_uses_bounded_pagination_and_does_not_accept_suffix_spoof(monkeypatch):
    calls = []

    def fake_request(url, headers=None):
        calls.append(url)
        page = int(parse_qs(urlsplit(url).query)["page"][0])
        if page == 1:
            return {"total": 101, "matches": [{"hostnames": ["one.example.com", "notexample.com"]}]}
        return {"total": 101, "matches": [{"hostnames": ["two.example.com"]}]}

    monkeypatch.setattr(api_sources, "_request_json", fake_request)
    _, names = asyncio.run(api_sources.fetch_shodan("example.com", "secret"))

    assert names == {"one.example.com", "two.example.com"}
    assert len(calls) == 2
    assert all("secret" in url for url in calls)  # Shodan's API requires a query-string key.


def test_cli_tool_preserves_partial_stdout_on_timeout(monkeypatch):
    from marsadix.recon import discovery

    class FakeStream:
        def __init__(self, data: bytes, delay: float = 0.0):
            self.data, self.delay = data, delay

        async def read(self, n=-1):
            if self.data:
                await asyncio.sleep(self.delay)
                chunk, self.data = self.data, b""
                return chunk
            await asyncio.sleep(0.2)              # a tool that is still running: no EOF yet
            return b""

    class FakeProcess:
        def __init__(self):
            self.killed = False
            self.returncode = None
            self.stdout = FakeStream(b"partial.example.com\n")
            self.stderr = FakeStream(b"timeout after partial result")
            self.stdin = None

        def kill(self):
            self.killed = True
            self.returncode = -9

        async def wait(self):
            while not self.killed:
                await asyncio.sleep(0.01)
            return -9

    fake = FakeProcess()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return fake

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr("marsadix.core.aproc.shutil.which", lambda name: name)   # the fake tool is not on PATH
    name, results = asyncio.run(discovery.run_cli_tool("fake-tool", ["fake-tool"], timeout=0.001))

    assert name == "fake-tool"
    assert results == {"partial.example.com"}
    assert fake.killed is True
