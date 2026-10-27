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


def test_censys_follows_cursor_and_filters_out_of_domain_names(monkeypatch):
    calls = []

    def fake_request(url, headers=None):
        calls.append(url)
        params = parse_qs(urlsplit(url).query)
        if "cursor" not in params:
            return {"result": {"hits": [{"names": ["a.example.com", "badexample.com"]}]},
                    "links": {"next": "?cursor=page-two"}}
        return {"result": {"hits": [{"names": ["b.example.com"]}]}, "links": {}}

    monkeypatch.setattr(api_sources, "_request_json", fake_request)
    _, names = asyncio.run(api_sources.fetch_censys("example.com", "secret"))

    assert names == {"a.example.com", "b.example.com"}
    assert len(calls) == 2
    assert parse_qs(urlsplit(calls[1]).query)["cursor"] == ["page-two"]


def test_cli_tool_preserves_partial_stdout_on_timeout(monkeypatch):
    from marsadix.recon import discovery

    class FakeProcess:
        def __init__(self):
            self.killed = False

        async def communicate(self):
            await asyncio.sleep(0.03)
            return b"partial.example.com\n", b"timeout after partial result"

        def kill(self):
            self.killed = True

        async def wait(self):
            return -9

    fake = FakeProcess()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return fake

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    name, results = asyncio.run(discovery.run_cli_tool("fake-tool", ["fake-tool"], timeout=0.001))

    assert name == "fake-tool"
    assert results == {"partial.example.com"}
    assert fake.killed is True
