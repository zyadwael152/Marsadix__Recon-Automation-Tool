import asyncio

import pytest

from marsadix.core.scope import Scope
from marsadix.web_recon.config import Member2Config
from marsadix.web_recon.crawler import BuiltinCrawler, LinkExtractor
from marsadix.web_recon.errors import ScopeViolation, UnsafeTarget
from marsadix.web_recon.http_client import SafeHTTPClient
from marsadix.web_recon.rate_limit import AsyncRateLimiter
from marsadix.web_recon.scope_filter import ScopeEnforcer


def test_scope_enforcer_rejects_out_of_scope_and_private_targets():
    scope = Scope.from_lines(["example.com", "*.example.com"])
    enforcer = ScopeEnforcer(scope, "example.com")
    with pytest.raises(ScopeViolation):
        enforcer.check("https://evil.test/a")
    with pytest.raises(UnsafeTarget):
        asyncio.run(enforcer.public_addresses("localhost"))


def test_explicit_scope_can_authorise_a_loopback_lab():
    scope = Scope.from_lines(["localhost", "127.0.0.1"])
    enforcer = ScopeEnforcer(scope, "localhost")
    assert asyncio.run(enforcer.public_addresses("localhost")) == ("127.0.0.1",)


def test_link_extractor_collects_links_scripts_forms_and_skips_js_scheme():
    parser = LinkExtractor()
    parser.feed("""<a href="/a">a</a><script src="/x.js"></script>
                   <form action="/f"></form><a href="javascript:void(0)">bad</a>
                   <a href="/a">dupe</a>""")
    assert parser.links == ["/a", "/x.js", "/f"]


def test_safe_http_client_status_and_size_cap(local_server):
    cfg = Member2Config(rate_limit=50, tools_dir="/nonexistent", httpx_bin="/nonexistent",
                        request_timeout=5)
    enforcer = ScopeEnforcer(Scope.from_lines(["127.0.0.1"]), "localhost")
    client = SafeHTTPClient(enforcer, cfg, AsyncRateLimiter(50))

    normalized, result = asyncio.run(client.status(local_server))
    assert result.status == 200 and "html" in result.content_type
    _, missing = asyncio.run(client.status(local_server + "missing"))
    assert missing.status == 404
    _, js = asyncio.run(client.fetch(local_server + "static/app.js", max_bytes=128))
    assert js.status == 200 and b"/api/v2/items" in js.body


def test_builtin_crawler_extracts_pages_js_and_statuses(local_server):
    cfg = Member2Config(rate_limit=50, tools_dir="/nonexistent", request_timeout=5,
                        max_pages=10, crawl_depth=2)
    enforcer = ScopeEnforcer(Scope.from_lines(["127.0.0.1"]), "localhost")
    client = SafeHTTPClient(enforcer, cfg, AsyncRateLimiter(50))
    crawler = BuiltinCrawler(enforcer, cfg, client)
    batch = asyncio.run(crawler.crawl([local_server]))
    urls = {r.url for r in batch.records}
    assert local_server in urls
    assert local_server + "about" in urls
    assert local_server + "static/app.js" in urls
    assert any(r.status_code == 404 for r in batch.records)
    assert batch.outcome.discovered >= 3
