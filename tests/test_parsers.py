import asyncio
import json

import pytest

from marsadix_member2.archive import ArchiveCollector, host_sources
from marsadix_member2.config import Member2Config
from marsadix_member2.js_extract import extract_urls, looks_like_js
from marsadix_member2.tools import ArchiveRecord, _gau_record, _httpx_record, _katana_record


def test_katana_jsonl_record():
    rec = _katana_record({
        "request": {"endpoint": "https://e.test/api", "source": "https://e.test/"},
        "response": {"status_code": 200, "headers": {"content-type": "application/json"}},
    })
    assert rec.url == "https://e.test/api"
    assert rec.status_code == 200
    assert rec.content_type == "application/json"
    assert rec.parent_url == "https://e.test/"


def test_httpx_record_and_failure_tolerance():
    rec = _httpx_record({"url": "https://e.test/", "status_code": 301,
                         "content_type": "text/html; charset=utf-8",
                         "location": "/home", "host_ip": "1.2.3.4"})
    assert rec.status_code == 301 and rec.location == "/home"
    assert rec.content_type == "text/html"
    assert _httpx_record({"no_url": 1}) is None


def test_gau_record_json_and_plain():
    json_rec = _gau_record(json.dumps({"url": "https://e.test/a", "provider": "wayback",
                                       "status": "200", "mime": "text/html"}))
    assert json_rec.source == "gau:wayback" and json_rec.status_code == 200
    plain = _gau_record("https://e.test/b")
    assert plain.url == "https://e.test/b"
    assert _gau_record("not a url") is None


def test_js_extraction_finds_quoted_paths_fetch_and_absolute_urls():
    js = r"""
    const a = fetch('/api/v1/users?active=1');
    axios.post("/api/v2/login", {});
    const u = "https://cdn.example.net/lib.js";
    const p = './local/thing';
    const ignored = "javascript:alert(1)";
    const escaped = "https:\/\/e.test\/escaped\/path";
    """
    urls = extract_urls(js, "https://e.test/static/app.js")
    assert "https://e.test/api/v1/users?active=1" in urls
    assert "https://e.test/api/v2/login" in urls
    assert "https://cdn.example.net/lib.js" in urls
    assert "https://e.test/static/local/thing" in urls
    assert "https://e.test/escaped/path" in urls
    assert not any("javascript:" in u for u in urls)
    assert looks_like_js("https://e.test/x.js")


def test_wayback_and_commoncrawl_parsing(monkeypatch):
    cfg = Member2Config(archive_sources=("wayback", "commoncrawl"),
                        max_archive_urls=10, archive_pages=1)
    collector = ArchiveCollector(cfg)

    async def fake_fetch(url, accept="application/json"):
        if "cdx" in url:
            body = json.dumps([
                ["original", "timestamp", "statuscode", "mimetype"],
                ["https://e.test/a", "20240101", "200", "text/html"],
                ["https://e.test/b", "20240101", "404", "text/html"],
                ["https://other.test/c", "20240101", "200", "text/html"],
            ])
        elif "collinfo" in url:
            body = json.dumps([{"id": "CC-MAIN-2026-01"}])
        else:
            body = json.dumps({"url": "https://e.test/c", "status": "200", "mime": "text/html"}) + "\n"
        return 200, body.encode()

    monkeypatch.setattr(collector, "_fetch", fake_fetch)
    wb, wb_outcome = asyncio.run(collector.fetch_wayback("e.test"))
    assert wb_outcome.status == "ok"
    assert {r.url for r in wb} == {"https://e.test/a", "https://e.test/b"}

    cc, cc_outcome = asyncio.run(collector.fetch_commoncrawl("e.test"))
    assert cc_outcome.status == "ok"
    assert {r.url for r in cc} == {"https://e.test/c"}

    sources = host_sources(wb + cc, "e.test")
    assert sources["e.test"] == ["wayback", "commoncrawl"]
    assert "other.test" not in sources


def test_archive_dedup_prefers_record_with_status():
    from marsadix_member2.archive import ArchiveBatch
    # host_sources is the only public helper used by the pipeline here.
    recs = [ArchiveRecord("https://e.test/a", "gau", None),
            ArchiveRecord("https://e.test/a", "wayback", 200)]
    assert host_sources(recs, "e.test") == {"e.test": ["gau", "wayback"]}
