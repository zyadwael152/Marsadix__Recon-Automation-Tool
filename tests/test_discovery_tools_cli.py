import asyncio
import json
import stat
from pathlib import Path

import pytest

from marsadix import db
from marsadix.core.scope import Scope
from marsadix.models import Scan, ScanMode
from marsadix.web_recon.archive import ArchiveBatch
from marsadix.web_recon.cli import main
from marsadix.web_recon.config import Member2Config
from marsadix.web_recon.discovery import SubdomainEnumerator
from marsadix.web_recon.errors import TOOL_OK, ToolOutcome
from marsadix.web_recon.scope_filter import ScopeEnforcer
from marsadix.web_recon.tools import (
    ArchiveRecord, ToolResolver, run_gau, run_httpx_verify, run_katana,
)


@pytest.fixture
def example_scan(tmp_path):
    path = tmp_path / "disc.db"
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n*.example.com\n", encoding="utf-8")
    conn = db.connect(str(path))
    db.init_db(conn)
    scan = Scan(target="example.com", mode=ScanMode.FULL, scope_file=str(scope))
    scan.id = db.save_scan(conn, scan)
    yield conn, scan.id, scope
    conn.close()


def test_discovery_merges_sources_and_stores_assets(example_scan, tmp_path, monkeypatch):
    conn, scan_id, scope = example_scan
    cfg = Member2Config(db_path=str(tmp_path / "disc.db"), tools_dir=str(tmp_path / "x"),
                        archive_sources=("wayback",))
    enforcer = ScopeEnforcer(Scope.from_file(str(scope)), "example.com")

    async def fake_subfinder(domain, config, resolver):
        return ["api.example.com", "evil.test"], ToolOutcome(
            "subfinder", TOOL_OK, discovered=2, kept=1)

    async def fake_crtsh(domain):
        return ["api.example.com", "www.example.com"], ToolOutcome(
            "crt.sh", TOOL_OK, discovered=2, kept=2)

    async def fake_archive(domain, resolver):
        return ArchiveBatch(
            records=[ArchiveRecord("https://api.example.com/v1", "wayback", 200),
                     ArchiveRecord("https://cdn.example.com/app.js", "gau:wayback")],
            outcomes=[ToolOutcome("wayback", TOOL_OK)])

    enumerator = SubdomainEnumerator(cfg, enforcer)
    monkeypatch.setattr("marsadix.web_recon.discovery.run_subfinder", fake_subfinder)
    monkeypatch.setattr(enumerator, "fetch_crtsh", fake_crtsh)
    monkeypatch.setattr(enumerator.archives, "collect", fake_archive)

    batch = asyncio.run(enumerator.discover("example.com", passive=True, active=False))
    assert batch.hosts_sources["api.example.com"] == ["subfinder", "crt.sh", "wayback"]
    assert batch.hosts_sources["www.example.com"] == ["crt.sh"]
    assert batch.hosts_sources["cdn.example.com"] == ["gau:wayback"]
    assert "evil.test" not in batch.hosts_sources

    async def fake_public(host):
        return ("93.184.216.34",)

    monkeypatch.setattr(enforcer, "public_addresses", fake_public)
    saved = asyncio.run(enumerator.store(
        conn, scan_id, "example.com", batch.hosts_sources, enforcer))
    assert saved == 3
    rows = {r["host"] for r in db.get_assets(conn, scan_id)}
    assert rows == {"api.example.com", "www.example.com", "cdn.example.com"}
    sources = db.get_asset_sources(conn, scan_id, "api.example.com")
    assert set(sources) == {"subfinder", "crt.sh", "wayback"}


def _fake_tool(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_external_tool_wrappers_parse_realistic_output(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    _fake_tool(tools, "httpx", """
if [ "$1" = "-version" ]; then echo "ProjectDiscovery httpx version 1.0"; exit 0; fi
echo '{"url":"https://e.test/","status_code":200,"content_type":"text/html","host_ip":"1.2.3.4"}'
""")
    _fake_tool(tools, "katana", """
cat >/dev/null
echo '{"request":{"endpoint":"https://e.test/a","source":"https://e.test/"},"response":{"status_code":200,"headers":{"content-type":"text/html"}}}'
echo 'https://e.test/b'
""")
    _fake_tool(tools, "gau", """
echo '{"url":"https://e.test/x","provider":"wayback","status":"200","mime":"text/html"}'
echo 'https://e.test/y'
""")
    cfg = Member2Config(tools_dir=str(tools), archive_sources=("gau",),
                        retries=0, tool_timeout=10, request_timeout=5)
    resolver = ToolResolver(cfg)
    assert resolver.path("httpx") == str(tools / "httpx")
    assert resolver.path("katana") == str(tools / "katana")
    assert resolver.path("gau") == str(tools / "gau")

    katana, katana_outcome = asyncio.run(run_katana(["https://e.test/"], cfg, resolver))
    assert {r.url for r in katana} == {"https://e.test/a", "https://e.test/b"}
    assert katana_outcome.status == TOOL_OK

    httpx, httpx_outcome = asyncio.run(run_httpx_verify(["https://e.test/"], cfg, resolver))
    assert httpx[0].status_code == 200 and httpx[0].ip == "1.2.3.4"
    assert httpx_outcome.status == TOOL_OK

    gau, gau_outcome = asyncio.run(run_gau(["e.test"], cfg, resolver))
    assert {r.url for r in gau} == {"https://e.test/x", "https://e.test/y"}
    assert next(r for r in gau if r.url.endswith("/x")).status_code == 200
    assert gau_outcome.status == TOOL_OK


def test_cli_doctor_and_normalize(capsys):
    assert main(["doctor", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["version"]
    assert isinstance(data["tools"], list)

    assert main(["normalize", "https://e.test/a?utm_source=x&b=2"]) == 0
    assert capsys.readouterr().out.strip() == "https://e.test/a?b=2"
