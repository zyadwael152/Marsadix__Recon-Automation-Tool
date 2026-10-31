"""Problems seen in the first real-target scan: provider requests that were always rejected,
unreadable error messages, rate-limit bursts, crt.sh 502, a tool whose output was not parsed,
and an 'incomplete' warning repeated on every stage."""

import asyncio
import io
import sys
import time
import types
import urllib.error

import pytest

from marsadix import db
from marsadix.core import pipeline, toolstatus
from marsadix.core.config import Config
from marsadix.recon import api_sources, discovery


def _http_error(code, headers=None):
    return urllib.error.HTTPError("https://x", code, "msg", headers or {}, io.BytesIO(b""))


def _capture(monkeypatch, responses):
    """Replace the provider HTTP call; `responses` is a list of dicts or exceptions, one per call."""
    seen = []

    async def fake(url, headers=None):
        seen.append((url, headers or {}))
        r = responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r
    monkeypatch.setattr(api_sources, "_request_json_async", fake)
    return seen


# ------------------------------------------------------------------ providers
def test_shodan_sends_the_key_in_the_parameter_shodan_actually_reads(monkeypatch):
    seen = _capture(monkeypatch, [{"matches": [{"hostnames": ["a.example.com"]}], "total": 1}])
    _, subs = asyncio.run(api_sources.fetch_shodan("example.com", "KEY123"))
    assert subs == {"a.example.com"}
    assert "key=KEY123" in seen[0][0] and "SHODAN-API-KEY" not in seen[0][0]


def test_censys_uses_basic_auth_for_id_secret_and_bearer_for_a_token(monkeypatch):
    seen = _capture(monkeypatch, [{"result": {"hits": []}}, {"result": {"hits": []}}])
    asyncio.run(api_sources.fetch_censys("example.com", "my-id:my-secret"))
    asyncio.run(api_sources.fetch_censys("example.com", "just-a-token"))
    assert seen[0][1]["Authorization"].startswith("Basic ") and "my-id" not in seen[0][1]["Authorization"]
    assert seen[1][1]["Authorization"] == "Bearer just-a-token"


@pytest.mark.parametrize("code,status,degrades", [(401, "denied", False), (403, "denied", False),
                                                  (402, "denied", False), (429, "failed", True), (502, "failed", True)])
def test_http_errors_are_explained_and_only_transient_ones_make_a_scan_incomplete(monkeypatch, caplog, code, status, degrades):
    toolstatus.reset()
    _capture(monkeypatch, [_http_error(code)])
    with caplog.at_level("WARNING"):
        asyncio.run(api_sources.fetch_shodan("example.com", "SECRETKEY"))
    assert f"HTTP {code}" in caplog.text and "SECRETKEY" not in caplog.text
    assert [(r.tool, r.status) for r in toolstatus.runs()] == [("shodan", status)]
    assert bool(toolstatus.degraded()) is degrades


def test_alienvault_retries_once_after_a_429_then_succeeds(monkeypatch):
    toolstatus.reset()
    slept = []

    async def fake_sleep(s):
        slept.append(s)
    monkeypatch.setattr(api_sources.asyncio, "sleep", fake_sleep)
    seen = _capture(monkeypatch, [_http_error(429, {"Retry-After": "7"}),
                                  {"passive_dns": [{"hostname": "old.example.com"}]}])
    _, subs = asyncio.run(api_sources.fetch_alienvault("example.com"))
    assert subs == {"old.example.com"} and len(seen) == 2 and 7 in slept
    assert toolstatus.degraded() == []


def test_alienvault_gives_up_after_one_retry(monkeypatch):
    toolstatus.reset()

    async def fake_sleep(s):
        pass
    monkeypatch.setattr(api_sources.asyncio, "sleep", fake_sleep)
    seen = _capture(monkeypatch, [_http_error(429), _http_error(429)])
    _, subs = asyncio.run(api_sources.fetch_alienvault("example.com"))
    assert subs == set() and len(seen) == 2 and [r.status for r in toolstatus.degraded()] == ["failed"]


def test_requests_to_one_provider_are_spaced_out(monkeypatch):
    monkeypatch.setattr(api_sources, "PROVIDER_GAP", {"shodan": 0.15})
    stamps = []

    async def go():
        async def one():
            await api_sources._throttle("shodan")
            stamps.append(time.monotonic())
        await asyncio.gather(*[one() for _ in range(3)])
    asyncio.run(go())
    assert stamps[1] - stamps[0] >= 0.13 and stamps[2] - stamps[1] >= 0.13


# --------------------------------------------------------------------- crt.sh
class _Resp:
    status = 200

    def __init__(self, body):
        self._b = body

    def read(self, n=-1):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_crtsh_is_retried_after_a_502_and_recorded_ok(monkeypatch):
    toolstatus.reset()
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(1)
        if len(calls) < 3:
            raise _http_error(502)
        return _Resp(b'[{"name_value": "a.example.com\\n*.example.com"}]')
    monkeypatch.setattr(discovery.urllib.request, "urlopen", fake_urlopen)
    _, subs = asyncio.run(discovery.fetch_crtsh("example.com"))
    assert subs == {"a.example.com"} and len(calls) == 3
    assert [(r.tool, r.status) for r in toolstatus.runs()] == [("crt.sh", "ok")]


def test_crtsh_gives_up_after_the_last_attempt_and_a_404_is_not_retried(monkeypatch):
    toolstatus.reset()
    calls = []
    monkeypatch.setattr(discovery.urllib.request, "urlopen", lambda req, timeout=0: (calls.append(1), (_ for _ in ()).throw(_http_error(502)))[1])
    asyncio.run(discovery.fetch_crtsh("example.com"))
    assert len(calls) == 3 and [r.status for r in toolstatus.degraded()] == ["failed"]
    calls.clear()
    toolstatus.reset()
    monkeypatch.setattr(discovery.urllib.request, "urlopen", lambda req, timeout=0: (calls.append(1), (_ for _ in ()).throw(_http_error(404)))[1])
    asyncio.run(discovery.fetch_crtsh("example.com"))
    assert len(calls) == 1


# ------------------------------------------------------- amass-style output
def _fake_tool(tmp_path, monkeypatch, name, output, code=0):
    f = tmp_path / name
    f.write_text("#!/bin/sh\ncat <<'EOF'\n" + output + "\nEOF\nexit " + str(code) + "\n")
    f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")


def test_rich_amass_style_lines_are_parsed_when_the_domain_is_known(tmp_path, monkeypatch):
    toolstatus.reset()
    _fake_tool(tmp_path, monkeypatch, "amass",
               "www.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)\n"
               "api.example.com (FQDN) --> cname_record --> x.cdn.net (FQDN)\n"
               "example.com (FQDN) --> ns_record --> ns1.other.org (FQDN)")
    _, subs = asyncio.run(discovery.run_cli_tool("amass", ["amass"], domain="example.com"))
    assert subs == {"www.example.com", "api.example.com"}      # the bare apex and foreign names are not added
    assert toolstatus.degraded() == []


def test_plain_one_name_per_line_output_still_works_without_a_domain(tmp_path, monkeypatch):
    _fake_tool(tmp_path, monkeypatch, "subfinder", "a.example.com\nB.example.com.\n")
    assert asyncio.run(discovery.run_cli_tool("subfinder", ["subfinder"]))[1] == {"a.example.com", "b.example.com"}


def test_output_that_contains_no_hostname_is_reported_not_called_zero(tmp_path, monkeypatch, caplog):
    toolstatus.reset()
    _fake_tool(tmp_path, monkeypatch, "amass", "usage: amass <command> [options]\nsee the manual")
    with caplog.at_level("WARNING"):
        _, subs = asyncio.run(discovery.run_cli_tool("amass", ["amass"], domain="example.com"))
    assert subs == set() and "none contained a hostname" in caplog.text
    assert [(r.tool, r.status, r.detail) for r in toolstatus.degraded()] == [("amass", "failed", "output format not recognised")]


def test_an_empty_output_is_a_legitimate_zero(tmp_path, monkeypatch):
    toolstatus.reset()
    _fake_tool(tmp_path, monkeypatch, "amass", "")
    asyncio.run(discovery.run_cli_tool("amass", ["amass"], domain="example.com"))
    assert toolstatus.degraded() == []


# ----------------------------------------------------- incomplete reporting
def test_summary_groups_repeats():
    runs = [toolstatus.ToolRun("alienvault", "failed", "HTTP 429")] * 4 + [toolstatus.ToolRun("crt.sh", "failed", "HTTP 502")]
    assert toolstatus.summary(runs) == "alienvault failed x4 (HTTP 429); crt.sh failed (HTTP 502)"


def test_only_the_stage_that_lost_data_is_marked_incomplete(tmp_path, monkeypatch):
    mod = types.ModuleType("fake_stage_mod2")
    mod.recon = lambda ctx: toolstatus.record("amass", "timeout", "after 300s")
    mod.web = lambda ctx: None
    mod.ports = lambda ctx: None
    mod.track = lambda ctx: None
    monkeypatch.setitem(sys.modules, "fake_stage_mod2", mod)
    monkeypatch.setattr(pipeline, "STAGES", [(n, f"fake_stage_mod2:{n}") for n in ("recon", "web", "ports", "track")])
    _, results = pipeline.run_scan("example.com", Config(db_path=str(tmp_path / "t.db")))
    by = {r.name: r for r in results}
    assert "amass timeout" in by["recon"].detail
    assert by["web"].detail == by["ports"].detail == by["track"].detail == ""


# --------------------------------------------------- tool lookup / report sections
def test_a_missing_program_says_it_was_not_found_on_path(tmp_path, monkeypatch):
    from marsadix.core.aproc import run_exec
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(FileNotFoundError, match="puredns: not found on PATH"):
        asyncio.run(run_exec(["puredns", "-h"]))


def test_a_program_in_a_path_folder_is_found_and_run(tmp_path, monkeypatch):
    from marsadix.core.aproc import run_exec
    tool = tmp_path / "puredns"
    tool.write_text("#!/bin/sh\necho ok\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":/usr/bin:/bin")
    assert asyncio.run(run_exec(["puredns"])).stdout.strip() == b"ok"


def _report_data(**kw):
    base = {"scan": {"id": 1, "mode": "standard"}, "target": "example.com", "assets": [], "services": [],
            "technologies": [], "web_items": [], "findings": []}
    base.update(kw)
    return base


def test_report_lists_open_ports_with_service_product_and_version():
    from marsadix.reports.generate import _services_section
    html = _services_section(_report_data(services=[
        {"host": "b.example.com", "ip": "1.2.3.4", "port": 443, "protocol": "tcp", "name": "https", "product": "nginx", "version": "1.24.0", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0", "banner": "<script>x</script>"},
        {"host": "a.example.com", "ip": "1.2.3.5", "port": 22, "protocol": "tcp", "name": "ssh", "product": "OpenSSH", "version": "9.6", "cpe": None, "banner": None}]))
    assert html.index("a.example.com") < html.index("b.example.com")            # sorted by host
    for cell in ("22/tcp", "OpenSSH", "9.6", "443/tcp", "nginx", "1.24.0"):
        assert f">{cell}<" in html.replace(" ", "").replace("\n", "") or cell in html
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html          # banner is escaped
    assert "2 open port(s) on 2 host(s)" in html


def test_empty_ports_section_explains_why():
    from marsadix.reports.generate import _services_section
    html = _services_section(_report_data(
        scan={"id": 1, "mode": "passive"},
        assets=[{"host": "a.example.com", "is_cdn": 1, "in_scope": 1}, {"host": "b.other.org", "is_cdn": 0, "in_scope": 0}]))
    assert "passive mode" in html and "1 of 2 host(s) are behind a CDN" in html and "1 host(s) are out of scope" in html


def test_report_lists_technologies_with_versions():
    from marsadix.reports.generate import _technologies_section
    html = _technologies_section(_report_data(technologies=[
        {"host": "a.example.com", "name": "nginx", "version": "1.24.0", "category": "web-server", "confidence": "likely", "source": "httpx", "cpe": "cpe:x"},
        {"host": "a.example.com", "name": "React", "version": "", "category": "js", "confidence": "possible", "source": "httpx", "cpe": None}]))
    assert "nginx" in html and "1.24.0" in html and "React" in html and "2 technology record(s)" in html
    assert "No technologies" in _technologies_section(_report_data())


def test_ports_and_technologies_reach_the_html_and_pdf_report(tmp_path):
    from marsadix.models import Asset, Scan, ScanStatus, Service, Technology
    from marsadix.reports.generate import generate_report
    conn = db.connect(":memory:")
    db.init_db(conn)
    scan = Scan(target="example.com", status=ScanStatus.COMPLETED)
    scan.id = db.save_scan(conn, scan)
    db.finish_scan(conn, scan.id, "completed")
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="a.example.com", ip="1.2.3.5", in_scope=True)])
    db.save_many(conn, "services", [Service(scan_id=scan.id, host="a.example.com", ip="1.2.3.5", port=22,
                                            name="ssh", product="OpenSSH", version="9.6")])
    db.save_many(conn, "technologies", [Technology(scan_id=scan.id, host="a.example.com", name="nginx", version="1.24.0")])
    assert generate_report(conn, "example.com", fmt="all", out_dir=str(tmp_path)) == 0
    page = next(tmp_path.glob("*.html")).read_text()
    assert "Open ports &amp; services" in page and "OpenSSH" in page and "22/tcp" in page
    assert "Technologies" in page and "1.24.0" in page
    pdf = next(tmp_path.glob("*.pdf")).read_bytes()
    assert b"OpenSSH" in pdf and b"nginx 1.24.0" in pdf


# ---------------------------------------------------------------- doctor
def test_doctor_shows_what_a_broken_httpx_launcher_answered(monkeypatch, capsys):
    from marsadix import cli
    monkeypatch.setattr(cli, "tool_status", lambda: [("httpx", "C:/venv/Scripts/httpx.exe", "probing")])
    monkeypatch.setattr(cli, "httpx_check", lambda: (False, "did not find executable at '/usr/bin\\python.exe'"))
    assert cli.cmd_doctor(None, Config()) == 0
    out = capsys.readouterr().out
    assert "Python:" in out and "does not look like ProjectDiscovery" in out and "/usr/bin" in out


def test_doctor_explains_that_wsl_tools_are_invisible_to_windows(monkeypatch, capsys):
    from marsadix import cli
    monkeypatch.setattr(cli.os, "name", "nt")
    monkeypatch.setattr(cli, "tool_status", lambda: [("puredns", None, "bruteforce"), ("massdns", None, "dns engine")])
    monkeypatch.setattr(cli, "httpx_check", lambda: (None, ""))
    cli.cmd_doctor(None, Config())
    out = capsys.readouterr().out
    assert "[MISSING] puredns" in out and "WSL" in out and "no native Windows build" in out
    monkeypatch.setattr(cli.os, "name", "posix")
    cli.cmd_doctor(None, Config())
    assert "WSL" not in capsys.readouterr().out
