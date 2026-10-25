"""
Ports stage: naabu (open ports) + nmap -sV (what runs on them).

Parser tests use REAL output captured from naabu 2.6.1 and nmap 7.94 (tests/fixtures);
stage tests replace the two tools with fakes that record what they were asked to scan.
"""

import pathlib

import pytest

from marsadix import db
from marsadix.core.config import Config
from marsadix.core.graph import build_graph
from marsadix.core.pipeline import Context, run_scan
from marsadix.core.runner import ToolNotFound, ToolResult
from marsadix.core.scope import Scope
from marsadix.models import Asset, Scan, ScanMode, ScanStatus
from marsadix.ports import probe, stage as ports_stage

FIX = pathlib.Path(__file__).parent / "fixtures"


# ----------------------------------------------------------------------- parsers

def test_parse_naabu_hostname_input_dedupes_repeated_ports():
    out = probe.parse_naabu((FIX / "naabu_hostname_sample.jsonl").read_text())
    assert out == {"localhost": {"ip": "127.0.0.1", "ports": [80, 8080]}}      # the file lists each port twice


def test_parse_naabu_ip_input_is_keyed_by_ip():
    out = probe.parse_naabu((FIX / "naabu_ip_sample.jsonl").read_text())
    assert out == {"127.0.0.1": {"ip": "127.0.0.1", "ports": [80, 8080]}}


def test_parse_naabu_ignores_garbage_lines():
    text = 'banner line\n{"host":"a.example.com","ip":"1.1.1.1","port":443}\n{"port":"x"}\n{"ip":"2.2.2.2"}\n{broken'
    assert probe.parse_naabu(text) == {"a.example.com": {"ip": "1.1.1.1", "ports": [443]}}


def test_parse_nmap_xml_returns_open_ports_only():
    recs = probe.parse_nmap_xml((FIX / "nmap_sv_sample.xml").read_text())
    assert [r["port"] for r in recs] == [80, 8080]                              # port 9 is closed in the file
    r = recs[0]
    assert (r["ip"], r["protocol"], r["name"], r["product"], r["version"]) == \
        ("127.0.0.1", "tcp", "http", "SimpleHTTPServer", "0.6")
    assert r["extrainfo"] == "Python 3.12.3"
    assert r["cpe"] == ["cpe:/a:python:simplehttpserver:0.6"]


@pytest.mark.parametrize("bad", ["", "not xml", "<nmaprun><host>", None])
def test_parse_nmap_xml_survives_empty_or_truncated_output(bad):
    assert probe.parse_nmap_xml(bad) == []


# ----------------------------------------------------------- command lines (no tools needed)

@pytest.fixture
def runs(monkeypatch):
    rec = []

    def fake_run_tool(cmd, timeout=600, input_text=None, **kw):
        rec.append({"cmd": list(cmd), "input": input_text, "timeout": timeout})
        return ToolResult(cmd, 0, "", "", 0.1)

    monkeypatch.setattr(probe, "run_tool", fake_run_tool)
    return rec


def test_naabu_command_line(runs):
    probe.run_naabu(["a.example.com", "b.example.com"], rate_limit=50, timeout=99)
    c = runs[0]
    assert c["cmd"][0] == "naabu" and "-json" in c["cmd"] and "-Pn" in c["cmd"] and "-exclude-cdn" in c["cmd"]
    assert c["cmd"][c["cmd"].index("-top-ports") + 1] == "100"
    assert c["cmd"][c["cmd"].index("-rate") + 1] == "50"
    assert c["input"] == "a.example.com\nb.example.com\n" and c["timeout"] == 99


def test_naabu_without_hosts_runs_nothing(runs):
    assert probe.run_naabu([], 50) == {} and runs == []


def test_nmap_command_line(runs):
    probe.run_nmap("203.0.113.5", [443, 22, 80], rate_limit=20, timeout=300)
    cmd = runs[0]["cmd"]
    assert cmd[0] == "nmap" and "-sV" in cmd and "-Pn" in cmd and "-n" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80,443"
    assert cmd[cmd.index("--max-rate") + 1] == "20"
    assert cmd[-3:] == ["-oX", "-", "203.0.113.5"]


def test_naabu_keeps_partial_results_when_it_times_out(monkeypatch):
    partial = '{"host":"a.example.com","ip":"1.1.1.1","port":80}\n'
    monkeypatch.setattr(probe, "run_tool", lambda *a, **k: ToolResult(["naabu"], -1, partial, "", 5.0, timed_out=True))
    assert probe.run_naabu(["a.example.com"], 50) == {"a.example.com": {"ip": "1.1.1.1", "ports": [80]}}


# ------------------------------------------------------------------------- stage

@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


@pytest.fixture
def tools(monkeypatch):
    """Fake naabu / nmap. Both record exactly what they were asked to scan."""
    rec = {"naabu": [], "nmap": [], "found": {}, "details": {}}

    def fake_naabu(hosts, rate, timeout=600, **kw):
        rec["naabu"].append({"hosts": list(hosts), "rate": rate})
        return rec["found"]

    def fake_nmap(ip, ports, rate, timeout=600):
        rec["nmap"].append({"ip": ip, "ports": list(ports), "rate": rate})
        return [dict(rec["details"][(ip, p)], ip=ip, port=p, protocol="tcp") for p in ports if (ip, p) in rec["details"]]

    monkeypatch.setattr(ports_stage, "run_naabu", fake_naabu)
    monkeypatch.setattr(ports_stage, "run_nmap", fake_nmap)
    rec["found"].update({
        "www.example.com": {"ip": "203.0.113.5", "ports": [22, 80, 443]},
        "api.example.com": {"ip": "203.0.113.5", "ports": [80, 443]},           # same IP as www
    })
    rec["details"].update({
        ("203.0.113.5", 22): {"name": "ssh", "product": "OpenSSH", "version": "8.9p1", "extrainfo": "Ubuntu Linux; protocol 2.0",
                              "cpe": ["cpe:/a:openbsd:openssh:8.9p1"]},
        ("203.0.113.5", 80): {"name": "http", "product": "nginx", "version": "1.18.0", "extrainfo": None, "cpe": ["cpe:/a:igor_sysoev:nginx:1.18.0"]},
        ("203.0.113.5", 443): {"name": "https", "product": None, "version": None, "extrainfo": None, "cpe": []},
    })
    return rec


def _ctx(conn, mode, scope=("example.com", "*.example.com", "!dev.example.com"), assets=None):
    scan = Scan(target="example.com", status=ScanStatus.RUNNING, mode=ScanMode(mode), rate_limit=30)
    db.save_scan(conn, scan)
    assets = assets if assets is not None else [
        Asset(scan_id=scan.id, host="www.example.com", in_scope=True),
        Asset(scan_id=scan.id, host="api.example.com", in_scope=True),
        Asset(scan_id=scan.id, host="evil.com", in_scope=False),
        Asset(scan_id=scan.id, host="dev.example.com", in_scope=True),           # flagged in scope, excluded by the rules
        Asset(scan_id=scan.id, host="cdn.example.com", in_scope=True, is_cdn=True, cdn_name="cloudflare"),
    ]
    for a in assets:
        a.scan_id = scan.id
    db.save_many(conn, "assets", assets)
    cfg = Config(db_path=":memory:", scan_mode=mode, rate_limit=30, tool_timeout=77)
    return Context(conn=conn, scan=scan, scope=Scope.from_lines(list(scope)), config=cfg)


def _services(conn, ctx):
    return {(s["host"], s["port"]): s for s in db.get_services(conn, ctx.scan.id)}


def test_passive_mode_scans_nothing(conn, tools):
    out = ports_stage.run(_ctx(conn, "passive"))
    assert "no contact with the target" in out["skipped"]
    assert tools["naabu"] == [] and tools["nmap"] == []


def test_only_in_scope_hosts_not_behind_a_cdn_are_scanned(conn, tools):
    ports_stage.run(_ctx(conn, "standard"))
    assert tools["naabu"] == [{"hosts": ["api.example.com", "www.example.com"], "rate": 30}]
    # not evil.com (flag), not dev.example.com (excluded by rule), not cdn.example.com (ports belong to the CDN)


def test_standard_mode_stores_open_ports_with_iana_names_and_no_nmap(conn, tools):
    ctx = _ctx(conn, "standard")
    out = ports_stage.run(ctx)

    assert tools["nmap"] == []
    svc = _services(conn, ctx)
    assert set(svc) == {("www.example.com", 22), ("www.example.com", 80), ("www.example.com", 443),
                        ("api.example.com", 80), ("api.example.com", 443)}
    assert svc[("www.example.com", 22)]["name"] == "ssh" and svc[("www.example.com", 80)]["name"] == "http"
    assert svc[("www.example.com", 80)]["product"] is None and svc[("www.example.com", 80)]["version"] is None
    assert svc[("www.example.com", 80)]["ip"] == "203.0.113.5"
    assert out["open_ports"] == 5 and out["technologies"] == 0
    assert db.get_technologies(conn, ctx.scan.id) == []


def test_port_names_do_not_depend_on_the_operating_systems_services_file(conn, tools, monkeypatch):
    """socket.getservbyport() read the OS file: 8080 had a name on Linux and none on Windows (and was slow)."""
    import socket

    def forbidden(*a, **k):
        raise AssertionError("the OS services database must not be consulted")
    monkeypatch.setattr(socket, "getservbyport", forbidden)

    ctx = _ctx(conn, "standard")
    ports_stage.run(ctx)
    svc = _services(conn, ctx)
    assert svc[("www.example.com", 22)]["name"] == "ssh"
    assert svc[("www.example.com", 80)]["name"] == "http"
    assert svc[("www.example.com", 443)]["name"] == "https"


def test_a_port_with_no_registered_name_has_no_name(conn, tools):
    tools["found"].clear()
    tools["found"]["www.example.com"] = {"ip": "203.0.113.5", "ports": [31337]}
    ctx = _ctx(conn, "standard")
    ports_stage.run(ctx)
    assert _services(conn, ctx)[("www.example.com", 31337)]["name"] is None


def test_port_name_table():
    from marsadix.ports.services import port_name
    assert [port_name(p) for p in (22, 80, 443, 3306, 8080)] == ["ssh", "http", "https", "mysql", "http-alt"]
    assert port_name(31337) is None


def test_ports_stage_fills_in_the_asset_ip(conn, tools):
    ctx = _ctx(conn, "standard")
    ports_stage.run(ctx)
    ips = {a["host"]: a["ip"] for a in db.get_assets(conn, ctx.scan.id)}
    assert ips["www.example.com"] == "203.0.113.5"


def test_full_mode_adds_product_version_banner_and_cpe_23(conn, tools):
    ctx = _ctx(conn, "full")
    ports_stage.run(ctx)

    ssh = _services(conn, ctx)[("www.example.com", 22)]
    assert (ssh["name"], ssh["product"], ssh["version"]) == ("ssh", "OpenSSH", "8.9p1")
    assert ssh["banner"] == "Ubuntu Linux; protocol 2.0"
    assert ssh["cpe"] == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
    https = _services(conn, ctx)[("www.example.com", 443)]
    assert https["name"] == "https" and https["product"] is None and https["cpe"] is None


def test_full_mode_scans_each_ip_once_even_if_several_hosts_share_it(conn, tools):
    ports_stage.run(_ctx(conn, "full"))
    assert len(tools["nmap"]) == 1
    assert tools["nmap"][0] == {"ip": "203.0.113.5", "ports": [22, 80, 443], "rate": 30}
    # ...and every hostname on that IP still gets the result
    ctx_services = db.get_services(conn, 1)
    assert {(s["host"], s["port"]): s["product"] for s in ctx_services}[("api.example.com", 80)] == "nginx"


def test_full_mode_turns_detected_products_into_technologies(conn, tools):
    ctx = _ctx(conn, "full")
    out = ports_stage.run(ctx)

    techs = {(t["host"], t["name"], t["version"]): t for t in db.get_technologies(conn, ctx.scan.id)}
    nginx = techs[("api.example.com", "nginx", "1.18.0")]
    assert nginx["source"] == "nmap" and nginx["category"] == "service" and nginx["confidence"] == "likely"
    assert nginx["cpe"] == "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*"     # nmap's own CPE wins
    assert ("www.example.com", "OpenSSH", "8.9p1") in techs
    assert out["technologies"] == len(techs)


def test_naabu_missing_skips_the_stage_with_the_reason(conn, monkeypatch):
    def boom(*a, **k):
        raise ToolNotFound("'naabu' is not installed or not in PATH. Run `marsadix doctor`.")
    monkeypatch.setattr(ports_stage, "run_naabu", boom)
    ctx = _ctx(conn, "standard")
    out = ports_stage.run(ctx)
    assert "naabu" in out["skipped"] and "doctor" in out["skipped"]
    assert db.get_services(conn, ctx.scan.id) == []


def test_nmap_missing_keeps_the_port_names(conn, tools, monkeypatch):
    def boom(*a, **k):
        raise ToolNotFound("'nmap' is not installed")
    monkeypatch.setattr(ports_stage, "run_nmap", boom)
    ctx = _ctx(conn, "full")
    out = ports_stage.run(ctx)
    assert "nmap" in out["note"]
    assert len(_services(conn, ctx)) == 5 and _services(conn, ctx)[("www.example.com", 22)]["product"] is None


def test_an_asset_that_is_an_ip_is_matched_through_the_ip_key(conn, tools):
    tools["found"].clear()
    tools["found"]["203.0.113.9"] = {"ip": "203.0.113.9", "ports": [8080]}
    ctx = _ctx(conn, "standard", scope=("203.0.113.0/24",),
               assets=[Asset(scan_id=0, host="203.0.113.9", ip="203.0.113.9", in_scope=True)])
    ports_stage.run(ctx)
    assert set(_services(conn, ctx)) == {("203.0.113.9", 8080)}
    assert _services(conn, ctx)[("203.0.113.9", 8080)]["name"] == "http-alt"


def test_a_value_that_is_not_an_ip_never_reaches_nmap(conn, tools):
    tools["found"].clear()
    tools["found"]["www.example.com"] = {"ip": "-oN /tmp/pwned", "ports": [80]}
    ctx = _ctx(conn, "full")
    ports_stage.run(ctx)
    assert tools["nmap"] == []                                  # no argv built from the bad value
    assert _services(conn, ctx)[("www.example.com", 80)]["ip"] is None     # the open port is still recorded


def test_rerunning_does_not_duplicate_rows(conn, tools):
    ctx = _ctx(conn, "full")
    first = ports_stage.run(ctx)
    second = ports_stage.run(ctx)
    assert first["services"] == 5 and second["services"] == 0
    assert len(db.get_services(conn, ctx.scan.id)) == 5


def test_no_in_scope_hosts_means_no_tool_runs(conn, tools):
    ports_stage.run(_ctx(conn, "full", scope=("other.org",)))
    assert tools["naabu"] == [] and tools["nmap"] == []


def test_stored_ports_and_technologies_appear_in_the_knowledge_graph(conn, tools):
    ctx = _ctx(conn, "full")
    ports_stage.run(ctx)
    build_graph(conn, ctx.scan.id)
    types = {n["id"]: n["node_type"] for n in db.get_graph(conn, ctx.scan.id)["nodes"]}
    assert types["port:www.example.com:22"] == "port"
    assert types["service:www.example.com:22:ssh"] == "service"
    assert types["technology:www.example.com:OpenSSH:8.9p1"] == "technology"
    assert "cpe:cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*" in types


# ------------------------------------------------------------- through the real pipeline

def _fake_recon(ctx):
    db.save_many(ctx.conn, "assets", [Asset(scan_id=ctx.scan.id, host="www.example.com", in_scope=True)])


def _stage(results, name):
    return next(r for r in results if r.name == name)


def test_pipeline_reports_the_ports_stage_per_mode(tmp_path, tools, monkeypatch):
    monkeypatch.setattr("marsadix.recon.stage.run", _fake_recon)
    monkeypatch.setattr("marsadix.web.stage.run", lambda ctx: {})
    scope = Scope.from_lines(["example.com", "*.example.com"])
    cfg = Config(db_path=str(tmp_path / "t.db"), output_dir=str(tmp_path / "out"))

    _, passive = run_scan("example.com", cfg)
    assert _stage(passive, "ports").status == "skipped" and "no contact" in _stage(passive, "ports").detail

    scan, standard = run_scan("example.com", cfg, scope=scope, mode="standard", rate_limit=7)
    assert _stage(standard, "ports").status == "ok"
    assert tools["naabu"][-1] == {"hosts": ["www.example.com"], "rate": 7}      # --rate reached the tool
    assert scan.status == ScanStatus.COMPLETED
