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


def test_nmap_xml_with_entity_declarations_is_refused():
    """nmap never writes <!ENTITY>; in this input it could only be an entity-expansion attack (billion laughs)."""
    bomb = ('<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            '<nmaprun><host><address addr="1.1.1.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
            '<state state="open"/><service name="&b;"/></port></ports></host></nmaprun>')
    assert probe.parse_nmap_xml(bomb) == []


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
    probe.run_nmap("93.184.216.34", [443, 22, 80], rate_limit=20, timeout=300)
    cmd = runs[0]["cmd"]
    assert cmd[0] == "nmap" and "-sV" in cmd and "-Pn" in cmd and "-n" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80,443"
    assert cmd[cmd.index("--max-rate") + 1] == "20"
    assert cmd[-3:] == ["-oX", "-", "93.184.216.34"]


def test_naabu_keeps_partial_results_when_it_times_out(monkeypatch):
    partial = '{"host":"a.example.com","ip":"1.1.1.1","port":80}\n'
    monkeypatch.setattr(probe, "run_tool", lambda *a, **k: ToolResult(["naabu"], -1, partial, "", 5.0, timed_out=True))
    assert probe.run_naabu(["a.example.com"], 50) == {"a.example.com": {"ip": "1.1.1.1", "ports": [80]}}


# ------------------------------------------------------------------------- stage

PUB = "93.184.216.34"          # a real public address (documentation ranges count as internal)


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
    rec["found"][PUB] = {"ip": PUB, "ports": [22, 80, 443]}          # naabu is given IPs, so it answers by IP
    rec["details"].update({
        (PUB, 22): {"name": "ssh", "product": "OpenSSH", "version": "8.9p1", "extrainfo": "Ubuntu Linux; protocol 2.0",
                    "cpe": ["cpe:/a:openbsd:openssh:8.9p1"]},
        (PUB, 80): {"name": "http", "product": "nginx", "version": "1.18.0", "extrainfo": None, "cpe": ["cpe:/a:igor_sysoev:nginx:1.18.0"]},
        (PUB, 443): {"name": "https", "product": None, "version": None, "extrainfo": None, "cpe": []},
    })
    return rec


def _ctx(conn, mode, scope=("example.com", "*.example.com", "!dev.example.com"), assets=None):
    scan = Scan(target="example.com", status=ScanStatus.RUNNING, mode=ScanMode(mode), rate_limit=30)
    db.save_scan(conn, scan)
    assets = assets if assets is not None else [
        Asset(scan_id=scan.id, host="www.example.com", ip=PUB, in_scope=True),
        Asset(scan_id=scan.id, host="api.example.com", ip=PUB, in_scope=True),          # same IP as www
        Asset(scan_id=scan.id, host="evil.com", ip="151.101.1.5", in_scope=False),
        Asset(scan_id=scan.id, host="dev.example.com", ip="151.101.1.6", in_scope=True),  # flagged in scope, excluded by the rules
        Asset(scan_id=scan.id, host="cdn.example.com", ip="104.21.5.9", in_scope=True, is_cdn=True, cdn_name="cloudflare"),
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


def test_naabu_gets_each_public_ip_once_for_in_scope_non_cdn_hosts(conn, tools):
    ports_stage.run(_ctx(conn, "standard"))
    # www and api share one IP -> scanned once. Not evil.com (flag), not dev.example.com (rule),
    # not cdn.example.com (the ports belong to the CDN). IPs, not names: no second DNS lookup.
    assert tools["naabu"] == [{"hosts": [PUB], "rate": 30}]


def test_standard_mode_stores_open_ports_for_every_name_on_the_ip(conn, tools):
    ctx = _ctx(conn, "standard")
    out = ports_stage.run(ctx)

    assert tools["nmap"] == []
    svc = _services(conn, ctx)
    assert set(svc) == {(h, p) for h in ("www.example.com", "api.example.com") for p in (22, 80, 443)}
    assert svc[("www.example.com", 22)]["name"] == "ssh" and svc[("www.example.com", 80)]["name"] == "http"
    assert svc[("www.example.com", 80)]["product"] is None and svc[("www.example.com", 80)]["version"] is None
    assert svc[("www.example.com", 80)]["ip"] == PUB
    assert out["open_ports"] == 6 and out["technologies"] == 0
    assert db.get_technologies(conn, ctx.scan.id) == []


def test_a_host_with_no_resolved_ip_is_not_scanned(conn, tools):
    ctx = _ctx(conn, "standard", assets=[Asset(scan_id=0, host="ghost.example.com", ip=None, in_scope=True)])
    out = ports_stage.run(ctx)
    assert tools["naabu"] == [] and out["no_ip"] == 1 and out["hosts"] == 0


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
    assert tools["nmap"] == [{"ip": PUB, "ports": [22, 80, 443], "rate": 30}]
    # ...and every hostname on that IP still gets the result
    assert {(s["host"], s["port"]): s["product"] for s in db.get_services(conn, 1)}[("api.example.com", 80)] == "nginx"


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
    assert len(_services(conn, ctx)) == 6 and _services(conn, ctx)[("www.example.com", 22)]["product"] is None


def test_an_asset_that_is_an_ip_literal_is_scanned_through_that_ip(conn, tools):
    tools["found"].clear()
    tools["found"]["93.184.216.9"] = {"ip": "93.184.216.9", "ports": [8080]}
    ctx = _ctx(conn, "standard", scope=("93.184.216.0/24",),
               assets=[Asset(scan_id=0, host="93.184.216.9", ip=None, in_scope=True)])
    ports_stage.run(ctx)
    assert tools["naabu"] == [{"hosts": ["93.184.216.9"], "rate": 30}]
    assert set(_services(conn, ctx)) == {("93.184.216.9", 8080)}
    assert _services(conn, ctx)[("93.184.216.9", 8080)]["name"] == "http-alt"


def test_a_malformed_tool_record_is_ignored_and_never_reaches_nmap(conn, tools):
    tools["found"].clear()
    tools["found"]["-oN /tmp/pwned"] = {"ip": "-oN /tmp/pwned", "ports": [80]}
    ctx = _ctx(conn, "full")
    ports_stage.run(ctx)
    assert tools["nmap"] == []                                  # no argv built from the bad value
    assert db.get_services(conn, ctx.scan.id) == []


def test_rerunning_does_not_duplicate_rows(conn, tools):
    ctx = _ctx(conn, "full")
    first = ports_stage.run(ctx)
    second = ports_stage.run(ctx)
    assert first["services"] == 6 and second["services"] == 0
    assert len(db.get_services(conn, ctx.scan.id)) == 6


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


# ------------------------------------------- never scan the tester's own machine or network

INTERNAL = ["127.0.0.1", "10.0.0.5", "172.16.0.9", "192.168.1.10", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "::ffff:127.0.0.1"]


@pytest.mark.parametrize("ip", INTERNAL)
def test_an_in_scope_name_that_resolves_to_an_internal_address_is_never_scanned(conn, tools, ip):
    """DNS is controlled by whoever owns the name: it can point anywhere, including at the tester."""
    tools["found"].clear()
    ctx = _ctx(conn, "full", assets=[Asset(scan_id=0, host="evil.example.com", ip=ip, in_scope=True),
                                     Asset(scan_id=0, host="ok.example.com", ip=PUB, in_scope=True)])
    out = ports_stage.run(ctx)
    assert tools["naabu"] == [{"hosts": [PUB], "rate": 30}]
    assert tools["nmap"] == [] and out["blocked"] == 1


def test_an_internal_range_listed_in_the_scope_file_is_scanned(conn, tools):
    tools["found"].clear()
    tools["found"]["10.0.0.5"] = {"ip": "10.0.0.5", "ports": [445]}
    ctx = _ctx(conn, "standard", scope=("example.com", "*.example.com", "10.0.0.0/8", "!10.0.0.99"),
               assets=[Asset(scan_id=0, host="lan.example.com", ip="10.0.0.5", in_scope=True),
                       Asset(scan_id=0, host="other.example.com", ip="10.0.0.99", in_scope=True),      # excluded address
                       Asset(scan_id=0, host="far.example.com", ip="172.16.0.9", in_scope=True)])      # not listed
    out = ports_stage.run(ctx)
    assert tools["naabu"] == [{"hosts": ["10.0.0.5"], "rate": 30}]
    assert out["blocked"] == 2
    assert set(_services(conn, ctx)) == {("lan.example.com", 445)}


# --------------------------------------------------------------- through the real pipeline

def _fake_recon(ctx):
    db.save_many(ctx.conn, "assets", [Asset(scan_id=ctx.scan.id, host="www.example.com", ip=PUB, in_scope=True)])


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
    assert tools["naabu"][-1] == {"hosts": [PUB], "rate": 7}                    # --rate reached the tool
    assert scan.status == ScanStatus.COMPLETED
