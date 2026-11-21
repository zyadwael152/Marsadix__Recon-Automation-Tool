"""Origin IP discovery: candidates, verification against the public site, storage and graph."""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from marsadix import db
from marsadix.core.graph import build_graph
from marsadix.models import Asset, Scan, ScanStatus
from marsadix.recon import origin

EDGE = "104.21.10.173"          # a CDN edge
MAIL = "93.184.216.34"          # a public host that is not a CDN


def test_spf_record_gives_single_addresses_only():
    txt = ['"v=spf1 ip4:93.184.216.34 ip4:10.0.0.0/8 ip4:203.0.113.0/30 +ip6:2606:2800:220:1::1 include:_spf.google.com ~all"',
           "google-site-verification=abc"]
    assert origin.parse_spf_ips(txt) == {"93.184.216.34", "2606:2800:220:1::1"}


def test_sibling_hosts_outside_the_cdn_are_candidates():
    active = {"example.com": {"ip": EDGE, "ips": [EDGE]}, "mail.example.com": {"ip": MAIL, "ips": [MAIL]},
              "cdn2.example.com": {"ip": "172.67.146.36", "ips": ["172.67.146.36"]}}
    info = {EDGE: {"is_cdn": True}, MAIL: {"is_cdn": False}, "172.67.146.36": {"is_cdn": True}}
    assert origin.sibling_candidates(active, info, {EDGE}) == {MAIL: {"sibling:mail.example.com"}}


def test_same_site_needs_a_healthy_page_and_a_real_match():
    page = (200, {}, b"<html><title> Acme  Corp </title>hello</html>")
    assert origin.same_site(page, (200, {}, b"<html><title>Acme Corp</title>other body</html>")) == "same status 200 and title 'Acme Corp'"
    assert origin.same_site(page, page[:2] + (page[2],)) == "identical body"
    assert origin.same_site(page, (200, {}, b"<title>Other</title>")) is None
    assert origin.same_site(page, (404, {}, page[2])) is None
    assert origin.same_site((404, {}, b"Not Found"), (404, {}, b"Not Found")) is None       # default error pages prove nothing
    redirect = (301, {"location": "https://acme.test/"}, b"")
    assert origin.same_site(redirect, (301, {"location": "https://acme.test/"}, b"")) == "same redirect to https://acme.test/"
    assert origin.same_site(None, page) is None


# ------------------------------------------------------------------ verification
class _Page(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = f"<html><title>{self.server.title}</title></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(address, title):
    try:
        srv = HTTPServer(address, _Page)
    except OSError:
        pytest.skip(f"cannot bind {address} on this system")
    srv.title = title
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_an_address_that_answers_like_the_public_site_is_verified():
    public = _serve(("127.0.0.1", 0), "Acme Corp")           # stands for the CDN-fronted site
    port = public.server_address[1]
    real = _serve(("127.0.0.2", port), "Acme Corp")          # the real server
    other = _serve(("127.0.0.3", port), "Parked domain")     # somebody else's server
    try:
        res = origin.verify_candidates("acme.test", ["127.0.0.2", "127.0.0.3", "127.0.0.9"], timeout=3,
                                       endpoints=((port, False),), reference_address="127.0.0.1")
    finally:
        for s in (public, real, other):
            s.shutdown()
    by_ip = {r["ip"]: r for r in res}
    assert by_ip["127.0.0.2"]["verified"] and "answered like" in by_ip["127.0.0.2"]["evidence"]
    assert not by_ip["127.0.0.3"]["verified"]
    assert not by_ip["127.0.0.9"]["verified"]                # nothing listens there


# --------------------------------------------------------------------- top level
ACTIVE = {"example.com": {"ip": EDGE, "ips": [EDGE]}, "mail.example.com": {"ip": MAIL, "ips": [MAIL]}}
INFO = {EDGE: {"is_cdn": True}, MAIL: {"is_cdn": False}}


def test_nothing_is_done_when_no_host_is_behind_a_cdn():
    assert origin.discover_origin("example.com", {"mail.example.com": {"ip": MAIL}}, {MAIL: {"is_cdn": False}}) == []


def test_candidates_are_reported_unverified_without_active_mode(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no request may be sent outside active mode")
    monkeypatch.setattr(origin, "verify_candidates", boom)
    monkeypatch.setattr(origin, "lookup_dns_records", boom)
    rows = origin.discover_origin("example.com", ACTIVE, INFO, verify=False, lookup_dns=False)
    assert rows == [{"host": "example.com", "ip": MAIL, "source": "sibling:mail.example.com",
                     "verified": False, "evidence": ""}]


def test_active_mode_adds_spf_and_mx_candidates_and_verifies(monkeypatch):
    spf_ip, mx_ip, mx_edge = "8.8.8.8", "8.8.4.4", "1.1.1.2"
    monkeypatch.setattr(origin, "lookup_dns_records", lambda t: ([f"v=spf1 ip4:{spf_ip} ~all"], ["mx.example.com"]))
    monkeypatch.setattr(origin, "resolve_ipv4", lambda hosts, limit=10: {"mx.example.com": {mx_ip, mx_edge, "10.1.1.1"}})

    async def fake_lookup(ips):
        return {ip: {"is_cdn": ip == mx_edge} for ip in ips}          # one MX address is a CDN edge
    monkeypatch.setattr("marsadix.recon.cdn_asn.lookup_cdn_asn", fake_lookup)

    asked = {}

    def fake_verify(host, ips, timeout=6.0, **kw):
        asked[host] = list(ips)
        return [{"ip": ip, "verified": ip == spf_ip, "evidence": "same title" if ip == spf_ip else ""} for ip in ips]
    monkeypatch.setattr(origin, "verify_candidates", fake_verify)

    rows = origin.discover_origin("example.com", ACTIVE, INFO, verify=True, lookup_dns=True)
    assert set(asked["example.com"]) == {MAIL, spf_ip, mx_ip}         # the CDN edge and the private address are gone
    verified = [r for r in rows if r["verified"]]
    assert [(r["ip"], r["source"]) for r in verified] == [(spf_ip, "spf")]
    assert {r["ip"] for r in rows if not r["verified"]} == {MAIL, mx_ip}


# --------------------------------------------------------------- storage + graph
def test_origin_ips_are_stored_and_only_verified_ones_reach_the_graph():
    conn = db.connect(":memory:")
    db.init_db(conn)
    scan = Scan(target="example.com", status=ScanStatus.RUNNING)
    scan.id = db.save_scan(conn, scan)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="example.com", ip=EDGE, in_scope=True)])
    rows = [{"host": "example.com", "ip": "8.8.8.8", "source": "spf", "verified": True, "evidence": "same title"},
            {"host": "example.com", "ip": MAIL, "source": "sibling:mail.example.com", "verified": False, "evidence": ""}]
    assert db.save_origin_ips(conn, scan.id, rows) == 2
    assert db.save_origin_ips(conn, scan.id, rows[:1]) == 1             # saving again updates, never duplicates
    stored = db.get_origin_ips(conn, scan.id)
    assert [(r["ip"], r["verified"]) for r in stored] == [("8.8.8.8", 1), (MAIL, 0)]

    build_graph(conn, scan.id)
    edges = {(e["src_id"], e["dst_id"]) for e in db.get_graph(conn, scan.id)["edges"] if e["relation"] == "origin_of"}
    assert edges == {("ip:8.8.8.8", "subdomain:example.com")}
    conn.close()
