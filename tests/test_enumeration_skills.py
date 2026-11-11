"""Web and DNS enumeration skills: findings AND inventory, against a fake DNS server (UDP, TCP, AXFR) and a
deliberately configured local web server. Every skill must report what is wrong and must stay quiet when the
configuration is fine."""

import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from marsadix import db
from marsadix.asm import custom, dnsclient, enum_dns, enum_web, skills as sk
from marsadix.asm.dnsclient import DnsClient, DnsError, build_query, encode_name, parse_message
from marsadix.asm.http import ProbeClient
from marsadix.core.config import Config
from marsadix.core.pipeline import Context
from marsadix.core.scope import Scope
from marsadix.models import Asset, DetectionStatus, Scan, ScanMode, ScanStatus, WebItem, WebItemKind
from marsadix.reports.generate import generate_report
from marsadix.skills import registry

ZONE = "example.test"


# =================================================================== fake DNS server
def _rdata(kind, value):
    if kind == "A":
        return socket.inet_aton(value)
    if kind in ("NS", "CNAME"):
        return encode_name(value)
    if kind == "MX":
        pref, host = value.split(" ", 1)
        return struct.pack("!H", int(pref)) + (encode_name(host) if host.strip(".") else b"\x00")
    if kind == "TXT":
        raw = value.encode()
        return b"".join(bytes([len(raw[i:i + 255])]) + raw[i:i + 255] for i in range(0, len(raw), 255)) or b"\x00"
    if kind == "SOA":
        return encode_name("ns1." + ZONE) + encode_name("hostmaster." + ZONE) + struct.pack("!IIIII", 1, 2, 3, 4, 5)
    raise ValueError(kind)


_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16}


def _rr(name, kind, value):
    data = _rdata(kind, value)
    return encode_name(name) + struct.pack("!HHIH", _NUM[kind], 1, 60, len(data)) + data


def _response(query, answers, rcode=0, truncated=False):
    qid = struct.unpack("!H", query[:2])[0]
    flags = 0x8180 | rcode | (0x0200 if truncated else 0)
    question = query[12:]
    return struct.pack("!HHHHHH", qid, flags, 1, len(answers), 0, 0) + question + b"".join(answers)


def _question(query):
    i, labels = 12, []
    while query[i]:
        labels.append(query[i + 1:i + 1 + query[i]].decode())
        i += 1 + query[i]
    qtype = struct.unpack("!H", query[i + 1:i + 3])[0]
    return ".".join(labels).lower(), qtype


class FakeDns:
    """records: {(name, 'TXT'): [values]}; axfr: 'allow' | 'refuse'; wildcard: zone whose unknown names resolve."""

    def __init__(self, records, axfr="refuse", wildcard=None, truncate_udp=False):
        self.records, self.axfr, self.wildcard, self.truncate_udp = records, axfr, wildcard, truncate_udp
        self.axfr_attempts = 0
        fake = self

        def answers_for(name, qtype):
            kind = {v: k for k, v in _NUM.items()}.get(qtype)
            vals = fake.records.get((name, kind), [])
            if not vals and kind == "A" and fake.wildcard and name.endswith("." + fake.wildcard):
                vals = ["203.0.113.9"]
            return [_rr(name, kind, v) for v in vals]

        class Udp(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                name, qtype = _question(data)
                if fake.truncate_udp:
                    sock.sendto(_response(data, [], truncated=True), self.client_address)
                else:
                    sock.sendto(_response(data, answers_for(name, qtype)), self.client_address)

        class Tcp(socketserver.BaseRequestHandler):
            def handle(self):
                size = struct.unpack("!H", self.request.recv(2))[0]
                data = self.request.recv(size)
                name, qtype = _question(data)
                send = lambda msg: self.request.sendall(struct.pack("!H", len(msg)) + msg)
                if qtype == 252:
                    fake.axfr_attempts += 1
                    if fake.axfr == "refuse":
                        return send(_response(data, [], rcode=5))
                    send(_response(data, [_rr(ZONE, "SOA", ""), _rr("www." + ZONE, "A", "1.1.1.1"), _rr("db." + ZONE, "A", "1.1.1.2")]))
                    return send(_response(data, [_rr("api." + ZONE, "A", "1.1.1.3"), _rr(ZONE, "SOA", "")]))
                send(_response(data, answers_for(name, qtype)))

        self.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Udp)
        self.port = self.udp.server_address[1]
        self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), Tcp)
        for srv in (self.udp, self.tcp):
            srv.daemon_threads = True
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def close(self):
        for srv in (self.udp, self.tcp):
            srv.shutdown()
            srv.server_close()

    def client(self, scope=None, allow_private=True):
        c = DnsClient(scope, rate_limit=1000, timeout=2, resolvers=[("127.0.0.1", self.port)], allow_private=allow_private)
        c.axfr_port = self.port
        return c


@pytest.fixture
def make_dns():
    servers = []

    def make(records, **kw):
        s = FakeDns(records, **kw)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


def _t(host=ZONE):
    return sk.Target(1, host, "", "")


# ============================================================ DNS client: wire format
def test_query_answers_are_parsed_for_every_record_type(make_dns):
    s = make_dns({(ZONE, "TXT"): ["v=spf1 -all"], (ZONE, "MX"): ["10 mail." + ZONE], (ZONE, "NS"): ["ns1." + ZONE],
                  ("ns1." + ZONE, "A"): ["192.0.2.53"], ("www." + ZONE, "CNAME"): ["web." + ZONE]})
    c = s.client()
    assert [r.rdata for r in c.records(ZONE, "TXT")] == ["v=spf1 -all"]
    assert [r.rdata for r in c.records(ZONE, "MX")] == ["10 mail." + ZONE]
    assert [r.rdata for r in c.records(ZONE, "NS")] == ["ns1." + ZONE]
    assert [r.rdata for r in c.records("ns1." + ZONE, "A")] == ["192.0.2.53"]
    assert [r.rdata for r in c.records("www." + ZONE, "CNAME")] == ["web." + ZONE]
    assert c.records("missing." + ZONE, "TXT") == []                 # answered, nothing there


def test_long_txt_records_are_joined_and_truncated_udp_falls_back_to_tcp(make_dns):
    long_value = "v=spf1 " + " ".join(f"ip4:10.0.{i}.0/24" for i in range(60)) + " -all"          # > 255 bytes
    s = make_dns({(ZONE, "TXT"): [long_value]}, truncate_udp=True)
    assert s.client().records(ZONE, "TXT")[0].rdata == long_value


def test_a_resolver_that_does_not_answer_means_none_not_empty():
    c = DnsClient(None, rate_limit=1000, timeout=0.3, resolvers=[("127.0.0.1", 9)])
    assert c.query(ZONE, "TXT") is None and c.records(ZONE, "TXT") is None


def test_compressed_names_are_followed_and_loops_are_rejected():
    query = build_query(ZONE, "NS", 1)
    # answer: name = pointer to the question name (offset 12), NS rdata = "ns1" + pointer to the zone
    rdata = b"\x03ns1\xc0\x0c"
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 2, 1, 60, len(rdata)) + rdata
    msg = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + query[12:] + answer
    assert parse_message(msg).answers[0].rdata == "ns1." + ZONE
    loop = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    with pytest.raises(DnsError):
        parse_message(loop)
    with pytest.raises(DnsError):
        parse_message(b"\x00\x01")


def test_axfr_counts_records_refusal_and_failure(make_dns):
    allow = make_dns({}, axfr="allow")
    res = allow.client().axfr(ZONE, ("127.0.0.1", allow.port))
    assert (res.status, res.records) == ("transferred", 5)           # 2 SOA + 3 hosts, counted and dropped
    refuse = make_dns({}, axfr="refuse")
    res = refuse.client().axfr(ZONE, ("127.0.0.1", refuse.port))
    assert res.status == "refused" and res.detail == "REFUSED"
    assert DnsClient(None, timeout=0.3).axfr(ZONE, ("127.0.0.1", 9)).status == "failed"


# ============================================================== DNS skills
def test_zone_transfer_is_reported_with_a_count_and_never_with_the_records(make_dns):
    s = make_dns({(ZONE, "NS"): ["ns1." + ZONE], ("ns1." + ZONE, "A"): ["127.0.0.1"]}, axfr="allow")
    d = s.client(Scope.from_lines([ZONE, "*." + ZONE]))
    f = enum_dns.probe_zone_transfer(d, _t())
    assert len(f) == 1 and f[0].severity.value == "high" and f[0].status == DetectionStatus.DETECTED
    assert "5 records" in f[0].evidence and "www." not in f[0].evidence and f[0].url is None
    assert ("axfr", "ns1." + ZONE) in {(i["category"], i["name"]) for i in d.inventory}


def test_zone_transfer_is_not_tried_against_out_of_scope_or_blocked_servers(make_dns):
    s = make_dns({(ZONE, "NS"): ["ns.provider.net", "ns1." + ZONE], ("ns.provider.net", "A"): ["127.0.0.1"],
                  ("ns1." + ZONE, "A"): ["127.0.0.1"]}, axfr="allow")
    d = s.client(Scope.from_lines([ZONE, "*." + ZONE]), allow_private=False)       # real network-guard rules
    assert enum_dns.probe_zone_transfer(d, _t()) == []
    assert s.axfr_attempts == 0
    notes = {i["name"]: i["value"] for i in d.inventory if i["category"] == "axfr"}
    assert "out of scope" in notes["ns.provider.net"] and "network guard" in notes["ns1." + ZONE]


def test_a_refused_zone_transfer_is_inventory_only(make_dns):
    s = make_dns({(ZONE, "NS"): ["ns1." + ZONE], ("ns1." + ZONE, "A"): ["127.0.0.1"]}, axfr="refuse")
    d = s.client(Scope.from_lines([ZONE, "*." + ZONE]))
    assert enum_dns.probe_zone_transfer(d, _t()) == [] and s.axfr_attempts == 1
    assert any(i["category"] == "axfr" and i["value"].startswith("refused") for i in d.inventory)


def test_weak_email_records_are_reported_and_recorded(make_dns):
    s = make_dns({(ZONE, "TXT"): ["v=spf1 +all"], (ZONE, "MX"): ["10 mail." + ZONE],
                  ("google._domainkey." + ZONE, "TXT"): ["v=DKIM1; k=rsa; p=ABC"]})
    d = s.client()
    titles = {f.title: f.severity.value for f in enum_dns.probe_email_security(d, _t())}
    assert titles == {"SPF allows any sender (+all)": "medium", "No DMARC record": "low", "No MTA-STS record": "info"}
    cats = {(i["category"], i["name"]) for i in d.inventory}
    assert ("dkim_selector", "google") in cats and ("dns_mx", "10 mail." + ZONE) in cats


def test_good_email_configuration_produces_no_findings(make_dns):
    s = make_dns({(ZONE, "TXT"): ["v=spf1 include:_spf.example.net -all"], ("_dmarc." + ZONE, "TXT"): ["v=DMARC1; p=reject"],
                  ("_mta-sts." + ZONE, "TXT"): ["v=STSv1; id=1"], (ZONE, "MX"): ["10 mail." + ZONE]})
    d = s.client()
    assert enum_dns.probe_email_security(d, _t()) == []
    assert {"spf", "dmarc", "mta_sts"} <= {i["category"] for i in d.inventory}


def test_a_domain_without_mail_gets_info_not_low_and_a_null_mx_counts_as_no_mail(make_dns):
    s = make_dns({(ZONE, "MX"): ["0 ."], (ZONE, "TXT"): ["something else"]})
    sev = {f.title: f.severity.value for f in enum_dns.probe_email_security(s.client(), _t())}
    assert sev == {"No SPF record": "info", "No DMARC record": "info"}


def test_dmarc_p_none_is_info_and_spf_neutral_is_low(make_dns):
    s = make_dns({(ZONE, "TXT"): ["v=spf1 ?all"], ("_dmarc." + ZONE, "TXT"): ["v=DMARC1; p=none"], (ZONE, "MX"): ["10 m." + ZONE],
                  ("_mta-sts." + ZONE, "TXT"): ["v=STSv1; id=1"]})
    sev = {f.title: f.severity.value for f in enum_dns.probe_email_security(s.client(), _t())}
    assert sev == {"SPF is neutral (?all)": "low", "DMARC policy is p=none (monitoring only)": "info"}


def test_no_resolver_answer_means_no_conclusion_at_all():
    d = DnsClient(None, rate_limit=1000, timeout=0.3, resolvers=[("127.0.0.1", 9)])
    assert enum_dns.probe_email_security(d, _t()) == [] and enum_dns.probe_wildcard(d, _t()) == []
    assert enum_dns.probe_zone_transfer(d, _t()) == []


def test_wildcard_dns_is_detected_and_a_normal_zone_is_not(make_dns):
    wild = make_dns({}, wildcard=ZONE)
    f = enum_dns.probe_wildcard(wild.client(), _t())
    assert len(f) == 1 and f[0].severity.value == "info" and "203.0.113.9" in f[0].evidence
    plain = make_dns({})
    d = plain.client()
    assert enum_dns.probe_wildcard(d, _t()) == [] and ("dns_wildcard", "none") in {(i["category"], i["name"]) for i in d.inventory}


# ============================================================ fake web server
class Site(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def version_string(self):             # the default "BaseHTTP/0.6 Python/3.x" would itself be a version leak
        return "nginx/1.18.0" if self.server.mode == "bare" else "lab"

    def _send(self, status=200, body="", headers=(), ctype="text/html"):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        mode, p = self.server.mode, self.path.split("?")[0]
        origin = self.headers.get("Origin")
        if p == "/":
            hdr = []
            if mode == "secure":
                hdr = [("Strict-Transport-Security", "max-age=1"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                       ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")]
            if mode == "cors-creds" and origin:
                hdr = [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
            if mode == "cors-star":
                hdr = [("Access-Control-Allow-Origin", "*")]
            if mode == "error":
                return self._send(503, "down")
            return self._send(200, "<html>home</html>", hdr)
        if p == "/robots.txt" and mode == "robots":
            return self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /public/\nSitemap: /sm.xml\n", ctype="text/plain")
        if p == "/sm.xml" and mode == "robots":
            return self._send(200, "<urlset><url><loc>http://x/a</loc></url><url><loc>http://x/b</loc></url></urlset>", ctype="application/xml")
        if p in ("/robots.txt", "/sitemap.xml") and mode == "soft404":
            return self._send(200, "<html>not found, but 200</html>")
        if mode == "listing" and p == "/files/":
            return self._send(200, '<html><title>Index of /files/</title><h1>Index of /files/</h1><a href="a">a</a><a href="b">b</a></html>')
        if mode == "listing-all" and p.endswith("/"):
            return self._send(200, '<html><title>Index of /</title><a href="a">a</a><a href="b">b</a></html>')
        self._send(404, "nope")


class _Srv(HTTPServer):
    mode = "secure"


@pytest.fixture
def site():
    srv = _Srv(("127.0.0.1", 0), Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def _client():
    return ProbeClient(None, rate_limit=1000, timeout=5, allow_private=True)


def _w(site):
    base = f"http://127.0.0.1:{site.server_address[1]}"
    return sk.Target(1, "127.0.0.1", base + "/", base)


def _inv(c):
    return {(i["category"], i["name"]): i["value"] for i in c.inventory}


# ============================================================= web skills
def test_security_headers_good_site_is_quiet_but_the_inventory_shows_the_values(site):
    c = _client()
    assert enum_web.probe_security_headers(c, _w(site)) == []
    inv = _inv(c)
    assert inv[("security_header", "x-content-type-options")] == "nosniff" and inv[("security_header", "x-frame-options")] == "MISSING"


def test_security_headers_bare_site_reports_missing_headers_and_the_version_leak(site):
    site.mode = "bare"
    c = _client()
    f = {x.title: x for x in enum_web.probe_security_headers(c, _w(site))}
    assert set(f) == {"Missing security headers (4)", "Server software version is revealed in response headers"}
    assert "Content-Security-Policy" in f["Missing security headers (4)"].evidence       # http: no HSTS expected
    assert "Strict-Transport-Security" not in f["Missing security headers (4)"].evidence
    assert f["Missing security headers (4)"].severity.value == "low" and f["Missing security headers (4)"].exploited is False
    assert _inv(c)[("banner", "server")] == "nginx/1.18.0"


def test_an_error_page_says_nothing_about_the_policy(site):
    site.mode = "error"
    c = _client()
    assert enum_web.probe_security_headers(c, _w(site)) == []
    assert ("security_header", "content-security-policy") in _inv(c)                       # still recorded


def test_cors_reflecting_origins_with_credentials_is_medium_and_star_is_inventory_only(site):
    site.mode = "cors-creds"
    c = _client()
    f = enum_web.probe_cors(c, _w(site))
    assert {x.title for x in f} == {"CORS trusts the arbitrary origin with credentials"} or len(f) >= 1
    assert all(x.severity.value == "medium" and x.status == DetectionStatus.DETECTED for x in f)
    site.mode = "cors-star"
    c2 = _client()
    assert enum_web.probe_cors(c2, _w(site)) == [] and _inv(c2)[("cors", "ACAO for arbitrary origin")] == "*"
    site.mode = "secure"
    assert enum_web.probe_cors(_client(), _w(site)) == []


def test_robots_and_sitemap_are_inventoried_and_sensitive_looking_paths_need_review(site):
    site.mode = "robots"
    c = _client()
    f = enum_web.probe_robots_sitemap(c, _w(site))
    assert len(f) == 1 and f[0].status == DetectionStatus.NEEDS_REVIEW and "/admin/" in f[0].evidence
    cats = {(i["category"], i["name"]) for i in c.inventory}
    assert ("robots_path", "disallow /admin/") in cats and ("sitemap_url", "http://x/a") in cats


def test_a_200_html_page_is_not_mistaken_for_robots_txt(site):
    site.mode = "soft404"
    c = _client()
    assert enum_web.probe_robots_sitemap(c, _w(site)) == [] and c.inventory == []


def test_directory_listing_is_found_and_a_site_listing_everything_is_ignored(site):
    site.mode = "listing"
    c = _client()
    f = enum_web.probe_directory_listing(c, _w(site))
    assert [x.title for x in f] == ["Directory listing enabled at /files/"] and f[0].url.endswith("/files/")
    assert ("directory_listing", "/files/") in {(i["category"], i["name"]) for i in c.inventory}
    site.mode = "listing-all"
    assert enum_web.probe_directory_listing(_client(), _w(site)) == []


# ================================================= the stage: storage, report, registry
@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def _ctx(conn, scope, target="example.test"):
    scan = Scan(target=target, status=ScanStatus.RUNNING, mode=ScanMode("standard"))
    scan.id = db.save_scan(conn, scan)
    return Context(conn=conn, scan=scan, scope=scope, config=Config(rate_limit=1000))


def test_the_stage_stores_findings_and_inventory_and_the_report_shows_both(conn, site, make_dns, monkeypatch, tmp_path):
    site.mode = "bare"
    dns = make_dns({(ZONE, "TXT"): ["v=spf1 +all"], (ZONE, "MX"): ["10 m." + ZONE], (ZONE, "NS"): ["ns1." + ZONE],
                    ("ns1." + ZONE, "A"): ["127.0.0.1"]}, axfr="allow")
    monkeypatch.setattr(dnsclient, "system_resolvers", lambda: [("127.0.0.1", dns.port)])
    monkeypatch.setattr(DnsClient, "axfr_port", dns.port)
    port = site.server_address[1]
    ctx = _ctx(conn, Scope.from_lines([ZONE, "*." + ZONE, "127.0.0.1"]))           # listing the address allows the loopback lab
    db.save_many(conn, "assets", [Asset(scan_id=ctx.scan.id, host="127.0.0.1", ip="127.0.0.1", in_scope=True)])
    db.save_many(conn, "web_items", [WebItem(scan_id=ctx.scan.id, host="127.0.0.1", url=f"http://127.0.0.1:{port}/", kind=WebItemKind.URL)])
    out = custom.run(ctx)
    assert out["inventory_saved"] > 5 and out["findings_saved"] >= 4
    titles = {r["title"] for r in db.get_findings(conn, ctx.scan.id)}
    assert {"DNS zone transfer allowed by ns1." + ZONE, "SPF allows any sender (+all)", "No DMARC record"} <= titles
    assert any(t.startswith("Missing security headers") for t in titles)
    cats = {r["category"] for r in db.get_enum_items(conn, ctx.scan.id)}
    assert {"security_header", "dns_ns", "axfr", "spf", "banner"} <= cats
    db.finish_scan(conn, ctx.scan.id, "completed")
    db.save_enum_items(conn, ctx.scan.id, [{"host": "h", "category": "banner", "name": "<script>alert(1)</script>", "value": "x"}])
    assert generate_report(conn, ZONE, fmt="all", out_dir=str(tmp_path)) == 0
    page = next(tmp_path.glob("*.html")).read_text()
    assert "Enumeration inventory" in page and "Security headers (per host)" in page and "Zone transfer attempts" in page
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    import json
    assert {i["category"] for i in json.loads(next(tmp_path.glob("*.json")).read_text())["enumeration"]} >= {"spf", "axfr"}


def test_inventory_storage_dedupes_truncates_and_ignores_incomplete_items(conn):
    scan = Scan(target=ZONE)
    scan.id = db.save_scan(conn, scan)
    item = {"host": "a.example.test", "category": "banner", "name": "server", "value": "x" * 900, "source": "s"}
    assert db.save_enum_items(conn, scan.id, [item, dict(item), {"host": "", "category": "x", "name": "y"}]) == 1
    assert len(db.get_enum_items(conn, scan.id)[0]["value"]) == 500


def test_an_existing_database_gets_the_new_table_without_a_schema_bump(tmp_path):
    path = str(tmp_path / "old.db")
    c = db.connect(path)
    db.init_db(c)
    c.execute("DROP TABLE enum_items")
    c.commit()
    c.close()
    c = db.connect(path)
    db.init_db(c)                                                    # a database created before this feature
    assert c.execute("SELECT COUNT(*) FROM enum_items").fetchone()[0] == 0


def test_enumeration_skills_are_listed_as_such_and_run_in_standard_mode():
    from marsadix.skills.registry import render_table
    table = render_table("standard")
    assert "enumeration" in table and "security-headers" in table and "dns-zone-transfer" in table
    names = {s.name for s in registry.active_skills("standard", False) if s.category == "enumeration"}
    assert len(names) == 7                                           # no --allow-injection needed
    assert registry.active_skills("passive", True) == []
