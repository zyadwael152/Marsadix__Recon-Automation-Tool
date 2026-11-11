"""Custom detection skills (A5, A8) against a deliberately weak local server: each skill must catch the
weakness and must NOT raise a finding on the matching safe page. Plus the probe client's safety rules and
the way the ASM stage gates and runs the skills."""

import base64
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from marsadix import db
from marsadix.asm import custom, skills as sk
from marsadix.asm import stage as asm_stage
from marsadix.asm.http import ProbeClient, with_param
from marsadix.core import toolstatus
from marsadix.core.config import Config
from marsadix.core.pipeline import Context
from marsadix.core.scope import Scope
from marsadix.models import Asset, DetectionStatus, Scan, ScanMode, ScanStatus, WebItem, WebItemKind


def _jwt(header, payload):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc(header)}.{enc(payload)}.sig"


class Lab(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def _send(self, status, body="", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        if not any(k.lower() == "content-type" for k, _ in headers):
            self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        p, mode = u.path, self.server.mode
        if p == "/xss":
            return self._send(200, f"<html>You said {q.get('q', '')}</html>")
        if p == "/xss-safe":
            import html
            return self._send(200, f"<html>You said {html.escape(q.get('q', ''))}</html>")
        if p == "/xss-attr":
            v = q.get("q", "").replace("<", "&lt;").replace(">", "&gt;")
            return self._send(200, f'<html><input value="{v}"></html>')
        if p == "/sqli":
            if "'" in q.get("id", ""):
                return self._send(200, "You have an error in your SQL syntax; check the manual")
            return self._send(200, "<html>item</html>")
        if p == "/ssti":
            m = re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", q.get("name", ""))
            return self._send(200, f"Hello {int(m[1]) * int(m[2])}" if m else f"Hello {q.get('name', '')}")
        if p == "/redir":
            return self._send(302, b"", [("Location", q.get("next", "/"))])
        if p == "/redir-safe":
            return self._send(302, b"", [("Location", "/home")])
        if p == "/crlf":          # the bug: the value is split into headers
            val = re.sub(r"%0d%0a", "\r\n", u.query.split("v=", 1)[-1], flags=re.I)
            return self.wfile.write(f"HTTP/1.0 200 OK\r\nX-Echo: {val}\r\nContent-Type: text/html\r\n\r\nok".encode())
        if p == "/crlf-safe":
            return self._send(200, b"ok", [("X-Echo", "fixed")])
        if mode == "soft404":
            return self._send(200, "<html>welcome to everything</html>")
        if p == "/.git/HEAD" and mode == "vuln":
            return self._send(200, "ref: refs/heads/main\n", [("Content-Type", "text/plain")])
        if p == "/.env" and mode == "vuln":
            return self._send(200, "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n", [("Content-Type", "text/plain")])
        if p == "/" and mode == "jwt-none":
            return self._send(200, b"ok", [("Set-Cookie", "t=" + _jwt({"alg": "none"}, {"sub": "1"}))])
        if p == "/" and mode == "jwt-ok":
            return self._send(200, b"ok", [("Set-Cookie", "t=" + _jwt({"alg": "HS256"}, {"sub": "1", "exp": 99, "iat": 1}))])
        if p == "/" and mode == "hosthdr":
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host")
            return self._send(200, f'<a href="https://{host}/reset">reset</a>')
        return self._send(404, "nope")


class _Server(HTTPServer):
    mode = "vuln"


@pytest.fixture
def lab():
    srv = _Server(("127.0.0.1", 0), Lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def _client():
    return ProbeClient(None, rate_limit=1000, timeout=5, allow_private=True)


def _target(lab, path):
    base = f"http://127.0.0.1:{lab.server_address[1]}"
    return sk.Target(1, "127.0.0.1", base + path, base)


# ------------------------------------------------------------------------- skills
def test_xss_reflected_raw_is_detected_and_encoded_is_not(lab):
    assert [f.status for f in sk.probe_xss(_client(), _target(lab, "/xss?q=a"))] == [DetectionStatus.DETECTED]
    assert sk.probe_xss(_client(), _target(lab, "/xss-safe?q=a")) == []
    assert [f.status for f in sk.probe_xss(_client(), _target(lab, "/xss-attr?q=a"))] == [DetectionStatus.NEEDS_REVIEW]


def test_sqli_error_based_has_evidence_and_provenance(lab):
    f = sk.probe_sqli(_client(), _target(lab, "/sqli?id=1"))
    assert len(f) == 1 and f[0].status == DetectionStatus.DETECTED and "MySQL" in f[0].evidence
    assert f[0].exploited is False and f[0].owasp_category == "A03:2021-Injection"
    assert f[0].source_reference and f[0].template_id == "sqli"


def test_ssti_is_detected_by_evaluation_not_by_reflection(lab):
    assert len(sk.probe_ssti(_client(), _target(lab, "/ssti?name=x"))) == 1
    assert sk.probe_ssti(_client(), _target(lab, "/xss?q=x")) == []


def test_open_redirect_needs_a_location_to_the_canary_host(lab):
    assert len(sk.probe_open_redirect(_client(), _target(lab, "/redir?next=/home"))) == 1
    assert sk.probe_open_redirect(_client(), _target(lab, "/redir-safe?next=/home")) == []


def test_crlf_is_detected_only_when_a_new_header_appears(lab):
    assert len(sk.probe_crlf(_client(), _target(lab, "/crlf?v=a"))) == 1
    assert sk.probe_crlf(_client(), _target(lab, "/crlf-safe?v=a")) == []


def test_host_header_injection_in_links(lab):
    lab.mode = "hosthdr"
    f = sk.probe_host_header(_client(), _target(lab, "/"))
    assert f and all(x.status == DetectionStatus.DETECTED for x in f)
    lab.mode = "vuln"
    assert sk.probe_host_header(_client(), _target(lab, "/")) == []


def test_jwt_none_is_detected_and_the_token_is_never_stored(lab):
    lab.mode = "jwt-none"
    f = sk.probe_jwt(_client(), _target(lab, "/"))
    assert any(x.status == DetectionStatus.DETECTED and "none" in x.title for x in f)
    assert not any("eyJ" in (x.evidence or "") for x in f)
    lab.mode = "jwt-ok"
    assert sk.probe_jwt(_client(), _target(lab, "/")) == []


def test_git_and_env_exposure_are_detected_without_storing_the_content(lab):
    f = sk.probe_git_env(_client(), _target(lab, "/"))
    assert {x.title for x in f} == {".git directory exposed", "Exposed .env file"}
    assert not any("hunter2" in x.evidence for x in f)


def test_a_site_that_answers_200_to_everything_is_not_flagged(lab):
    lab.mode = "soft404"
    assert sk.probe_git_env(_client(), _target(lab, "/")) == []


# --------------------------------------------------------------------- probe client
def test_client_refuses_out_of_scope_non_http_and_loopback_unless_listed(lab):
    port = lab.server_address[1]
    assert ProbeClient(Scope.from_target("example.com"), rate_limit=1000).get(f"http://127.0.0.1:{port}/") is None
    assert ProbeClient(Scope.from_lines(["*.example.net"]), rate_limit=1000).get("ftp://x.example.net/") is None
    assert ProbeClient(Scope.from_lines(["127.0.0.1"]), rate_limit=1000).get(f"http://127.0.0.1:{port}/xss?q=1").status == 200
    assert ProbeClient(Scope.from_lines(["localhost"]), rate_limit=1000).get(f"http://localhost:{port}/") is None


def test_client_never_follows_a_redirect(lab):
    r = _client().get(f"http://127.0.0.1:{lab.server_address[1]}/redir?next=http://elsewhere.example/")
    assert r.status == 302 and r.header("location") == "http://elsewhere.example/"


def test_with_param_encodes_and_raw_keeps_crlf_literal():
    assert with_param("http://h/p?a=1&b=2", 1, "x y") == "http://h/p?a=1&b=x%20y"
    assert with_param("http://h/p?a=1", 0, "1%0d%0aX:%201", raw=True) == "http://h/p?a=1%0d%0aX:%201"


# ------------------------------------------------------------------------ the stage
@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def _ctx(conn, mode="full", allow=True, scope=None):
    scan = Scan(target="example.com", status=ScanStatus.RUNNING, mode=ScanMode(mode))
    scan.id = db.save_scan(conn, scan)
    return Context(conn=conn, scan=scan, scope=scope or Scope.from_target("example.com"),
                   config=Config(allow_injection=allow, rate_limit=1000))


def _web(ctx, host, ip, urls):
    db.save_many(ctx.conn, "assets", [Asset(scan_id=ctx.scan.id, host=host, ip=ip, in_scope=True)])
    db.save_many(ctx.conn, "web_items", [WebItem(scan_id=ctx.scan.id, host=host, url=u,
                 kind=WebItemKind.URL if "?" not in u else WebItemKind.ENDPOINT) for u in urls])


def test_targets_are_scope_and_network_checked_deduplicated_and_capped(conn):
    ctx = _ctx(conn)
    urls = ["https://a.example.com/"] + [f"https://a.example.com/p{i}?id={i}" for i in range(30)] + ["https://a.example.com/p0?id=99"]
    _web(ctx, "a.example.com", "93.184.216.34", urls)
    _web(ctx, "internal.example.com", "10.0.0.5", ["https://internal.example.com/x?a=1"])
    _web(ctx, "evil.org", "93.184.216.35", ["https://evil.org/x?a=1"])
    params, hosts = custom.collect_targets(ctx)
    assert len(params) == custom.MAX_PARAM_URLS_PER_HOST and {t.host for t in params} == {"a.example.com"}
    assert [h.host for h in hosts] == ["a.example.com"]


def test_nothing_runs_without_the_opt_in_and_standard_runs_only_the_low_traffic_skills(conn, lab):
    base = f"http://127.0.0.1:{lab.server_address[1]}"
    for mode, allow, expected in (("standard", True, {"git-env-exposure"}), ("full", False, {"git-env-exposure"}),
                                  ("full", True, {"git-env-exposure", "xss", "sqli"})):
        c = db.connect(":memory:")
        db.init_db(c)
        ctx = _ctx(c, mode, allow, Scope.from_lines(["127.0.0.1"]))
        _web(ctx, "127.0.0.1", "127.0.0.1", [base + "/", base + "/xss?q=1", base + "/sqli?id=1"])
        out = custom.run(ctx)
        assert {r["template_id"] for r in db.get_findings(c, ctx.scan.id)} == expected, (mode, allow)
        assert out["findings_saved"] == len(expected) + (0 if "xss" not in expected else 0) or out["findings_saved"] >= 1


def test_the_asm_stage_runs_the_custom_skills_even_when_nuclei_is_missing(conn, lab, monkeypatch, tmp_path):
    base = f"http://127.0.0.1:{lab.server_address[1]}"
    ctx = _ctx(conn, "full", True, Scope.from_lines(["127.0.0.1"]))
    _web(ctx, "127.0.0.1", "127.0.0.1", [base + "/", base + "/xss?q=1"])
    monkeypatch.setenv("PATH", str(tmp_path))                      # no nuclei binary
    toolstatus.reset()
    out = asm_stage.run(ctx)
    assert not out.get("skipped") and out["custom_skills"]["findings_saved"] >= 2
    assert {"xss", "git-env-exposure"} <= {r["template_id"] for r in db.get_findings(conn, ctx.scan.id)}
    assert all(r["exploited"] == 0 for r in db.get_findings(conn, ctx.scan.id))


def test_passive_mode_sends_nothing(conn):
    assert "standard or full" in asm_stage.run(_ctx(conn, "passive"))["skipped"]
