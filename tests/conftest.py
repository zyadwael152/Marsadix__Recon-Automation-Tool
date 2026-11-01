"""
Shared pytest fixtures, applied automatically to every test in tests/.

Why this exists: `marsadix scan` now runs a REAL recon stage (subprocess
tools + crt.sh/VirusTotal/AlienVault over the network). Many tests across
test_cli.py and test_pipeline.py call `scan` / run_scan(), so without this
fixture every test run performs real, slow, network-dependent work -- on a
filtering or slow network that can mean many minutes just to run `pytest`,
and the result depends on whatever network the machine happens to have at
that moment. Tests must be fast and deterministic.

This replaces ONLY the reference `discover_subdomains` that recon/stage.py
already imported into its own namespace (`from .discovery import
discover_subdomains`) -- it does not touch discovery.py itself, and a test
that wants to exercise the real discovery logic can still import and call
`marsadix.recon.discovery.discover_subdomains` directly, bypassing this.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class _Member2Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    ROUTES = {
        "/": ("text/html", """<html><body>
            <a href="/about">about</a>
            <a href="/missing">missing</a>
            <script src="/static/app.js"></script>
            <form action="/search"><input name="q"></form>
        </body></html>"""),
        "/about": ("text/html", '<a href="/api/v1/users?x=1">users</a>'),
        "/search": ("text/html", "<html>search</html>"),
        "/api/v1/users?x=1": ("application/json", '{"users": []}'),
        "/api/v2/items?q=1": ("application/json", '{"items": []}'),
        "/api/v3/login": ("application/json", '{"ok": true}'),
        "/static/app.js": ("application/javascript", """
            const a = fetch('/api/v2/items?q=1');
            const b = "/api/v3/login";
            const c = "https://outside.test/ignored";
        """),
        "/robots.txt": ("text/plain", "User-agent: *\nAllow: /\n"),
    }

    def _serve(self, body: bool):
        path = self.path
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/about")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        item = self.ROUTES.get(path)
        if item is None:
            payload = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if body:
                self.wfile.write(payload)
            return
        ctype, text = item
        payload = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if body:
            self.wfile.write(payload)

    def do_GET(self):
        self._serve(True)

    def do_HEAD(self):
        self._serve(False)

    def log_message(self, fmt, *args):
        return


@pytest.fixture(scope="session")
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Member2Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}/"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _fake_discover_subdomains(domain, api_keys=None, *args, **kwargs):
    # No tool calls, no HTTP requests: an empty result is enough for every
    # existing test, which only cares that the pipeline runs end-to-end,
    # not about what recon actually finds.
    return {}


@pytest.fixture(autouse=True)
def _no_real_recon_network(monkeypatch):
    monkeypatch.setattr(
        "marsadix.recon.stage.discover_subdomains", _fake_discover_subdomains)
    # Pipeline/CLI tests must never launch puredns or query public resolvers.
    # Candidate expansion has its own unit-test surface and is intentionally
    # bypassed in end-to-end lifecycle tests.
    async def _fake_expand_candidates(ctx, target, raw_results):
        return raw_results
    monkeypatch.setattr("marsadix.recon.stage._expand_candidates", _fake_expand_candidates)


@pytest.fixture(autouse=True)
def _no_provider_spacing(monkeypatch):
    """API providers are spaced out in real scans (rate limits); tests must not wait for that."""
    from marsadix.recon import api_sources
    monkeypatch.setattr(api_sources, "PROVIDER_GAP", {})
    from marsadix.recon import discovery
    monkeypatch.setattr(discovery, "CRTSH_RETRY_WAITS", (0, 0))


@pytest.fixture(autouse=True)
def _no_real_external_tools(monkeypatch):
    """
    The suite must never run a REAL external tool (subfinder, httpx, gau, nmap ...).

    On a machine where the tools are installed, tests that call `scan` would otherwise start
    them against example.com: slow, networked, and different from CI. PATH is therefore an
    empty directory for every test. A test that needs a program sets its own PATH (see the
    fake-tool tests); sys.executable is absolute and unaffected.
    """
    import tempfile
    monkeypatch.setenv("PATH", tempfile.mkdtemp(prefix="marsadix_nopath_"))
