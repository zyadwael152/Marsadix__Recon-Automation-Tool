import json
from marsadix.alerts.discord import COLORS, DiscordNotifier, build_payload, LIMITS
from marsadix.alerts.http import HttpResponse, TransportError, TransportTimeout
from .fakes import FakeClient, Sleeper, payload

URL = "https://discord.com/api/webhooks/123/SECRETTOKEN"


def mk(*script, **kw):
    c, s = FakeClient(*script), Sleeper()
    return DiscordNotifier(URL, client=c, sleep=s, **kw), c, s


def test_success_embed_contents():
    n, c, _ = mk(HttpResponse(204))
    r = n.send(payload())
    assert r.ok and r.attempts == 1 and c.calls[0]["url"] == URL and c.calls[0]["timeout"] > 0
    emb = c.json()["embeds"][0]
    f = {x["name"]: x["value"] for x in emb["fields"]}
    for k in ("Host", "CVE", "Technology", "Version", "CVSS", "EPSS", "KEV", "Confidence", "Priority", "Remediation"):
        assert k in f
    assert f["KEV"] == "YES" and "Upgrade to 2.4.51" in f["Remediation"] and f["CVSS"] == "9.8"
    assert emb["color"] == COLORS["critical"] and c.json()["allowed_mentions"] == {"parse": []}


def test_colors_by_priority():
    for lvl, col in COLORS.items():
        assert build_payload(payload(priority_level=lvl))["embeds"][0]["color"] == col


def test_limits_respected():
    big = "A" * 20000
    emb = build_payload(payload(description=big, remediation_text=big, host=big, technology=big))["embeds"][0]
    assert len(emb["title"]) <= 256 and len(emb["description"]) <= 4096 and len(emb["fields"]) <= 25
    assert all(len(f["name"]) <= 256 and 0 < len(f["value"]) <= 1024 for f in emb["fields"])
    tot = len(emb["title"]) + len(emb["description"]) + sum(len(f["name"]) + len(f["value"]) for f in emb["fields"]) + len(emb["footer"]["text"])
    assert tot <= 6000


def test_429_retry_after_header():
    n, c, s = mk(HttpResponse(429, {"Retry-After": "2"}), HttpResponse(204))
    r = n.send(payload())
    assert r.ok and r.attempts == 2 and s.delays == [2.0]


def test_429_retry_after_json_body():
    n, c, s = mk(HttpResponse(429, {}, json.dumps({"retry_after": 1.5})), HttpResponse(204))
    assert n.send(payload()).ok and s.delays == [1.5]


def test_429_malformed_body_uses_backoff_and_caps():
    n, c, s = mk(HttpResponse(429, {}, "<html>"), HttpResponse(429, {"Retry-After": "9999"}), HttpResponse(204))
    assert n.send(payload()).ok
    assert s.delays == [1.0, 60.0]


def test_500_exponential_backoff_bounded():
    n, c, s = mk(HttpResponse(500))
    r = n.send(payload())
    assert not r.ok and r.attempts == 4 and len(c.calls) == 4 and s.delays == [1.0, 2.0, 4.0]
    assert "500" in r.error


def test_timeout_and_network_errors_retry():
    n, c, s = mk(TransportTimeout("timeout"), TransportError("network error (ConnectionResetError)"), HttpResponse(204))
    assert n.send(payload()).ok and len(c.calls) == 3
    n2, _, _ = mk(TransportTimeout("timeout"))
    assert n2.send(payload()).error == "timeout"


def test_4xx_not_retried():
    n, c, s = mk(HttpResponse(400, {}, "bad"))
    r = n.send(payload())
    assert not r.ok and r.attempts == 1 and s.delays == [] and r.status == 400


def test_malformed_2xx_response_is_success():
    n, c, s = mk(HttpResponse(200, {}, "not json at all"))
    assert n.send(payload()).ok


def test_secret_never_in_results_or_repr(caplog):
    n, c, s = mk(HttpResponse(500), TransportError("network error (X)"))
    r = n.send(payload())
    assert "SECRETTOKEN" not in r.error and "SECRETTOKEN" not in repr(n) and "SECRETTOKEN" not in caplog.text


def test_not_configured():
    r = DiscordNotifier("").send(payload())
    assert r.skipped and not r.ok
