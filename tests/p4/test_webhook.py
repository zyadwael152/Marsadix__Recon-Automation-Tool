import hashlib, hmac, json
import pytest
from marsadix.alerts.http import HttpResponse
from marsadix.alerts.webhook import (SIGNATURE_HEADER, SlackNotifier, TeamsNotifier, UnsafeDestination, WebhookNotifier,
                                     validate_destination)
from .fakes import FakeClient, Sleeper, payload

PUB = lambda host: ["93.184.216.34"]
URL = "https://hooks.example.com/services/SECRETPATH"


def mk(cls, *script, secret="", url=URL, **kw):
    c, s = FakeClient(*script or [HttpResponse(200)]), Sleeper()
    return cls(url, secret=secret, client=c, sleep=s, resolver=PUB, **kw), c, s


def test_generic_payload_and_signature():
    n, c, _ = mk(WebhookNotifier, secret="topsecret")
    assert n.send(payload()).ok
    body = c.calls[0]["body"]
    sig = c.calls[0]["headers"][SIGNATURE_HEADER]
    assert sig == "sha256=" + hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()
    d = json.loads(body)
    assert d["event"] == "marsadix.alert" and d["alert"]["cve_id"] == "CVE-2021-41773" and d["alert"]["kev"] is True


def test_no_signature_without_secret_and_deterministic_body():
    n, c, _ = mk(WebhookNotifier)
    n.send(payload()); n.send(payload())
    assert SIGNATURE_HEADER not in c.calls[0]["headers"] and c.calls[0]["body"] == c.calls[1]["body"]


def test_slack_shape():
    n, c, _ = mk(SlackNotifier)
    assert n.send(payload(host="a<b>&c")).ok
    b = c.json()
    assert b["text"] and [x["type"] for x in b["blocks"]] == ["header", "section", "section"]
    assert "a&lt;b&gt;&amp;c" in json.dumps(b) and SIGNATURE_HEADER not in c.calls[0]["headers"]
    assert all(len(f["text"]) <= 2000 for f in b["blocks"][1]["fields"])


def test_teams_adaptive_card_shape():
    n, c, _ = mk(TeamsNotifier)
    assert n.send(payload()).ok
    b = c.json()
    att = b["attachments"][0]
    assert b["type"] == "message" and att["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert att["content"]["type"] == "AdaptiveCard" and any(x["type"] == "FactSet" for x in att["content"]["body"])


def test_retry_and_429():
    n, c, s = mk(WebhookNotifier, HttpResponse(503), HttpResponse(429, {"Retry-After": "4"}), HttpResponse(200))
    r = n.send(payload())
    assert r.ok and r.attempts == 3 and s.delays == [1.0, 4.0]
    n, c, s = mk(WebhookNotifier, HttpResponse(500))
    assert not n.send(payload()).ok and len(c.calls) == 4


@pytest.mark.parametrize("url", [
    "http://localhost/hook", "http://127.0.0.1/x", "http://10.0.0.5/x", "https://192.168.1.1/x", "http://169.254.169.254/latest",
    "http://[::1]/x", "http://[::ffff:127.0.0.1]/x", "http://172.16.0.1/", "http://0.0.0.0/", "http://100.64.0.1/", "http://foo.localhost/",
])
def test_private_destinations_blocked_by_default(url):
    n, c, _ = mk(WebhookNotifier, url=url)
    r = n.send(payload())
    assert not r.ok and "blocked" in r.error and c.calls == [] and url not in r.error


def test_dns_resolving_to_private_is_blocked():
    n = WebhookNotifier(URL, client=FakeClient(), resolver=lambda h: ["10.1.2.3"])
    assert "blocked" in n.send(payload()).error
    n = WebhookNotifier(URL, client=FakeClient(), resolver=lambda h: [])
    assert not n.send(payload()).ok


def test_private_opt_in():
    n, c, _ = mk(WebhookNotifier, url="http://127.0.0.1:8080/hook", allow_private=True)
    assert n.send(payload()).ok and len(c.calls) == 1


@pytest.mark.parametrize("url", ["ftp://x.com/a", "file:///etc/passwd", "javascript:alert(1)", "", "http://", "https://u:p@x.com/", "http://x.com:99999/"])
def test_invalid_urls_rejected(url):
    with pytest.raises(UnsafeDestination):
        validate_destination(url, resolver=PUB)


def test_no_secret_leak_in_logs_or_errors(caplog):
    n, c, _ = mk(WebhookNotifier, HttpResponse(500), secret="topsecret")
    r = n.send(payload())
    assert "SECRETPATH" not in r.error + repr(n) + caplog.text and "topsecret" not in r.error + repr(n) + caplog.text
