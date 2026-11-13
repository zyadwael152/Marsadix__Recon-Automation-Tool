import json
from marsadix.alerts.http import HttpResponse, TransportError
from marsadix.alerts.telegram import TelegramNotifier, build_lines, split_message
from .fakes import FakeClient, Sleeper, payload

OK = HttpResponse(200, {}, json.dumps({"ok": True, "result": {}}))


def mk(*script):
    c, s = FakeClient(*script), Sleeper()
    return TelegramNotifier("123:SECRETBOT", "-100777", client=c, sleep=s), c, s


def test_send_uses_bot_api_and_html():
    n, c, _ = mk(OK)
    assert n.send(payload()).ok
    call = c.calls[0]
    assert call["url"] == "https://api.telegram.org/bot123:SECRETBOT/sendMessage"
    b = c.json()
    assert b["chat_id"] == "-100777" and b["parse_mode"] == "HTML" and "CVE-2021-41773" in b["text"]


def test_user_controlled_fields_escaped():
    p = payload(host="<script>alert(1)</script>", description="a & b <b>x</b>", remediation_text="<i>x</i>", technology="A<B")
    text = "\n".join(build_lines(p))
    assert "<script>" not in text and "&lt;script&gt;" in text and "a &amp; b &lt;b&gt;x&lt;/b&gt;" in text
    assert "&lt;i&gt;" in text


def test_split_long_messages():
    lines = [f"<b>line {i}</b> " + "x" * 500 for i in range(30)]
    chunks = split_message(lines)
    assert len(chunks) > 1 and all(len(c) <= 4096 for c in chunks)
    assert "".join(c.replace("\n", "") for c in chunks).count("<b>line") == 30


def test_huge_alert_stays_under_limit():
    chunks = split_message(build_lines(payload(description="x" * 50000, remediation_text="y" * 50000)))
    assert all(len(c) <= 4096 for c in chunks)


def test_429_retry_after_in_body():
    n, c, s = mk(HttpResponse(429, {}, json.dumps({"ok": False, "parameters": {"retry_after": 3}})), OK)
    assert n.send(payload()).ok and s.delays == [3.0]


def test_transient_errors():
    n, c, s = mk(HttpResponse(502), TransportError("network error (X)"), OK)
    assert n.send(payload()).ok and len(c.calls) == 3


def test_malformed_and_not_ok_responses_fail_without_retry():
    n, c, s = mk(HttpResponse(200, {}, "<html>"))
    r = n.send(payload())
    assert not r.ok and r.error == "malformed response" and len(c.calls) == 1
    n, c, s = mk(HttpResponse(200, {}, json.dumps({"ok": False})))
    assert not n.send(payload()).ok


def test_token_never_leaks():
    n, c, s = mk(HttpResponse(500))
    r = n.send(payload())
    assert "SECRETBOT" not in r.error and "SECRETBOT" not in repr(n)


def test_not_configured():
    assert TelegramNotifier("", "1").send(payload()).skipped
