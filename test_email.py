import smtplib
from marsadix.alerts.email import EmailNotifier, build_message
from .fakes import payload


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.calls, self.msg = [], None
        FakeSMTP.instances.append(self)
        self.fail_login = False

    def ehlo(self): self.calls.append("ehlo")
    def starttls(self, context=None): self.calls.append("starttls"); assert context is not None
    def login(self, u, p):
        self.calls.append("login")
        if self.fail_login:
            raise smtplib.SMTPAuthenticationError(535, b"bad PASSWORD123")
    def send_message(self, m): self.calls.append("send"); self.msg = m
    def quit(self): self.calls.append("quit")


def mk(**kw):
    FakeSMTP.instances.clear()
    args = dict(user="u", password="PASSWORD123", smtp_factory=FakeSMTP)
    args.update(kw)
    return EmailNotifier("smtp.example.com", 587, "alerts@example.com", ["a@example.com", "b@example.com"], **args)


def test_sends_multipart_with_tls_and_login():
    n = mk()
    assert n.send(payload()).ok
    s = FakeSMTP.instances[0]
    assert s.calls == ["ehlo", "starttls", "ehlo", "login", "send", "quit"] and s.timeout
    m = s.msg
    assert m.is_multipart() and m.get_body(("plain",)) and m.get_body(("html",))
    assert "CVE-2021-41773" in m["Subject"] and m["To"] == "a@example.com, b@example.com"


def test_no_starttls_no_login_when_disabled():
    n = mk(starttls=False, user="")
    assert n.send(payload()).ok and "starttls" not in FakeSMTP.instances[0].calls and "login" not in FakeSMTP.instances[0].calls


def test_html_escaped_and_header_injection_blocked():
    p = payload(host="evil\r\nBcc: x@evil.com", description="<script>x</script>")
    m = build_message(p, "a@b.c", ["d@e.f"])
    assert "\n" not in m["Subject"] and "Bcc" not in m.keys()
    assert "<script>" not in m.get_body(("html",)).get_content()


def test_auth_failure_does_not_leak_credentials():
    class Bad(FakeSMTP):
        def __init__(self, *a, **k):
            super().__init__(*a, **k); self.fail_login = True
    n = mk(smtp_factory=Bad)
    r = n.send(payload())
    assert not r.ok and "PASSWORD123" not in r.error and "PASSWORD123" not in repr(n)


def test_connection_error_graceful():
    def boom(*a, **k): raise ConnectionRefusedError("nope smtp.example.com")
    r = mk(smtp_factory=boom).send(payload())
    assert not r.ok and "smtp.example.com" not in r.error


def test_not_configured_is_graceful():
    r = EmailNotifier("", 587, "", []).send(payload())
    assert r.skipped and not r.ok and "not configured" in r.error


def test_port_465_uses_implicit_tls():
    n = EmailNotifier("h", 465, "a@b.c", ["d@e.f"], smtp_factory=FakeSMTP)
    FakeSMTP.instances.clear()
    assert n.send(payload()).ok and "starttls" not in FakeSMTP.instances[0].calls
