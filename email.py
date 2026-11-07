"""M14 - SMTP email sender (plain text + HTML, STARTTLS / implicit TLS)."""
from __future__ import annotations

import html
import smtplib
import ssl
from email.message import EmailMessage
from typing import Callable, Optional

from .base import AlertPayload, DeliveryResult, fmt_score, truncate

__all__ = ["EmailNotifier", "build_message"]


def _clean_header(v: str) -> str:
    return " ".join(str(v).replace("\r", " ").replace("\n", " ").split())


def build_message(a: AlertPayload, sender: str, recipients) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = _clean_header(f"[Marsadix][{a.priority_level.upper()}] {a.title}")[:200]
    msg["From"] = _clean_header(sender)
    msg["To"] = ", ".join(_clean_header(r) for r in recipients)
    rows = [("Host", a.host), ("CVE", a.cve_id), ("Technology", " ".join(x for x in (a.technology or a.product, a.version) if x) or "-"),
            ("CVSS", fmt_score(a.cvss)), ("EPSS", fmt_score(a.epss, 3)), ("KEV", "YES" if a.kev else "no"),
            ("Confidence", a.confidence), ("Priority", f"{a.priority_level.upper()} ({a.priority_score:.1f})")]
    rem = (a.remediation_title + ": " if a.remediation_title else "") + (a.remediation_text or "n/a")
    text = "\n".join(f"{k}: {v}" for k, v in rows) + f"\n\nDescription:\n{truncate(a.description, 2000)}\n\nRemediation:\n{rem}\n"
    if a.reasons:
        text += "\nWhy this priority:\n" + "\n".join(f"- {r}" for r in a.reasons) + "\n"
    msg.set_content(text)
    trs = "".join(f"<tr><th align='left'>{html.escape(k)}</th><td>{html.escape(str(v))}</td></tr>" for k, v in rows)
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in a.reasons)
    msg.add_alternative(
        f"<html><body><h2>{html.escape(a.title)}</h2><table>{trs}</table>"
        f"<h3>Description</h3><p>{html.escape(truncate(a.description, 2000))}</p>"
        f"<h3>Remediation</h3><p>{html.escape(rem)}</p>" + (f"<h3>Why this priority</h3><ul>{reasons}</ul>" if reasons else "") +
        "</body></html>", subtype="html")
    return msg


class EmailNotifier:
    name = "email"

    def __init__(self, host: str, port: int, sender: str, recipients, *, user: str = "", password: str = "",
                 starttls: bool = True, timeout: float = 15.0, smtp_factory: Optional[Callable[..., object]] = None):
        self._host, self._port, self._from = host or "", int(port or 587), sender or ""
        self._to = list(recipients or [])
        self._user, self._password, self._starttls, self._timeout = user or "", password or "", starttls, timeout
        self._factory = smtp_factory

    @property
    def configured(self) -> bool:
        return bool(self._host and self._from and self._to)

    def send(self, alert: AlertPayload) -> DeliveryResult:
        if not self.configured:
            return DeliveryResult(False, error="email not configured", skipped=True)
        try:
            msg = build_message(alert, self._from, self._to)
            ctx = ssl.create_default_context()
            if self._port == 465:
                factory = self._factory or (lambda h, p, timeout: smtplib.SMTP_SSL(h, p, timeout=timeout, context=ctx))
                server = factory(self._host, self._port, timeout=self._timeout)
            else:
                factory = self._factory or (lambda h, p, timeout: smtplib.SMTP(h, p, timeout=timeout))
                server = factory(self._host, self._port, timeout=self._timeout)
            try:
                if self._port != 465:
                    server.ehlo()
                    if self._starttls:
                        server.starttls(context=ctx)
                        server.ehlo()
                if self._user:
                    server.login(self._user, self._password)
                server.send_message(msg)
            finally:
                try:
                    server.quit()
                except (smtplib.SMTPException, OSError):
                    server.close() if hasattr(server, "close") else None
            return DeliveryResult(True, attempts=1)
        except smtplib.SMTPAuthenticationError:
            return DeliveryResult(False, attempts=1, error="smtp authentication failed")
        except smtplib.SMTPException as exc:
            return DeliveryResult(False, attempts=1, error=f"smtp error ({type(exc).__name__})")
        except (OSError, ssl.SSLError) as exc:
            return DeliveryResult(False, attempts=1, error=f"smtp connection failed ({type(exc).__name__})")

    def __repr__(self) -> str:
        return "EmailNotifier(configured=%s)" % self.configured
