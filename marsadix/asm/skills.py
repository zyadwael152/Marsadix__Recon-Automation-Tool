"""
Custom detection skills (A5, A8). Each one is built on a documented methodology
(see skills/registry.py) and each one stops at EVIDENCE:

  * a unique random marker proves reflection / evaluation / header injection
  * a database error signature or a confirmed time delay proves SQL handling
  * the content of an exposed file is never stored: only that it matches a signature

No skill reads, extracts or changes data on the target, and every Finding is created
with exploited=False. A result is one of three states (A10): Detected (clear
evidence), Needs Review (a partial signal), or nothing at all. "Nothing" is never
reported as "safe": the stage counts what it tested and the report says so.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import statistics
from dataclasses import dataclass
from typing import Callable, List, Optional
from urllib.parse import urlsplit

from ..models import Confidence, DetectionStatus, Finding, FindingSource, Severity
from ..owasp import OWASP_MAPPING
from ..skills import registry
from .http import ProbeClient, Response, query_pairs, with_param

CANARY_DOMAIN = "marsadix-canary.example"        # reserved TLD: never resolves, never contacted
MAX_PARAMS_PER_URL = 8


@dataclass
class Target:
    """One thing to test: a URL with parameters, or a host's base URL."""
    scan_id: int
    host: str
    url: str
    base: str               # scheme://host[:port]


def _token() -> str:
    return secrets.token_hex(4)


def _mk(t: Target, skill: str, title: str, severity: Severity, status: DetectionStatus,
        confidence: Confidence, evidence: str, param: str = "", method: str = "") -> Finding:
    sk = registry.get_skill(skill)
    return Finding(
        scan_id=t.scan_id, host=t.host, source=FindingSource.SKILL, title=title,
        template_id=skill, url=t.url, severity=severity, confidence=confidence,
        evidence=evidence[:400], verified=(status == DetectionStatus.DETECTED),
        verification_method=method or "marker/signature evidence, no data extracted",
        owasp_category=OWASP_MAPPING.get(sk.finding_type) if sk else None,
        source_reference=sk.source_reference if sk else None,
        status=status, exploited=False,
        dedup_key=f"skill|{skill}|{t.host}|{urlsplit(t.url).path}|{param}|{title}")


# -------------------------------------------------------------------------- XSS
@registry.register_handler("xss")
def probe_xss(c: ProbeClient, t: Target) -> List[Finding]:
    out = []
    pairs = query_pairs(t.url)[:MAX_PARAMS_PER_URL]
    for i, (name, _) in enumerate(pairs):
        tok = _token()
        r = c.get(with_param(t.url, i, f"{tok}\"'<{tok}>"))
        if r is None or not r.is_html:
            continue
        body = r.text
        if f"<{tok}>" in body:
            out.append(_mk(t, "xss", f"Reflected XSS in parameter '{name}'", Severity.MEDIUM,
                           DetectionStatus.DETECTED, Confidence.LIKELY,
                           f"A random marker with < > \" ' was reflected unencoded in an HTML response (parameter {name}).",
                           name))
        elif f'{tok}"' in body or f"{tok}'" in body:
            out.append(_mk(t, "xss", f"Possible attribute-context XSS in parameter '{name}'", Severity.LOW,
                           DetectionStatus.NEEDS_REVIEW, Confidence.POSSIBLE,
                           f"A random marker was reflected with quote characters unencoded but angle brackets encoded (parameter {name}).",
                           name))
    return out


# ------------------------------------------------------------------------- SQLi
_SQL_ERRORS = [
    ("MySQL/MariaDB", re.compile(r"you have an error in your sql syntax|warning: mysqli?_|mysql_fetch|supplied argument is not a valid mysql", re.I)),
    ("PostgreSQL", re.compile(r"pg_query\(\)|postgresql.{0,40}error|unterminated quoted string at or near|syntax error at or near", re.I)),
    ("Microsoft SQL Server", re.compile(r"unclosed quotation mark after the character string|microsoft ole db provider for sql server|\[sqlclient|system\.data\.sqlclient", re.I)),
    ("Oracle", re.compile(r"\bora-\d{5}\b|quoted string not properly terminated", re.I)),
    ("SQLite", re.compile(r"sqlite3?\.operationalerror|sqlite error|unrecognized token:", re.I)),
    ("Generic SQL", re.compile(r"sqlstate\[\w+\]|sql syntax.{0,40}error", re.I)),
]
_DELAY = 3
_TIME_PAYLOADS = [("MySQL/MariaDB", "{v}' AND SLEEP({n})-- -"), ("MySQL/MariaDB", "{v} AND SLEEP({n})-- -"),
                  ("PostgreSQL", "{v}';SELECT pg_sleep({n})--"), ("Microsoft SQL Server", "{v}';WAITFOR DELAY '0:0:{n}'--")]


def _sql_family(body: str) -> Optional[str]:
    for fam, rx in _SQL_ERRORS:
        if rx.search(body):
            return fam
    return None


@registry.register_handler("sqli")
def probe_sqli(c: ProbeClient, t: Target) -> List[Finding]:
    out = []
    base = c.get(t.url)
    if base is None:
        return out
    base_family = _sql_family(base.text)
    pairs = query_pairs(t.url)[:MAX_PARAMS_PER_URL]
    for i, (name, value) in enumerate(pairs):
        found = False
        for quote_char in ("'", '"'):                                  # error-based: one stray quote
            r = c.get(with_param(t.url, i, value + quote_char))
            fam = _sql_family(r.text) if r else None
            if fam and fam != base_family:
                out.append(_mk(t, "sqli", f"SQL injection (error-based) in parameter '{name}'", Severity.HIGH,
                               DetectionStatus.DETECTED, Confidence.LIKELY,
                               f"A single quote in '{name}' produced a {fam} error message that the normal page does not show.",
                               name))
                found = True
                break
        if found:
            continue
        # time-based: only after the cheap check found nothing; confirmed with a control request
        times = [c.get(t.url).elapsed for _ in range(2) if c.get(t.url)]
        if not times:
            continue
        base_t = statistics.median(times)
        for fam, tmpl in _TIME_PAYLOADS:
            slow = c.get(with_param(t.url, i, tmpl.format(v=value, n=_DELAY)), timeout=_DELAY + 8)
            if slow is None or slow.elapsed < base_t + _DELAY - 0.5:
                continue
            control = c.get(with_param(t.url, i, tmpl.format(v=value, n=0)), timeout=_DELAY + 8)
            again = c.get(with_param(t.url, i, tmpl.format(v=value, n=_DELAY)), timeout=_DELAY + 8)
            confirmed = (control is not None and control.elapsed < base_t + 1.5
                         and again is not None and again.elapsed >= base_t + _DELAY - 0.5)
            out.append(_mk(t, "sqli", f"SQL injection (time-based) in parameter '{name}'",
                           Severity.HIGH,
                           DetectionStatus.DETECTED if confirmed else DetectionStatus.NEEDS_REVIEW,
                           Confidence.LIKELY if confirmed else Confidence.POSSIBLE,
                           (f"A {_DELAY}s {fam} delay payload slowed the response twice (~{slow.elapsed:.1f}s vs ~{base_t:.1f}s normal) "
                            f"while the same payload with 0s delay did not." if confirmed else
                            f"A {_DELAY}s {fam} delay payload slowed one response (~{slow.elapsed:.1f}s vs ~{base_t:.1f}s) "
                            f"but could not be reproduced; may be network noise."),
                           name, "timing difference with control request"))
            break
    return out


# ------------------------------------------------------------------------- SSTI
@registry.register_handler("ssti")
def probe_ssti(c: ProbeClient, t: Target) -> List[Finding]:
    out = []
    base = c.get(t.url)
    if base is None:
        return out
    pairs = query_pairs(t.url)[:MAX_PARAMS_PER_URL]
    for i, (name, _) in enumerate(pairs):
        a, b = 311 + secrets.randbelow(600), 313 + secrets.randbelow(600)
        product = str(a * b)
        if product in base.text:
            continue
        for syntax, payload in (("{{ }}", f"{{{{{a}*{b}}}}}"), ("${ }", f"${{{a}*{b}}}"),
                                ("<%= %>", f"<%= {a}*{b} %>"), ("#{ }", f"#{{{a}*{b}}}")):
            r = c.get(with_param(t.url, i, payload))
            if r is not None and product in r.text:
                out.append(_mk(t, "ssti", f"Server-side template injection in parameter '{name}'", Severity.HIGH,
                               DetectionStatus.DETECTED, Confidence.LIKELY,
                               f"The expression {a}*{b} sent as {syntax} syntax was evaluated by the server "
                               f"(result {product} appeared in the response).", name))
                break
    return out


# ---------------------------------------------------------------- open redirect
_REDIRECT_NAMES = {"url", "redirect", "redirect_url", "redirect_uri", "redirecturl", "next", "return", "return_to",
                   "returnurl", "returnto", "continue", "dest", "destination", "target", "goto", "link", "rurl",
                   "forward", "callback", "out", "view", "to", "u"}


@registry.register_handler("open-redirect")
def probe_open_redirect(c: ProbeClient, t: Target) -> List[Finding]:
    out = []
    for i, (name, value) in enumerate(query_pairs(t.url)[:MAX_PARAMS_PER_URL]):
        if not (name.lower() in _REDIRECT_NAMES or value.startswith(("http://", "https://", "//", "/"))):
            continue
        host = f"{_token()}.{CANARY_DOMAIN}"
        r = c.get(with_param(t.url, i, f"https://{host}/"))
        loc = r.header("location") if r else None
        if r and r.status in (301, 302, 303, 307, 308) and loc and (urlsplit(loc).hostname or "") == host:
            out.append(_mk(t, "open-redirect", f"Open redirect via parameter '{name}'", Severity.LOW,
                           DetectionStatus.DETECTED, Confidence.CONFIRMED,
                           f"HTTP {r.status} with a Location header pointing at an attacker-chosen host (not followed).", name,
                           "Location header read, redirect not followed"))
    return out


# -------------------------------------------------------------------------- CRLF
@registry.register_handler("crlf")
def probe_crlf(c: ProbeClient, t: Target) -> List[Finding]:
    out = []
    for i, (name, value) in enumerate(query_pairs(t.url)[:MAX_PARAMS_PER_URL]):
        tok = _token()
        r = c.get(with_param(t.url, i, f"{value}%0d%0aX-Marsadix-Check:%20{tok}", raw=True))
        # substring, not equality: a server that decodes only part of the value leaves e.g. "%20<tok>" in the header
        if r is not None and any(tok in v for v in r.header_all("x-marsadix-check")):
            out.append(_mk(t, "crlf", f"CRLF / response-header injection in parameter '{name}'", Severity.MEDIUM,
                           DetectionStatus.DETECTED, Confidence.CONFIRMED,
                           f"A header (X-Marsadix-Check) built from CR/LF characters in '{name}' appeared in the response headers.",
                           name))
    return out


# ------------------------------------------------------------------ Host header
@registry.register_handler("host-header")
def probe_host_header(c: ProbeClient, t: Target) -> List[Finding]:
    out = []
    host = f"{_token()}.{CANARY_DOMAIN}"
    link = re.compile(r"""(?:href|src|action)\s*=\s*["']?(?:https?:)?//""" + re.escape(host), re.I)
    for header in ("Host", "X-Forwarded-Host"):
        r = c.get(t.base + "/", headers={header: host})
        if r is None:
            continue
        loc = r.header("location") or ""
        if host in loc:
            out.append(_mk(t, "host-header", f"Host header injection ({header} used in redirect)", Severity.MEDIUM,
                           DetectionStatus.DETECTED, Confidence.CONFIRMED,
                           f"The {header} value was placed in the Location header of the response.", header))
        elif link.search(r.text):
            out.append(_mk(t, "host-header", f"Host header injection ({header} used in page links)", Severity.MEDIUM,
                           DetectionStatus.DETECTED, Confidence.LIKELY,
                           f"The {header} value appeared in an absolute link (href/src/action) of the page.", header))
        elif host in r.text:
            out.append(_mk(t, "host-header", f"{header} value reflected in the page", Severity.LOW,
                           DetectionStatus.NEEDS_REVIEW, Confidence.POSSIBLE,
                           f"The {header} value is reflected in the body but not in a link; check whether it ends up in e-mails or caches.",
                           header))
    return out


# --------------------------------------------------------------------------- JWT
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def _b64json(part: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        val = json.loads(raw)
        return val if isinstance(val, dict) else None
    except (ValueError, TypeError):
        return None


@registry.register_handler("jwt")
def probe_jwt(c: ProbeClient, t: Target) -> List[Finding]:
    out, seen = [], set()
    r = c.get(t.base + "/")
    if r is None:
        return out
    blob = "\n".join(f"{k}: {v}" for k, v in r.headers) + "\n" + r.text
    for token in list(dict.fromkeys(_JWT_RE.findall(blob)))[:5]:
        h_part, p_part, _ = token.split(".")
        header, payload = _b64json(h_part), _b64json(p_part)
        if header is None or payload is None:
            continue
        alg = str(header.get("alg", ""))
        issues = []
        if alg.lower() == "none":
            issues.append(("JWT accepts the 'none' algorithm", Severity.HIGH, DetectionStatus.DETECTED, Confidence.LIKELY,
                           "A token issued by the site declares alg=none (unsigned)."))
        if "exp" not in payload:
            issues.append(("JWT without an expiry (exp)", Severity.LOW, DetectionStatus.NEEDS_REVIEW, Confidence.POSSIBLE,
                           "A token issued by the site has no exp claim, so it never expires."))
        elif isinstance(payload.get("exp"), (int, float)) and isinstance(payload.get("iat"), (int, float)) \
                and payload["exp"] - payload["iat"] > 365 * 86400:
            issues.append(("JWT with a very long lifetime", Severity.LOW, DetectionStatus.NEEDS_REVIEW, Confidence.POSSIBLE,
                           "A token issued by the site is valid for more than a year."))
        kid = str(header.get("kid", ""))
        if "/" in kid or ".." in kid or "'" in kid:
            issues.append(("JWT kid header looks injectable", Severity.MEDIUM, DetectionStatus.NEEDS_REVIEW,
                           Confidence.POSSIBLE, "The kid header contains path or quote characters."))
        for title, sev, st, conf, ev in issues:
            if title in seen:
                continue
            seen.add(title)
            # the token itself is a credential: it is never stored, only its algorithm and claim names
            out.append(_mk(t, "jwt", title, sev, st, conf,
                           f"{ev} alg={alg or '?'}; claims: {', '.join(sorted(payload))[:80]}. Token value not stored.",
                           title, "decoded header/claims only, signature not tested"))
    return out


# ---------------------------------------------------------------- .git / .env
def _env_lines(text: str) -> int:
    return len(re.findall(r"^[A-Za-z_][A-Za-z0-9_]{2,}\s*=", text, re.M))


_EXPOSURES = [
    ("/.git/HEAD", ".git directory exposed", lambda r: r.status == 200 and re.match(r"^(ref: refs/|[0-9a-f]{40}\s*$)", r.text.strip()) is not None,
     lambda r: "The file /.git/HEAD is downloadable (repository metadata can be fetched).", Severity.HIGH, Confidence.CONFIRMED),
    ("/.git/config", ".git/config exposed", lambda r: r.status == 200 and "[core]" in r.text and "repositoryformatversion" in r.text,
     lambda r: "The file /.git/config is downloadable.", Severity.HIGH, Confidence.CONFIRMED),
    ("/.env", "Exposed .env file", lambda r: r.status == 200 and not r.is_html and _env_lines(r.text) >= 2,
     lambda r: f"/.env is downloadable and holds {_env_lines(r.text)} KEY=value line(s). Values not stored.", Severity.HIGH, Confidence.LIKELY),
]


@registry.register_handler("git-env-exposure")
def probe_git_env(c: ProbeClient, t: Target) -> List[Finding]:
    out = []
    soft404 = c.get(t.base + f"/mx{_token()}")
    for path, title, check, evidence, sev, conf in _EXPOSURES:
        r = c.get(t.base + path)
        if r is None or not check(r):
            continue
        if soft404 is not None and soft404.status == 200 and soft404.body[:200] == r.body[:200]:
            continue                                        # the site answers 200 with the same page for everything
        f = _mk(t, "git-env-exposure", title, sev, DetectionStatus.DETECTED, conf, evidence(r), path,
                "signature match on the response, content not stored")
        f.url = t.base + path
        out.append(f)
    return out


# --------------------------------------------------------------------- dispatch
PARAM_SKILLS = {"xss", "sqli", "ssti", "open-redirect", "crlf"}          # need a URL with parameters
HOST_SKILLS = {"host-header", "jwt", "git-env-exposure"}                  # one run per host base URL


def handler_for(name: str) -> Optional[Callable]:
    return registry._HANDLERS.get(name)
