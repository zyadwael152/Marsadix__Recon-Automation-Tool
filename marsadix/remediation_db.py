"""M19 - database-backed remediation store.

Lookup order (first hit wins):

    1. skill / template   (finding.skill, finding.template_id / .template)
    2. keyword            (whole-word, hyphen/underscore/space-insensitive match in
                           title + description + category; highest ``priority``,
                           then longest keyword, then lowest id wins)
    3. cve                (finding.cve_id)
    4. cwe                (finding.cwe / cwe_ids)
    5. product            (finding.product / technology name)
    6. owasp              (finding.owasp, e.g. "A05:2021" or "A05")
    7. generic fallback   (built-in text, never None)

``seed_defaults`` is idempotent: it inserts built-in OWASP Top 10 + common
entries and (best effort) the content of the legacy ``marsadix.remediation``
module, never overwriting rows that already exist (so user edits survive).
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .dbutil import fetch_all, fetch_one, has_table

__all__ = ["MATCH_TYPES", "EFFORTS", "RemediationEntry", "add_entry", "get_entry", "list_entries",
           "search", "update_entry", "delete_entry", "lookup", "seed_defaults", "keyword_matches",
           "GENERIC_ENTRY", "RemediationError"]

MATCH_TYPES = ("skill", "template", "keyword", "cve", "cwe", "owasp", "product")
EFFORTS = ("low", "medium", "high")
_ORDER = ("skill", "template", "keyword", "cve", "cwe", "product", "owasp")


class RemediationError(ValueError):
    """Raised for invalid input."""


@dataclass
class RemediationEntry:
    id: Optional[int]
    match_type: str
    match_value: str
    title: str
    fix_text: str
    references: List[str] = field(default_factory=list)
    effort: str = "medium"
    priority: int = 50
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


GENERIC_ENTRY = RemediationEntry(
    None, "owasp", "generic", "Review and remediate",
    "Review the finding, confirm exposure, apply the vendor-recommended fix or a compensating control "
    "(restrict access, patch, harden configuration) and re-scan to verify.",
    ["https://owasp.org/Top10/"], "medium", 0)


# ---------------------------------------------------------------------------
def _norm_value(match_type: str, value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise RemediationError("match_value must not be empty")
    if match_type == "cve":
        return v.upper()
    if match_type == "cwe":
        v = v.upper()
        return v if v.startswith("CWE-") else f"CWE-{v}"
    if match_type == "owasp":
        m = re.match(r"^(A\d{1,2})", v.upper())
        return (m.group(1)[:1] + m.group(1)[1:].zfill(2)) if m else v.lower()
    return v.lower()


def _row(r: Mapping[str, Any]) -> RemediationEntry:
    try:
        refs = json.loads(r.get("references") or "[]")
    except ValueError:
        refs = []
    return RemediationEntry(r["id"], r["match_type"], r["match_value"], r["title"], r["fix_text"],
                            refs if isinstance(refs, list) else [], r["effort"], int(r["priority"]), r["created_at"])


def _validate(match_type: str, effort: str, priority: int) -> None:
    if match_type not in MATCH_TYPES:
        raise RemediationError(f"invalid match_type {match_type!r}; expected one of {', '.join(MATCH_TYPES)}")
    if effort not in EFFORTS:
        raise RemediationError(f"invalid effort {effort!r}; expected one of {', '.join(EFFORTS)}")
    if not isinstance(priority, int) or not 0 <= priority <= 100:
        raise RemediationError("priority must be an integer 0-100")


# ---- CRUD ------------------------------------------------------------------
def add_entry(conn: sqlite3.Connection, match_type: str, match_value: str, title: str, fix_text: str,
              references: Iterable[str] = (), effort: str = "medium", priority: int = 50,
              *, replace: bool = False) -> RemediationEntry:
    _validate(match_type, effort, priority)
    if not (title or "").strip() or not (fix_text or "").strip():
        raise RemediationError("title and fix_text are required")
    value = _norm_value(match_type, match_value)
    verb = "INSERT OR REPLACE" if replace else "INSERT"
    try:
        cur = conn.execute(
            f'{verb} INTO remediation(match_type,match_value,title,fix_text,"references",effort,priority) VALUES (?,?,?,?,?,?,?)',
            (match_type, value, title.strip(), fix_text.strip(), json.dumps(list(references)), effort, priority))
    except sqlite3.IntegrityError as exc:
        raise RemediationError(f"entry already exists for {match_type}:{value}") from exc
    conn.commit()
    return get_entry(conn, cur.lastrowid)  # type: ignore[arg-type]


def get_entry(conn: sqlite3.Connection, entry_id: int) -> Optional[RemediationEntry]:
    r = fetch_one(conn, "SELECT * FROM remediation WHERE id=?", (entry_id,))
    return _row(r) if r else None


def list_entries(conn: sqlite3.Connection, match_type: Optional[str] = None) -> List[RemediationEntry]:
    if match_type:
        rows = fetch_all(conn, "SELECT * FROM remediation WHERE match_type=? ORDER BY match_type, match_value", (match_type,))
    else:
        rows = fetch_all(conn, "SELECT * FROM remediation ORDER BY match_type, match_value")
    return [_row(r) for r in rows]


def search(conn: sqlite3.Connection, term: str, limit: int = 50) -> List[RemediationEntry]:
    like = "%" + term.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = fetch_all(
        conn, "SELECT * FROM remediation WHERE lower(match_value) LIKE ? ESCAPE '\\' OR lower(title) LIKE ? ESCAPE '\\' "
              "OR lower(fix_text) LIKE ? ESCAPE '\\' ORDER BY priority DESC, id LIMIT ?", (like, like, like, limit))
    return [_row(r) for r in rows]


def update_entry(conn: sqlite3.Connection, entry_id: int, **changes: Any) -> RemediationEntry:
    cur = get_entry(conn, entry_id)
    if cur is None:
        raise RemediationError(f"no remediation entry with id {entry_id}")
    data = cur.to_dict()
    data.update({k: v for k, v in changes.items() if v is not None})
    _validate(data["match_type"], data["effort"], data["priority"])
    value = _norm_value(data["match_type"], data["match_value"])
    try:
        conn.execute('UPDATE remediation SET match_type=?, match_value=?, title=?, fix_text=?, "references"=?, effort=?, priority=? WHERE id=?',
                     (data["match_type"], value, data["title"], data["fix_text"], json.dumps(list(data["references"])),
                      data["effort"], data["priority"], entry_id))
    except sqlite3.IntegrityError as exc:
        raise RemediationError("another entry already uses that match_type/match_value") from exc
    conn.commit()
    return get_entry(conn, entry_id)  # type: ignore[return-value]


def delete_entry(conn: sqlite3.Connection, entry_id: int) -> bool:
    cur = conn.execute("DELETE FROM remediation WHERE id=?", (entry_id,))
    conn.commit()
    return cur.rowcount > 0


# ---- lookup ----------------------------------------------------------------
def _words(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9.+#]+", " ", (text or "").lower()).strip() + " "


def keyword_matches(keyword: str, text: str) -> bool:
    """Whole-word match; hyphen/underscore/space are interchangeable separators."""
    kw = _words(keyword)
    return len(kw.strip()) > 0 and kw in _words(text)


def _g(finding: Any, *names: str) -> Any:
    for n in names:
        v = finding.get(n) if isinstance(finding, Mapping) else getattr(finding, n, None)
        if v not in (None, "", [], ()):
            return v
    return None


def _one(conn: sqlite3.Connection, match_type: str, value: Any) -> Optional[RemediationEntry]:
    if value in (None, ""):
        return None
    try:
        v = _norm_value(match_type, str(value))
    except RemediationError:
        return None
    r = fetch_one(conn, "SELECT * FROM remediation WHERE match_type=? AND match_value=?", (match_type, v))
    return _row(r) if r else None


def lookup(conn: sqlite3.Connection, finding: Any) -> RemediationEntry:
    """Resolve the best remediation for a finding (dict or object). Never returns None."""
    if not has_table(conn, "remediation"):
        return GENERIC_ENTRY
    for mt, names in (("skill", ("skill", "skill_id")), ("template", ("template_id", "template"))):
        e = _one(conn, mt, _g(finding, *names))
        if e:
            return e
    text = " ".join(str(_g(finding, n) or "") for n in ("title", "description", "category", "rule_id", "name"))
    best = None
    for r in fetch_all(conn, "SELECT * FROM remediation WHERE match_type='keyword'"):
        if keyword_matches(r["match_value"], text):
            k = (int(r["priority"]), len(r["match_value"]), -int(r["id"]))
            if best is None or k > best[0]:
                best = (k, r)
    if best:
        return _row(best[1])
    e = _one(conn, "cve", _g(finding, "cve_id", "cve"))
    if e:
        return e
    cwe = _g(finding, "cwe", "cwe_id", "cwes", "cwe_ids")
    for c in (cwe if isinstance(cwe, (list, tuple)) else [cwe]):
        e = _one(conn, "cwe", c)
        if e:
            return e
    for c in (_g(finding, "product"), _g(finding, "technology"), _g(finding, "name")):
        e = _one(conn, "product", c)
        if e:
            return e
    e = _one(conn, "owasp", _g(finding, "owasp", "owasp_category"))
    return e or GENERIC_ENTRY


# ---- seed ------------------------------------------------------------------
_OWASP = [
    ("A01", "Broken Access Control", "Enforce server-side authorization on every request, deny by default, remove unneeded exposure and test access control paths.", "medium"),
    ("A02", "Cryptographic Failures", "Use TLS 1.2+ everywhere, strong ciphers, valid certificates and encrypt sensitive data at rest; rotate exposed secrets.", "medium"),
    ("A03", "Injection", "Use parameterized queries and context-aware output encoding; validate input server-side.", "medium"),
    ("A04", "Insecure Design", "Add threat modelling and secure design patterns; enforce rate limits and abuse-case tests.", "high"),
    ("A05", "Security Misconfiguration", "Apply a hardened baseline: disable debug/default features, remove unused services, set security headers, restrict exposure.", "low"),
    ("A06", "Vulnerable and Outdated Components", "Upgrade to a patched version, track dependencies and subscribe to vendor advisories.", "medium"),
    ("A07", "Identification and Authentication Failures", "Enforce MFA, strong password policy, lockout and remove default credentials.", "medium"),
    ("A08", "Software and Data Integrity Failures", "Verify signatures/integrity of updates and pipelines; avoid unsafe deserialization.", "medium"),
    ("A09", "Security Logging and Monitoring Failures", "Log security events centrally, alert on anomalies and protect log integrity.", "medium"),
    ("A10", "Server-Side Request Forgery", "Allow-list outbound destinations, block internal address ranges and validate URLs server-side.", "medium"),
]
_OWASP_REF = "https://owasp.org/Top10/"

# (match_type, value, title, fix_text, effort, priority)
_BUILTIN = [
    ("skill", "exposed-sensitive-file", "Remove exposed sensitive file", "Delete the file from the web root, block dotfiles/backups at the web server, rotate any secrets it contained and review access logs.", "low", 90),
    ("skill", "directory-listing", "Disable directory listing", "Disable autoindex (nginx: 'autoindex off'; Apache: 'Options -Indexes') and remove files that should not be public.", "low", 80),
    ("skill", "missing-security-headers", "Add security headers", "Set Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options/frame-ancestors, Referrer-Policy and Strict-Transport-Security (HTTPS only).", "low", 60),
    ("skill", "cors-misconfiguration", "Restrict CORS", "Replace '*' / reflected origins with an explicit allow-list and never combine wildcard origins with credentials.", "low", 80),
    ("skill", "exposed-admin-panel", "Restrict admin interface", "Put admin panels behind VPN/IP allow-list and MFA, change default credentials and remove public exposure.", "medium", 85),
    ("skill", "debug-endpoint", "Disable debug endpoints", "Disable actuator/phpinfo/debug consoles in production or restrict them to an internal network with authentication.", "low", 85),
    ("skill", "weak-tls", "Fix TLS configuration", "Disable SSLv3/TLS 1.0/1.1, enable TLS 1.2+, use strong ciphers and renew expired certificates.", "medium", 75),
    ("skill", "outdated-component", "Patch outdated component", "Upgrade the component to a vendor-patched release; if not possible, restrict exposure and apply virtual patching.", "medium", 80),
    ("skill", "exposed-service-port", "Close exposed service port", "Bind the service to localhost/private network, add firewall rules and require authentication.", "low", 95),
    ("skill", "verbose-error", "Suppress verbose errors", "Return generic error pages in production, disable stack traces/debug output and log details server-side only.", "low", 60),
    ("skill", "public-cloud-storage", "Lock down cloud storage", "Remove public ACLs, enable block-public-access and require authenticated, least-privilege access.", "low", 95),
    ("keyword", "sql injection", "Fix SQL injection", "Use parameterized queries / ORM bindings and least-privilege DB accounts.", "medium", 80),
    ("keyword", "xss", "Fix cross-site scripting", "Apply contextual output encoding, a strict CSP and sanitize user HTML.", "medium", 70),
    ("keyword", "csrf", "Add CSRF protection", "Use anti-CSRF tokens and SameSite cookies.", "low", 65),
    ("keyword", "open redirect", "Fix open redirect", "Validate redirect targets against an allow-list.", "low", 60),
    ("keyword", "default credentials", "Change default credentials", "Change all default accounts/passwords and enforce strong authentication.", "low", 90),
    ("keyword", "subdomain takeover", "Remove dangling DNS", "Remove or re-claim dangling CNAME/A records pointing to deprovisioned services.", "low", 85),
    ("product", "nginx", "Update nginx", "Upgrade nginx to the latest stable release and review security advisories.", "medium", 40),
    ("product", "http_server", "Update Apache HTTP Server", "Upgrade Apache httpd to the latest patched release and disable unused modules.", "medium", 40),
    ("product", "openssl", "Update OpenSSL", "Upgrade OpenSSL to a supported release and restart dependent services.", "medium", 40),
    ("product", "openssh", "Update OpenSSH", "Upgrade OpenSSH, disable password auth where possible and restrict access by network.", "medium", 40),
    ("cwe", "CWE-89", "SQL injection (CWE-89)", "Use parameterized queries and input validation.", "medium", 50),
    ("cwe", "CWE-79", "Cross-site scripting (CWE-79)", "Encode output contextually and use a strict CSP.", "medium", 50),
    ("cwe", "CWE-22", "Path traversal (CWE-22)", "Canonicalize and validate file paths against an allow-listed base directory.", "medium", 50),
]


def _legacy_entries() -> List[tuple]:
    """Best-effort import of the legacy static remediation module."""
    try:
        import importlib
        mod = importlib.import_module("marsadix.remediation")
    except Exception:
        return []
    out = []
    for name, val in vars(mod).items():
        if name.startswith("_") or not isinstance(val, dict) or not val:
            continue
        for k, v in val.items():
            if not isinstance(k, str):
                continue
            if isinstance(v, str):
                text, title = v, k.replace("_", " ").replace("-", " ").title()
            elif isinstance(v, Mapping):
                text = str(v.get("fix") or v.get("remediation") or v.get("text") or v.get("fix_text") or "")
                title = str(v.get("title") or k.replace("_", " ").title())
            else:
                continue
            if len(text) < 10:
                continue
            out.append(("skill", k.strip().lower(), title, text, "medium", 55))
    return out


def seed_defaults(conn: sqlite3.Connection, *, include_legacy: bool = True) -> int:
    """Insert built-in/legacy remediation rows that are missing. Returns rows inserted."""
    inserted = 0
    rows: List[tuple] = []
    for code, title, text, effort in _OWASP:
        rows.append(("owasp", code, f"{code}:2021 {title}", text, effort, 30))
    rows.extend(_BUILTIN)
    if include_legacy:
        rows.extend(_legacy_entries())
    for mt, value, title, text, effort, prio in rows:
        refs = [_OWASP_REF] if mt == "owasp" else []
        cur = conn.execute(
            'INSERT OR IGNORE INTO remediation(match_type,match_value,title,fix_text,"references",effort,priority) VALUES (?,?,?,?,?,?,?)',
            (mt, _norm_value(mt, value), title, text, json.dumps(refs), effort, prio))
        inserted += cur.rowcount
    conn.commit()
    return inserted
