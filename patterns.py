"""M16 - rule-based misconfiguration pattern hunter (passive: stored data only).

No probes are sent.  Rules read ``assets``, ``services``, ``technologies``, ``web_items``
and ``findings`` rows that earlier scans already stored.

Status semantics (never a false "confirmed"):
  * ``confirmed``     - at least one *definitive* evidence item (e.g. a directory-index page,
                        ``ref: refs/heads`` in /.git/HEAD, KEY=VALUE lines in /.env, a bucket listing)
  * ``needs-review``  - medium/high confidence indicator that a human should verify
  * ``possible``      - low confidence indicator (e.g. 200 on a backup-looking URL that returned HTML)

Each :class:`Rule` has ``id, title, severity, predicate, confidence, owasp, remediation_key``;
hits carry their own evidence and may override severity/confidence.  Findings are
deduplicated on ``pattern:<rule>|host:<host>|target:<target>`` both in-run and in the DB.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from . import p4data

__all__ = ["Rule", "Hit", "PatternData", "PatternFinding", "RULES", "hunt", "load_pattern_data", "persist_findings",
           "run_patterns", "SEVERITY_ORDER"]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class PatternData:
    assets: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    web_items: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class Hit:
    host: str
    target: str
    evidence: str
    definitive: bool = False
    severity: Optional[str] = None
    confidence: Optional[str] = None
    scan_id: Optional[int] = None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    predicate: Callable[[PatternData], Iterable[Hit]]
    confidence: str
    owasp: str
    remediation_key: str


@dataclass
class PatternFinding:
    rule_id: str
    title: str
    severity: str
    host: str
    target: str
    evidence: List[str]
    confidence: str
    status: str
    owasp: str
    remediation_key: str
    dedup_key: str
    scan_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


# ---- helpers ---------------------------------------------------------------
def _path(url: str) -> str:
    try:
        return urlsplit(url or "").path.lower() or "/"
    except ValueError:
        return "/"


def _ok(item: Mapping[str, Any]) -> bool:
    try:
        return 200 <= int(item.get("status_code") or 0) < 300
    except (TypeError, ValueError):
        return False


def _body(item: Mapping[str, Any]) -> str:
    return str(item.get("body") or "")[:20000]


def _is_html(item: Mapping[str, Any]) -> bool:
    ct = str(item.get("content_type") or (item.get("headers") or {}).get("content-type") or "").lower()
    return "html" in ct or (not ct and _body(item).lstrip()[:15].lower().startswith(("<!doctype", "<html")))


def _web(data: PatternData) -> Iterator[Mapping[str, Any]]:
    for w in data.web_items:
        if w.get("host") is not None or w.get("url"):
            yield w


def _hostof(w: Mapping[str, Any]) -> str:
    h = w.get("host")
    if h:
        return str(h)
    try:
        return urlsplit(w.get("url") or "").hostname or ""
    except ValueError:
        return ""


# ---- rule predicates ---------------------------------------------------------
_SENSITIVE = [
    (re.compile(r"/\.env(\.[\w.-]+)?$"), ".env file", "critical", re.compile(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S")),
    (re.compile(r"/\.git/(head|config|index|logs/head)$|/\.git/?$"), ".git repository metadata", "high", re.compile(r"ref: refs/|\[core\]|\[remote ")),
    (re.compile(r"/\.(svn|hg)/"), "VCS metadata", "high", None),
    (re.compile(r"/\.ds_store$"), ".DS_Store file", "low", re.compile(r"Bud1")),
    (re.compile(r"/\.htpasswd$"), ".htpasswd file", "high", re.compile(r"(?m)^[\w.-]+:\S{8,}")),
    (re.compile(r"/(id_rsa|id_dsa|id_ecdsa|id_ed25519)$"), "private key file", "critical", re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")),
    (re.compile(r"\.(bak|old|orig|swp|sql|dump|zip|tar|tgz|tar\.gz|7z|rar|backup)$|~$"), "backup/archive file", "high", None),
    (re.compile(r"/(wp-config|config|configuration|settings|database|db|web|application)\.(php|json|ya?ml|ini|xml|conf|inc)\.?(bak|old|txt|orig|save|swp)$"), "config backup file", "high", None),
]


def _exposed_files(data: PatternData) -> Iterator[Hit]:
    for w in _web(data):
        if not _ok(w):
            continue
        p = _path(w.get("url", ""))
        for rx, label, sev, sig in _SENSITIVE:
            if not rx.search(p):
                continue
            body = _body(w)
            if sig is not None and sig.search(body):
                yield Hit(_hostof(w), p, f"{label} reachable (HTTP {w.get('status_code')}) and content matches its signature: {w.get('url')}",
                          True, sev, "high", w.get("scan_id"))
            elif not _is_html(w):
                yield Hit(_hostof(w), p, f"{label} reachable (HTTP {w.get('status_code')}), non-HTML response: {w.get('url')}",
                          False, sev, "medium", w.get("scan_id"))
            else:
                yield Hit(_hostof(w), p, f"{label} URL answered HTTP {w.get('status_code')} with HTML (may be a soft-404): {w.get('url')}",
                          False, "medium", "low", w.get("scan_id"))
            break


_LISTING = re.compile(r"<title>\s*index of /|<h1>\s*index of /|directory listing for /|<a href=\"\?C=N;O=D\">|Parent Directory</a>", re.I)


def _dir_listing(data: PatternData) -> Iterator[Hit]:
    for w in _web(data):
        if _ok(w) and (_LISTING.search(_body(w)) or _LISTING.search(str(w.get("title") or ""))):
            yield Hit(_hostof(w), _path(w.get("url", "")), f"directory index page served at {w.get('url')}", True, scan_id=w.get("scan_id"))


_HEADERS = (("content-security-policy", "Content-Security-Policy"), ("x-content-type-options", "X-Content-Type-Options"),
            ("referrer-policy", "Referrer-Policy"), ("strict-transport-security", "Strict-Transport-Security"))


def _missing_headers(data: PatternData) -> Iterator[Hit]:
    per_host: Dict[str, Tuple[set, str, Optional[int]]] = {}
    for w in _web(data):
        hdrs = w.get("headers") or {}
        if not _ok(w) or not hdrs or not _is_html(w):
            continue
        missing = set()
        https = str(w.get("url", "")).lower().startswith("https://")
        for key, label in _HEADERS:
            if key == "strict-transport-security" and not https:
                continue
            if key not in hdrs:
                missing.add(label)
        csp = hdrs.get("content-security-policy", "")
        if "x-frame-options" not in hdrs and "frame-ancestors" not in csp.lower():
            missing.add("X-Frame-Options/frame-ancestors")
        host = _hostof(w)
        cur = per_host.get(host)
        per_host[host] = ((cur[0] | missing) if cur else missing, cur[1] if cur else str(w.get("url")), w.get("scan_id"))
    for host, (missing, url, scan) in sorted(per_host.items()):
        if missing:
            sev = "medium" if len(missing) >= 4 else "low"
            yield Hit(host, "headers", f"missing security headers: {', '.join(sorted(missing))} (e.g. {url})", False, sev, "high", scan)


def _cors(data: PatternData) -> Iterator[Hit]:
    for w in _web(data):
        h = w.get("headers") or {}
        acao, acac = h.get("access-control-allow-origin", "").strip(), h.get("access-control-allow-credentials", "").strip().lower()
        if not acao:
            continue
        origin = str(w.get("origin") or "").strip()
        host = _hostof(w)
        t = _path(w.get("url", ""))
        if acao == "*" and acac == "true":
            yield Hit(host, t, f"Access-Control-Allow-Origin '*' together with Allow-Credentials true at {w.get('url')}", False, "high", "medium", w.get("scan_id"))
        elif acao == "*":
            yield Hit(host, t, f"wildcard Access-Control-Allow-Origin at {w.get('url')}", False, "low", "medium", w.get("scan_id"))
        elif origin and acao == origin and host not in origin:
            yield Hit(host, t, f"Access-Control-Allow-Origin reflects the request Origin {origin!r}" + (" with credentials" if acac == "true" else "") + f" at {w.get('url')}",
                      False, "high" if acac == "true" else "medium", "medium", w.get("scan_id"))
        elif acao.lower() == "null":
            yield Hit(host, t, f"Access-Control-Allow-Origin 'null' at {w.get('url')}", False, "medium", "medium", w.get("scan_id"))


_ADMIN = re.compile(r"/(wp-admin|wp-login\.php|phpmyadmin|pma|adminer(\.php)?|manager/html|admin|administrator|cpanel|webmin|solr|jenkins|grafana|kibana|console)(/|$)")


def _admin_panels(data: PatternData) -> Iterator[Hit]:
    for w in _web(data):
        p = _path(w.get("url", ""))
        if not _ADMIN.search(p):
            continue
        try:
            code = int(w.get("status_code") or 0)
        except (TypeError, ValueError):
            continue
        if code == 200:
            yield Hit(_hostof(w), p, f"admin interface reachable without redirect at {w.get('url')}", False, "medium", "medium", w.get("scan_id"))
        elif code == 401:
            yield Hit(_hostof(w), p, f"admin interface exposed to the internet (authentication prompt) at {w.get('url')}", False, "low", "low", w.get("scan_id"))


_DEFAULT = re.compile(r"default (password|credentials|login)|admin\s*/\s*admin|admin:admin|installation wizard|initial setup|"
                      r"please (change|set) (the )?(default )?password|tomcat manager application", re.I)


def _default_login(data: PatternData) -> Iterator[Hit]:
    for w in _web(data):
        if _ok(w) and (_DEFAULT.search(_body(w)) or _DEFAULT.search(str(w.get("title") or ""))):
            yield Hit(_hostof(w), _path(w.get("url", "")), f"page hints at default credentials / setup mode: {w.get('url')}", False, "high", "low", w.get("scan_id"))


_DEBUG = [
    (re.compile(r"/actuator/(env|heapdump|configprops|beans|mappings|threaddump|loggers|httptrace|jolokia)$"), "Spring actuator sensitive endpoint", "high", re.compile(r'"(activeProfiles|propertySources|beans|contexts)"|JAVA PROFILE|HPROF', re.I)),
    (re.compile(r"/actuator/?$"), "Spring actuator index", "medium", re.compile(r'"_links"')),
    (re.compile(r"/(phpinfo|info|test|pi)\.php$"), "phpinfo page", "medium", re.compile(r"phpinfo\(\)|PHP Version", re.I)),
    (re.compile(r"/server-(status|info)$"), "Apache server status/info", "medium", re.compile(r"Apache Server Status|Server Version", re.I)),
    (re.compile(r"/(console|_debug|__debug__|_profiler|_debugbar|telescope|elmah\.axd|trace\.axd)(/|$)"), "debug/profiler console", "high", re.compile(r"Werkzeug|Interactive Console|Symfony Profiler|Laravel Telescope|ELMAH|Debug Toolbar", re.I)),
]


def _debug(data: PatternData) -> Iterator[Hit]:
    for w in _web(data):
        if not _ok(w):
            continue
        p = _path(w.get("url", ""))
        for rx, label, sev, sig in _DEBUG:
            if rx.search(p):
                d = bool(sig.search(_body(w)))
                yield Hit(_hostof(w), p, f"{label} reachable at {w.get('url')}" + (" (content signature matched)" if d else ""),
                          d, sev, "high" if d else "medium", w.get("scan_id"))
                break


_WEAK_TLS = {"sslv2": "critical", "sslv3": "high", "tlsv1": "high", "tlsv1.0": "high", "tls1.0": "high", "tlsv1.1": "medium", "tls1.1": "medium"}


def _parse_dt(v: Any) -> Optional[datetime]:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _tls(data: PatternData) -> Iterator[Hit]:
    for s in data.services:
        host, port = str(s.get("host") or ""), s.get("port")
        ver = str(s.get("tls_version") or "").lower().replace(" ", "")
        if ver in _WEAK_TLS:
            yield Hit(host, f"port:{port}:version", f"service on port {port} negotiates deprecated {s.get('tls_version')}", False, _WEAK_TLS[ver], "high", s.get("scan_id"))
        exp = _parse_dt(s.get("tls_not_after"))
        if (exp and exp < data.now) or str(s.get("tls_expired") or "").lower() in ("1", "true"):
            yield Hit(host, f"port:{port}:expired", f"TLS certificate on port {port} expired" + (f" on {exp.date()}" if exp else ""), False, "high", "high", s.get("scan_id"))


def _outdated(data: PatternData) -> Iterator[Hit]:
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for f in data.findings:
        if str(f.get("status") or "open").lower() in ("fixed", "resolved", "closed", "false_positive"):
            continue
        cve = f.get("cve_id")
        if not cve:
            continue
        cvss = f.get("cvss")
        if int(f.get("kev") or 0) or (cvss is not None and float(cvss) >= 7.0):
            groups.setdefault((str(f.get("host") or ""), str(f.get("product") or "unknown")), []).append(f)
    for (host, product), items in sorted(groups.items()):
        ids = sorted({str(i["cve_id"]) for i in items})
        kev = any(int(i.get("kev") or 0) for i in items)
        yield Hit(host, f"product:{product.lower()}", f"{product} {items[0].get('version') or ''} has {len(ids)} high-impact known CVE(s): {', '.join(ids[:10])}".replace("  ", " "),
                  False, "critical" if kev else "high", "high" if any(str(i.get('confidence')).lower() == "high" for i in items) else "medium", items[0].get("scan_id"))


_PORTS = {3306: ("MySQL", "high"), 5432: ("PostgreSQL", "high"), 1433: ("MS SQL Server", "high"), 1521: ("Oracle DB", "high"),
          27017: ("MongoDB", "critical"), 6379: ("Redis", "critical"), 11211: ("Memcached", "high"), 9200: ("Elasticsearch", "critical"),
          5984: ("CouchDB", "high"), 2375: ("Docker API (unauthenticated)", "critical"), 2379: ("etcd", "high"), 5900: ("VNC", "high"),
          3389: ("RDP", "high"), 5601: ("Kibana", "high"), 8500: ("Consul", "high"), 9042: ("Cassandra", "high"), 15672: ("RabbitMQ management", "medium"),
          5672: ("RabbitMQ AMQP", "medium"), 10250: ("Kubelet API", "high"), 8888: ("Jupyter", "high"), 23: ("Telnet", "high"), 445: ("SMB", "high")}


def _open_ports(data: PatternData) -> Iterator[Hit]:
    facing = {str(a.get("host")): str(a.get("internet_facing", 1)).lower() not in ("0", "false") for a in data.assets}
    for s in data.services:
        try:
            port = int(s.get("port"))
        except (TypeError, ValueError):
            continue
        if port not in _PORTS or str(s.get("state") or "open").lower() != "open":
            continue
        host = str(s.get("host") or "")
        if not facing.get(host, True):
            continue
        name, sev = _PORTS[port]
        yield Hit(host, f"port:{port}", f"{name} port {port}/{s.get('protocol') or 'tcp'} open on an internet-facing host", False, sev, "high", s.get("scan_id"))


_VERBOSE = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback", "medium"),
    (re.compile(r"\bat [\w.$]+\([\w]+\.java:\d+\)|Exception in thread|java\.lang\.\w+Exception"), "Java stack trace", "medium"),
    (re.compile(r"System\.\w+Exception|Stack trace:|Server Error in '/' Application"), ".NET/PHP stack trace", "medium"),
    (re.compile(r"Fatal error:.* in .* on line \d+|Warning: (mysql|pg|oci)\w*\(|Parse error: syntax error"), "PHP error output", "medium"),
    (re.compile(r"SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|PG::\w+Error|SQLite3::"), "database error message", "high"),
    (re.compile(r"Whitelabel Error Page|Django.*DEBUG = True|Laravel.*Whoops|Rails\.root:"), "framework debug error page", "medium"),
]


def _verbose(data: PatternData) -> Iterator[Hit]:
    for w in _web(data):
        b = _body(w)
        for rx, label, sev in _VERBOSE:
            if rx.search(b):
                yield Hit(_hostof(w), _path(w.get("url", "")), f"{label} disclosed at {w.get('url')} (HTTP {w.get('status_code')})", False, sev, "medium", w.get("scan_id"))
                break


_CLOUD_LISTING = re.compile(r"<ListBucketResult|<EnumerationResults|\"kind\":\s*\"storage#objects\"")


def _cloud_storage(data: PatternData) -> Iterator[Hit]:
    for w in _web(data):
        if not _ok(w):
            continue
        if _CLOUD_LISTING.search(_body(w)):
            yield Hit(_hostof(w), _path(w.get("url", "")), f"cloud storage bucket listing is publicly readable at {w.get('url')}", True, "high", "high", w.get("scan_id"))
    for f in data.findings:
        txt = f"{f.get('title') or ''} {f.get('description') or ''}"
        if re.search(r"public (s3|bucket|blob|container)|bucket.*(public|AllUsers)", txt, re.I) and f.get("source") != "pattern":
            yield Hit(str(f.get("host") or ""), f"finding:{f.get('id')}", f"stored finding hints at public cloud storage: {str(f.get('title'))[:120]}", False, "medium", "low", f.get("scan_id"))


RULES: List[Rule] = [
    Rule("exposed-sensitive-file", "Exposed sensitive file (.env/.git/backup/config)", "high", _exposed_files, "medium", "A05:2021", "exposed-sensitive-file"),
    Rule("directory-listing", "Directory listing enabled", "medium", _dir_listing, "high", "A05:2021", "directory-listing"),
    Rule("missing-security-headers", "Missing security headers", "low", _missing_headers, "high", "A05:2021", "missing-security-headers"),
    Rule("cors-misconfiguration", "Permissive or reflected CORS policy", "medium", _cors, "medium", "A05:2021", "cors-misconfiguration"),
    Rule("exposed-admin-panel", "Admin interface exposed", "medium", _admin_panels, "medium", "A05:2021", "exposed-admin-panel"),
    Rule("default-login-panel", "Default credentials / setup mode hint", "high", _default_login, "low", "A07:2021", "default credentials"),
    Rule("debug-endpoint", "Debug / actuator / phpinfo endpoint exposed", "high", _debug, "medium", "A05:2021", "debug-endpoint"),
    Rule("weak-tls", "Weak or expired TLS", "medium", _tls, "high", "A02:2021", "weak-tls"),
    Rule("outdated-component", "Outdated component with known exploitable CVEs", "high", _outdated, "medium", "A06:2021", "outdated-component"),
    Rule("exposed-service-port", "Database/cache/admin service port exposed", "high", _open_ports, "high", "A05:2021", "exposed-service-port"),
    Rule("verbose-error", "Verbose error / stack trace disclosure", "low", _verbose, "medium", "A05:2021", "verbose-error"),
    Rule("public-cloud-storage", "Public or unsafe cloud storage", "high", _cloud_storage, "medium", "A01:2021", "public-cloud-storage"),
]


def _status(definitive: bool, confidence: str) -> str:
    if definitive:
        return "confirmed"
    return "possible" if confidence == "low" else "needs-review"


def hunt(data: PatternData, rules: Iterable[Rule] = RULES) -> List[PatternFinding]:
    out: Dict[str, PatternFinding] = {}
    for rule in rules:
        for hit in rule.predicate(data):
            host = (hit.host or "").lower()
            key = f"pattern:{rule.id}|host:{host}|target:{hit.target}"
            sev = hit.severity or rule.severity
            conf = hit.confidence or rule.confidence
            cur = out.get(key)
            if cur is None:
                out[key] = PatternFinding(rule.id, rule.title, sev, host, hit.target, [hit.evidence], conf,
                                          _status(hit.definitive, conf), rule.owasp, rule.remediation_key, key, hit.scan_id)
            else:  # in-run dedup: merge evidence, keep strongest severity / status
                if hit.evidence not in cur.evidence:
                    cur.evidence.append(hit.evidence)
                if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(cur.severity, 0):
                    cur.severity = sev
                if hit.definitive:
                    cur.status = "confirmed"
    return sorted(out.values(), key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.host, f.rule_id, f.target))


def load_pattern_data(conn: sqlite3.Connection, now: Optional[datetime] = None) -> PatternData:
    return PatternData(assets=p4data.load_assets(conn), services=p4data.load_services(conn),
                       technologies=p4data.load_technologies(conn), web_items=p4data.load_web_items(conn),
                       findings=p4data.load_findings(conn), now=now or datetime.now(timezone.utc))


def persist_findings(conn: sqlite3.Connection, findings: Iterable[PatternFinding], *, monitor_run_id: Optional[int] = None) -> Dict[str, int]:
    created = updated = 0
    default_scan = p4data.latest_scan_id(conn)
    for f in findings:
        res = p4data.upsert_finding(conn, f.dedup_key, {
            "scan_id": f.scan_id if f.scan_id is not None else default_scan, "host": f.host, "title": f.title,
            "severity": f.severity, "status": f.status, "category": "pattern", "source": "pattern", "rule_id": f.rule_id,
            "owasp": f.owasp, "remediation_key": f.remediation_key, "confidence": f.confidence,
            "evidence": "\n".join(f.evidence)[:8000], "description": "\n".join(f.evidence)[:2000], "template_id": f.rule_id,
            "monitor_run_id": monitor_run_id})
        created += res["created"]
        updated += not res["created"]
    conn.commit()
    return {"created": created, "updated": updated}


def run_patterns(conn: sqlite3.Connection, *, persist: bool = True, now: Optional[datetime] = None) -> List[PatternFinding]:
    found = hunt(load_pattern_data(conn, now))
    if persist:
        persist_findings(conn, found)
    return found
