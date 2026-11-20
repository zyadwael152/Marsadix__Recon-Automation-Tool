"""
cve_verify.py — Post-Nuclei CVE verification layer (v2.0)
==========================================================
الإصلاحات في v2.0:
  - فصل "version detection" عن "vulnerability check" تماماً
  - version detection بيشتغل دايماً حتى لو Brotli مش مفعّل كـ encoding
  - إضافة strategy للـ SSH CVEs (قراءة SSH banner على port 22)
  - إضافة Go version detection
  - إضافة fallback strategies أكثر لـ Node.js version
  - تحسين الـ confidence logic
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import http.client
from dataclasses import dataclass, field
from typing import Optional, List
from urllib.parse import urlsplit
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CVE affected ranges
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AffectedRange:
    introduced: str
    fixed: str
    component: str

    def is_affected(self, version_str: str) -> Optional[bool]:
        try:
            v   = Version(version_str)
            lo  = Version(self.introduced)
            hi  = Version(self.fixed)
            return lo <= v < hi
        except InvalidVersion:
            return None


CVE_RANGES: dict[str, list[AffectedRange]] = {
    "CVE-2026-111497": [
        AffectedRange("1.0.3", "1.0.10", "brotli"),
        AffectedRange("1.1.0", "1.1.1",  "brotli"),
        AffectedRange("1.2.0", "1.2.1",  "brotli"),
    ],
    "CVE-2025-22873": [
        # golang.org/x/crypto/ssh — path escape via Root.Open("../")
        # fixed in golang.org/x/crypto v0.35.0
        AffectedRange("0.0.1", "0.35.0", "golang.org/x/crypto"),
    ],
}

# Node.js release → bundled Brotli version
_NODE_TO_BROTLI: list[tuple[str, str, str]] = [
    ("18.0.0", "18.20.5", "1.0.9"),
    ("20.0.0", "20.18.1", "1.1.0"),
    ("22.0.0", "22.11.0", "1.1.0"),
    ("23.0.0", "23.1.0",  "1.2.0"),
    ("24.0.0", "24.0.2",  "1.2.0"),
]

# Go release → x/crypto version (approximate)
_GO_TO_XCRYPTO: list[tuple[str, str, str]] = [
    ("1.21.0", "1.21.13", "0.17.0"),
    ("1.22.0", "1.22.8",  "0.28.0"),
    ("1.23.0", "1.23.3",  "0.31.0"),
    ("1.24.0", "1.24.2",  "0.33.0"),
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class VerificationResult:
    cve_id: str
    host: str
    detected_version: Optional[str] = None
    detection_method: Optional[str] = None
    is_affected: Optional[bool] = None
    component_present: Optional[bool] = None
    suggested_confidence: str = "low"
    notes: str = ""
    # قايمة بكل الـ methods اللي جرّبناها (للـ debugging)
    tried_methods: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def _fetch(host: str, port: int, path: str = "/",
           tls: bool = True, timeout: float = 8.0,
           accept_encoding: str = "identity") -> Optional[tuple]:
    """
    Returns (status, headers_dict, body_bytes) or None on failure.
    headers_dict: lowercase keys.
    """
    try:
        ctx = None
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        if tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": "Marsadix/2.0 (authorized security assessment)",
            "Accept": "*/*",
            "Accept-Encoding": accept_encoding,
        })
        resp = conn.getresponse()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read(8192)
        return (resp.status, hdrs, body)
    except Exception as exc:
        logger.debug("_fetch %s:%d%s failed: %s", host, port, path, exc)
        return None


# ---------------------------------------------------------------------------
# Version extractors — مستقلة عن الـ CVE
# ---------------------------------------------------------------------------

def _extract_node_version(host: str, port: int, tls: bool) -> Optional[tuple[str, str]]:
    """
    Returns (version_str, method) or None.
    يجرّب كل الـ strategies بالترتيب من الأكثر دقة للأقل.
    """
    # Strategy 1: Server / X-Powered-By header
    for path in ("/", "/favicon.ico"):
        r = _fetch(host, port, path, tls)
        if not r:
            continue
        _, hdrs, _ = r
        for hdr in ("server", "x-powered-by", "x-runtime"):
            val = hdrs.get(hdr, "")
            m = re.search(r"[Nn]ode[./ ]v?(\d+\.\d+\.\d+)", val)
            if m:
                return m.group(1), f"HTTP header '{hdr}': {val}"

    # Strategy 2: Common version/health endpoints (JSON)
    for path in ("/version", "/_version", "/api/version", "/api/v1/version",
                 "/health", "/_health", "/api/health", "/status", "/api/status",
                 "/__version__", "/info", "/api/info", "/.well-known/version"):
        r = _fetch(host, port, path, tls)
        if not r:
            continue
        status, hdrs, body = r
        if status not in (200, 206):
            continue
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            continue

        # Node version مباشرة في JSON
        for pattern in [
            r'"node(?:Version|_version|\.version)"[:\s]+"?v?(\d+\.\d+\.\d+)"?',
            r'"node"[:\s]+"?v?(\d+\.\d+\.\d+)"?',
            r'"runtime"[:\s]+"?[Nn]ode[./ ]v?(\d+\.\d+\.\d+)"?',
            r'"version"[:\s]+"?v?(\d+\.\d+\.\d+)"?',
            r'[Nn]ode\.js[/ ]v?(\d+\.\d+\.\d+)',
        ]:
            m = re.search(pattern, text)
            if m:
                return m.group(1), f"JSON endpoint {path}"

        # Brotli version مباشرة
        m = re.search(r'"brotli"[:\s]+"?(\d+\.\d+\.\d+)"?', text, re.I)
        if m:
            return m.group(1), f"brotli field in {path}"

    # Strategy 3: Error pages (404 / 500 responses)
    for path in ("/this-path-does-not-exist-marsadix-probe",):
        r = _fetch(host, port, path, tls)
        if not r:
            continue
        _, _, body = r
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            continue
        m = re.search(r"[Nn]ode[./ ]v?(\d+\.\d+\.\d+)", text)
        if m:
            return m.group(1), f"error page at {path}"

    # Strategy 4: ETag / Last-Modified timing heuristics (low confidence)
    # (محتاج implementation أكتر تعقيداً — placeholder)

    return None


def _extract_brotli_version(host: str, port: int, tls: bool) -> Optional[tuple[str, str]]:
    """
    محاولة جيب Brotli version بشكل مستقل.
    الغالب بنستنتجه من Node version.
    """
    # محاولة 1: Brotli مباشرة من endpoints
    for path in ("/health", "/api/health", "/version", "/api/version", "/status"):
        r = _fetch(host, port, path, tls)
        if not r:
            continue
        status, _, body = r
        if status not in (200, 206):
            continue
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            continue
        m = re.search(r'"brotli"[:\s]+"?(\d+\.\d+\.\d+)"?', text, re.I)
        if m:
            return m.group(1), f"brotli field in {path}"

    # محاولة 2: استنتاج من Node version
    node_result = _extract_node_version(host, port, tls)
    if node_result:
        node_ver_str, node_method = node_result
        brotli_ver = _infer_brotli_from_node(node_ver_str)
        if brotli_ver:
            return brotli_ver, f"inferred from Node.js {node_ver_str} ({node_method})"

    return None


def _infer_brotli_from_node(node_ver_str: str) -> Optional[str]:
    try:
        node_ver = Version(node_ver_str)
    except InvalidVersion:
        return None
    for lo, hi, brotli in _NODE_TO_BROTLI:
        try:
            if Version(lo) <= node_ver < Version(hi):
                return brotli
        except InvalidVersion:
            continue
    return None


def _check_brotli_content_encoding(host: str, port: int, tls: bool) -> bool:
    """هل السيرفر بيرد بـ Content-Encoding: br لو طلبناه؟"""
    r = _fetch(host, port, "/", tls, accept_encoding="br, gzip, deflate")
    if not r:
        return False
    _, hdrs, _ = r
    return "br" in (hdrs.get("content-encoding") or "").lower()


# ---------------------------------------------------------------------------
# SSH version detection (للـ Go CVEs)
# ---------------------------------------------------------------------------

def _extract_ssh_banner(host: str, port: int = 22,
                         timeout: float = 8.0) -> Optional[tuple[str, str]]:
    """
    قراءة SSH banner الـ plain-text اللي بيبعته أي SSH server قبل authentication.
    مثال: SSH-2.0-Go   أو   SSH-2.0-OpenSSH_9.2
    Returns (banner_line, raw_banner) or None.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        # الـ SSH server بيبعت الـ banner فوراً من غير ما نطلب
        banner = b""
        while len(banner) < 512:
            chunk = sock.recv(256)
            if not chunk:
                break
            banner += chunk
            if b"\n" in banner:
                break
        sock.close()
        line = banner.decode("utf-8", errors="replace").strip()
        return line, line
    except Exception as exc:
        logger.debug("SSH banner read from %s:%d failed: %s", host, port, exc)
        return None


def _extract_go_version_from_ssh(host: str, port: int = 22) -> Optional[tuple[str, str]]:
    """
    Go SSH servers بيبعتوا: SSH-2.0-Go
    ما بيبعتوش الـ Go version في الـ banner مباشرة،
    بس ممكن نستنتج من الـ server string.
    """
    result = _extract_ssh_banner(host, port)
    if not result:
        return None
    banner, _ = result

    # SSH-2.0-Go → بيبقى Go SSH implementation
    if re.search(r"SSH-2\.0-Go\b", banner, re.I):
        return "Go", f"SSH banner: {banner}"

    # SSH-2.0-Go_1.21.5 (بعض الـ builds بيحطوا الـ version)
    m = re.search(r"SSH-2\.0-Go[_/](\d+\.\d+(?:\.\d+)?)", banner, re.I)
    if m:
        return m.group(1), f"SSH banner: {banner}"

    return None


def _infer_xcrypto_from_go(go_ver_str: str) -> Optional[str]:
    """استنتج x/crypto version من Go version."""
    try:
        go_ver = Version(go_ver_str)
    except InvalidVersion:
        return None
    for lo, hi, xcrypto in _GO_TO_XCRYPTO:
        try:
            if Version(lo) <= go_ver < Version(hi):
                return xcrypto
        except InvalidVersion:
            continue
    return None


# ---------------------------------------------------------------------------
# CVE-specific verification strategies
# ---------------------------------------------------------------------------

def _verify_brotli_cve(host: str, port: int, tls: bool,
                        res: VerificationResult) -> VerificationResult:
    """
    CVE-2026-111497 — Brotli buffer overflow.

    المنطق الصحيح:
      1. جيب الـ Brotli version بكل الطرق المتاحة (بغض النظر عن encoding)
      2. لو لقيناها → قارن بالـ affected range
      3. الـ content-encoding: br معلومة إضافية بس مش شرط
    """
    res.tried_methods = []

    # الخطوة 1: جيب Brotli version بكل الطرق
    brotli_result = _extract_brotli_version(host, port, tls)
    res.tried_methods.append("brotli_direct + node_inference")

    if brotli_result:
        brotli_ver, method = brotli_result
        res.detected_version = brotli_ver
        res.detection_method = method

        # هل بيستخدم Brotli كـ content encoding؟ (معلومة إضافية)
        res.component_present = _check_brotli_content_encoding(host, port, tls)
        res.tried_methods.append("content-encoding check")

        # الخطوة 2: قارن بالـ affected range
        ranges = CVE_RANGES.get(res.cve_id, [])
        for r in ranges:
            affected = r.is_affected(brotli_ver)
            if affected is True:
                res.is_affected = True
                res.suggested_confidence = "high" if res.component_present else "medium"
                res.notes = (
                    f"Brotli {brotli_ver} is in affected range "
                    f"[{r.introduced}, {r.fixed}). "
                    f"Detection: {method}. "
                    f"Brotli used as content-encoding: {res.component_present}."
                )
                return res
            elif affected is False:
                res.is_affected = False
                res.suggested_confidence = "confirmed_not_affected"
                res.notes = (
                    f"Brotli {brotli_ver} is NOT in affected range "
                    f"[{r.introduced}, {r.fixed}). "
                    f"Detection: {method}. This is a false positive."
                )
                return res

    # الخطوة 3: ما لقيناش الـ version
    # هنتحقق على الأقل إن الـ component موجود
    res.component_present = _check_brotli_content_encoding(host, port, tls)
    res.tried_methods.append("content-encoding fallback")

    if res.component_present:
        res.notes = (
            "Server uses Brotli content-encoding but exact version could not be determined. "
            f"Tried: {', '.join(res.tried_methods)}. "
            "Consider manual version check."
        )
        res.suggested_confidence = "medium"
    else:
        # محاولة أخيرة: هل في Node.js على الإطلاق؟
        node_result = _extract_node_version(host, port, tls)
        if node_result:
            node_ver, node_method = node_result
            res.detected_version = f"Node/{node_ver} (Brotli unknown)"
            res.detection_method = node_method
            res.notes = (
                f"Node.js {node_ver} detected ({node_method}) but "
                "Brotli version could not be mapped and content-encoding:br is not active. "
                f"CVE-2026-111497 may not be applicable or Brotli is handled upstream."
            )
            res.suggested_confidence = "low"
        else:
            res.notes = (
                "Could not detect Node.js or Brotli version. "
                f"Server does not use Brotli content-encoding. "
                f"Tried: {', '.join(res.tried_methods)}. "
                "Likely false positive — Brotli not in use."
            )
            res.suggested_confidence = "low"

    return res


def _verify_golang_ssh_cve(host: str, port: int, tls: bool,
                             res: VerificationResult) -> VerificationResult:
    """
    CVE-2025-22873 — golang.org/x/crypto/ssh path escape.

    Strategy:
      1. قرا الـ SSH banner على port 22
      2. تحقق إن السيرفر Go SSH
      3. استنتج الـ x/crypto version
    """
    res.tried_methods = []

    # SSH بيشتغل على port 22 مش 80/443
    ssh_port = 22

    # خطوة 1: SSH banner
    res.tried_methods.append(f"SSH banner on port {ssh_port}")
    go_result = _extract_go_version_from_ssh(host, ssh_port)

    if not go_result:
        res.component_present = False
        res.notes = (
            f"Could not connect to {host}:{ssh_port} or SSH banner "
            "is not a Go SSH implementation. CVE-2025-22873 may not apply."
        )
        res.suggested_confidence = "low"
        return res

    go_ver_or_label, banner_method = go_result
    res.component_present = True
    res.tried_methods.append(f"SSH is Go implementation: {go_ver_or_label}")

    # لو بس "Go" من غير version رقم
    if go_ver_or_label == "Go":
        res.detected_version = "Go/unknown"
        res.detection_method = banner_method
        res.notes = (
            "SSH server is Go implementation (confirmed from banner). "
            "Exact Go version not in banner. "
            "Cannot determine x/crypto version automatically — "
            "manual check required (e.g., check /proc/self/exe or deploy metadata)."
        )
        res.suggested_confidence = "medium"
        return res

    # لو عندنا Go version رقم
    xcrypto_ver = _infer_xcrypto_from_go(go_ver_or_label)
    if xcrypto_ver:
        res.detected_version = xcrypto_ver
        res.detection_method = f"inferred from Go {go_ver_or_label} via {banner_method}"

        ranges = CVE_RANGES.get(res.cve_id, [])
        for r in ranges:
            affected = r.is_affected(xcrypto_ver)
            if affected is True:
                res.is_affected = True
                res.suggested_confidence = "high"
                res.notes = (
                    f"Go {go_ver_or_label} → x/crypto {xcrypto_ver} "
                    f"is in affected range [{r.introduced}, {r.fixed}). "
                    f"Detection: {res.detection_method}."
                )
                return res
            elif affected is False:
                res.is_affected = False
                res.suggested_confidence = "confirmed_not_affected"
                res.notes = (
                    f"Go {go_ver_or_label} → x/crypto {xcrypto_ver} "
                    f"is NOT in affected range [{r.introduced}, {r.fixed}). "
                    "Likely false positive."
                )
                return res

    res.notes = (
        f"Go SSH confirmed but x/crypto version could not be determined. "
        f"Go version from banner: {go_ver_or_label}. "
        f"Detection: {banner_method}."
    )
    res.suggested_confidence = "medium"
    return res


def _generic_version_check(cve_id: str, host: str, port: int, tls: bool,
                             res: VerificationResult) -> VerificationResult:
    """Fallback عام لأي CVE مفيش ليه strategy خاصة."""
    r = _fetch(host, port, "/", tls)
    if r:
        _, hdrs, _ = r
        server = hdrs.get("server") or hdrs.get("x-powered-by") or ""
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", server)
        if m:
            ver = m.group(1)
            for rng in CVE_RANGES.get(cve_id, []):
                affected = rng.is_affected(ver)
                if affected is True:
                    res.detected_version = ver
                    res.detection_method = f"Server header: {server}"
                    res.is_affected = True
                    res.suggested_confidence = "medium"
                    res.notes = f"Version {ver} in affected range [{rng.introduced}, {rng.fixed})."
                    return res
                elif affected is False:
                    res.detected_version = ver
                    res.detection_method = f"Server header: {server}"
                    res.is_affected = False
                    res.suggested_confidence = "confirmed_not_affected"
                    res.notes = f"Version {ver} NOT in affected range. Likely false positive."
                    return res
    res.notes = "No version detected. Keeping Nuclei confidence."
    return res


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

def verify_cve(cve_id: str, url: str, timeout: float = 10.0) -> VerificationResult:
    """
    الدالة الرئيسية.
    بتستقبل CVE ID و URL وبترجع VerificationResult.
    """
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    tls  = parsed.scheme == "https"

    res = VerificationResult(cve_id=cve_id, host=host)

    if cve_id not in CVE_RANGES:
        res.notes = f"No strategy for {cve_id}. Keeping Nuclei result."
        return res

    if cve_id == "CVE-2026-111497":
        return _verify_brotli_cve(host, port, tls, res)

    if cve_id == "CVE-2025-22873":
        return _verify_golang_ssh_cve(host, port, tls, res)

    return _generic_version_check(cve_id, host, port, tls, res)


# ---------------------------------------------------------------------------
# Apply verification to Finding
# ---------------------------------------------------------------------------

def apply_verification(finding, result: VerificationResult):
    """
    بتحدّث الـ Finding بناءً على نتيجة verify_cve.
    Returns None لو confirmed false positive (يتحذف من الـ batch).
    """
    if result.suggested_confidence == "confirmed_not_affected":
        logger.info("False positive: %s on %s — %s",
                    result.cve_id, result.host, result.notes)
        return None

    # حدّث الـ evidence
    if result.notes:
        try:
            import json
            ev = json.loads(finding.evidence) if finding.evidence else {}
            ev["verification"] = {
                "detected_version":  result.detected_version,
                "detection_method":  result.detection_method,
                "is_affected":       result.is_affected,
                "component_present": result.component_present,
                "confidence_upgrade": result.suggested_confidence,
                "notes":             result.notes,
                "tried_methods":     result.tried_methods,
            }
            finding.evidence = json.dumps(ev, sort_keys=True, default=str)[:4000]
        except Exception:
            pass

    # حدّث الـ confidence
    _MAP = {
        "high":   _conf("CONFIRMED"),
        "medium": _conf("LIKELY"),
        "low":    _conf("LOW"),
    }
    new_conf = _MAP.get(result.suggested_confidence)
    if new_conf and result.suggested_confidence != "low":
        finding.confidence       = new_conf
        finding.verified         = (result.suggested_confidence == "high")
        finding.verification_method = result.detection_method or \
                                       getattr(finding, "verification_method", None)
    return finding


def _conf(name: str):
    try:
        from marsadix.models import Confidence
        return getattr(Confidence, name, None)
    except ImportError:
        return None
