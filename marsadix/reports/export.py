"""
Report exports beyond JSON/HTML (C20): CSV, SARIF 2.1.0 and PDF.

All three are stdlib-only, like the rest of the reports package.

  CSV    one row per finding, written server-side. Cells that a spreadsheet would
         treat as a formula (=, +, -, @ ...) are neutralised, because finding text
         comes from the scanned target and is not trustworthy.
  SARIF  the interchange format GitHub code scanning, GitLab and most security
         dashboards read. One rule per distinct check, one result per finding.
  PDF    a compact, text-only summary (executive summary, OWASP coverage,
         prioritized findings, limitations) written by a tiny built-in PDF
         writer. For the full interactive report use the HTML file.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Iterable, List

from ..core.textfile import safe_filename

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
_STATUS_LABEL = {"detected": "Detected", "needs_review": "Needs Review", "no_indicators": "No Indicators"}


def prioritize(findings: Iterable[dict]) -> List[dict]:
    """Most important first: severity, then Detected > Needs Review > No Indicators, then KEV, then confidence."""
    sev = {s: i for i, s in enumerate(_SEV_ORDER)}
    st = {"detected": 0, "needs_review": 1, "no_indicators": 2}
    conf = {"confirmed": 0, "likely": 1, "possible": 2}
    return sorted(findings, key=lambda f: (
        sev.get(str(f.get("severity")), 9), st.get(str(f.get("status")), 9),
        0 if f.get("in_kev") else 1, conf.get(str(f.get("confidence")), 9),
        str(f.get("host")), str(f.get("title"))))


# ----------------------------------------------------------------------- CSV
CSV_COLUMNS = ["host", "title", "severity", "status", "confidence", "owasp_category", "cve_id",
               "port", "url", "template_id", "source_reference", "evidence", "exploited"]


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    # Formula injection: a cell starting with these is executed by Excel/LibreOffice.
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def write_csv(data: dict, out_dir: Path, target: str, scan_id: int) -> Path:
    path = Path(out_dir) / f"{safe_filename(target)}_scan{scan_id}_findings.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:      # BOM: Excel reads UTF-8 correctly
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        for f in prioritize(data.get("findings", [])):
            w.writerow([_csv_safe(f.get(c)) for c in CSV_COLUMNS[:-1]] + ["false"])
    return path


# --------------------------------------------------------------------- SARIF
def build_sarif(data: dict) -> dict:
    findings = prioritize(data.get("findings", []))
    rules: dict = {}
    results = []
    for f in findings:
        rule_id = str(f.get("template_id") or f.get("cve_id") or re.sub(r"\W+", "-", str(f.get("title") or "finding")).strip("-") or "finding")
        rule = rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": str(f.get("title") or rule_id)},
            "properties": {"owasp": f.get("owasp_category"), "source_reference": f.get("source_reference")},
        })
        if f.get("cve_id"):
            rule["helpUri"] = f"https://nvd.nist.gov/vuln/detail/{f['cve_id']}"
        loc = {"logicalLocations": [{"name": str(f.get("host")), "kind": "host"}]}
        if f.get("url"):
            loc["physicalLocation"] = {"artifactLocation": {"uri": str(f["url"])}}
        sev = str(f.get("severity") or "info")
        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": f"{f.get('title') or rule_id} on {f.get('host')}"
                                f" [{_STATUS_LABEL.get(str(f.get('status')), f.get('status'))}]"},
            "locations": [loc],
            "properties": {
                "security-severity": _SARIF_SCORE.get(sev, "0.0"),
                "severity": sev, "status": f.get("status"), "confidence": f.get("confidence"),
                "owasp_category": f.get("owasp_category"), "cve_id": f.get("cve_id"),
                "evidence": f.get("evidence"), "exploited": False,    # detection only, never exploitation
            },
        }
        if f.get("dedup_key"):
            result["partialFingerprints"] = {"marsadixDedupKey/v1": str(f["dedup_key"])}
        results.append(result)
    scan = data.get("scan", {})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Marsadix", "informationUri": "https://github.com/zyadwael152/Marsadix__Recon-Automation-Tool",
                                "rules": list(rules.values())}},
            "results": results,
            "properties": {"target": data.get("target"), "scan_id": scan.get("id"), "mode": scan.get("mode")},
        }],
    }


def write_sarif(data: dict, out_dir: Path, target: str, scan_id: int) -> Path:
    path = Path(out_dir) / f"{safe_filename(target)}_scan{scan_id}.sarif"
    path.write_text(json.dumps(build_sarif(data), indent=2, default=str), encoding="utf-8")
    return path


# ----------------------------------------------------------------------- PDF
# Helvetica advance widths (1/1000 em) for ASCII 32..126, used to wrap lines.
_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
      556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
      1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
      667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
      333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
      556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]


def _clean(text) -> str:
    s = "" if text is None else str(text)
    s = "".join(ch if ch in "\n" or ch >= " " else " " for ch in s)
    return s.encode("cp1252", "replace").decode("cp1252")


def _width(text: str, size: float, bold: bool = False) -> float:
    total = sum(_W[ord(c) - 32] if 32 <= ord(c) <= 126 else 556 for c in text)
    return total * size / 1000.0 * (1.06 if bold else 1.0)


def _wrap(text: str, size: float, max_w: float, bold: bool = False) -> List[str]:
    lines: List[str] = []
    for para in _clean(text).split("\n"):
        cur = ""
        for word in para.split(" "):
            while _width(word, size, bold) > max_w and len(word) > 1:      # a very long token (URL, hash)
                cut = len(word)
                while cut > 1 and _width(word[:cut], size, bold) > max_w:
                    cut -= 1
                if cur:
                    lines.append(cur)
                    cur = ""
                lines.append(word[:cut])
                word = word[cut:]
            trial = f"{cur} {word}".strip() if cur else word
            if _width(trial, size, bold) <= max_w:
                cur = trial
            else:
                lines.append(cur)
                cur = word
        lines.append(cur)
    return lines


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class _Pdf:
    PAGE_W, PAGE_H, MARGIN = 595, 842, 50

    def __init__(self):
        self.pages: List[List[str]] = [[]]
        self.y = self.PAGE_H - self.MARGIN

    def _new_page(self):
        self.pages.append([])
        self.y = self.PAGE_H - self.MARGIN

    def text(self, text, size=10, bold=False, gap=2, indent=0):
        max_w = self.PAGE_W - 2 * self.MARGIN - indent
        for line in _wrap(text, size, max_w, bold):
            lead = size * 1.25
            if self.y - lead < self.MARGIN:
                self._new_page()
            self.y -= lead
            self.pages[-1].append(f"BT /{'F2' if bold else 'F1'} {size} Tf {self.MARGIN + indent:.1f} {self.y:.1f} Td ({_esc(line)}) Tj ET")
        self.y -= gap

    def space(self, pts=6):
        self.y -= pts

    def render(self) -> bytes:
        objs: List[bytes] = []                                   # 1-based object numbers
        n_pages = len(self.pages)
        font1, font2 = 3 + 2 * n_pages, 4 + 2 * n_pages
        kids = " ".join(f"{3 + 2 * i} 0 R" for i in range(n_pages))
        objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objs.append(f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode())
        for i, ops in enumerate(self.pages):
            page_no, content_no = 3 + 2 * i, 4 + 2 * i
            footer = f"BT /F1 8 Tf {self.MARGIN} 30 Td (Marsadix report - page {i + 1} of {n_pages}) Tj ET"
            stream = "\n".join(ops + [footer]).encode("cp1252", "replace")
            objs.append((f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.PAGE_W} {self.PAGE_H}] "
                         f"/Contents {content_no} 0 R /Resources << /Font << /F1 {font1} 0 R /F2 {font2} 0 R >> >> >>").encode())
            objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        out = bytearray(b"%PDF-1.4\n")
        offsets = []
        for num, body in enumerate(objs, 1):
            offsets.append(len(out))
            out += f"{num} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)


def summary_lines(data: dict) -> List[str]:
    """The plain-language executive summary shared by the PDF and the HTML report."""
    findings = data.get("findings", [])
    sev = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev[str(f.get("severity") or "info")] = sev.get(str(f.get("severity") or "info"), 0) + 1
    detected = sum(1 for f in findings if f.get("status") == "detected")
    review = sum(1 for f in findings if f.get("status") == "needs_review")
    scan = data.get("scan", {})
    lines = [
        f"Marsadix scanned {data.get('target')} (scan #{scan.get('id')}, mode: {scan.get('mode', 'passive')}) and "
        f"found {len(data.get('assets', []))} asset(s), {len(data.get('services', []))} service(s) and "
        f"{len(findings)} finding(s).",
        f"Findings by severity: critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, "
        f"low {sev['low']}, info {sev['info']}. {detected} are Detected and {review} Need Review.",
    ]
    d = data.get("diff")
    if d:
        lines.append(f"Since scan #{data.get('previous_scan_id')}: {len(d.get('new_assets', []))} new asset(s), "
                     f"{len(d.get('removed_assets', []))} removed, {len(d.get('new_ports', []))} new open port(s).")
    cov = data.get("owasp_coverage", {})
    if cov:
        lines.append(f"OWASP Top 10 coverage: {cov.get('coverage_pct', 0)}%.")
    lines.append("Findings are detections only; nothing was exploited.")
    return lines


LIMITATIONS = ("Detection, not exploitation: no payload extracts data, changes state or runs code on the target. "
               "\"No Indicators\" means the automated checks found nothing; it does not mean the asset is free of the issue. "
               "Automated detection relies on fixed signatures and can miss custom logic, WAF-filtered variants and "
               "context-specific bugs (false negatives). Review sensitive assets manually.")


def write_pdf(data: dict, out_dir: Path, target: str, scan_id: int, max_findings: int = 200) -> Path:
    pdf = _Pdf()
    pdf.text(f"Marsadix Security Report - {target}", 16, bold=True, gap=4)
    scan = data.get("scan", {})
    pdf.text(f"Scan #{scan.get('id')} | mode: {scan.get('mode', 'passive')} | generated {data.get('generated_at', '')}", 9, gap=8)
    pdf.text("Executive summary", 13, bold=True)
    for line in summary_lines(data):
        pdf.text(line, 10, gap=3)
    pdf.space(8)

    cov = data.get("owasp_coverage", {})
    if cov:
        from ..owasp import ALL_CATEGORIES
        pdf.text("OWASP Top 10 (2021) coverage", 13, bold=True)
        for cat in ALL_CATEGORIES:
            n = cov.get("breakdown", {}).get(cat, 0)
            pdf.text(f"{cat}: {n} finding(s)" if n else f"{cat}: no findings", 9, indent=10, gap=1)
        pdf.space(8)
    skills = [s for s in data.get("detection_skills", []) if s.get("state") == "active"]
    if skills:
        pdf.text("Active detection skills", 13, bold=True)
        for s in skills:
            pdf.text(f"{s['name']} ({s['engine']}) - {s['source_reference']}", 9, indent=10, gap=1)
        pdf.space(8)

    ordered = prioritize(data.get("findings", []))
    pdf.text(f"Prioritized findings ({len(ordered)})", 13, bold=True)
    for i, f in enumerate(ordered[:max_findings], 1):
        head = (f"{i}. [{str(f.get('severity')).upper()}] {f.get('title')} - {f.get('host')}"
                f" ({_STATUS_LABEL.get(str(f.get('status')), f.get('status'))})")
        pdf.text(head, 10, bold=True, gap=1)
        bits = [f"{k}: {f.get(k)}" for k in ("owasp_category", "cve_id", "url", "source_reference") if f.get(k)]
        if bits:
            pdf.text("; ".join(bits), 8.5, indent=12, gap=1)
        if f.get("evidence"):
            pdf.text("Evidence: " + str(f["evidence"])[:600], 8.5, indent=12, gap=1)
        pdf.text("Exploited: no (detection only)", 8.5, indent=12, gap=4)
    if len(ordered) > max_findings:
        pdf.text(f"... {len(ordered) - max_findings} more finding(s) are in the JSON/HTML report.", 9)
    pdf.space(8)
    pdf.text("Methodology and limitations", 13, bold=True)
    pdf.text(LIMITATIONS, 9)

    path = Path(out_dir) / f"{safe_filename(target)}_scan{scan_id}_report.pdf"
    path.write_bytes(pdf.render())
    return path
