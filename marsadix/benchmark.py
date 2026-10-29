"""
Benchmarks (C14, C14b): numbers instead of claims.

  marsadix benchmark recon <domain>
      subfinder ALONE vs Marsadix with every source (subfinder, assetfinder, amass,
      crt.sh, API sources, recursion ...). Reports how many extra subdomains the
      combination finds and which source found what. There is no ground truth for a
      real domain, so "gain" is measured against what the two runs found together,
      not against "everything that exists". Results depend on network, installed
      tools and which API keys are set -- say so whenever you quote them.

  marsadix benchmark detection <target> --truth truth.json
      Detection Rate and Precision of ONE finished scan against a labeled training
      target (DVWA, Juice Shop ...). The ground truth is a file you write; see
      benchmarks/truth/README.md. Only findings with status "detected" count as a
      detection; "needs_review" is reported separately, never as a hit.
"""

from __future__ import annotations

import asyncio
import json
import sys
from types import SimpleNamespace
from typing import Dict, List, Optional, Set

from . import db
from .core import limits, toolstatus
from .core.config import Config


# ------------------------------------------------------------------- recon
def compare_recon(subfinder_only: Set[str], marsadix: Dict[str, List[str]]) -> dict:
    """Pure comparison of two result sets (unit-testable)."""
    m = set(marsadix)
    union = subfinder_only | m
    per_source: Dict[str, Set[str]] = {}
    for host, sources in marsadix.items():
        for s in sources:
            per_source.setdefault(s, set()).add(host)
    unique_by_source = {s: sorted(h for h in hosts
                                  if all(h not in other for o, other in per_source.items() if o != s))
                        for s, hosts in per_source.items()}
    base = len(subfinder_only)
    return {
        "subfinder_count": base,
        "marsadix_count": len(m),
        "union_count": len(union),
        "marsadix_only": sorted(m - subfinder_only),
        "subfinder_only": sorted(subfinder_only - m),     # should be empty: Marsadix runs subfinder too
        "gain_pct_over_subfinder": round(len(m - subfinder_only) / base * 100, 1) if base else None,
        "marsadix_share_of_union_pct": round(len(m) / len(union) * 100, 1) if union else None,
        "per_source_count": {s: len(h) for s, h in sorted(per_source.items())},
        "unique_by_source": {s: len(v) for s, v in sorted(unique_by_source.items())},
    }


def run_recon_benchmark(domain: str, cfg: Config, out_file: Optional[str] = None) -> int:
    from .core.scope import normalize_host
    from .recon.discovery import discover_subdomains, run_cli_tool
    from .recon.stage import _extract_api_keys

    domain = normalize_host(domain) or domain
    toolstatus.reset()
    limits.configure(tool_timeout=cfg.tool_timeout, max_concurrency=cfg.max_concurrent_tools)

    print(f"[1/2] subfinder alone on {domain} ...")
    _, sf = asyncio.run(run_cli_tool("subfinder", ["subfinder", "-d", domain, "-silent"],
                                     timeout=cfg.tool_timeout))
    if any(r.tool == "subfinder" and r.status == "missing" for r in toolstatus.runs()):
        print("error: subfinder is not installed (run `marsadix doctor`); a benchmark needs the baseline tool.",
              file=sys.stderr)
        return 1
    print(f"[2/2] Marsadix with all sources (depth {cfg.max_depth}) ...")
    keys = _extract_api_keys(SimpleNamespace(config=cfg))
    mx = discover_subdomains(domain, keys, max_depth=cfg.max_depth)

    result = compare_recon(sf, mx)
    result.update({"domain": domain, "api_keys_used": sorted(k for k, v in keys.items() if v),
                   "incomplete_tools": [r.tool for r in toolstatus.degraded()]})
    print_recon(result)
    if out_file:
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"\nwrote {out_file}")
    return 0


def print_recon(r: dict) -> None:
    print(f"\nRecon benchmark: {r.get('domain', '')}")
    print(f"  subfinder alone : {r['subfinder_count']}")
    print(f"  Marsadix (all)  : {r['marsadix_count']}"
          + (f"   (+{r['gain_pct_over_subfinder']}% over subfinder)" if r['gain_pct_over_subfinder'] is not None else ""))
    print(f"  found only by Marsadix: {len(r['marsadix_only'])}")
    if r["subfinder_only"]:
        print(f"  WARNING: {len(r['subfinder_only'])} host(s) only the standalone subfinder run found "
              f"(timeouts / rate limits differ between runs).")
    print("  per source (hosts found / found ONLY by that source):")
    for s, n in r["per_source_count"].items():
        print(f"    {s:<14} {n:>6} / {r['unique_by_source'].get(s, 0)}")
    if r.get("api_keys_used") is not None:
        print(f"  API keys in use: {', '.join(r['api_keys_used']) or 'none'}")
    if r.get("incomplete_tools"):
        print(f"  NOTE: incomplete runs: {', '.join(r['incomplete_tools'])} - numbers are a lower bound.")
    print("  Gain is measured against what both runs found together, not against every subdomain that exists.")


# --------------------------------------------------------------- detection
def load_truth(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    entries = raw.get("entries") if isinstance(raw, dict) else raw
    if not isinstance(entries, list) or not entries:
        raise ValueError("truth file needs a non-empty list of entries")
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not (e.get("template_id") or e.get("owasp_category") or e.get("url_contains")):
            raise ValueError(f"truth entry #{i + 1} needs at least one of: template_id, owasp_category, url_contains")
    return entries


def _matches(finding: dict, entry: dict) -> bool:
    if entry.get("template_id") and str(finding.get("template_id") or "").lower() != str(entry["template_id"]).lower():
        return False
    if entry.get("owasp_category") and finding.get("owasp_category") != entry["owasp_category"]:
        return False
    if entry.get("url_contains"):
        where = f"{finding.get('url') or ''} {finding.get('host') or ''}".lower()
        if str(entry["url_contains"]).lower() not in where:
            return False
    return True


def score_detection(findings: List[dict], entries: List[dict]) -> dict:
    detected = [f for f in findings if f.get("status") == "detected"]
    review = [f for f in findings if f.get("status") == "needs_review"]
    found = [e for e in entries if any(_matches(f, e) for f in detected)]
    missed = [e for e in entries if e not in found]
    correct = [f for f in detected if any(_matches(f, e) for e in entries)]
    false_pos = [f for f in detected if f not in correct]
    return {
        "truth_entries": len(entries),
        "true_positives": len(found),
        "false_negatives": len(missed),
        "detected_findings": len(detected),
        "false_positive_findings": len(false_pos),
        "needs_review_findings": len(review),
        "detection_rate_pct": round(len(found) / len(entries) * 100, 1),
        "precision_pct": round(len(correct) / len(detected) * 100, 1) if detected else None,
        "missed": [e.get("id") or e for e in missed],
        "false_positives": [{"host": f.get("host"), "title": f.get("title"), "url": f.get("url")} for f in false_pos],
    }


def run_detection_benchmark(conn, target: str, truth_file: str, scan_id: Optional[int] = None,
                            out_file: Optional[str] = None) -> int:
    try:
        entries = load_truth(truth_file)
    except (OSError, ValueError) as e:
        print(f"error: cannot use truth file: {e}", file=sys.stderr)
        return 1
    if scan_id is None:
        latest = db.get_latest_scans(conn, target, limit=1, completed_only=True)
        if not latest:
            print(f"error: no completed scan of {target!r}.", file=sys.stderr)
            return 1
        scan_id = latest[0]["id"]
    elif conn.execute("SELECT 1 FROM scans WHERE id=? AND target=?", (scan_id, target)).fetchone() is None:
        print(f"error: scan #{scan_id} is not a scan of {target!r}.", file=sys.stderr)
        return 1

    res = score_detection([dict(r) for r in db.get_findings(conn, scan_id)], entries)
    res.update({"target": target, "scan_id": scan_id})
    print(f"Detection benchmark: {target} (scan #{scan_id})")
    print(f"  Detection Rate : {res['detection_rate_pct']}%  ({res['true_positives']}/{res['truth_entries']} known issues found)")
    print(f"  Precision      : {res['precision_pct']}%  "
          f"({res['detected_findings'] - res['false_positive_findings']}/{res['detected_findings']} detections were real)"
          if res["precision_pct"] is not None else "  Precision      : n/a (no detections)")
    print(f"  Needs Review   : {res['needs_review_findings']} (not counted as detections)")
    for m in res["missed"]:
        print(f"  missed: {m}")
    for f in res["false_positives"]:
        print(f"  false positive: {f['title']} on {f['host']} {f['url'] or ''}")
    print("  Valid only for this scan, this target and this truth file - not a general accuracy claim.")
    if out_file:
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
        print(f"\nwrote {out_file}")
    return 0
