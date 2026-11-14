"""CLI glue for the Person 4 commands (argparse; handlers are plain functions so they can be
re-registered in whichever CLI framework ``marsadix/cli.py`` uses).

    marsadix risk [--top N] [--json]
    marsadix patterns [--no-persist] [--min-severity S] [--json]
    marsadix attack-surface [--target T] [--history N] [--no-record] [--json]
    marsadix remediation list|search <term>|add ...|delete <id>|seed
    marsadix monitor ... [--dry-run] [--since X] [--all] [--no-alerts] [--channel C ...]   (extra flags)
    marsadix doctor                                       (use ``doctor_lines``)
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from typing import Any, Callable, List, Optional

from . import attack_surface, patterns as pat, remediation_db as rdb
from .alerts.base import CHANNELS
from .alerts.settings import AlertSettings
from .db_v4 import migrate_v3_to_v4
from .monitor.matching_run import MatchRunSummary, run_matching
from .reports.p4_sections import build_p4_report_data, collect_risked_findings
from .risk import top_fixes

__all__ = ["register", "add_monitor_arguments", "monitor_post_sync", "cmd_risk", "cmd_patterns", "cmd_attack_surface",
           "cmd_remediation", "doctor_lines"]


def _prep(conn: sqlite3.Connection) -> None:
    migrate_v3_to_v4(conn)
    rdb.seed_defaults(conn)


def cmd_risk(conn: sqlite3.Connection, args: argparse.Namespace, out: Callable[[str], Any] = print) -> int:
    _prep(conn)
    findings = collect_risked_findings(conn)
    fixes = top_fixes(findings, args.top)
    if args.json:
        out(json.dumps({"top_fixes": [t.to_dict() for t in fixes], "findings": [f.to_dict() for f in findings]}, indent=2))
        return 0
    out(f"Top {len(fixes)} fixes (of {len(findings)} open CVE findings)")
    for i, t in enumerate(fixes, 1):
        out(f"{i:>2}. {t.cve_id:<16} risk {t.risk_score:>5.1f}  {t.host}  [{t.effort} effort]")
        out(f"      why:    {t.reason}")
        out(f"      action: {t.action}")
    return 0


def cmd_patterns(conn: sqlite3.Connection, args: argparse.Namespace, out: Callable[[str], Any] = print) -> int:
    _prep(conn)
    found = pat.run_patterns(conn, persist=not args.no_persist)
    floor = pat.SEVERITY_ORDER.get(args.min_severity, 0)
    found = [f for f in found if pat.SEVERITY_ORDER.get(f.severity, 0) >= floor]
    if args.json:
        out(json.dumps([f.to_dict() for f in found], indent=2))
        return 0
    out(f"{len(found)} misconfiguration pattern finding(s)" + ("" if args.no_persist else " (persisted)"))
    for f in found:
        out(f"[{f.severity.upper():<8}] {f.status:<12} {f.rule_id}  {f.host}  {f.target}")
        out(f"    {f.evidence[0]}")
    return 0


def cmd_attack_surface(conn: sqlite3.Connection, args: argparse.Namespace, out: Callable[[str], Any] = print) -> int:
    _prep(conn)
    r = attack_surface.record_score(conn, target=args.target, run_type="cli", persist=not args.no_record)
    hist = attack_surface.history(conn, args.target, args.history) if args.history else []
    if args.json:
        out(json.dumps({"current": r.to_dict(), "history": hist}, indent=2))
        return 0
    out(f"Attack surface score: {r.score:.1f}/100 (grade {r.grade}, 100 = healthiest)  trend: {r.trend}"
        + (f"  delta {r.delta:+.1f} vs {r.previous_score:.1f}" if r.delta is not None else ""))
    for line in r.reasons:
        out(f"  - {line}")
    for h in hist:
        out(f"  history #{h['id']}: {h['score']:.1f} ({h['trend']}) {h['created_at']}")
    return 0


def cmd_remediation(conn: sqlite3.Connection, args: argparse.Namespace, out: Callable[[str], Any] = print) -> int:
    _prep(conn)
    act = args.rem_action
    try:
        if act == "list":
            rows = rdb.list_entries(conn, args.type)
        elif act == "search":
            rows = rdb.search(conn, args.term)
        elif act == "add":
            e = rdb.add_entry(conn, args.type, args.value, args.title, args.fix, args.ref or [], args.effort, args.priority)
            out(f"added remediation #{e.id} ({e.match_type}:{e.match_value})")
            return 0
        elif act == "delete":
            out("deleted" if rdb.delete_entry(conn, args.id) else "not found")
            return 0
        else:  # seed
            out(f"seeded {rdb.seed_defaults(conn)} new entries")
            return 0
    except rdb.RemediationError as exc:
        out(f"error: {exc}")
        return 2
    for e in rows:
        out(f"#{e.id:<4} {e.match_type:<9} {e.match_value:<28} [{e.effort}/{e.priority}] {e.title}")
        if getattr(args, "verbose", False):
            out(f"      {e.fix_text}")
    out(f"{len(rows)} entr{'y' if len(rows) == 1 else 'ies'}")
    return 0


def register(subparsers: Any, get_conn: Callable[[argparse.Namespace], sqlite3.Connection]) -> None:
    """Attach the Person 4 commands to an argparse ``subparsers`` object."""
    def wrap(fn):
        return lambda a: fn(get_conn(a), a)

    p = subparsers.add_parser("risk", help="context-aware risk + Top-N remediation list")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=wrap(cmd_risk))

    p = subparsers.add_parser("patterns", help="passive misconfiguration pattern hunter (stored data only)")
    p.add_argument("--no-persist", action="store_true")
    p.add_argument("--min-severity", default="info", choices=sorted(pat.SEVERITY_ORDER))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=wrap(cmd_patterns))

    p = subparsers.add_parser("attack-surface", help="attack-surface score (100 = healthiest) with trend")
    p.add_argument("--target", default="*")
    p.add_argument("--history", type=int, default=0)
    p.add_argument("--no-record", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=wrap(cmd_attack_surface))

    p = subparsers.add_parser("remediation", help="remediation database")
    sub = p.add_subparsers(dest="rem_action", required=True)
    s = sub.add_parser("list"); s.add_argument("--type", choices=rdb.MATCH_TYPES); s.add_argument("-v", "--verbose", action="store_true")
    s = sub.add_parser("search"); s.add_argument("term"); s.add_argument("-v", "--verbose", action="store_true")
    s = sub.add_parser("add")
    s.add_argument("--type", required=True, choices=rdb.MATCH_TYPES); s.add_argument("--value", required=True)
    s.add_argument("--title", required=True); s.add_argument("--fix", required=True)
    s.add_argument("--ref", action="append"); s.add_argument("--effort", default="medium", choices=rdb.EFFORTS)
    s.add_argument("--priority", type=int, default=50)
    s = sub.add_parser("delete"); s.add_argument("id", type=int)
    sub.add_parser("seed")
    p.set_defaults(func=wrap(cmd_remediation))


def add_monitor_arguments(parser: argparse.ArgumentParser) -> None:
    """Flags to add to the existing ``monitor`` command. Flags the parser already has (``--dry-run`` and
    ``--since`` exist in cli.py) are skipped: argparse raises on a duplicate option string."""
    def add(*flags, **kw):
        if not any(f in parser._option_string_actions for f in flags):
            parser.add_argument(*flags, **kw)
    add("--dry-run", action="store_true", help="match and report, but write nothing and send nothing")
    add("--all", dest="all_cves", action="store_true", help="re-match all stored CVEs, not only new ones")
    add("--no-alerts", action="store_true", help="match and persist findings but do not send alerts")
    add("--channel", action="append", choices=CHANNELS, help="restrict alert channels (repeatable)")


def monitor_post_sync(conn: sqlite3.Connection, args: argparse.Namespace, sync_result: Any = None, *, config: Any = None,
                      out: Callable[[str], Any] = print, **overrides: Any) -> MatchRunSummary:
    """Call right after the NVD/KEV/EPSS sync inside ``marsadix monitor``; prints the summary."""
    from .monitor.matching_run import extract_sync_info
    info = extract_sync_info(sync_result)
    summary = run_matching(conn, settings=AlertSettings.from_env(config=config), changed_cve_ids=info["changed_cve_ids"],
                           new_kev=info["new_kev"], synced=info["synced"], all_cves=getattr(args, "all_cves", False),
                           dry_run=getattr(args, "dry_run", False), no_alerts=getattr(args, "no_alerts", False),
                           channels=getattr(args, "channel", None), **overrides)
    for line in summary.lines():
        out(line)
    return summary


def doctor_lines(settings: Optional[AlertSettings] = None) -> List[str]:
    """Lines for ``marsadix doctor`` - which alert channels are configured (no secrets)."""
    settings = settings or AlertSettings.from_env()
    lines = [f"alert channel {name:<9} {state}" for name, state in settings.describe().items()]
    if settings.allow_private_webhooks:
        lines.append("webhooks: private/loopback destinations ALLOWED (MARSADIX_ALLOW_PRIVATE_WEBHOOKS=1)")
    return lines
