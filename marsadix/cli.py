"""
Marsadix command line.

    marsadix scan example.com --scope scope.txt
    marsadix monitor [--dry-run]
    marsadix diff example.com
    marsadix report example.com --format html
    marsadix doctor                      # which tools are installed?
    marsadix scope scope.txt dev.example.com 8.8.8.8

Commands whose module isn't written yet print "not implemented yet" (exit 3).
When you write your module, expose EXACTLY this function and the command works:

  monitor  ->  marsadix/monitor/runner.py : run(conn, config, dry_run=False, since=None)
  diff     ->  marsadix/core/diff.py      : run_diff(conn, target, old_id=None, new_id=None)
  report   ->  marsadix/reports/generate.py : generate_report(conn, target, fmt, out_dir, scan_id=None)
  scan     ->  stages, see core/pipeline.py
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional, Sequence

from . import db
from .core.config import Config, ConfigError, load_config
from .core.loader import load_callable
from .core.log import setup_logging
from .core.pipeline import run_scan
from .core.runner import httpx_is_projectdiscovery, tool_status
from .core.scope import Scope, ScopeError, normalize_host

log = logging.getLogger("marsadix.cli")
EXIT_NOT_IMPLEMENTED = 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="marsadix",
        description="Recon, ASM and CVE monitoring.")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--config", metavar="FILE", help="path to config.toml")
    p.add_argument("--db", metavar="FILE", help="SQLite file (overrides config)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run recon + ASM on a target")
    s.add_argument("target", help="root domain, e.g. example.com")
    s.add_argument("--scope", metavar="FILE", help="scope.txt (default: target + its subdomains)")
    s.add_argument("--depth", type=int, help="recursion depth limit")
    s.add_argument("--rate", type=int, help="requests per second")

    m = sub.add_parser("monitor", help="match new CVEs against stored technologies")
    m.add_argument("--dry-run", action="store_true", help="show matches, send nothing")
    m.add_argument("--since", metavar="ISO_DATE", help="override last sync time")

    d = sub.add_parser("diff", help="compare the last two scans of a target")
    d.add_argument("target")
    d.add_argument("--old", type=int, metavar="SCAN_ID")
    d.add_argument("--new", type=int, metavar="SCAN_ID")

    r = sub.add_parser("report", help="generate HTML / JSON report")
    r.add_argument("target")
    r.add_argument("--format", choices=["html", "json", "both"], default="both")
    r.add_argument("--out", metavar="DIR", help="output directory")
    r.add_argument("--scan-id", type=int)

    sub.add_parser("doctor", help="check which external tools are installed")

    sc = sub.add_parser("scope", help="test hosts against a scope file")
    sc.add_argument("file", help="scope.txt")
    sc.add_argument("hosts", nargs="+", help="hosts / IPs / URLs to test")
    return p


# ------------------------------------------------------------------ commands

def cmd_scan(a, cfg: Config) -> int:
    target = normalize_host(a.target)
    if not target:
        print(f"error: invalid target: {a.target!r}", file=sys.stderr)
        return 1
    if a.scope:
        scope = Scope.from_file(a.scope)
    else:
        scope = Scope.from_target(target)
        log.warning("no --scope given: using %s and *.%s", target, target)

    scan, results = run_scan(target, cfg, scope=scope, max_depth=a.depth, rate_limit=a.rate)
    print(f"\nScan #{scan.id} of {scan.target}: {scan.status.value}"
          f"{' (baseline)' if scan.is_baseline else ''}")
    for r in results:
        print(f"  {r.name:<8} {r.status:<8} {r.detail}")
    return 0 if scan.status.value == "completed" else 1


def _optional(path: str, what: str, **kwargs):
    fn = load_callable(path)
    if fn is None:
        file = path.split(":")[0].replace(".", "/") + ".py"
        print(f"{what} is not implemented yet (expected: {file}).", file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
    rc = fn(**kwargs)
    return rc if isinstance(rc, int) else 0


def _open_db(cfg: Config):
    conn = db.connect(cfg.db_path)
    db.init_db(conn)
    return conn


def cmd_monitor(a, cfg: Config) -> int:
    if load_callable("marsadix.monitor.runner:run") is None:
        return _optional("marsadix.monitor.runner:run", "monitor")
    return _optional("marsadix.monitor.runner:run", "monitor", conn=_open_db(cfg),
                     config=cfg, dry_run=a.dry_run, since=a.since)


def cmd_diff(a, cfg: Config) -> int:
    target = normalize_host(a.target) or a.target
    if load_callable("marsadix.core.diff:run_diff") is None:
        return _optional("marsadix.core.diff:run_diff", "diff")
    return _optional("marsadix.core.diff:run_diff", "diff", conn=_open_db(cfg),
                     target=target, old_id=a.old, new_id=a.new)


def cmd_report(a, cfg: Config) -> int:
    target = normalize_host(a.target) or a.target
    if load_callable("marsadix.reports.generate:generate_report") is None:
        return _optional("marsadix.reports.generate:generate_report", "report")
    return _optional("marsadix.reports.generate:generate_report", "report",
                     conn=_open_db(cfg), target=target, fmt=a.format,
                     out_dir=a.out or cfg.output_dir, scan_id=a.scan_id)


def cmd_doctor(a, cfg: Config) -> int:
    rows = tool_status()
    w = max(len(n) for n, _, _ in rows)
    missing = 0
    print("External tools:")
    for name, path, purpose in rows:
        mark = "OK     " if path else "MISSING"
        missing += 0 if path else 1
        print(f"  [{mark}] {name:<{w}}  {purpose}" + (f"  ({path})" if path else ""))
    flavor = httpx_is_projectdiscovery()
    if flavor is False:
        print("\n  WARNING: the 'httpx' on your PATH does not look like ProjectDiscovery's.\n"
              "  The Python package 'httpx' installs a command with the same name.\n"
              "  Use a full path to the right one, or avoid installing Python httpx globally.")
    print(f"\n{len(rows) - missing}/{len(rows)} tools found."
          f" API key: {'set' if cfg.nvd_api_key else 'NOT set (NVD_API_KEY in .env)'}."
          f" Discord webhook: {'set' if cfg.discord_webhook else 'NOT set (DISCORD_WEBHOOK_URL in .env)'}.")
    return 0


def cmd_scope(a, cfg: Config) -> int:
    scope = Scope.from_file(a.file)
    for h in a.hosts:
        d = scope.check(h)
        print(f"  {'IN ' if d else 'OUT'}  {h:<40} {d.reason}")
    return 0


COMMANDS = {"scan": cmd_scan, "monitor": cmd_monitor, "diff": cmd_diff,
            "report": cmd_report, "doctor": cmd_doctor, "scope": cmd_scope}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        cfg = load_config(args.config)
        if args.db:
            cfg.db_path = args.db
        return COMMANDS[args.command](args, cfg)
    except (ConfigError, ScopeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
