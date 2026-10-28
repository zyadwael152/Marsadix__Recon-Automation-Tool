"""
Marsadix command line.

    marsadix scan example.com --scope scope.txt --mode passive
    marsadix monitor [--dry-run]
    marsadix ct-monitor example.com       # 🆕 R14: Real-time CT Log monitoring
    marsadix diff example.com
    marsadix report example.com --format html
    marsadix graph example.com             # Knowledge Graph summary
    marsadix doctor                        # which tools are installed?
    marsadix scope scope.txt dev.example.com 8.8.8.8

Commands whose module isn't written yet print "not implemented yet" (exit 3).
When you write your module, expose EXACTLY this function and the command works:

  monitor   ->  marsadix/monitor/runner.py : run(conn, config, dry_run=False, since=None)
  diff      ->  marsadix/core/diff.py      : run_diff(conn, target, old_id=None, new_id=None)
  snapshots ->  marsadix/core/diff.py      : run_snapshots(conn, target)
  report    ->  marsadix/reports/generate.py : generate_report(conn, target, fmt, out_dir, scan_id=None)
  graph     ->  marsadix/core/graph.py     : run_graph(conn, target, scan_id=None)
  scan      ->  stages, see core/pipeline.py

scan --mode (C15): passive (default, no contact with the target) | standard
(+ resolve/probe/ports) | full (+ active web checks, nuclei, injection
detection). scan --allow-injection (A5) is a separate, explicit opt-in: a
"full" scan does NOT run injection-style checks unless this flag is also
given, and it requires an authorized scope.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Optional, Sequence

from . import db
from .core.banner import print_banner
from .core.config import SCAN_MODES, Config, ConfigError, load_config
from .core.loader import load_callable
from .core.log import setup_logging
from .core.pipeline import run_scan
from .core.runner import httpx_is_projectdiscovery, tool_status
from .core.scope import Scope, ScopeError, normalize_host, valid_hostname

log = logging.getLogger("marsadix.cli")
EXIT_NOT_IMPLEMENTED = 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="marsadix",
        description="Recon, ASM and CVE monitoring.")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--config", metavar="FILE", help="path to config.toml")
    p.add_argument("--db", metavar="FILE", help="SQLite file (overrides config)")
    p.add_argument("--no-banner", action="store_true", help="do not print the startup banner")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="run recon + ASM on a target")
    s.add_argument("target", help="root domain, e.g. example.com")
    s.add_argument("--scope", metavar="FILE", help="scope.txt (default: target + its subdomains)")
    s.add_argument("--depth", type=int, help="recursion depth limit")
    s.add_argument("--rate", type=int, help="requests per second")
    s.add_argument("--mode", choices=list(SCAN_MODES), default=None,
                   help="passive (default) | standard | full")
    s.add_argument("--allow-injection", action="store_true",
                   help="explicit opt-in for injection-style checks (XSS/SQLi/SSTI probes)")

    m = sub.add_parser("monitor", help="match new CVEs against stored technologies")
    m.add_argument("--dry-run", action="store_true", help="show matches, send nothing")
    m.add_argument("--since", metavar="ISO_DATE", help="override last sync time")

    # 🆕 R14: CT Log stream monitoring parser
    ct = sub.add_parser("ct-monitor", help="continuously monitor CT logs for new subdomains in real-time")
    ct.add_argument("target", help="target domain to monitor, e.g. hackerone.com")

    d = sub.add_parser("diff", help="compare the last two scans of a target")
    d.add_argument("target")
    d.add_argument("--old", type=int, metavar="SCAN_ID")
    d.add_argument("--new", type=int, metavar="SCAN_ID")

    sn = sub.add_parser("snapshots", help="list every scan of a target as a timeline")
    sn.add_argument("target")

    r = sub.add_parser("report", help="generate HTML / JSON report")
    r.add_argument("target")
    r.add_argument("--format", choices=["html", "json", "both"], default="both")
    r.add_argument("--out", metavar="DIR", help="output directory")
    r.add_argument("--scan-id", type=int)

    g = sub.add_parser("graph", help="Knowledge Graph summary for a target")
    g.add_argument("target")
    g.add_argument("--scan-id", type=int, help="defaults to the latest scan")

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
    scope = Scope.from_file(a.scope) if a.scope else None
    if scope is None and (a.mode or cfg.scan_mode) == "passive":
        log.warning("no --scope given: using %s and *.%s", target, target)

    scan, results = run_scan(target, cfg, scope=scope, scope_file=a.scope, max_depth=a.depth,
                             rate_limit=a.rate, mode=a.mode,
                             allow_injection=(True if a.allow_injection else None))
    print(f"\nScan #{scan.id} of {scan.target}: {scan.status.value}"
          f"{' (baseline)' if scan.is_baseline else ''} [mode={scan.mode.value}]")
    for r in results:
        print(f"  {r.name:<8} {r.status:<8} {r.detail}")
    return 0 if scan.status.value == "completed" else 1


def _missing(path: str, what: str) -> int:
    file = path.split(":")[0].replace(".", "/") + ".py"
    print(f"{what} is not implemented yet (expected: {file}).", file=sys.stderr)
    return EXIT_NOT_IMPLEMENTED


def _db_command(path: str, what: str, cfg: Config, **kwargs):
    """
    Resolve `path`, open the database once, call it, and always close the
    connection.

    It used to load the module twice (once to test, once to call) and pass
    `_open_db(cfg)` as an argument -- so the connection was opened even when
    the module was missing, and was never closed. On Windows an unclosed
    SQLite handle keeps the file locked for the rest of the process.
    """
    fn = load_callable(path)
    if fn is None:
        return _missing(path, what)
    conn = db.connect(cfg.db_path)
    try:
        db.init_db(conn)
        rc = fn(conn=conn, **kwargs)
    finally:
        conn.close()
    return rc if isinstance(rc, int) else 0


def cmd_monitor(a, cfg: Config) -> int:
    return _db_command("marsadix.monitor.runner:run", "monitor", cfg,
                       config=cfg, dry_run=a.dry_run, since=a.since)


# 🆕 R14: Command implementation for CT stream monitoring
def cmd_ct_monitor(a, cfg: Config) -> int:
    # Imported here, not at the top: a problem inside the recon package must not
    # take every other command down with it.
    from marsadix.recon.ct_monitor import monitor_ct_logs

    # The target becomes part of a file name, so it must be a clean host. It used
    # to fall back to the raw argument, and "../../x" wrote outside the folder.
    target = valid_hostname(a.target)
    if not target:
        raise ScopeError(f"invalid target for ct-monitor (a domain name is required): {a.target!r}")
    os.makedirs(cfg.output_dir, exist_ok=True)         # the configured output folder (already git-ignored)
    out_file = os.path.join(cfg.output_dir, f"{target}_ct_assets.txt")

    try:
        asyncio.run(monitor_ct_logs(target, output_file=out_file))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
    return 0


def cmd_diff(a, cfg: Config) -> int:
    target = normalize_host(a.target) or a.target
    return _db_command("marsadix.core.diff:run_diff", "diff", cfg,
                       target=target, old_id=a.old, new_id=a.new)


def cmd_snapshots(a, cfg: Config) -> int:
    target = normalize_host(a.target) or a.target
    return _db_command("marsadix.core.diff:run_snapshots", "snapshots", cfg,
                       target=target)


def cmd_report(a, cfg: Config) -> int:
    target = normalize_host(a.target) or a.target
    return _db_command("marsadix.reports.generate:generate_report", "report", cfg,
                       target=target, fmt=a.format,
                       out_dir=a.out or cfg.output_dir, scan_id=a.scan_id)


def cmd_graph(a, cfg: Config) -> int:
    target = normalize_host(a.target) or a.target
    return _db_command("marsadix.core.graph:run_graph", "graph", cfg,
                       target=target, scan_id=a.scan_id)


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


COMMANDS = {"scan": cmd_scan, "monitor": cmd_monitor, "ct-monitor": cmd_ct_monitor,
            "diff": cmd_diff, "snapshots": cmd_snapshots, "report": cmd_report,
            "graph": cmd_graph, "doctor": cmd_doctor, "scope": cmd_scope}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.no_banner:
        print_banner()
    if not args.command:                      # plain `marsadix`: banner + help
        parser.print_help()
        return 0
    setup_logging(args.verbose)
    try:
        cfg = load_config(args.config)
        if args.db:
            cfg.db_path = args.db
        return COMMANDS[args.command](args, cfg)
    except (ConfigError, ScopeError, db.SchemaVersionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except OSError as e:                      # unreadable / missing / locked file: a message, not a traceback
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
