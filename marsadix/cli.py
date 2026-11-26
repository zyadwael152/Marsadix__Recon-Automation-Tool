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

scan --mode (C15): passive (default: recon + archived URLs, no contact with
the target) | active (+ HTTP probe, crawl, port scan, nmap, nuclei, custom
checks). The old names "standard" and "full" still work and mean "active".
scan --allow-injection (A5) is a separate, explicit opt-in: an "active" scan
does NOT run injection-style checks unless this flag is also given, and it
requires an authorized scope.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import platform
import sys
from typing import Optional, Sequence

from . import db
from .core.banner import print_banner
from .core.config import SCAN_MODES, Config, ConfigError, load_config, normalize_mode
from .core.loader import load_callable
from .core.log import setup_logging
from .core.pipeline import run_scan
from .core.runner import httpx_check, tool_status
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
    s.add_argument("--mode", type=normalize_mode, choices=list(SCAN_MODES), default=None,
                   help="passive (default) | active")
    s.add_argument("--allow-injection", action="store_true",
                   help="explicit opt-in for injection-style checks (XSS/SQLi/SSTI probes)")

    m = sub.add_parser("monitor", help="CVE monitor: sync the feeds, match them against your technologies and alert; repeats every --interval-hours (default 0.5, i.e. every 30 minutes)")
    m.add_argument("--interval-hours", type=float, default=0.5, help="hours between cycles (default 0.5 = 30 minutes)")
    m.add_argument("--once", action="store_true", help="run a single cycle and exit (--dry-run implies it)")
    m.add_argument("--dry-run", action="store_true", help="show matches, send nothing")
    m.add_argument("--since", metavar="ISO_DATE", help="override last sync time")
    m.add_argument("action", nargs="?", choices=["start", "stop", "status"],
                   help="start / stop / status: run the monitors in the background (CVE monitor + CT monitor)")
    m.add_argument("domain", nargs="?",
                   help="with start: monitor only this domain's CT logs. Without it, every target in the database")

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
    r.add_argument("--format", choices=["html", "json", "csv", "sarif", "pdf", "both", "all"], default="both",
                   help="both = html + json (default); all = every format")
    r.add_argument("--out", metavar="DIR", help="output directory")
    r.add_argument("--scan-id", type=int)

    g = sub.add_parser("graph", help="Knowledge Graph summary for a target")
    g.add_argument("target")
    g.add_argument("--scan-id", type=int, help="defaults to the latest scan")
    g.add_argument("--out", metavar="FILE", help="interactive graph page (default: <output dir>/<target>_graph.html)")
    g.add_argument("--no-open", action="store_true", help="write the page but do not open the browser")
    g.add_argument("--no-html", action="store_true", help="text summary only, no interactive page")

    tm = sub.add_parser("timemachine", help="Attack Path Time Machine: how attack paths changed scan over scan")
    tm.add_argument("target")
    tm.add_argument("--last", type=int, metavar="N", help="only the last N completed scans")
    tm.add_argument("--json", action="store_true", help="machine-readable output")

    iv = sub.add_parser("investigate", help="everything known about one host of a target")
    iv.add_argument("target")
    iv.add_argument("host", help="a discovered host, e.g. api.example.com")
    iv.add_argument("--scan-id", type=int, help="defaults to the latest completed scan")

    sk = sub.add_parser("skills", help="list the detection skills (active / planned)")
    sk.add_argument("--mode", type=normalize_mode, choices=list(SCAN_MODES), default="active", help="show what would be active in this mode")

    bm = sub.add_parser("benchmark", help="measure recon coverage or detection quality")
    bsub = bm.add_subparsers(dest="bench", required=True)
    br = bsub.add_parser("recon", help="subfinder alone vs Marsadix with all its sources (C14)")
    br.add_argument("domain")
    br.add_argument("--out", metavar="FILE", help="also write the result as JSON")
    bd = bsub.add_parser("detection", help="Detection Rate and Precision on a training target (C14b)")
    bd.add_argument("target")
    bd.add_argument("--truth", required=True, metavar="FILE", help="ground-truth JSON (see benchmarks/truth/README.md)")
    bd.add_argument("--scan-id", type=int, help="defaults to the latest completed scan")
    bd.add_argument("--out", metavar="FILE", help="also write the result as JSON")

    sub.add_parser("doctor", help="check which external tools are installed")

    sc = sub.add_parser("scope", help="test hosts against a scope file")
    sc.add_argument("file", help="scope.txt")
    sc.add_argument("hosts", nargs="+", help="hosts / IPs / URLs to test")

    # Person 4: risk / patterns / attack-surface / remediation + extra monitor flags.
    # Optional on purpose: a problem inside that package must not take every other command down.
    try:
        from .p4_cli import add_monitor_arguments, register as register_p4
        add_monitor_arguments(m)
        register_p4(sub, lambda a: a._conn)
    except ModuleNotFoundError as exc:
        if exc.name not in ("marsadix.p4_cli",):
            print(f"warning: Person 4 commands unavailable: {exc}", file=sys.stderr)
    except Exception as exc:
        print(f"warning: Person 4 commands unavailable: {exc}", file=sys.stderr)
    return p


# ------------------------------------------------------------------ commands

def cmd_scan(a, cfg: Config) -> int:
    target = normalize_host(a.target)
    if not target:
        print(f"error: invalid target: {a.target!r}", file=sys.stderr)
        return 1
    scope = Scope.from_file(a.scope) if a.scope else None
    if scope is None and normalize_mode(a.mode or cfg.scan_mode) == "passive":
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
    """Sync NVD/KEV/EPSS, match the CVEs against the stored technologies and alert; then repeat every
    --interval-hours (default 0.5). --once (or --dry-run) runs a single cycle. Leave it running (tmux / nohup / Docker)."""
    if a.interval_hours <= 0:
        print("--interval-hours must be positive", file=sys.stderr)
        return 2
    action = getattr(a, "action", None)
    domain = getattr(a, "domain", None)
    if action:
        from marsadix.monitor import background
        if action == "stop":
            return background.stop(cfg)
        if action == "status":
            return background.status(cfg)
        if domain:
            host = valid_hostname(domain)
            if not host:
                print(f"invalid domain: {domain!r}", file=sys.stderr)
                return 2
            targets = [host]
        else:
            targets = [t for t in background.db_targets(cfg) if valid_hostname(t)]
        return background.start(cfg, targets, a.interval_hours)
    if domain:
        print("a domain only goes with start, e.g. marsadix monitor start 0xnull.site", file=sys.stderr)
        return 2
    watch = load_callable("marsadix.monitor.scheduler:watch")
    if watch is None:
        return _missing("marsadix.monitor.scheduler:watch", "monitor")
    return watch(cfg, interval_hours=a.interval_hours, once=a.once or a.dry_run, dry_run=a.dry_run,
                 send_alerts=not getattr(a, "no_alerts", False), since=a.since,
                 all_cves=getattr(a, "all_cves", False), channels=getattr(a, "channel", None))


def cmd_p4(a, cfg: Config) -> int:
    """risk / patterns / attack-surface / remediation (handlers live in p4_cli.py)."""
    conn = db.connect(cfg.db_path)
    try:
        db.init_db(conn)
        a._conn = conn
        rc = a.func(a)
    finally:
        conn.close()
    return rc if isinstance(rc, int) else 0


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
    rc = _db_command("marsadix.core.graph:run_graph", "graph", cfg,
                     target=target, scan_id=a.scan_id)
    if rc != 0 or a.no_html:
        return rc
    # Also write the interactive page and open it, so one command is enough.
    from pathlib import Path
    out = Path(a.out) if a.out else Path(cfg.output_dir) / f"{target}_graph.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    rc = _db_command("marsadix.monitor.graph_view:export_html", "graph page", cfg,
                     target=target, scan_id=a.scan_id, out=str(out))
    if rc == 0 and not a.no_open:
        try:
            import webbrowser
            webbrowser.open(out.resolve().as_uri())
        except Exception:                       # no browser (server / container): the path is printed
            pass
    return rc


def cmd_timemachine(a, cfg: Config) -> int:
    target = normalize_host(a.target) or a.target
    return _db_command("marsadix.core.attackpaths:run_timemachine", "timemachine", cfg,
                       target=target, limit=a.last, as_json=a.json)


def cmd_investigate(a, cfg: Config) -> int:
    target = normalize_host(a.target) or a.target
    return _db_command("marsadix.core.attackpaths:run_investigate", "investigate", cfg,
                       target=target, host=a.host, scan_id=a.scan_id)


def cmd_skills(a, cfg: Config) -> int:
    from marsadix.skills import render_table
    print(render_table(a.mode))
    return 0


def cmd_benchmark(a, cfg: Config) -> int:
    from marsadix import benchmark
    if a.bench == "recon":
        return benchmark.run_recon_benchmark(a.domain, cfg, out_file=a.out)
    target = normalize_host(a.target) or a.target
    return _db_command("marsadix.benchmark:run_detection_benchmark", "benchmark", cfg,
                       target=target, truth_file=a.truth, scan_id=a.scan_id, out_file=a.out)


def cmd_doctor(a, cfg: Config) -> int:
    rows = tool_status()
    w = max(len(n) for n, _, _ in rows)
    missing = 0
    print(f"Python: {sys.executable}  ({platform.system()})")
    print("External tools:")
    for name, path, purpose in rows:
        mark = "OK     " if path else "MISSING"
        missing += 0 if path else 1
        print(f"  [{mark}] {name:<{w}}  {purpose}" + (f"  ({path})" if path else ""))
    flavor, first_line = httpx_check()
    if flavor is False:
        print("\n  WARNING: the 'httpx' on your PATH does not look like ProjectDiscovery's.\n"
              "  The Python package 'httpx' installs a command with the same name.\n"
              "  Use a full path to the right one, or avoid installing Python httpx globally.")
        if first_line:
            print(f"  `httpx -version` answered: {first_line[:160]}")
    found = {n for n, p, _ in rows if p}
    if os.name == "nt" and ("massdns" not in found or "puredns" not in found):
        print("\n  NOTE (Windows): massdns is a C program with no native Windows build, and puredns needs it.\n"
              "  Tools installed inside WSL are NOT visible to this PowerShell. To use DNS bruteforce, run Marsadix\n"
              "  inside WSL (or Docker). Without it Marsadix falls back to a plain resolver wordlist check.")
    # Which recon data sources have a key loaded (names only, never values), so "I put the key in"
    # can be checked instead of guessed.
    sources = [("VirusTotal", cfg.virustotal_api_key, "VIRUSTOTAL_API_KEY"), ("AlienVault OTX", cfg.otx_api_key, "OTX_API_KEY"),
               ("Chaos", cfg.chaos_api_key, "CHAOS_API_KEY")]
    print("\nRecon data sources (key loaded from .env / environment):")
    for name, key, var in sources:
        print(f"  [{'KEY SET' if key else 'no key '}] {name:<15} ({var})")
    print("  A set key is only sent to its own provider. 'no key' = skipped (AlienVault OTX still runs, anonymously and rate-limited).")
    try:
        from .alerts.settings import AlertSettings
        from .p4_cli import doctor_lines
        print("\nAlert channels:")
        for line in doctor_lines(AlertSettings.from_env(config=cfg)):
            print(f"  {line}")
    except Exception:
        pass
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
            "graph": cmd_graph, "timemachine": cmd_timemachine, "investigate": cmd_investigate,
            "skills": cmd_skills, "benchmark": cmd_benchmark, "doctor": cmd_doctor, "scope": cmd_scope,
            "risk": cmd_p4, "patterns": cmd_p4, "attack-surface": cmd_p4, "remediation": cmd_p4}


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
