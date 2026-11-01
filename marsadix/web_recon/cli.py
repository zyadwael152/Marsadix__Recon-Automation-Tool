"""Command-line interface for the Member 2 extension.

Examples (after a normal Marsadix scan):

    marsadix-web-recon run target.example --scope scope.txt --json
    marsadix-web-recon run target.example --scan-id 4 --no-archive --no-crawl
    marsadix-web-recon discover target.example --active --json
    marsadix-web-recon doctor
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from typing import Optional, Sequence

from marsadix import db

from . import __version__
from .config import CRAWLER_BACKENDS, Member2Config, load_member2_config
from .discovery import SubdomainEnumerator
from .errors import ConfigError, ScopeViolation
from .logging_utils import configure_logging
from .pipeline import run_web_pipeline
from .scope_filter import ScopeEnforcer
from .storage import load_scan, resolve_scope
from .tools import ToolResolver, tool_doctor


def _base_config(path: Optional[str]):
    """Read the untouched Marsadix config when available (optional).

    A single config.toml may contain both the base keys and a [member2] table.
    The base loader rejects unknown tables, so in that case the [member2] table
    is stripped into a temporary TOML file for the base loader only.
    """
    try:
        from marsadix.core.config import load_config
        return load_config(path)
    except Exception:
        if not path:
            return None

    try:
        import tomllib
        from pathlib import Path as _Path
        data = tomllib.loads(_Path(path).read_text(encoding="utf-8"))
        data.pop("member2", None)
        if not data:
            return None
        base_text = "\n".join(f"{key} = {json.dumps(value)}"
                               for key, value in data.items())
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".toml", prefix="marsadix-base-", delete=False,
            encoding="utf-8")
        try:
            tmp.write(base_text)
            tmp.close()
            from marsadix.core.config import load_config as load_base
            return load_base(tmp.name)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
    except Exception:
        return None


def _build_config(args) -> Member2Config:
    base = _base_config(getattr(args, "config", None))
    if base is not None:
        cfg = Member2Config(
            db_path=base.db_path, output_dir=base.output_dir,
            rate_limit=base.rate_limit, tool_timeout=base.tool_timeout,
        )
    else:
        cfg = Member2Config()
    cfg = load_member2_config(getattr(args, "config", None), base=cfg)
    updates = {}
    if getattr(args, "db", None):
        updates["db_path"] = args.db
    if getattr(args, "output_dir", None):
        updates["output_dir"] = args.output_dir
    if getattr(args, "rate", None):
        updates["rate_limit"] = args.rate
    if getattr(args, "tools_dir", None):
        updates["tools_dir"] = args.tools_dir
    if getattr(args, "log_file", None):
        updates["log_file"] = args.log_file
    if getattr(args, "crawler", None):
        updates["crawler_backend"] = args.crawler
    if getattr(args, "status_allow", None):
        updates["status_allow"] = args.status_allow
    if getattr(args, "max_urls", None):
        updates["max_urls"] = args.max_urls
    if getattr(args, "max_per_host", None):
        updates["max_per_host"] = args.max_per_host
    if getattr(args, "archive_source", None):
        updates["archive_sources"] = tuple(args.archive_source)
    if getattr(args, "no_js", False):
        updates["extract_js"] = False
    return cfg.with_overrides(**updates)


def _print_report(report, as_json: bool) -> None:
    data = report.to_dict()
    if as_json:
        print(json.dumps(data, indent=2, default=str))
        return
    print(f"\nMember 2 web-surface run — scan #{report.scan_id} ({report.target}, mode={report.mode})")
    print(f"  status          {report.status}")
    print(f"  archive records {report.archive_records}")
    print(f"  candidates      {report.candidates}")
    print(f"  stored          {report.stored}  (already present: {report.skipped_existing})")
    print(f"  checked         {report.checked}")
    print(f"  new assets      {report.assets_stored}")
    print(f"  findings        {report.findings_stored} stored"
          f" (nuclei={report.nuclei_findings}, security={report.security_findings})")
    if report.counts:
        print("  kinds           " + ", ".join(f"{k}={v}" for k, v in sorted(report.counts.items())))
    if report.source_counts:
        print("  sources         " + ", ".join(f"{k}={v}" for k, v in sorted(report.source_counts.items())))
    for outcome in report.outcomes:
        line = f"  tool {outcome.name:<22} {outcome.status:<8} discovered={outcome.discovered}"
        if outcome.error:
            line += f"  {outcome.error}"
        print(line)
    for note in report.skipped:
        print(f"  note: {note}")
    for error in report.errors:
        print(f"  error: {error}", file=sys.stderr)
    if report.output_files:
        print("  files:")
        for path in report.output_files:
            print(f"    {path}")
    print()


def cmd_run(args) -> int:
    cfg = _build_config(args)
    configure_logging(args.verbose, cfg.log_file, force=True)
    try:
        report = run_web_pipeline(
            target=args.target, scan_id=args.scan_id, scope_path=args.scope,
            config=cfg, seeds=args.seed or (),
            use_archive=not args.no_archive,
            crawl=not args.no_crawl,
            check_status=False if args.no_status else None,
            discover_hosts=False if args.no_discover_hosts else None,
            dry_run=args.dry_run, mode=getattr(args, "mode", None),
        )
    except (ConfigError, ScopeViolation, db.SchemaVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_report(report, args.json)
    return 0 if report.status in ("completed", "dry-run") else 1


def cmd_discover(args) -> int:
    cfg = _build_config(args)
    configure_logging(args.verbose, cfg.log_file, force=True)
    conn = db.connect(cfg.db_path)
    try:
        db.init_db(conn)
        scan = load_scan(conn, target=args.target, scan_id=args.scan_id)
        scope = resolve_scope(scan, args.scope)
        enforcer = ScopeEnforcer(scope, scan["target"], allow_private=cfg.allow_private,
                                 dns_timeout=cfg.dns_timeout)
        resolver = ToolResolver(cfg)
        enumerator = SubdomainEnumerator(cfg, enforcer, resolver)
        batch = asyncio.run(enumerator.discover(
            scan["target"],
            passive=not args.no_passive,
            active=args.active,
        ))
        saved = 0
        if args.save:
            saved = asyncio.run(enumerator.store(
                conn, int(scan["id"]), scan["target"], batch.hosts_sources, enforcer))
        data = {
            "target": scan["target"],
            "scan_id": scan["id"],
            "hosts": batch.hosts_sources,
            "host_count": len(batch.hosts_sources),
            "saved_assets": saved,
            "outcomes": [o.to_dict() for o in batch.outcomes],
        }
        if args.json:
            print(json.dumps(data, indent=2, default=str))
        else:
            print(f"\nDiscovered {len(batch.hosts_sources)} in-scope host(s) for {scan['target']}")
            for host, sources in sorted(batch.hosts_sources.items()):
                print(f"  {host:<45} {', '.join(sources)}")
            for outcome in batch.outcomes:
                print(f"  {outcome.name:<18} {outcome.status:<8} {outcome.discovered}"
                      + (f"  {outcome.error}" if outcome.error else ""))
            if args.save:
                print(f"\nStored {saved} new asset(s) in scan #{scan['id']}.")
        return 0
    except (ConfigError, ScopeViolation, db.SchemaVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


def cmd_doctor(args) -> int:
    cfg = _build_config(args)
    configure_logging(False, None, force=True)
    rows = tool_doctor(cfg)
    resolver = ToolResolver(cfg)
    pd = resolver.projectdiscovery_httpx()
    data = {
        "version": __version__,
        "tools": rows,
        "projectdiscovery_httpx": pd or "",
        "config": cfg.to_dict(),
    }
    if args.json:
        print(json.dumps(data, indent=2, default=str))
        return 0
    print(f"Marsadix Member 2 extension v{__version__}")
    print("External tools:")
    for row in rows:
        mark = "OK     " if row["available"] else "MISSING"
        print(f"  [{mark}] {row['name']:<12} {row['path']}")
    if not pd:
        print("\n  NOTE: ProjectDiscovery httpx was not found; status checks fall back to stdlib.")
    print(f"\nDB: {cfg.db_path}")
    print(f"Output: {cfg.output_dir}")
    print(f"Rate limit: {cfg.rate_limit}/s  |  archive: {','.join(cfg.archive_sources)}")
    return 0


def cmd_normalize(args) -> int:
    from .normalize import normalize_url
    values = list(args.urls)
    if not values:
        values = [line.strip() for line in sys.stdin if line.strip()]
    bad = 0
    for raw in values:
        try:
            n = normalize_url(raw, strip_tracking=not args.keep_tracking)
            print(json.dumps({"input": raw, "url": n.url, "host": n.host,
                              "key": n.key, "has_params": n.has_params}) if args.json
                  else n.url)
        except ScopeViolation as exc:
            bad += 1
            print(f"rejected {raw!r}: {exc}", file=sys.stderr)
    return 0 if bad == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="marsadix-web-recon",
        description="Member 2 web-surface extension for Marsadix (URLs, archives, JS endpoints).")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--config", metavar="FILE", help="config.toml (base or [member2] section)")
    p.add_argument("--db", metavar="FILE", help="SQLite database path")
    p.add_argument("--output-dir", metavar="DIR")
    p.add_argument("--rate", type=int, metavar="N", help="requests/second")
    p.add_argument("--tools-dir", metavar="DIR", help="directory with locally installed tools")
    p.add_argument("--log-file", metavar="FILE")
    p.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command")

    r = sub.add_parser("run", help="run the web-surface pipeline on a scan")
    r.add_argument("target", nargs="?", help="target (latest scan is used; a scan is created if needed)")
    r.add_argument("--scan-id", type=int, help="explicit scan id (target mismatch auto-resolves)")
    r.add_argument("--scope", metavar="FILE", help="scope file (needed for active scans if not stored)")
    r.add_argument("--mode", choices=["passive", "standard", "full"],
                   help="mode for a newly created scan (default: full with --scope, else passive)")
    r.add_argument("--seed", action="append", metavar="URL", help="extra seed URL (repeatable)")
    r.add_argument("--no-archive", action="store_true", help="do not query archive providers")
    r.add_argument("--archive-source", action="append",
                   choices=["gau", "wayback", "commoncrawl"],
                   help="archive provider (repeatable; replaces the configured list)")
    r.add_argument("--no-crawl", action="store_true", help="skip katana/built-in crawling")
    r.add_argument("--no-status", action="store_true", help="do not verify status codes")
    r.add_argument("--no-js", action="store_true", help="do not extract JS endpoints")
    r.add_argument("--no-discover-hosts", action="store_true",
                   help="do not add archive-derived hosts as assets")
    r.add_argument("--crawler", choices=list(CRAWLER_BACKENDS), help="auto|katana|builtin|both")
    r.add_argument("--status-allow", metavar="SPEC", help="e.g. 200-399,401,403")
    r.add_argument("--max-urls", type=int)
    r.add_argument("--max-per-host", type=int)
    r.add_argument("--dry-run", action="store_true", help="collect/verify but do not write DB rows")
    r.add_argument("--json", action="store_true", help="machine-readable report")

    d = sub.add_parser("discover", help="subdomain discovery (subfinder/crt.sh/archive)")
    d.add_argument("target", nargs="?", help="target (latest scan is used)")
    d.add_argument("--scan-id", type=int)
    d.add_argument("--scope", metavar="FILE")
    d.add_argument("--active", action="store_true", help="verify DNS/public addresses")
    d.add_argument("--save", action="store_true", help="store new hosts as assets in the scan")
    d.add_argument("--no-passive", action="store_true",
                   help="skip subfinder/crt.sh/archive sources")
    d.add_argument("--json", action="store_true")

    doc = sub.add_parser("doctor", help="show tool resolution and config")
    doc.add_argument("--json", action="store_true")

    n = sub.add_parser("normalize", help="normalize URLs from arguments or stdin")
    n.add_argument("urls", nargs="*")
    n.add_argument("--keep-tracking", action="store_true",
                   help="keep utm_*/click-id parameters")
    n.add_argument("--json", action="store_true")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    handler = {
        "run": cmd_run,
        "discover": cmd_discover,
        "doctor": cmd_doctor,
        "normalize": cmd_normalize,
    }[args.command]
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except (ConfigError, ScopeViolation) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
