"""Continuous CVE monitoring behind `marsadix monitor`: sync NVD/KEV/EPSS, match against the technologies in the
database, alert - now, and then again every --interval-hours (default 5). Leave it running (tmux, nohup, systemd,
Docker). A failing cycle is logged and the next one still runs; Ctrl+C stops it cleanly.
`python -m marsadix.monitor.scheduler` does the same thing.
"""
import argparse
import logging
import sys
import time
import types
from datetime import datetime, timezone

from .. import db
from ..core.config import load_config
from .runner import run

log = logging.getLogger(__name__)
DEFAULT_INTERVAL_HOURS = 5.0


def _post_sync():
    """Matching + alerts live in marsadix/p4_cli.py; without it (other branch) the monitor only syncs."""
    try:
        from ..p4_cli import monitor_post_sync
        return monitor_post_sync
    except ImportError:
        return None


def cycle(config, dry_run=False, send_alerts=True, since=None, all_cves=False, channels=None):
    """One sync + match + alert pass. Returns an exit code: 0 ok, 1 failed, 2 skipped (another sync is running)."""
    conn = db.connect(config.db_path)
    try:
        db.init_db(conn)
        post = _post_sync()
        if post is None:
            return run(conn, config, dry_run=dry_run, since=since)
        rc, summary = run(conn, config, dry_run=dry_run, since=since, return_summary=True)
        if rc != 0:
            return rc                                       # never match on a failed / skipped sync
        args = types.SimpleNamespace(dry_run=dry_run, all_cves=all_cves, no_alerts=not send_alerts, channel=channels)
        post(conn, args, summary, config=config)
        return 0
    finally:
        conn.close()


def _say(msg):
    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC] {msg}", file=sys.stderr, flush=True)


def watch(config, interval_hours=DEFAULT_INTERVAL_HOURS, once=False, dry_run=False, send_alerts=True,
          since=None, all_cves=False, channels=None, sleep=time.sleep):
    """Run cycles forever (or once). --since / --all only make sense for the FIRST cycle; later ones are incremental."""
    if interval_hours <= 0:
        raise ValueError("interval_hours must be positive")
    alerts = "on" if (send_alerts and not dry_run) else "off"
    n = 0
    try:
        while True:
            n += 1
            _say(f"monitor cycle {n} starting (alerts {alerts})")
            try:
                rc = cycle(config, dry_run=dry_run, send_alerts=send_alerts,
                           since=since if n == 1 else None, all_cves=all_cves if n == 1 else False, channels=channels)
            except Exception:
                log.exception("monitor cycle failed; the next one still runs")
                rc = 1
            if once:
                _say(f"cycle {n} finished (exit {rc})")
                return rc
            _say(f"cycle {n} finished (exit {rc}); next one in {interval_hours:g} h  (Ctrl+C to stop)")
            sleep(interval_hours * 3600)
    except KeyboardInterrupt:
        _say("monitor stopped")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--interval-hours", type=float, default=DEFAULT_INTERVAL_HOURS)
    p.add_argument("--once", action="store_true", help="run a single cycle and exit")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-alerts", action="store_true", help="sync and match but never alert")
    args = p.parse_args(argv)
    if args.interval_hours <= 0:
        p.error("--interval-hours must be positive")
    return watch(load_config(), args.interval_hours, args.once or args.dry_run, args.dry_run, not args.no_alerts)


if __name__ == "__main__":
    raise SystemExit(main())
