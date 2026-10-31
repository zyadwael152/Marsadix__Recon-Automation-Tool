"""Simple blocking scheduled CVE sync (use systemd timer / cron in production)."""
import argparse
import time
from .. import db
from ..core.config import load_config
from .runner import run

def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--interval-hours', type=float, default=6)
    p.add_argument('--once', action='store_true')
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args(argv)
    if args.interval_hours <= 0: p.error('--interval-hours must be positive')
    config = load_config()
    while True:
        conn = db.connect(config.db_path)
        try:
            db.init_db(conn)
            rc = run(conn, config, dry_run=args.dry_run)
        finally:
            conn.close()
        if args.once: return rc
        time.sleep(args.interval_hours * 3600)

if __name__ == '__main__': raise SystemExit(main())
