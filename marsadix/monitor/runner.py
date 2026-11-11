"""Incremental passive intelligence sync. Matcher/alerts are Person 4's responsibility."""
from __future__ import annotations
import argparse
import json
import logging
from datetime import datetime, timedelta, timezone
from .sources import fetch_nvd, fetch_kev, fetch_epss
from .. import db
from ..core.config import load_config

log = logging.getLogger(__name__)
STATE = 'nvd_last_sync'

def parse_timestamp(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)

def synchronize(conn, config, dry_run=False, since=None, now=None):
    """Sync in a transaction. NVD watermark advances only after ALL sources succeed.

    Failed KEV/EPSS requests must not silently clear existing intelligence. A dry
    run never writes. New KEV membership is returned for Person 4 to re-evaluate.
    """
    now = now or datetime.now(timezone.utc)
    saved = db.get_state(conn, STATE)
    start = parse_timestamp(since or saved) if (since or saved) else now - timedelta(days=7)
    # Small overlap protects against provider indexing lag and equal timestamps.
    if not since and saved: start -= timedelta(minutes=5)
    if start > now: raise ValueError('sync start is in the future')
    changed = list(fetch_nvd(start, now, getattr(config, 'nvd_api_key', '')))
    kev = fetch_kev()
    if not kev:
        raise ValueError("CISA KEV feed unexpectedly empty")
    ids = {x['cve_id'] for x in changed} | kev
    epss = fetch_epss(ids)
    old_kev = {r['cve_id'] for r in conn.execute('SELECT cve_id FROM cves WHERE in_kev=1')}
    newly_kev = sorted(kev - old_kev)
    # changed_cve_ids / total are what marsadix.monitor.matching_run.extract_sync_info reads,
    # so the matcher re-evaluates every CVE NVD modified in this window (not only KEV ones).
    summary = {'nvd_records': len(changed), 'total': len(changed),
               'changed_cve_ids': sorted({x['cve_id'] for x in changed}),
               'kev_total': len(kev),
               'new_kev': newly_kev, 'epss_updated': len(epss),
               'since': start.isoformat(), 'until': now.isoformat(), 'dry_run': dry_run}
    if dry_run: return summary
    try:
        # Do not use db.save_cve: its REPLACE operation resets EPSS/KEV and may
        # delete dependent rows in future schemas.
        for item in changed:
            conn.execute('''INSERT INTO cves
                (cve_id,description,cvss_score,severity,published,modified,cpe_matches,refs,in_kev,epss_score)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,cvss_score=excluded.cvss_score,
                severity=excluded.severity,published=excluded.published,modified=excluded.modified,
                cpe_matches=excluded.cpe_matches,refs=excluded.refs''',
                (item['cve_id'], item['description'], item['cvss_score'], item['severity'],
                 item['published'], item['modified'], json.dumps(item['cpe_matches']),
                 json.dumps(item['references']), int(item['cve_id'] in kev), epss.get(item['cve_id'])))
        # KEV feed is an authoritative current membership snapshot. New KEV records
        # not yet present in NVD still need to be represented for recheck.
        for cve_id in kev:
            conn.execute("INSERT OR IGNORE INTO cves (cve_id,severity,in_kev) VALUES (?,'info',1)", (cve_id,))
        conn.execute('UPDATE cves SET in_kev=0 WHERE in_kev=1')
        conn.executemany('UPDATE cves SET in_kev=1 WHERE cve_id=?', ((x,) for x in kev))
        conn.executemany('UPDATE cves SET epss_score=? WHERE cve_id=?',
                         ((score, cid) for cid, score in epss.items()))
        conn.execute('INSERT INTO monitor_state(key,value,updated_at) VALUES (?,?,?) '
                     'ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at',
                     (STATE, now.isoformat(), now.isoformat()))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return summary

def run(conn, config, dry_run=False, since=None, return_summary=False):
    """CLI entry used by `marsadix monitor`. Returns 0/1, or (rc, summary) when return_summary=True
    so the caller can hand the summary to marsadix.p4_cli.monitor_post_sync (matching + alerts)."""
    try:
        outcome = synchronize(conn, config, dry_run=dry_run, since=since)
        shown = {k: v for k, v in outcome.items() if k != 'changed_cve_ids'}
        shown['changed_cve_count'] = len(outcome['changed_cve_ids'])
        print(json.dumps(shown, indent=2))
        return (0, outcome) if return_summary else 0
    except Exception as exc:
        log.exception('CVE sync failed; state not advanced')
        print(f'CVE sync failed: {exc}')
        return (1, None) if return_summary else 1

def main(argv=None):
    p = argparse.ArgumentParser(description='Marsadix CVE intelligence updater')
    p.add_argument('--db', default=None, help='default: db_path from config')
    p.add_argument('--since')
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args(argv)
    config = load_config()  # reads NVD_API_KEY from .env / environment
    conn = db.connect(args.db or config.db_path)
    try:
        db.init_db(conn)
        return run(conn, config, args.dry_run, args.since)
    finally: conn.close()

if __name__ == '__main__': raise SystemExit(main())
