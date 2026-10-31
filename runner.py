"""Incremental passive intelligence sync. Matcher/alerts are Person 4's responsibility."""
from __future__ import annotations
import argparse
import json
import logging
from datetime import datetime, timedelta, timezone
from .sources import fetch_nvd, fetch_kev, fetch_epss
from .. import db
from ..models import CVE

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
    summary = {'nvd_records': len(changed), 'kev_total': len(kev),
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
        if not kev:
            # Empty feed is probably corrupt/partial; never clear KEV on it.
            raise ValueError('CISA KEV feed unexpectedly empty')
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

def run(conn, config, dry_run=False, since=None):
    try:
        outcome = synchronize(conn, config, dry_run=dry_run, since=since)
        print(json.dumps(outcome, indent=2))
        if outcome['new_kev']:
            print('KEV transition detected: Person 4 matcher should re-evaluate these CVEs.')
        return 0
    except Exception as exc:
        log.exception('CVE sync failed; state not advanced')
        print(f'CVE sync failed: {exc}')
        return 1

def main(argv=None):
    p = argparse.ArgumentParser(description='Marsadix CVE intelligence updater')
    p.add_argument('--db', default='marsadix.db')
    p.add_argument('--since')
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args(argv)
    conn = db.connect(args.db)
    try:
        db.init_db(conn)
        return run(conn, argparse.Namespace(nvd_api_key=''), args.dry_run, args.since)
    finally: conn.close()

if __name__ == '__main__': raise SystemExit(main())
