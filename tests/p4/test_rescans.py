"""A database that was scanned more than once must migrate and keep working (real schema)."""
import json

from marsadix import db
from marsadix.alerts.settings import AlertSettings
from marsadix.db_v4 import migrate_v3_to_v4
from marsadix.monitor.matching_run import run_matching

CFG = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{
    "vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}]}]}]


def _rescanned_db():
    c = db.connect(":memory:"); db.init_db(c)
    for _ in (1, 2):                                   # same target scanned twice
        c.execute("insert into scans(target,started_at,status) values('a.example','2025-01-01','completed')")
    for scan in (1, 2):                                # the scanner stores the SAME dedup_key in each scan
        c.execute("insert into assets(scan_id,host,in_scope,source,first_seen) values(?,'www.a.example',1,'subfinder','2025-01-01')", (scan,))
        c.execute("insert into technologies(scan_id,host,name,version,cpe,source,confidence) values(?,'www.a.example','Apache','2.4.49','cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*','nmap','high')", (scan,))
        c.execute("insert into findings(scan_id,host,source,severity,confidence,found_at,dedup_key) values(?,'www.a.example','nuclei','low','possible','2025-01-01','nuclei|x|www.a.example')", (scan,))
    c.execute("insert into cves(cve_id,description,cvss_score,severity,cpe_matches,in_kev,epss_score,refs) values('CVE-2021-41773','x',7.5,'high',?,1,0.9,'[]')", (json.dumps(CFG),))
    c.commit(); return c


def test_migration_works_on_a_database_with_rescans_and_is_idempotent():
    c = _rescanned_db()
    migrate_v3_to_v4(c); migrate_v3_to_v4(c)
    assert c.execute("select count(*) from findings where dedup_key='nuclei|x|www.a.example'").fetchone()[0] == 2


def test_scanner_can_still_store_the_same_finding_in_a_later_scan_after_migrating():
    c = _rescanned_db(); migrate_v3_to_v4(c)
    c.execute("insert into scans(target,started_at,status) values('a.example','2025-02-01','completed')")
    c.execute("insert into findings(scan_id,host,source,severity,confidence,found_at,dedup_key) values(3,'www.a.example','nuclei','low','possible','2025-02-01','nuclei|x|www.a.example')")
    c.commit()                                           # must not raise: the old global unique index is gone


def test_old_global_index_from_an_earlier_migration_is_dropped():
    c = db.connect(":memory:"); db.init_db(c)
    migrate_v3_to_v4(c)
    c.execute("CREATE UNIQUE INDEX ux_findings_dedup ON findings(dedup_key) WHERE dedup_key IS NOT NULL")
    migrate_v3_to_v4(c)
    assert c.execute("select count(*) from sqlite_master where name='ux_findings_dedup'").fetchone()[0] == 0


def test_matching_on_a_rescanned_database_creates_one_finding_per_cve_and_host():
    c = _rescanned_db()
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    assert c.execute("select count(*) from findings where source='monitor'").fetchone()[0] == 1
    assert c.execute("select count(*) from findings where source='nuclei'").fetchone()[0] == 2     # scanner rows untouched


def test_duplicate_p4_rows_from_an_earlier_run_are_collapsed_not_fatal():
    c = _rescanned_db(); migrate_v3_to_v4(c)
    c.execute("DROP INDEX ux_findings_p4_dedup")
    for scan in (1, 2):
        c.execute("insert into findings(scan_id,host,source,severity,confidence,found_at,dedup_key) values(?,'h','monitor','low','possible','2025-01-01','cvefinding:X|host:h|product:p')", (scan,))
    c.commit(); migrate_v3_to_v4(c)
    assert c.execute("select count(*) from findings where source='monitor'").fetchone()[0] == 1
