import json
import sqlite3
import pytest
from marsadix.alerts.http import HttpResponse, TransportError
from marsadix.alerts.settings import AlertSettings
from marsadix.monitor.matching_run import extract_sync_info, run_matching
from .conftest import APACHE_CVE_CFG, seed_basic
from .fakes import FakeClient, Sleeper

DISCORD = "https://discord.com/api/webhooks/1/SECRET"


def settings(**kw):
    kw.setdefault("discord_webhook", DISCORD)
    return AlertSettings(**kw)


def go(db, client, **kw):
    kw.setdefault("settings", settings())
    kw.setdefault("changed_cve_ids", ["CVE-2021-41773"])
    return run_matching(db, client=client, sleep=Sleeper(), **kw)


def dump(conn):
    out = {}
    for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        out[t] = conn.execute(f'SELECT * FROM "{t}"').fetchall()
    return out


def test_end_to_end_db_adapter_match_finding_dedup_alert(db):
    seed_basic(db, kev=0, cvss=9.8, epss=0.9)
    client = FakeClient(HttpResponse(204))
    s = go(db, client)
    assert (s.technologies_evaluated, s.matches, s.alerts_sent, s.findings_created) == (1, 1, 1, 1)
    assert s.channels == ["discord"] and not s.failures and s.attack_surface and s.attack_surface["score"] < 100
    f = db.execute("SELECT host, severity, category, source, cve_id, product, version, cvss, kev, confidence, priority_score, risk_score, scan_id, monitor_run_id, remediation_key FROM findings").fetchone()
    assert f[0] == "www.example.com" and f[2:5] == ("cve", "monitor", "CVE-2021-41773") and f[5] == "http_server" and f[6] == "2.4.49"
    assert f[9] == "high" and f[10] > 0 and f[11] > 0 and f[12] == 1 and f[13] == s.run_id
    emb = client.json()["embeds"][0]
    names = {x["name"]: x["value"] for x in emb["fields"]}
    assert names["Host"] == "www.example.com" and "Apache" in names["Technology"] and names["Remediation"]
    assert db.execute("SELECT delivered, attempts FROM alerts").fetchall() == [(1, 1)]
    run = db.execute("SELECT status, technologies, matches, alerts_sent FROM monitor_runs").fetchone()
    assert run == ("ok", 1, 1, 1)
    assert db.execute("SELECT count(*) FROM attack_surface_scores").fetchone()[0] == 1
    assert "new alerts sent:         1" in "\n".join(s.lines())


def test_second_run_does_not_send_again(db):
    seed_basic(db)
    client = FakeClient(HttpResponse(204))
    go(db, client)
    s2 = go(db, client)
    assert s2.alerts_sent == 0 and s2.alerts_deduplicated == 1 and len(client.calls) == 1
    assert s2.findings_created == 0 and s2.findings_updated == 1
    assert db.execute("SELECT count(*) FROM findings").fetchone()[0] == 1


def test_kev_transition_alert_via_reeval_of_new_kev(db):
    seed_basic(db, kev=0, cvss=7.0, epss=0.9)
    client = FakeClient(HttpResponse(204))
    s1 = go(db, client)
    assert s1.alerts_sent == 1
    db.execute("UPDATE cves SET in_kev=1 WHERE cve_id='CVE-2021-41773'"); db.commit()
    s2 = go(db, client, changed_cve_ids=None, new_kev=["CVE-2021-41773"])
    assert s2.alerts_sent == 1 and len(client.calls) == 2
    assert client.json()["embeds"][0]["title"].startswith("[KEV]")
    s3 = go(db, client, changed_cve_ids=None, new_kev=["CVE-2021-41773"])
    assert s3.alerts_sent == 0 and len(client.calls) == 2


def test_failed_send_is_retried_next_run_and_not_marked_delivered(db):
    seed_basic(db)
    bad = FakeClient(TransportError("network error (X)"))
    s1 = go(db, bad)
    assert s1.alerts_sent == 0 and s1.alerts_failed == 1 and any("network error" in f for f in s1.failures)
    assert db.execute("SELECT delivered, attempts FROM alerts").fetchall() == [(0, 1)]
    good = FakeClient(HttpResponse(204))
    s2 = go(db, good)
    assert s2.alerts_sent == 1 and db.execute("SELECT delivered FROM alerts").fetchone()[0] == 1
    assert "SECRET" not in json.dumps(s1.failures)


def test_dry_run_writes_nothing_and_sends_nothing(db):
    seed_basic(db)
    before = dump(db)
    client = FakeClient(HttpResponse(204))
    s = go(db, client, dry_run=True)
    assert client.calls == [] and dump(db) == before
    assert s.matches == 1 and s.alerts_would_send == 1 and s.alerts_sent == 0 and s.run_id is None
    assert "dry-run" in "\n".join(s.lines())


def test_dry_run_on_unmigrated_v3_db_leaves_it_untouched(v3db):
    seed_basic(v3db)
    before = dump(v3db)
    s = run_matching(v3db, settings=settings(), changed_cve_ids=["CVE-2021-41773"], dry_run=True, client=FakeClient(), sleep=Sleeper())
    assert s.matches == 1 and dump(v3db) == before and v3db.execute("PRAGMA user_version").fetchone()[0] == 3


def test_no_alerts_persists_findings_but_sends_nothing(db):
    seed_basic(db)
    client = FakeClient()
    s = go(db, client, no_alerts=True)
    assert client.calls == [] and s.findings_created == 1 and db.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


def test_channel_selection_and_unconfigured_channel_reported(db):
    seed_basic(db)
    client = FakeClient(HttpResponse(204))
    s = run_matching(db, settings=settings(), client=client, sleep=Sleeper(), changed_cve_ids=["CVE-2021-41773"],
                     channels=["discord", "telegram"])
    assert s.channels == ["discord"] and any("'telegram' is not configured" in f for f in s.failures)
    assert [c["url"] for c in client.calls] == [DISCORD]


def test_multiple_channels(db):
    seed_basic(db)
    client = FakeClient(HttpResponse(204), HttpResponse(200, {}, '{"ok": true}'))
    st = settings(telegram_bot_token="123:tok", telegram_chat_id="42")
    s = run_matching(db, settings=st, client=client, sleep=Sleeper(), changed_cve_ids=["CVE-2021-41773"])
    assert s.channels == ["discord", "telegram"] and s.alerts_sent == 2
    assert db.execute("SELECT count(DISTINCT channel) FROM alerts").fetchone()[0] == 2


def test_unknown_version_matches_low_confidence_stored_not_alerted(db):
    seed_basic(db, version=None)
    client = FakeClient()
    s = go(db, client)
    assert s.matches == 1 and s.alerts_below_threshold == 1 and client.calls == []
    assert db.execute("SELECT confidence FROM findings").fetchone()[0] == "low"


def test_not_vulnerable_version_no_match(db):
    seed_basic(db, version="2.4.60")
    s = go(db, FakeClient())
    assert s.matches == 0 and db.execute("SELECT count(*) FROM findings").fetchone()[0] == 0


def test_new_technology_is_matched_against_all_cves_without_changed_ids(db):
    seed_basic(db)
    client = FakeClient(HttpResponse(204))
    s = go(db, client, changed_cve_ids=None)
    assert s.matches == 1 and s.alerts_sent == 1          # first run: tech is new -> matched against ALL cves
    s2 = go(db, client, changed_cve_ids=None)
    assert s2.matches == 0 and s2.technologies_evaluated == 1  # nothing new, nothing changed


def test_all_flag_rematches_everything_and_resolves_stale(db):
    sid = seed_basic(db)
    go(db, FakeClient(HttpResponse(204)), changed_cve_ids=None, all_cves=True)
    assert db.execute("SELECT status FROM findings").fetchone()[0] == "open"
    # host is upgraded in a newer scan
    db.execute("INSERT INTO scans(target,status) VALUES ('example.com','completed')")
    sid2 = db.execute("SELECT max(id) FROM scans").fetchone()[0]
    db.execute("INSERT INTO assets(scan_id,host) VALUES (?,?)", (sid2, "www.example.com"))
    db.execute("INSERT INTO technologies(scan_id,host,name,version,cpe,source) VALUES (?,?,?,?,?,?)",
               (sid2, "www.example.com", "Apache", "2.4.58", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "nmap"))
    db.commit()
    s = go(db, FakeClient(), changed_cve_ids=None, all_cves=True)
    assert s.matches == 0 and s.findings_resolved == 1
    assert db.execute("SELECT status FROM findings").fetchone()[0] == "resolved"


def test_internal_asset_gets_lower_risk_than_internet_facing(db):
    seed_basic(db, host="pub.example.com", internet_facing=1)
    seed_basic(db, host="int.example.com", internet_facing=0)
    go(db, FakeClient(HttpResponse(204)), no_alerts=True)
    rows = dict(db.execute("SELECT host, risk_score FROM findings").fetchall())
    assert rows["pub.example.com"] > rows["int.example.com"]


def test_bad_rows_do_not_abort_run(db):
    seed_basic(db)
    sid = 1
    db.execute("INSERT INTO technologies(scan_id,host,name,version,cpe,source) VALUES (?,?,?,?,?,?)", (sid, "bad.example.com", "X", "1", "garbage-cpe", "nmap"))
    db.execute("INSERT INTO cves(cve_id,cvss_score,cpe_matches) VALUES ('CVE-BAD', 'not-a-number', '{not json')")
    db.commit()
    s = go(db, FakeClient(HttpResponse(204)), changed_cve_ids=["CVE-2021-41773", "CVE-BAD"])
    assert s.matches == 1 and s.alerts_sent == 1 and any("bad.example.com" in f for f in s.failures)


def test_run_failure_marks_run_error(db, monkeypatch):
    seed_basic(db)
    import marsadix.monitor.matching_run as mr
    monkeypatch.setattr(mr, "record_score", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        go(db, FakeClient(HttpResponse(204)))
    assert db.execute("SELECT status FROM monitor_runs").fetchone()[0] == "error"


def test_no_secrets_in_summary_output(db):
    seed_basic(db)
    s = go(db, FakeClient(HttpResponse(500)))
    assert "SECRET" not in "\n".join(s.lines()) and "discord.com" not in "\n".join(s.lines())


def test_extract_sync_info_variants():
    class R: new_kev = ["cve-1"]; changed_cve_ids = ["cve-2"]; total = 12
    assert extract_sync_info(R()) == {"changed_cve_ids": ["CVE-2"], "new_kev": ["CVE-1"], "synced": 12}
    assert extract_sync_info({"new_cve_ids": ["a"], "records": [1, 2]}) == {"changed_cve_ids": ["A"], "new_kev": [], "synced": 2}
    assert extract_sync_info(None) == {"changed_cve_ids": None, "new_kev": [], "synced": 0}
