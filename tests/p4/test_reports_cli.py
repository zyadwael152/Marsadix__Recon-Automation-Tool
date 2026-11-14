import argparse
import json
from marsadix import p4_cli, remediation_db as rdb
from marsadix.alerts.settings import AlertSettings
from marsadix.reports.p4_sections import (augment_report_json, build_p4_report_data, collect_risked_findings, p4_csv_rows,
                                          render_p4_html, sarif_results)
from marsadix.monitor.matching_run import run_matching
from .conftest import seed_basic
from .fakes import FakeClient, Sleeper


def populated(db):
    seed_basic(db, kev=1)
    db.execute("INSERT INTO web_items(scan_id,host,url,status_code,body,content_type) VALUES (1,'www.example.com','https://www.example.com/.env',200,'A_KEY=1','text/plain')")
    db.commit()
    run_matching(db, settings=AlertSettings(), notifiers={}, changed_cve_ids=["CVE-2021-41773"], no_alerts=True)
    rdb.add_entry(db, "cve", "CVE-2021-41773", "Apache path traversal", "Upgrade Apache httpd to 2.4.51 or later.", effort="low", priority=99)
    return db


def test_report_data_contains_everything(db):
    populated(db)
    d = build_p4_report_data(db)
    assert d["risk"]["findings"][0]["remediation"] == "Upgrade Apache httpd to 2.4.51 or later."
    assert d["top_fixes"][0]["cve_id"] == "CVE-2021-41773" and d["top_fixes"][0]["action"].startswith("Upgrade Apache")
    assert any(p["rule_id"] == "exposed-sensitive-file" and p["remediation"] for p in d["patterns"])
    assert d["attack_surface"]["score"] < 100 and d["attack_surface"]["direction"].startswith("100")
    n = db.execute("SELECT count(*) FROM attack_surface_scores").fetchone()[0]
    build_p4_report_data(db)
    assert db.execute("SELECT count(*) FROM attack_surface_scores").fetchone()[0] == n  # report is read-only


def test_html_json_csv_sarif(db):
    d = build_p4_report_data(populated(db))
    h = render_p4_html(d)
    assert "Attack surface score" in h and "CVE-2021-41773" in h and "Upgrade Apache httpd" in h and "Misconfiguration patterns" in h
    j = augment_report_json({"existing": 1}, d)
    assert j["existing"] == 1 and {"risk", "top_fixes", "patterns", "attack_surface"} <= set(j)
    json.dumps(j)
    rows = p4_csv_rows(d)
    assert {r["type"] for r in rows} == {"cve", "pattern"} and rows[0]["risk_score"]
    s = sarif_results(d)
    assert s and all({"ruleId", "level", "message"} <= set(x) for x in s)


def test_html_escapes_untrusted_content(db):
    populated(db)
    db.execute("UPDATE findings SET host='<img src=x onerror=alert(1)>' WHERE source='monitor'")
    db.commit()
    assert "<img src=x" not in render_p4_html(build_p4_report_data(db))


def run_cli(db, argv):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p4_cli.register(sub, lambda a: db)
    args = parser.parse_args(argv)
    lines = []
    import marsadix.p4_cli as m
    # route output through a capture by calling the handler directly
    fn = {"risk": m.cmd_risk, "patterns": m.cmd_patterns, "attack-surface": m.cmd_attack_surface, "remediation": m.cmd_remediation}[args.cmd]
    code = fn(db, args, lines.append)
    return code, "\n".join(lines)


def test_cli_risk_patterns_attack_surface(db):
    populated(db)
    code, text = run_cli(db, ["risk", "--top", "5"])
    assert code == 0 and "CVE-2021-41773" in text and "action: Upgrade Apache" in text
    code, text = run_cli(db, ["risk", "--json"])
    assert json.loads(text)["top_fixes"][0]["host"] == "www.example.com"
    code, text = run_cli(db, ["patterns"])
    assert "exposed-sensitive-file" in text and "persisted" in text
    code, text = run_cli(db, ["patterns", "--no-persist", "--min-severity", "critical", "--json"])
    assert all(x["severity"] == "critical" for x in json.loads(text))
    code, text = run_cli(db, ["attack-surface", "--history", "3"])
    assert "100 = healthiest" in text and "history #" in text
    before = db.execute("SELECT count(*) FROM attack_surface_scores").fetchone()[0]
    run_cli(db, ["attack-surface", "--no-record"])
    assert db.execute("SELECT count(*) FROM attack_surface_scores").fetchone()[0] == before


def test_cli_remediation_crud(db):
    code, text = run_cli(db, ["remediation", "list", "--type", "owasp"])
    assert code == 0 and "A05" in text and "10 entries" in text
    code, text = run_cli(db, ["remediation", "add", "--type", "keyword", "--value", "log4shell", "--title", "Patch Log4j", "--fix", "Upgrade log4j-core to 2.17.1+", "--ref", "https://logging.apache.org", "--effort", "low", "--priority", "95"])
    assert code == 0 and "added remediation" in text
    code, text = run_cli(db, ["remediation", "search", "log4j", "-v"])
    assert "log4shell" in text and "2.17.1" in text
    assert rdb.lookup(db, {"title": "Log4Shell RCE"}).title == "Patch Log4j"
    code, text = run_cli(db, ["remediation", "add", "--type", "keyword", "--value", "log4shell", "--title", "dup", "--fix", "dup"])
    assert code == 2 and "already exists" in text
    eid = rdb.search(db, "log4shell")[0].id
    assert run_cli(db, ["remediation", "delete", str(eid)])[1] == "deleted"


def test_monitor_flags_and_post_sync(db):
    seed_basic(db)
    parser = argparse.ArgumentParser()
    p4_cli.add_monitor_arguments(parser)
    a = parser.parse_args(["--dry-run", "--all", "--channel", "discord", "--channel", "telegram"])
    assert a.dry_run and a.all_cves and a.channel == ["discord", "telegram"] and not a.no_alerts
    lines = []
    client = FakeClient()
    s = p4_cli.monitor_post_sync(db, a, {"new_kev": [], "total": 5}, out=lines.append, client=client, sleep=Sleeper())
    assert s.records_synced == 5 and s.dry_run and client.calls == [] and any("matches found" in l for l in lines)


def test_doctor_lines_show_state_not_secrets():
    s = AlertSettings(discord_webhook="https://discord.com/api/webhooks/1/SECRETTOKEN")
    lines = p4_cli.doctor_lines(s)
    assert [l.split()[2:4] for l in lines] == [["discord", "configured"], ["telegram", "not"]]
    assert "SECRETTOKEN" not in "\n".join(lines)
