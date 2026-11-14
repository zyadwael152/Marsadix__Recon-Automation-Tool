"""CLI + report wiring of Person 4 (real schema, no network)."""
import json

from marsadix import db
from marsadix.cli import main
from marsadix.reports import generate

CFG = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{
    "vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}]}]}]


def _db(tmp_path, targets=("a.example", "b.example")):
    path = str(tmp_path / "t.db")
    c = db.connect(path); db.init_db(c)
    c.execute("insert into cves(cve_id,description,cvss_score,severity,cpe_matches,in_kev,epss_score,refs) values('CVE-2021-41773','x',7.5,'high',?,1,0.9,'[]')",
              (json.dumps(CFG),))
    for i, t in enumerate(targets, 1):
        host = f"www.{t}"
        c.execute("insert into scans(target,started_at,finished_at,status) values(?,?,?,'completed')", (t, "2025-01-01", "2025-01-01"))
        c.execute("insert into assets(scan_id,host,in_scope,source,first_seen) values(?,?,1,'subfinder','2025-01-01')", (i, host))
        c.execute("insert into technologies(scan_id,host,name,version,cpe,source,confidence) values(?,?,'Apache','2.4.49','cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*','nmap','high')", (i, host))
    c.commit(); c.close()
    return path


def _run(db_path, *args):
    return main(["--no-banner", "--db", db_path, *args])


def test_monitor_accepts_the_p4_flags_without_duplicate_option_errors(tmp_path, monkeypatch):
    seen = {}

    def fake_run(conn, config, dry_run=False, since=None, return_summary=False):
        return (0, {"changed_cve_ids": ["CVE-2021-41773"], "new_kev": [], "total": 1})

    def fake_post(conn, args, summary, config=None):
        seen.update(dry=args.dry_run, no_alerts=args.no_alerts, all=args.all_cves, channel=args.channel, summary=summary)

    monkeypatch.setattr("marsadix.cli.load_callable", lambda p: fake_run if p.endswith("runner:run") else fake_post)
    assert _run(_db(tmp_path), "monitor", "--dry-run", "--no-alerts", "--all", "--channel", "discord") == 0
    assert seen["dry"] and seen["no_alerts"] and seen["all"] and seen["channel"] == ["discord"]
    assert seen["summary"]["changed_cve_ids"] == ["CVE-2021-41773"]


def test_monitor_does_not_match_when_the_sync_failed_or_was_skipped(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr("marsadix.cli.load_callable",
                        lambda p: (lambda conn, config, dry_run=False, since=None, return_summary=False: (1, None))
                        if p.endswith("runner:run") else (lambda *a, **k: called.append(1)))
    assert _run(_db(tmp_path), "monitor") == 1 and not called


def test_p4_commands_run_end_to_end_on_the_real_schema(tmp_path, capsys):
    p = _db(tmp_path)
    c = db.connect(p); db.init_db(c)                               # seed through the matcher: `monitor` itself would hit NVD
    from marsadix.monitor.matching_run import run_matching
    from marsadix.alerts.settings import AlertSettings
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True); c.close()
    for cmd in (["risk"], ["patterns", "--json"], ["attack-surface", "--no-record"], ["remediation", "list"]):
        assert _run(p, *cmd) == 0, cmd


def test_report_has_p4_sections_and_never_shows_another_targets_findings(tmp_path):
    p = _db(tmp_path)
    c = db.connect(p); db.init_db(c)
    from marsadix.monitor.matching_run import run_matching
    from marsadix.alerts.settings import AlertSettings
    run_matching(c, settings=AlertSettings(), all_cves=True, no_alerts=True)
    assert generate.generate_report(c, "a.example", "both", str(tmp_path / "out")) == 0
    html = (tmp_path / "out" / "a.example_scan1_report.html").read_text(encoding="utf-8")
    js = json.loads((tmp_path / "out" / "a.example_scan1_report.json").read_text(encoding="utf-8"))
    assert 'id="marsadix-p4"' in html and "Attack surface score" in html
    assert "www.a.example" in html and "www.b.example" not in html           # no cross-target leak
    assert {f["host"] for f in js["risk"]["findings"]} == {"www.a.example"}
    assert all("www.b.example" not in json.dumps(js[k]) for k in ("top_fixes", "patterns", "risk"))
    assert not any(k.startswith("_") for k in js)                              # no internal HTML fragment in JSON
    assert js["posture_score"] == int(round(js["attack_surface"]["score"]))
