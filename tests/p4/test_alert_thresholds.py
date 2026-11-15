"""Alert thresholds come from .env, and a per-run cap stops a low threshold from flooding the channels."""
import json

from marsadix import db
from marsadix.alerts.base import AlertPayload
from marsadix.alerts.http import HttpResponse
from marsadix.alerts.settings import AlertSettings
from marsadix.core.config import load_config
from marsadix.monitor.matching_run import run_matching

from .fakes import FakeClient

HOOK = "https://discord.com/api/webhooks/1/abc"
VARS = ("MARSADIX_ALERT_MIN_CONFIDENCE", "MARSADIX_ALERT_MIN_PRIORITY", "MARSADIX_ALERT_MAX_PER_RUN",
        "DISCORD_WEBHOOK_URL", "DISCORD_WEBHOOK", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")


def _seed(n_cves):
    """One technology with no version (httpx only knows the product) and n CVEs for it -> n LOW-confidence matches."""
    c = db.connect(":memory:"); db.init_db(c)
    c.execute("insert into scans(target,started_at,status) values('a.example','2026-11-14','completed')")
    c.execute("insert into assets(scan_id,host,in_scope,source,first_seen) values(1,'www.a.example',1,'subfinder','2026-11-14')")
    c.execute("insert into technologies(scan_id,host,name,version,cpe,source,confidence) values(1,'www.a.example','apache','','cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*','httpx','medium')")
    cfg = json.dumps([{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": True,
          "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "versionEndExcluding": "99.0"}]}]}])
    for i in range(n_cves):                      # CVE-2024-1000 has the highest CVSS, then descending
        c.execute("insert into cves(cve_id,description,cvss_score,severity,cpe_matches,in_kev,epss_score,refs) values(?,'x',?,'high',?,0,0.1,'[]')",
                  (f"CVE-2024-{1000 + i}", 9.5 - i * 0.1, cfg))
    c.commit(); return c


def _run(c, **settings_kw):
    client = FakeClient(HttpResponse(204))
    s = run_matching(c, settings=AlertSettings(discord_webhook=HOOK, **settings_kw), client=client, all_cves=True)
    return s, client


def test_thresholds_are_read_from_dotenv_and_not_exported(tmp_path, monkeypatch):
    import os
    for v in VARS:
        monkeypatch.delenv(v, raising=False)
    (tmp_path / ".env").write_text("MARSADIX_ALERT_MIN_CONFIDENCE=low\nMARSADIX_ALERT_MIN_PRIORITY=Medium\nMARSADIX_ALERT_MAX_PER_RUN=7\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    s = AlertSettings.from_env(config=load_config())
    assert (s.min_confidence, s.min_priority, s.max_alerts_per_run) == ("low", "medium", 7)
    assert "MARSADIX_ALERT_MIN_CONFIDENCE" not in os.environ


def test_real_environment_variables_still_win_over_dotenv(tmp_path, monkeypatch):
    for v in VARS:
        monkeypatch.delenv(v, raising=False)
    (tmp_path / ".env").write_text("MARSADIX_ALERT_MIN_CONFIDENCE=low\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path); monkeypatch.setenv("MARSADIX_ALERT_MIN_CONFIDENCE", "high")
    assert AlertSettings.from_env(config=load_config()).min_confidence == "high"


def test_defaults_and_invalid_values_fall_back_safely():
    s = AlertSettings.from_env({})
    assert (s.min_confidence, s.min_priority, s.max_alerts_per_run) == ("medium", "high", 25)
    bad = AlertSettings.from_env({"MARSADIX_ALERT_MIN_CONFIDENCE": "lwo", "MARSADIX_ALERT_MIN_PRIORITY": "urgent", "MARSADIX_ALERT_MAX_PER_RUN": "0"})
    assert (bad.min_confidence, bad.min_priority, bad.max_alerts_per_run) == ("medium", "high", 25)    # a typo never silences or floods


def test_default_thresholds_still_hold_back_low_confidence_matches():
    c = _seed(6)
    s, client = _run(c)
    assert s.matches == 6 and s.alerts_sent == 0 and s.alerts_below_threshold == 6 and client.calls == []


def test_low_thresholds_alert_on_low_confidence_matches():
    c = _seed(6)
    s, client = _run(c, min_confidence="low", min_priority="low")
    assert s.alerts_sent == 6 and s.alerts_below_threshold == 0 and s.alerts_deferred == 0 and len(client.calls) == 6


def test_cap_sends_the_most_important_first_and_the_rest_on_the_next_run():
    c = _seed(12)
    s1, _ = _run(c, min_confidence="low", min_priority="low", max_alerts_per_run=5)
    first = [r[0] for r in c.execute("select cve_id from alerts order by id")]
    assert (s1.alerts_sent, s1.alerts_deferred) == (5, 7)
    assert sorted(first) == [f"CVE-2024-{1000 + i}" for i in range(5)]            # the 5 highest-priority CVEs
    s2, _ = _run(c, min_confidence="low", min_priority="low", max_alerts_per_run=5)
    second = [r[0] for r in c.execute("select cve_id from alerts order by id")][5:]
    assert (s2.alerts_sent, s2.alerts_deferred, s2.alerts_deduplicated) == (5, 2, 5)
    assert sorted(second) == [f"CVE-2024-{1005 + i}" for i in range(5)]           # drips on, never repeats
    s3, _ = _run(c, min_confidence="low", min_priority="low", max_alerts_per_run=5)
    assert (s3.alerts_sent, s3.alerts_deferred) == (2, 0)
    assert any("deferred" in l for l in s1.lines()) and not any("deferred" in l for l in s3.lines())
