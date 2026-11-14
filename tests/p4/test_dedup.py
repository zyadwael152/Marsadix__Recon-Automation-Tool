import pytest
from marsadix.alerts.base import DeliveryResult
from marsadix.alerts.dedup import group_key, plan_alert, process_alert, MAX_ATTEMPTS
from marsadix.alerts.dispatch import UnknownChannel, build_notifiers
from marsadix.alerts.settings import AlertSettings
from .fakes import payload


class Fake:
    name = "discord"
    configured = True

    def __init__(self, ok=True):
        self.ok, self.sent = ok, []

    def send(self, a):
        self.sent.append((a.kind, a.priority_level, a.kev))
        return DeliveryResult(self.ok, 204 if self.ok else 500, 1, "" if self.ok else "server error (HTTP 500)")


def run(db, p, n, dry=False):
    return process_alert(db, p, "discord", n, dry_run=dry)


def rows(db):
    return db.execute("SELECT dedup_key, delivered, attempts, kind FROM alerts ORDER BY id").fetchall()


NONKEV = dict(kev=False, priority_level="high", priority_score=70.0)


def test_group_key_format_and_stability():
    k = group_key("cve-1", "Host A", "Http Server", "discord")
    assert k == "cve:CVE-1|host:host_a|product:http_server|channel:discord"
    assert k == group_key("CVE-1", "host a", "http server", "DISCORD")


def test_first_run_sends_second_does_not(db):
    n = Fake()
    assert run(db, payload(**NONKEV), n)["result"].ok
    assert run(db, payload(**NONKEV), n) is None
    assert len(n.sent) == 1
    r = rows(db)
    assert len(r) == 1 and r[0][1] == 1 and r[0][2] == 1


def test_different_channel_or_host_is_independent(db):
    n = Fake()
    run(db, payload(**NONKEV), n)
    process_alert(db, payload(**NONKEV), "telegram", n)
    run(db, payload(host="other", **NONKEV), n)
    assert len(n.sent) == 3 and len(rows(db)) == 3


def test_kev_transition_sends_exactly_once(db):
    n = Fake()
    run(db, payload(**NONKEV), n)
    kev = payload(kev=True, priority_level="critical", priority_score=95)
    a = run(db, kev, n)
    assert a["action"].kind == "kev_transition" and a["action"].dedup_key.endswith("|event:kev")
    assert run(db, kev, n) is None and run(db, kev, n) is None
    assert [s[0] for s in n.sent] == ["new", "kev_transition"]  # escalation folded into the KEV alert


def test_kev_from_start_is_plain_new_and_no_transition(db):
    n = Fake()
    kev = payload()
    assert run(db, kev, n)["action"].kind == "new"
    assert run(db, kev, n) is None


def test_escalation_once_per_level_no_spam(db):
    n = Fake()
    run(db, payload(kev=False, priority_level="medium", priority_score=50), n)
    assert run(db, payload(kev=False, priority_level="medium", priority_score=55), n) is None  # medium isn't alert-worthy escalation
    assert run(db, payload(kev=False, priority_level="high", priority_score=65), n)["action"].kind == "escalation"
    assert run(db, payload(kev=False, priority_level="high", priority_score=66), n) is None
    assert run(db, payload(kev=False, priority_level="critical", priority_score=85), n)["action"].kind == "escalation"
    # flapping down and up again does not re-alert
    assert run(db, payload(kev=False, priority_level="high", priority_score=65), n) is None
    assert run(db, payload(kev=False, priority_level="critical", priority_score=85), n) is None
    assert len(n.sent) == 3


def test_failed_send_not_delivered_and_retried(db):
    bad = Fake(ok=False)
    r = run(db, payload(**NONKEV), bad)
    assert not r["result"].ok
    row = db.execute("SELECT delivered, attempts, last_error FROM alerts").fetchone()
    assert row[0] == 0 and row[1] == 1 and "HTTP 500" in row[2]
    good = Fake()
    r2 = run(db, payload(**NONKEV), good)
    assert r2["action"].kind == "retry" and r2["result"].ok
    row = db.execute("SELECT delivered, attempts, last_error FROM alerts").fetchone()
    assert row[0] == 1 and row[1] == 2 and row[2] is None
    assert run(db, payload(**NONKEV), good) is None and len(good.sent) == 1
    assert len(rows(db)) == 1


def test_retry_gives_up_after_max_attempts(db):
    bad = Fake(ok=False)
    for _ in range(MAX_ATTEMPTS):
        assert run(db, payload(**NONKEV), bad) is not None
    assert run(db, payload(**NONKEV), bad) is None


def test_notifier_exception_does_not_mark_delivered(db):
    class Boom(Fake):
        def send(self, a): raise RuntimeError("token=SECRET")
    r = run(db, payload(**NONKEV), Boom())
    assert not r["result"].ok and "SECRET" not in r["result"].error
    assert db.execute("SELECT delivered FROM alerts").fetchone()[0] == 0


def test_dry_run_writes_nothing_and_sends_nothing(db):
    n = Fake()
    r = run(db, payload(**NONKEV), n, dry=True)
    assert r["action"].kind == "new" and r["result"] is None
    assert n.sent == [] and rows(db) == []
    run(db, payload(**NONKEV), n)
    before = rows(db)
    r = run(db, payload(kev=True, priority_level="critical", priority_score=95), n, dry=True)
    assert r["action"].kind == "kev_transition" and rows(db) == before and len(n.sent) == 1


def test_unique_constraint_prevents_duplicate_rows(db):
    n = Fake()
    a = plan_alert(db, payload(**NONKEV), "discord")
    from marsadix.alerts.dedup import deliver
    deliver(db, a, payload(**NONKEV), n)
    deliver(db, a, payload(**NONKEV), n)  # forced double-record is still one row
    assert len(rows(db)) == 1


# ---- settings / dispatch -----------------------------------------------------
def test_settings_env_and_describe_no_secrets():
    env = {"DISCORD_WEBHOOK_URL": "https://d/SECRET1", "TELEGRAM_BOT_TOKEN": "tokSECRET", "TELEGRAM_CHAT_ID": "1",
           # channels that no longer exist must be ignored, not half-configured
           "SMTP_HOST": "h", "SMTP_FROM": "a@b.c", "SMTP_TO": "x@y.z", "WEBHOOK_URL": "https://w/", "SLACK_WEBHOOK_URL": "https://s/"}
    s = AlertSettings.from_env(env)
    assert s.configured_channels() == ["discord", "telegram"]
    assert set(s.describe()) == {"discord", "telegram"}
    blob = repr(s) + str(s.describe())
    assert "SECRET1" not in blob and "tokSECRET" not in blob


def test_settings_config_object_fallback_env_wins():
    class Cfg:
        discord_webhook = "https://cfg"; telegram_bot_token = "t"; telegram_chat_id = "c"; pass
    s = AlertSettings.from_env({"DISCORD_WEBHOOK_URL": "https://env"}, Cfg())
    assert s.discord_webhook == "https://env" and s.telegram_bot_token == "t" and s.configured_channels() == ["discord", "telegram"]


def test_build_notifiers():
    s = AlertSettings(discord_webhook="https://d")
    assert set(build_notifiers(s)) == {"discord"}
    assert set(build_notifiers(s, ["discord", "telegram"])) == {"discord"}      # unconfigured channel is just omitted
    for gone in ("fax", "email", "webhook", "slack", "teams"):
        with pytest.raises(UnknownChannel):
            build_notifiers(s, [gone])
