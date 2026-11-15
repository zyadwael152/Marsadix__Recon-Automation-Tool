"""`monitor` shows progress (stderr) and `doctor` reads .env."""
import json
from datetime import datetime, timezone

import pytest

CFG = type("C", (), {"nvd_api_key": ""})()


def test_monitor_reports_progress_on_stderr_and_keeps_stdout_json(monkeypatch, capsys):
    runner = pytest.importorskip("marsadix.monitor.runner")
    from marsadix import db
    c = db.connect(":memory:"); db.init_db(c)
    monkeypatch.setattr(runner, "fetch_nvd", lambda s, e, k="": iter([]))
    monkeypatch.setattr(runner, "fetch_kev", lambda: {"CVE-2023-9999"})
    monkeypatch.setattr(runner, "fetch_epss", lambda ids: {})
    assert runner.run(c, CFG) == 0
    cap = capsys.readouterr()
    out, err = cap.out, cap.err
    json.loads(out)                                             # stdout is still machine-readable
    for step in ("NVD: fetching", "NVD: 0 CVE(s) received", "CISA KEV: 1 entries", "EPSS: fetching", "Writing to the database"):
        assert step in err, step


def test_nvd_pagination_reports_page_progress(monkeypatch, capsys):
    sources = pytest.importorskip("marsadix.monitor.sources")
    pages = [{"vulnerabilities": [{"cve": {"id": f"CVE-2024-{i}", "metrics": {}, "descriptions": []}} for i in range(2)],
              "totalResults": 4},
             {"vulnerabilities": [{"cve": {"id": f"CVE-2025-{i}", "metrics": {}, "descriptions": []}} for i in range(2)],
              "totalResults": 4}]
    monkeypatch.setattr(sources, "request_json", lambda *a, **k: pages.pop(0))
    monkeypatch.setattr(sources.time, "sleep", lambda s: None)
    now = datetime(2025, 1, 2, tzinfo=timezone.utc); start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert len(list(sources.fetch_nvd(start, now, "k", page_size=2))) == 4
    err = capsys.readouterr().err
    assert "NVD: 2/4 records" in err and "NVD: 4/4 records" in err


def test_doctor_shows_channels_configured_in_dotenv(tmp_path, monkeypatch, capsys):
    pytest.importorskip("marsadix.p4_cli")
    from marsadix.cli import main
    for v in ("DISCORD_WEBHOOK_URL", "DISCORD_WEBHOOK", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(v, raising=False)
    (tmp_path / ".env").write_text("DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1/SECRETTOKEN\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    main(["--no-banner", "--db", str(tmp_path / "t.db"), "doctor"])
    out = capsys.readouterr().out
    rows = {l.split()[2]: l.split()[3] for l in out.splitlines() if l.strip().startswith("alert channel")}
    assert rows == {"discord": "configured", "telegram": "not"}
    assert "SECRETTOKEN" not in out
