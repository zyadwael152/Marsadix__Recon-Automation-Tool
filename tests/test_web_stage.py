"""
The web stage sends traffic to the target (httpx, katana), so it must obey the
scan mode (C15) and the scope. httpx/katana are replaced by fakes that record
what they were asked to touch: nothing here needs the real tools or a network.
"""

import pytest

from marsadix import db
from marsadix.core.config import Config
from marsadix.core.pipeline import Context, run_scan
from marsadix.core.scope import Scope
from marsadix.models import Asset, Scan, ScanMode, ScanStatus
from marsadix.web import stage as web_stage


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


@pytest.fixture
def calls(monkeypatch):
    """Fake httpx/katana. httpx 'finds' every host alive and returns its URL."""
    rec = {"httpx": [], "katana": [], "rates": []}

    async def fake_httpx(hosts, rate_limit=None):
        rec["httpx"].append(list(hosts))
        rec["rates"].append(("httpx", rate_limit))
        return [{"url": f"https://{h}", "status_code": 200} for h in hosts]

    async def fake_katana(urls, rate_limit=None):
        rec["katana"].append(list(urls))
        rec["rates"].append(("katana", rate_limit))
        # a crawler follows links to hosts that were never in its input
        return ([f"{u}/login" for u in urls] + [f"{u}/static/app.js" for u in urls]
                + [f"{u}/search?q=1" for u in urls] + list(urls)
                + ["https://evil.com/leak", "https://dev.example.com/admin"])

    monkeypatch.setattr(web_stage, "run_httpx", fake_httpx)
    monkeypatch.setattr(web_stage, "run_katana", fake_katana)
    return rec


def _ctx(conn, tmp_path, mode, scope_lines=("example.com", "*.example.com", "!dev.example.com")):
    scan = Scan(target="example.com", status=ScanStatus.RUNNING, mode=ScanMode(mode), rate_limit=25)
    db.save_scan(conn, scan)
    db.save_many(conn, "assets", [
        Asset(scan_id=scan.id, host="www.example.com", in_scope=True),
        Asset(scan_id=scan.id, host="api.example.com", in_scope=True),
        # recon flagged this one out of scope (e.g. from a shared certificate)
        Asset(scan_id=scan.id, host="evil.com", in_scope=False),
        # flagged in scope, but the scope file explicitly excludes it
        Asset(scan_id=scan.id, host="dev.example.com", in_scope=True),
    ])
    cfg = Config(db_path=":memory:", output_dir=str(tmp_path / "out"), scan_mode=mode, rate_limit=25)
    return Context(conn=conn, scan=scan, scope=Scope.from_lines(list(scope_lines)), config=cfg)


# ------------------------------------------------------------------ mode (bug 6)

def test_passive_mode_never_touches_the_target(conn, tmp_path, calls):
    out = web_stage.run(_ctx(conn, tmp_path, "passive"))

    assert calls["httpx"] == [] and calls["katana"] == []
    assert "makes no contact with the target" in out["skipped"]


def test_standard_mode_probes_but_does_not_crawl(conn, tmp_path, calls):
    out = web_stage.run(_ctx(conn, tmp_path, "standard"))

    assert len(calls["httpx"]) == 1
    assert calls["katana"] == []
    assert out["endpoints"] == []
    assert out["live_urls"] == ["https://api.example.com", "https://www.example.com"]


def test_full_mode_probes_and_crawls(conn, tmp_path, calls):
    out = web_stage.run(_ctx(conn, tmp_path, "full"))

    assert len(calls["httpx"]) == 1 and len(calls["katana"]) == 1
    assert "https://www.example.com/login" in out["endpoints"]


# ----------------------------------------------------------------- scope (bug 5)

@pytest.mark.parametrize("mode", ["standard", "full"])
def test_out_of_scope_hosts_are_never_probed(conn, tmp_path, calls, mode):
    web_stage.run(_ctx(conn, tmp_path, mode))

    probed = calls["httpx"][0]
    assert "evil.com" not in probed            # stored flag in_scope=0
    assert "dev.example.com" not in probed     # flagged in scope, excluded by the scope rules
    assert probed == ["api.example.com", "www.example.com"]


def test_crawler_results_pointing_outside_scope_are_dropped(conn, tmp_path, calls):
    out = web_stage.run(_ctx(conn, tmp_path, "full"))

    assert not any("evil.com" in u or "dev.example.com" in u for u in out["endpoints"])


def test_no_in_scope_hosts_means_no_tool_runs(conn, tmp_path, calls):
    ctx = _ctx(conn, tmp_path, "full", scope_lines=("other.org",))
    out = web_stage.run(ctx)

    assert calls["httpx"] == [] and calls["katana"] == []
    assert out == {"live_urls": [], "endpoints": []}


# ------------------------------------------------------------------- output dir

def test_results_are_written_to_the_configured_output_dir(conn, tmp_path, calls, monkeypatch):
    monkeypatch.chdir(tmp_path)                 # a stray "outputs/" would appear here
    web_stage.run(_ctx(conn, tmp_path, "full"))

    out = tmp_path / "out"
    assert (out / "example.com_live_urls.txt").read_text().splitlines() == [
        "https://api.example.com", "https://www.example.com"]
    assert (out / "example.com_endpoints.txt").exists()
    assert not (tmp_path / "outputs").exists()


# --------------------------------------------------- through the real pipeline

def _fake_recon(ctx):
    db.save_many(ctx.conn, "assets", [
        Asset(scan_id=ctx.scan.id, host="www.example.com", in_scope=True),
        Asset(scan_id=ctx.scan.id, host="evil.com", in_scope=False),
    ])


@pytest.fixture
def pipeline(monkeypatch, calls):
    monkeypatch.setattr("marsadix.recon.stage.run", _fake_recon)


def _stage(results, name):
    return next(r for r in results if r.name == name)


def test_scan_default_mode_reports_web_as_skipped_and_stays_off_the_target(tmp_path, pipeline, calls):
    cfg = Config(db_path=str(tmp_path / "t.db"), output_dir=str(tmp_path / "out"))
    scan, results = run_scan("example.com", cfg)          # default = passive

    web = _stage(results, "web")
    assert web.status == "skipped" and "no contact" in web.detail
    assert calls["httpx"] == [] and calls["katana"] == []
    assert scan.status == ScanStatus.COMPLETED


def test_scan_mode_flag_reaches_the_stages_through_config_too(tmp_path, calls, monkeypatch):
    seen = {}
    monkeypatch.setattr("marsadix.recon.stage.run",
                        lambda ctx: seen.update(config_mode=ctx.config.scan_mode, ctx_mode=ctx.mode))
    cfg = Config(db_path=str(tmp_path / "t.db"), output_dir=str(tmp_path / "out"), scan_mode="passive")
    run_scan("example.com", cfg, mode="full", scope=Scope.from_lines(["example.com", "*.example.com"]))

    # ctx.config.scan_mode used to stay "passive" and ignore the --mode flag
    assert seen == {"config_mode": "full", "ctx_mode": "full"}


def test_scan_standard_mode_probes_only_in_scope_hosts(tmp_path, pipeline, calls):
    cfg = Config(db_path=str(tmp_path / "t.db"), output_dir=str(tmp_path / "out"))
    scan, results = run_scan("example.com", cfg, mode="standard", scope=Scope.from_lines(["example.com", "*.example.com"]))

    assert _stage(results, "web").status == "ok"
    assert calls["httpx"] == [["www.example.com"]]
    assert calls["katana"] == []


# --------------------------------------------------------------- rate limit (C6)

def test_scan_rate_limit_is_passed_to_both_tools(conn, tmp_path, calls):
    web_stage.run(_ctx(conn, tmp_path, "full"))
    assert calls["rates"] == [("httpx", 25), ("katana", 25)]


def test_cli_rate_flag_reaches_the_tools_through_the_pipeline(tmp_path, pipeline, calls):
    cfg = Config(db_path=str(tmp_path / "t.db"), output_dir=str(tmp_path / "out"), rate_limit=50)
    run_scan("example.com", cfg, mode="full", rate_limit=3,
             scope=Scope.from_lines(["example.com", "*.example.com"]))
    assert calls["rates"] == [("httpx", 3), ("katana", 3)]


# ------------------------------------------------------- stored in the database

def _items(conn, scan_id):
    return {(r["kind"], r["url"]): r for r in db.get_web_items(conn, scan_id)}


def test_live_urls_are_stored_with_their_status_code(conn, tmp_path, calls):
    ctx = _ctx(conn, tmp_path, "standard")
    web_stage.run(ctx)

    items = _items(conn, ctx.scan.id)
    assert set(items) == {("url", "https://api.example.com"), ("url", "https://www.example.com")}
    row = items[("url", "https://www.example.com")]
    assert row["status_code"] == 200 and row["host"] == "www.example.com"
    assert row["source"] == "active" and row["has_params"] == 0


def test_crawled_endpoints_are_classified_and_stored(conn, tmp_path, calls):
    ctx = _ctx(conn, tmp_path, "full")
    web_stage.run(ctx)

    items = _items(conn, ctx.scan.id)
    assert items[("endpoint", "https://www.example.com/login")]["has_params"] == 0
    assert ("js_file", "https://www.example.com/static/app.js") in items
    assert items[("endpoint", "https://www.example.com/search?q=1")]["has_params"] == 1
    # out-of-scope links the crawler followed are never stored
    assert not any("evil.com" in url or "dev.example.com" in url for _, url in items)
    # the root URL katana echoes back is not stored a second time as an "endpoint"
    assert ("endpoint", "https://www.example.com") not in items


def test_rerunning_the_stage_does_not_duplicate_rows(conn, tmp_path, calls):
    ctx = _ctx(conn, tmp_path, "full")
    first = web_stage.run(ctx)["stored"]
    second = web_stage.run(ctx)["stored"]

    assert first > 0 and second == 0
    assert len(db.get_web_items(conn, ctx.scan.id)) == first


def test_passive_mode_stores_nothing(conn, tmp_path, calls):
    ctx = _ctx(conn, tmp_path, "passive")
    web_stage.run(ctx)
    assert db.get_web_items(conn, ctx.scan.id) == []


def test_stored_items_appear_in_the_json_report(conn, tmp_path, calls):
    import json
    from marsadix.reports.generate import generate_report

    ctx = _ctx(conn, tmp_path, "full")
    web_stage.run(ctx)
    ctx.conn.execute("UPDATE scans SET status='completed' WHERE id=?", (ctx.scan.id,))
    ctx.conn.commit()

    out = tmp_path / "rep"
    generate_report(conn, "example.com", out_dir=str(out))
    data = json.loads(next(out.glob("*_report.json")).read_text())
    assert any(w["url"] == "https://www.example.com/login" for w in data["web_items"])
