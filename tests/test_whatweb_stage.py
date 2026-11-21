"""The web stage asks WhatWeb about the live URLs and merges its answer with httpx's."""

import pytest

from marsadix import db
from marsadix.core.config import Config
from marsadix.core.pipeline import Context
from marsadix.core.scope import Scope
from marsadix.models import Asset, Scan, ScanMode, ScanStatus
from marsadix.web import stage as web_stage


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def _ctx(conn, tmp_path):
    scan = Scan(target="example.com", status=ScanStatus.RUNNING, mode=ScanMode("active"), rate_limit=25)
    db.save_scan(conn, scan)
    db.save_many(conn, "assets", [Asset(scan_id=scan.id, host="www.example.com", in_scope=True)])
    cfg = Config(db_path=":memory:", output_dir=str(tmp_path / "out"), scan_mode="active", rate_limit=25)
    return Context(conn=conn, scan=scan, scope=Scope.from_lines(["example.com", "*.example.com"]), config=cfg)


@pytest.fixture
def fakes(monkeypatch):
    seen = {"whatweb": []}

    async def fake_httpx(hosts, rate_limit=None, timeout=None):
        return [{"url": f"https://{h}", "status_code": 200, "webserver": "nginx", "tech": ["Nginx"]} for h in hosts]

    async def fake_katana(urls, rate_limit=None, timeout=None):
        return []

    async def fake_gau(domain, timeout=180):
        return None

    async def fake_whatweb(urls, rate_limit=None, timeout=None):
        seen["whatweb"].append(list(urls))
        plugins = {"HTTPServer": {"string": ["nginx/1.18.0 (Ubuntu)"]}, "PHP": {"version": ["8.1.2"]},
                   "Title": {"string": ["x"]}}
        return ([{"url": u + "/", "status_code": 200, "ip": None, "plugins": plugins} for u in urls]
                + [{"url": "https://evil.com/", "status_code": 200, "ip": None, "plugins": {"Drupal": {"version": ["7"]}}}])

    monkeypatch.setattr(web_stage, "run_httpx", fake_httpx)
    monkeypatch.setattr(web_stage, "run_katana", fake_katana)
    monkeypatch.setattr(web_stage, "run_gau", fake_gau)
    monkeypatch.setattr(web_stage, "run_whatweb", fake_whatweb)
    return seen


def test_whatweb_results_are_merged_with_httpx_and_stored_with_both_sources(conn, tmp_path, fakes):
    ctx = _ctx(conn, tmp_path)
    web_stage.run(ctx)

    assert fakes["whatweb"] == [["https://www.example.com"]]
    rows = {(t["name"].lower(), t["version"]): t for t in db.get_technologies(conn, ctx.scan.id)}
    assert rows[("nginx", "1.18.0")]["source"] == "httpx+whatweb"
    assert rows[("php", "8.1.2")]["source"] == "whatweb"
    assert ("nginx", None) not in rows                          # the version-less httpx entry was folded in
    assert not any(name == "drupal" for name, _ in rows)        # an out-of-scope answer is never recorded


def test_whatweb_is_not_asked_in_passive_mode(conn, tmp_path, fakes):
    ctx = _ctx(conn, tmp_path)
    ctx.scan.mode = ScanMode("passive")
    web_stage.run(ctx)
    assert fakes["whatweb"] == []
