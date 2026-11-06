"""Integration contract: Web URL inventory is handed to ASM without losing paths."""

from marsadix import db
from marsadix.asm import nuclei as nuclei_module
from marsadix.asm import stage as asm_stage
from marsadix.asm.runtime import ToolExecution
from marsadix.core.config import Config
from marsadix.core.pipeline import Context
from marsadix.core.scope import Scope
from marsadix.models import Asset, Scan, ScanMode, ScanStatus, WebItem, WebItemKind


def test_asm_receives_scoped_web_endpoints_and_preserves_paths(tmp_path, monkeypatch):
    conn = db.connect(":memory:")
    db.init_db(conn)
    scan = Scan(target="example.com", status=ScanStatus.RUNNING,
                mode=ScanMode.STANDARD, rate_limit=10)
    db.save_scan(conn, scan)
    db.save_many(conn, "assets", [
        Asset(scan_id=scan.id, host="api.example.com", in_scope=True),
        Asset(scan_id=scan.id, host="evil.test", in_scope=False),
    ])
    db.save_many(conn, "web_items", [
        WebItem(scan_id=scan.id, host="api.example.com",
                url="https://api.example.com/", kind=WebItemKind.URL),
        WebItem(scan_id=scan.id, host="api.example.com",
                url="https://api.example.com/admin/login", kind=WebItemKind.ENDPOINT),
        WebItem(scan_id=scan.id, host="api.example.com",
                url="https://api.example.com/assets/app.js", kind=WebItemKind.JS_FILE),
        WebItem(scan_id=scan.id, host="evil.test",
                url="https://evil.test/private", kind=WebItemKind.ENDPOINT),
        WebItem(scan_id=scan.id, host="dev.example.com",
                url="https://dev.example.com/admin", kind=WebItemKind.ENDPOINT),
    ])
    ctx = Context(
        conn=conn, scan=scan,
        scope=Scope.from_lines(["example.com", "*.example.com", "!dev.example.com"]),
        config=Config(db_path=":memory:", output_dir=str(tmp_path / "out"),
                      scan_mode="standard", rate_limit=10),
    )

    captured = {}

    async def no_dns(self, normalized):
        return ()

    async def fake_run_tool(name, executable, argv, *, input_text=None, timeout=300):
        captured["targets"] = input_text.splitlines() if input_text else []
        return ToolExecution(name=name, argv=[executable, *argv], stdout="", returncode=0)

    monkeypatch.setattr(asm_stage.ToolResolver, "path", lambda self, name: "/bin/nuclei")
    monkeypatch.setattr(nuclei_module.ScopeEnforcer, "ensure_safe_url", no_dns)
    monkeypatch.setattr(nuclei_module, "run_tool", fake_run_tool)

    result = asm_stage.run(ctx)

    assert result["asm"]["status"] == "ok"
    assert "https://api.example.com/" in captured["targets"]
    assert "https://api.example.com/admin/login" in captured["targets"]
    assert "https://api.example.com/assets/app.js" in captured["targets"]
    assert not any("evil.test" in target or "dev.example.com" in target
                   for target in captured["targets"])
    conn.close()
