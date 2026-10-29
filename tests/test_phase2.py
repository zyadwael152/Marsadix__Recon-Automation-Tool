"""Person-5 completion: exports, report template, skills registry, attack paths /
time machine / investigate, benchmarks, parallel stages."""

import csv
import json
import re
import sys
import threading
import types
from pathlib import Path

import pytest

from marsadix import benchmark, db
from marsadix.core import attackpaths, pipeline
from marsadix.core.config import Config, load_config
from marsadix.models import (Asset, Confidence, DetectionStatus, Finding, FindingSource, Scan,
                             ScanStatus, Service, Severity)
from marsadix.reports import export
from marsadix.reports.generate import _gather, generate_report
from marsadix.skills import registry


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def _scan(conn, target="example.com", status=ScanStatus.COMPLETED):
    s = Scan(target=target, status=status)
    s.id = db.save_scan(conn, s)
    db.finish_scan(conn, s.id, status.value)
    return s


def _finding(scan, host="a.example.com", title="Reflected XSS", sev=Severity.HIGH,
             status=DetectionStatus.DETECTED, **kw):
    kw.setdefault("dedup_key", f"{host}|{title}")           # findings with one key are merged by the DB
    return Finding(scan_id=scan.id, host=host, title=title, severity=sev, status=status,
                   source=FindingSource.SKILL, **kw)


def _populated(conn):
    s = _scan(conn)
    db.save_many(conn, "assets", [Asset(scan_id=s.id, host="a.example.com", in_scope=True, ip="1.2.3.4")])
    db.save_many(conn, "findings", [
        _finding(s, title="Low thing", sev=Severity.LOW, status=DetectionStatus.NO_INDICATORS),
        _finding(s, title="=cmd|' /C calc'!A0", sev=Severity.CRITICAL, evidence="boom, \"quoted\"",
                 owasp_category="A03:2021-Injection", url="https://a.example.com/x?q=1"),
        _finding(s, title="Review me", sev=Severity.CRITICAL, status=DetectionStatus.NEEDS_REVIEW),
    ])
    return s


# ------------------------------------------------------------------ exports
def test_findings_are_prioritized_severity_then_status(conn):
    s = _populated(conn)
    titles = [f["title"] for f in _gather(conn, "example.com", s.id)["findings"]]
    assert titles == ["=cmd|' /C calc'!A0", "Review me", "Low thing"]


def test_csv_neutralises_spreadsheet_formulas(conn, tmp_path):
    s = _populated(conn)
    path = export.write_csv(_gather(conn, "example.com", s.id), tmp_path, "example.com", s.id)
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig", newline="")))
    assert rows[0]["title"].startswith("'=")            # not executable as a formula
    assert rows[0]["evidence"] == 'boom, "quoted"'      # quoting round-trips
    assert {r["exploited"] for r in rows} == {"false"}


def test_sarif_has_the_required_structure_and_never_claims_exploitation(conn, tmp_path):
    s = _populated(conn)
    doc = json.loads(export.write_sarif(_gather(conn, "example.com", s.id), tmp_path, "example.com", s.id).read_text())
    assert doc["version"] == "2.1.0" and doc["runs"][0]["tool"]["driver"]["name"] == "Marsadix"
    res = doc["runs"][0]["results"]
    assert len(res) == 3 and res[0]["level"] == "error" and res[-1]["level"] == "note"
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in res)
    assert all(r["properties"]["exploited"] is False for r in res)
    assert res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("https://")


def test_pdf_is_structurally_valid_and_paginates(conn, tmp_path):
    s = _populated(conn)
    data = _gather(conn, "example.com", s.id)
    data["findings"] = data["findings"] * 80 + [dict(data["findings"][0], title="paren ( and \\ slash " + "x" * 300)]
    raw = export.write_pdf(data, tmp_path, "example.com", s.id).read_bytes()
    assert raw.startswith(b"%PDF-1.4") and raw.rstrip().endswith(b"%%EOF")
    n_objs = len(re.findall(rb"\n\d+ 0 obj\n", raw))
    xref = int(re.search(rb"startxref\n(\d+)\n", raw).group(1))
    assert raw[xref:xref + 4] == b"xref"
    offsets = re.findall(rb"(\d{10}) 00000 n ", raw)
    assert len(offsets) == n_objs
    for i, off in enumerate(offsets, 1):                # every xref entry points at its object
        assert raw[int(off):].startswith(f"{i} 0 obj".encode())
    assert int(re.search(rb"/Count (\d+)", raw).group(1)) > 1


def test_generate_report_all_writes_every_format_and_rejects_unknown(conn, tmp_path, capsys):
    _populated(conn)
    assert generate_report(conn, "example.com", fmt="all", out_dir=str(tmp_path)) == 0
    assert sorted(p.suffix for p in tmp_path.iterdir()) == [".csv", ".html", ".json", ".pdf", ".sarif"]
    assert generate_report(conn, "example.com", fmt="docx", out_dir=str(tmp_path)) == 1
    assert "unknown format" in capsys.readouterr().err


def test_html_report_has_the_professional_sections(conn, tmp_path):
    _populated(conn)
    generate_report(conn, "example.com", fmt="html", out_dir=str(tmp_path))
    page = next(tmp_path.glob("*.html")).read_text()
    for h in ("Executive summary", "Scope &amp; methodology", "Prioritized findings",
              "Detection skills", "Detection, not exploitation"):
        assert h in page
    assert "Remediation" in page and "pending" in page   # placeholder until the remediation DB exists
    assert "=cmd|" in page and "<script>alert" not in page


def test_report_reads_tool_status_next_to_it(conn, tmp_path):
    s = _populated(conn)
    (tmp_path / f"example.com_scan{s.id}_tools.json").write_text(
        json.dumps([{"tool": "subfinder", "status": "timeout", "detail": "after 600s"}]))
    generate_report(conn, "example.com", fmt="html", out_dir=str(tmp_path))
    page = next(tmp_path.glob("*.html")).read_text()
    assert "incomplete" in page and "subfinder" in page


# ------------------------------------------------------------ skills registry
def test_every_skill_maps_to_a_real_owasp_category():
    assert all(s.owasp_category for s in registry.all_skills())
    assert len({s.name for s in registry.all_skills()}) == len(registry.all_skills())


def test_a_skill_without_a_handler_is_never_reported_active():
    assert registry.active_skills() == []


def test_registered_handler_makes_a_skill_active_subject_to_mode_and_opt_in(monkeypatch):
    monkeypatch.setattr(registry, "_HANDLERS", {})
    registry.register_handler("ssti")(lambda ctx, t: None)
    registry.register_handler("jwt")(lambda ctx, t: None)
    assert {s.name for s in registry.active_skills("full", True)} == {"ssti", "jwt"}
    assert {s.name for s in registry.active_skills("full", False)} == {"jwt"}      # injection needs opt-in
    assert registry.active_skills("passive", True) == []                           # passive never probes
    assert {s.name for s in registry.active_skills("full", True, disabled=["jwt"])} == {"ssti"}
    with pytest.raises(KeyError):
        registry.register_handler("no-such-skill")


# --------------------------------------------- attack paths / time machine
def _g(*edges, types_):
    ids = {i for e in edges for i in e[:2]}
    return {"nodes": [{"id": i, "node_type": types_.get(i.split(":")[0], "x"), "label": i} for i in ids],
            "edges": [{"src_id": a, "dst_id": b, "relation": r} for a, b, r in edges]}


_T = {"subdomain": "subdomain", "port": "port", "service": "service", "technology": "technology",
      "cve": "cve", "finding": "finding", "ip": "ip", "cpe": "cpe"}


def test_attack_paths_follow_exposure_edges_only():
    g = _g(("subdomain:a", "technology:a:nginx:1.0", "uses"),
           ("technology:a:nginx:1.0", "cve:CVE-1", "affected_by"),
           ("finding:7", "subdomain:a", "found_on"),
           ("subdomain:a", "ip:1.1.1.1", "resolves_to"),        # infrastructure link: not a path
           ("subdomain:b", "ip:1.1.1.1", "resolves_to"),
           ("subdomain:b", "port:b:80", "exposes"), types_=_T)
    paths = {" > ".join(p) for p in attackpaths.compute_attack_paths(g)}
    assert paths == {"subdomain:a > technology:a:nginx:1.0 > cve:CVE-1", "subdomain:a > finding:7"}


def test_time_machine_reports_opened_and_closed_paths(conn, monkeypatch):
    s1, s2, bad = _scan(conn), _scan(conn), _scan(conn, status=ScanStatus.FAILED)
    graphs = {s1.id: _g(("subdomain:a", "cve:CVE-1", "affected_by"), types_=_T),
              s2.id: _g(("subdomain:a", "cve:CVE-2", "affected_by"), types_=_T),
              bad.id: _g(("subdomain:a", "cve:CVE-9", "affected_by"), types_=_T)}
    monkeypatch.setattr(attackpaths, "_graph_for", lambda c, sid: graphs[sid])
    steps = attackpaths.time_machine(conn, "example.com")
    assert [s["scan_id"] for s in steps] == [s1.id, s2.id]           # failed scan ignored
    assert steps[1]["opened"] == ["subdomain:a > cve:CVE-2"]
    assert steps[1]["closed"] == ["subdomain:a > cve:CVE-1"]


def test_timemachine_cli_output_and_empty_target(conn, capsys, monkeypatch):
    assert attackpaths.run_timemachine(conn, "example.com") == 1
    s = _scan(conn)
    monkeypatch.setattr(attackpaths, "_graph_for", lambda c, sid: _g(("subdomain:a", "cve:CVE-1", "affected_by"), types_=_T))
    assert attackpaths.run_timemachine(conn, "example.com") == 0
    out = capsys.readouterr().out
    assert "first snapshot" in out and "paths: 1" in out


# ------------------------------------------------------------- investigate
def test_investigate_shows_everything_known_about_one_host(conn, capsys):
    s = _scan(conn)
    db.save_many(conn, "assets", [Asset(scan_id=s.id, host="a.example.com", in_scope=True, ip="1.2.3.4"),
                                  Asset(scan_id=s.id, host="b.example.com", in_scope=True, ip="1.2.3.4")])
    db.save_many(conn, "services", [Service(scan_id=s.id, host="a.example.com", port=8080, name="http")])
    db.save_many(conn, "findings", [_finding(s, host="a.example.com", title="Open thing"),
                                    _finding(s, host="b.example.com", title="Other host")])
    assert attackpaths.run_investigate(conn, "example.com", "A.example.com.") == 0
    out = capsys.readouterr().out
    assert "8080/tcp" in out and "Open thing" in out and "Other host" not in out
    assert "Attack paths from this host (1)" in out and "seen in 1 scan" in out


def test_investigate_rejects_unknown_host_and_foreign_scan(conn, capsys):
    s = _scan(conn)
    other = _scan(conn, target="other.org")
    db.save_many(conn, "assets", [Asset(scan_id=s.id, host="a.example.com", in_scope=True)])
    assert attackpaths.run_investigate(conn, "example.com", "nope.example.com") == 1
    assert attackpaths.run_investigate(conn, "example.com", "a.example.com", scan_id=other.id) == 1


# -------------------------------------------------------------- benchmarks
def test_recon_comparison_numbers():
    r = benchmark.compare_recon({"a.x.com", "b.x.com"},
                                {"a.x.com": ["subfinder"], "b.x.com": ["subfinder", "crt.sh"],
                                 "c.x.com": ["crt.sh"], "d.x.com": ["amass"]})
    assert r["subfinder_count"] == 2 and r["marsadix_count"] == 4 and r["union_count"] == 4
    assert r["marsadix_only"] == ["c.x.com", "d.x.com"] and r["gain_pct_over_subfinder"] == 100.0
    assert r["subfinder_only"] == [] and r["unique_by_source"] == {"amass": 1, "crt.sh": 1, "subfinder": 1}


def test_detection_rate_and_precision():
    truth = [{"id": "xss", "owasp_category": "A03:2021-Injection", "url_contains": "/xss"},
             {"id": "sqli", "template_id": "sqli"},
             {"id": "missed", "url_contains": "/never"}]
    findings = [{"status": "detected", "owasp_category": "A03:2021-Injection", "url": "http://h/xss?a", "host": "h"},
                {"status": "detected", "template_id": "SQLI", "host": "h", "url": None},
                {"status": "detected", "template_id": "ssti", "host": "h", "title": "wrong", "url": "http://h/y"},
                {"status": "needs_review", "template_id": "sqli", "host": "h"}]
    r = benchmark.score_detection(findings, truth)
    assert (r["true_positives"], r["false_negatives"]) == (2, 1)
    assert r["detection_rate_pct"] == 66.7 and r["precision_pct"] == 66.7
    assert r["needs_review_findings"] == 1 and r["missed"] == ["missed"]


def test_truth_file_validation_and_cli_flow(conn, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"entries": [{"id": "no-matcher"}]}))
    with pytest.raises(ValueError):
        benchmark.load_truth(str(bad))
    assert benchmark.run_detection_benchmark(conn, "example.com", str(bad)) == 1
    good = tmp_path / "t.json"
    good.write_text(json.dumps({"entries": [{"id": "x", "template_id": "xss"}]}))
    assert benchmark.run_detection_benchmark(conn, "example.com", str(good)) == 1     # no completed scan
    s = _scan(conn)
    db.save_many(conn, "findings", [_finding(s, template_id="xss")])
    out = tmp_path / "o.json"
    assert benchmark.run_detection_benchmark(conn, "example.com", str(good), out_file=str(out)) == 0
    assert json.loads(out.read_text())["detection_rate_pct"] == 100.0
    assert benchmark.run_detection_benchmark(conn, "example.com", str(good), scan_id=999) == 1


def test_shipped_example_truth_file_is_valid():
    assert benchmark.load_truth(str(Path(__file__).resolve().parents[1] / "benchmarks/truth/dvwa.example.json"))


# -------------------------------------------------------- parallel stages
def test_plan_groups_adjacent_independent_stages():
    stages = [("recon", "m:r"), ("web", "m:w"), ("ports", "m:p"), ("asm", "m:a")]
    assert [[n for n, _ in step] for step in pipeline._plan(stages)] == [["recon"], ["web", "ports"], ["asm"]]
    assert [[n for n, _ in step] for step in pipeline._plan([("ports", "m:p"), ("web", "m:w")])] == [["ports"], ["web"]]


def _fake_stages(monkeypatch, barrier=None):
    mod = types.ModuleType("fake_stage_mod")
    seen = {}

    def make(name, table, model):
        def run(ctx):
            seen[name] = threading.get_ident()
            if barrier is not None:
                barrier.wait(timeout=10)            # only passes if the other stage runs AT THE SAME TIME
            db.save_many(ctx.conn, table, [model(ctx.scan.id)])
        return run

    mod.web = make("web", "assets", lambda sid: Asset(scan_id=sid, host="w.example.com", in_scope=True))
    mod.ports = make("ports", "services", lambda sid: Service(scan_id=sid, host="w.example.com", port=80))
    monkeypatch.setitem(sys.modules, "fake_stage_mod", mod)
    monkeypatch.setattr(pipeline, "STAGES", [("web", "fake_stage_mod:web"), ("ports", "fake_stage_mod:ports")])
    return seen


def test_web_and_ports_really_run_at_the_same_time_and_both_save(tmp_path, monkeypatch):
    seen = _fake_stages(monkeypatch, barrier=threading.Barrier(2))
    cfg = Config(db_path=str(tmp_path / "t.db"))
    scan, results = pipeline.run_scan("example.com", cfg)
    assert [(r.name, r.status) for r in results] == [("web", "ok"), ("ports", "ok")]
    assert len(set(seen.values())) == 2                         # two different threads
    c = db.connect(str(tmp_path / "t.db"))
    assert c.execute("SELECT COUNT(*) FROM assets WHERE scan_id=?", (scan.id,)).fetchone()[0] == 1
    assert c.execute("SELECT COUNT(*) FROM services WHERE scan_id=?", (scan.id,)).fetchone()[0] == 1


def test_parallel_can_be_switched_off_and_one_failing_stage_does_not_stop_the_other(tmp_path, monkeypatch):
    seen = _fake_stages(monkeypatch)
    cfg = Config(db_path=str(tmp_path / "t.db"), parallel_stages=False)
    _, results = pipeline.run_scan("example.com", cfg)
    assert len(set(seen.values())) == 1 and all(r.status == "ok" for r in results)

    sys.modules["fake_stage_mod"].web = lambda ctx: 1 / 0
    cfg2 = Config(db_path=str(tmp_path / "t2.db"))
    _, results = pipeline.run_scan("example.com", cfg2)
    assert [(r.name, r.status) for r in results] == [("web", "failed"), ("ports", "ok")]


def test_parallel_stages_setting_is_read_from_toml(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("parallel_stages = false\nmax_concurrent_tools = 3\n")
    cfg = load_config(str(p))
    assert cfg.parallel_stages is False and cfg.max_concurrent_tools == 3


def test_the_same_finding_in_two_scans_is_not_a_new_attack_path(conn):
    # finding nodes are keyed by DB id, which changes every scan; the path must not
    s1, s2 = _scan(conn), _scan(conn)
    for sc in (s1, s2):
        db.save_many(conn, "assets", [Asset(scan_id=sc.id, host="a.example.com", in_scope=True)])
        db.save_many(conn, "findings", [_finding(sc, title="Open admin panel")])
    steps = attackpaths.time_machine(conn, "example.com")
    assert len(steps) == 2 and steps[1]["opened"] == [] and steps[1]["closed"] == []
    assert steps[0]["paths"] == ["subdomain:a.example.com > finding:Open admin panel"]
