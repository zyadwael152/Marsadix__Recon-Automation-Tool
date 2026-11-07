import pytest
from marsadix import remediation_db as R


def test_seed_idempotent_and_owasp_present(db):
    n = R.seed_defaults(db, include_legacy=False)
    assert n > 20 and R.seed_defaults(db, include_legacy=False) == 0
    owasp = R.list_entries(db, "owasp")
    assert {e.match_value for e in owasp} == {f"A{i:02d}" for i in range(1, 11)}


def test_seed_does_not_overwrite_user_edits(db):
    R.seed_defaults(db, include_legacy=False)
    e = R.list_entries(db, "skill")[0]
    R.update_entry(db, e.id, fix_text="custom text")
    R.seed_defaults(db, include_legacy=False)
    assert R.get_entry(db, e.id).fix_text == "custom text"


def test_crud(db):
    e = R.add_entry(db, "cve", "cve-2021-41773", "Apache fix", "Upgrade to 2.4.51", ["https://httpd.apache.org"], "low", 90)
    assert e.match_value == "CVE-2021-41773" and e.references == ["https://httpd.apache.org"] and e.created_at
    assert R.get_entry(db, e.id).title == "Apache fix"
    with pytest.raises(R.RemediationError):
        R.add_entry(db, "cve", "CVE-2021-41773", "dup", "dup")
    u = R.update_entry(db, e.id, effort="high", priority=10)
    assert (u.effort, u.priority) == ("high", 10)
    assert [x.id for x in R.search(db, "apache")] == [e.id]
    assert R.delete_entry(db, e.id) and R.get_entry(db, e.id) is None and not R.delete_entry(db, e.id)


@pytest.mark.parametrize("kw", [dict(match_type="nope"), dict(effort="huge"), dict(priority=500), dict(match_value=" ")])
def test_validation(db, kw):
    args = dict(match_type="keyword", match_value="x", title="t", fix_text="f", effort="low", priority=1)
    args.update(kw)
    with pytest.raises(R.RemediationError):
        R.add_entry(db, **args)


def test_persistence_across_connections(tmp_path):
    import sqlite3
    from marsadix.db_v4 import migrate_v3_to_v4
    from .conftest import make_v3
    p = tmp_path / "x.db"
    c = sqlite3.connect(p); make_v3(c); migrate_v3_to_v4(c)
    R.add_entry(c, "product", "redis", "Secure redis", "Bind to localhost and require auth.")
    c.close()
    c = sqlite3.connect(p)
    assert R.lookup(c, {"product": "Redis"}).title == "Secure redis"


def test_lookup_order(db):
    R.add_entry(db, "owasp", "A05", "owasp", "owasp text")
    R.add_entry(db, "product", "nginx", "product", "product text")
    R.add_entry(db, "cwe", "79", "cwe", "cwe text")
    R.add_entry(db, "cve", "CVE-1", "cve", "cve text")
    R.add_entry(db, "keyword", "directory listing", "keyword", "keyword text")
    R.add_entry(db, "template", "tmpl-1", "template", "template text")
    R.add_entry(db, "skill", "my-skill", "skill", "skill text")
    f = {"skill": "my-skill", "template_id": "tmpl-1", "title": "Directory listing enabled", "cve_id": "CVE-1",
         "cwe": ["CWE-79"], "product": "nginx", "owasp": "A05:2021"}
    order = []
    for drop in ("skill", "template", "keyword", "cve", "cwe", "product", "owasp"):
        order.append(R.lookup(db, f).title)
        db.execute("DELETE FROM remediation WHERE match_type=?", (drop,))
    assert order == ["skill", "template", "keyword", "cve", "cwe", "product", "owasp"]
    assert R.lookup(db, f) is R.GENERIC_ENTRY


def test_fallback_generic_and_no_table(v3db):
    assert R.lookup(v3db, {"title": "x"}) is R.GENERIC_ENTRY
    assert R.lookup(v3db, object()) is R.GENERIC_ENTRY


def test_keyword_whole_word_hyphen_aware(db):
    assert R.keyword_matches("xss", "Reflected XSS in search")
    assert not R.keyword_matches("xss", "xssshield module")
    assert not R.keyword_matches("cors", "Scorsese page")
    assert R.keyword_matches("open redirect", "Open-Redirect on /login")
    assert R.keyword_matches("open-redirect", "open_redirect found")
    assert not R.keyword_matches("sql", "mysql exposed")
    R.add_entry(db, "keyword", "sql", "sqlkw", "x")
    assert R.lookup(db, {"title": "MySQL exposed"}) is R.GENERIC_ENTRY
    assert R.lookup(db, {"title": "SQL error"}).title == "sqlkw"


def test_keyword_priority_then_length(db):
    R.add_entry(db, "keyword", "injection", "short", "x", priority=50)
    R.add_entry(db, "keyword", "sql injection", "long", "x", priority=50)
    R.add_entry(db, "keyword", "login", "hi", "x", priority=90)
    assert R.lookup(db, {"title": "SQL injection"}).title == "long"
    assert R.lookup(db, {"title": "SQL injection on login"}).title == "hi"


def test_object_findings(db):
    class F:
        title = "Exposed admin"; description = ""; cve_id = None
    R.seed_defaults(db, include_legacy=False)
    assert R.lookup(db, {"title": "SQL injection in search"}).title == "Fix SQL injection"
    assert R.lookup(db, F()) is not None


def test_legacy_import(db, monkeypatch, tmp_path):
    import sys, types
    mod = types.ModuleType("marsadix.remediation")
    mod.REMEDIATIONS = {"git-exposure": "Remove .git directory from the web root and rotate credentials.", "x": "short"}
    monkeypatch.setitem(sys.modules, "marsadix.remediation", mod)
    R.seed_defaults(db)
    assert R.lookup(db, {"skill": "git-exposure"}).fix_text.startswith("Remove .git")
