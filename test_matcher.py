import pytest
from marsadix.matching.matcher import Matcher, match_all, evaluate
from marsadix.matching.models import CVE, Asset, VersionSource
from marsadix.matching.adapter import to_p4_cve, to_p4_asset, normalize_configurations, map_version_source, build_assets

APACHE = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
OPENSSL = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"


def m(criteria, vulnerable=True, **rng):
    return {"vulnerable": vulnerable, "criteria": criteria, **rng}


def cfg(*nodes, operator=None):
    c = {"nodes": list(nodes)}
    if operator:
        c["operator"] = operator
    return c


def node(entries=(), operator="OR", negate=False, children=()):
    n = {"operator": operator, "negate": negate, "cpeMatch": list(entries)}
    if children:
        n["children"] = list(children)
    return n


def cve(*configs, id="CVE-2021-0001", **kw):
    return CVE(id=id, configurations=list(configs), **kw)


def asset(cpe=APACHE, version="2.4.49", **kw):
    kw.setdefault("version_source", VersionSource.BANNER)
    return Asset(host="h1", cpe=cpe, version=version, **kw)


def test_exact_cpe_version():
    c = cve(cfg(node([m("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")])))
    r = evaluate(c, asset())
    assert r and r.version_compared
    assert evaluate(c, asset(version="2.4.50")) is None


def test_exact_version_from_asset_cpe():
    c = cve(cfg(node([m("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")])))
    a = asset(cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", version=None)
    assert evaluate(c, a)


@pytest.mark.parametrize("version,expected", [
    ("2.4.0", True), ("2.4.48", True), ("2.4.49", False), ("2.3.99", False), ("2.4.50", False),
])
def test_range_start_incl_end_excl(version, expected):
    c = cve(cfg(node([m(APACHE, versionStartIncluding="2.4.0", versionEndExcluding="2.4.49")])))
    assert bool(evaluate(c, asset(version=version))) is expected


@pytest.mark.parametrize("version,expected", [("2.4.0", False), ("2.4.1", True), ("2.4.49", True), ("2.4.50", False)])
def test_range_start_excl_end_incl(version, expected):
    c = cve(cfg(node([m(APACHE, versionStartExcluding="2.4.0", versionEndIncluding="2.4.49")])))
    assert bool(evaluate(c, asset(version=version))) is expected


def test_openssl_letter_range():
    c = cve(cfg(node([m(OPENSSL, versionStartIncluding="1.0.2", versionEndExcluding="1.0.2h")])))
    a = lambda v: asset(cpe=OPENSSL, version=v)
    assert evaluate(c, a("1.0.2a")) and evaluate(c, a("1.0.2g"))
    assert evaluate(c, a("1.0.2h")) is None


def test_product_vendor_mismatch():
    c = cve(cfg(node([m(APACHE)])))
    assert evaluate(c, asset(cpe="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")) is None
    assert evaluate(c, asset(cpe="cpe:2.3:a:other:http_server:*:*:*:*:*:*:*:*")) is None


def test_target_sw():
    c = cve(cfg(node([m("cpe:2.3:a:vend:plug:*:*:*:*:*:wordpress:*:*")])))
    assert evaluate(c, asset(cpe="cpe:2.3:a:vend:plug:*:*:*:*:*:wordpress:*:*", version="1")) 
    assert evaluate(c, asset(cpe="cpe:2.3:a:vend:plug:*:*:*:*:*:drupal:*:*", version="1")) is None
    assert evaluate(c, asset(cpe="cpe:2.3:a:vend:plug:*:*:*:*:*:*:*:*", version="1"))


def test_unconstrained_cve_matches_but_not_compared():
    r = evaluate(cve(cfg(node([m(APACHE)]))), asset())
    assert r and not r.version_compared


def test_unknown_version_policy():
    c = cve(cfg(node([m(APACHE, versionEndExcluding="2.4.49")])))
    r = evaluate(c, asset(version=None))
    assert r and not r.version_compared and any("unknown" in n for n in r.notes)
    assert evaluate(c, asset(version="-")) is not None
    assert evaluate(c, asset(version="garbage")) is not None
    assert evaluate(c, asset(version=None), allow_unknown_version=False) is None


def test_asset_version_used_when_cpe_version_star_or_na():
    c = cve(cfg(node([m(APACHE, versionEndExcluding="2.4.49")])))
    assert evaluate(c, asset(cpe="cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", version="2.4.10")).version_compared


def test_empty_nodes_do_not_match():
    for c in (cve(cfg(node([]))), cve(cfg()), cve({}), cve(cfg({"operator": "AND"})),
              cve(cfg(node([], operator="AND", children=[node([])])))):
        assert evaluate(c, asset()) is None
    assert evaluate(CVE(id="x"), asset()) is None


def test_platform_only_or_config_never_matches():
    win = m("cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*", vulnerable=False)
    c = cve(cfg(node([win], operator="OR")))
    assert evaluate(c, asset(platform_cpes=["cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"])) is None
    assert match_all([asset()], [c]) == []


def test_or_mixed_vuln_and_platform_uses_vuln_side_only():
    win = m("cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*", vulnerable=False)
    c = cve(cfg(node([m(APACHE, versionEndExcluding="2.0"), win], operator="OR")))
    assert evaluate(c, asset(version="2.4.49")) is None


def test_and_requires_all_vulnerable_entries():
    c = cve(cfg(node([m(APACHE, versionEndExcluding="2.4.50"), m(OPENSSL)], operator="AND")))
    assert evaluate(c, asset()) is None  # openssl entry cannot match an apache asset
    c2 = cve(cfg(node([m(APACHE, versionEndExcluding="2.4.50"), m(APACHE, versionStartIncluding="2.4.40")], operator="AND")))
    assert evaluate(c2, asset(version="2.4.49"))
    assert evaluate(c2, asset(version="2.4.20")) is None


def test_or_any_entry():
    c = cve(cfg(node([m(OPENSSL), m(APACHE, versionEndExcluding="2.4.50")], operator="OR")))
    assert evaluate(c, asset())


def test_and_platform_verified_and_unverified():
    app = m(APACHE, versionEndExcluding="2.4.50")
    linux = m("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*", vulnerable=False)
    c = cve(cfg(node([app]), node([linux]), operator="AND"))
    unv = evaluate(c, asset())
    assert unv and unv.platform_unverified
    ver = evaluate(c, asset(platform_cpes=["cpe:2.3:o:linux:linux_kernel:5.4:*:*:*:*:*:*:*"]))
    assert ver and not ver.platform_unverified
    wrong = evaluate(c, asset(platform_cpes=["cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"]))
    assert wrong is None


def test_platform_version_range():
    app = m(APACHE)
    win = m("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", vulnerable=False, versionEndExcluding="5.0")
    c = cve(cfg(node([app]), node([win]), operator="AND"))
    assert evaluate(c, asset(platform_cpes=["cpe:2.3:o:linux:linux_kernel:4.19:*:*:*:*:*:*:*"]))
    assert evaluate(c, asset(platform_cpes=["cpe:2.3:o:linux:linux_kernel:5.4:*:*:*:*:*:*:*"])) is None


def test_nested_children():
    inner = node([m(APACHE, versionEndExcluding="2.4.50")])
    outer = node([], operator="AND", children=[inner, node([m("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")])])
    assert evaluate(cve(cfg(outer)), asset())
    deep = node([], operator="OR", children=[node([], operator="AND", children=[inner])])
    assert evaluate(cve(cfg(deep)), asset())


def test_negate():
    c = cve(cfg(node([m(APACHE, versionEndExcluding="2.4.50")], negate=True)))
    assert evaluate(c, asset(version="2.4.49")) is None
    # negated non-match is True but has no positive vulnerable hit -> still no match
    assert evaluate(c, asset(version="2.4.60")) is None
    # negate on an exclusion node inside AND
    excl = node([m("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")], negate=True)
    inc = node([m(APACHE, versionEndExcluding="2.4.60")])
    c2 = cve(cfg(inc, excl, operator="AND"))
    assert evaluate(c2, asset(version="2.4.49")) is None
    assert evaluate(c2, asset(version="2.4.48"))


def test_multiple_configurations_are_or():
    c = cve(cfg(node([m(OPENSSL)])), cfg(node([m(APACHE, versionEndExcluding="2.4.50")])))
    assert evaluate(c, asset())


def test_legacy_keys():
    c = cve({"nodes": [{"operator": "OR", "cpe_match": [{"vulnerable": True, "cpe23Uri": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]})
    assert evaluate(c, asset())


def test_malformed_cve_cpe_skipped():
    c = cve(cfg(node([m("garbage"), m(APACHE, versionEndExcluding="2.4.50")])))
    assert evaluate(c, asset())
    bad = cve(cfg(node([m("garbage")])), id="CVE-BAD")
    assert match_all([asset()], [bad]) == []


def test_one_bad_asset_does_not_stop_batch():
    mt = Matcher()
    good = asset()
    bad = Asset(host="bad", cpe="not-a-cpe", version="1")
    bad2 = Asset(host="bad2", cpe=None, version="1")  # type: ignore
    c = cve(cfg(node([m(APACHE, versionEndExcluding="2.4.50")])))
    res = mt.match_all([bad, good, bad2], [c, CVE(id="junk", configurations=["x", None, 5])])
    assert [r.asset.host for r in res] == ["h1"]
    assert len(mt.errors) == 2


def test_index_avoids_unrelated_evaluation(monkeypatch):
    mt = Matcher()
    calls = []
    orig = mt.evaluate_prepared
    monkeypatch.setattr(mt, "evaluate_prepared", lambda c, p: calls.append(c.id) or orig(c, p))
    cves = [cve(cfg(node([m(OPENSSL)])), id=f"CVE-{i}") for i in range(50)] + [cve(cfg(node([m(APACHE)])), id="CVE-A")]
    mt.match_all([asset()], cves)
    assert calls == ["CVE-A"]


def test_realistic_nvd_fixture():
    nvd = {"nodes": [{"operator": "AND", "negate": False, "cpeMatch": [], "children": [
        {"operator": "OR", "negate": False, "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "8.2", "versionEndExcluding": "9.3p2", "matchCriteriaId": "X"}]},
        {"operator": "OR", "negate": False, "cpeMatch": [
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*", "matchCriteriaId": "Y"}]},
    ]}]}
    c = cve(nvd)
    ssh = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    plat = ["cpe:2.3:o:linux:linux_kernel:5.4:*:*:*:*:*:*:*"]
    assert evaluate(c, Asset(host="h", cpe=ssh, version="9.3p1", platform_cpes=plat))
    assert evaluate(c, Asset(host="h", cpe=ssh, version="9.3p2", platform_cpes=plat)) is None
    assert evaluate(c, Asset(host="h", cpe=ssh, version="8.1", platform_cpes=plat)) is None
    assert evaluate(c, Asset(host="h", cpe=ssh, version="8.2p1", platform_cpes=plat))


# ---- adapter ---------------------------------------------------------------
def test_adapter_cve_mapping():
    class P3:
        cve_id = "CVE-1"; cvss_score = 9.8; epss_score = 0.5; in_kev = 1
        cpe_matches = ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]; description = "d"
    c = to_p4_cve(P3())
    assert (c.id, c.cvss, c.epss, c.kev) == ("CVE-1", 9.8, 0.5, True)
    assert evaluate(c, asset())


def test_adapter_cve_dict_json_and_missing():
    import json
    c = to_p4_cve({"cve_id": "CVE-2", "cvss_score": None, "epss_score": "0.1", "in_kev": 0,
                   "cpe_matches": json.dumps([{"vulnerable": True, "criteria": APACHE, "versionEndExcluding": "3"}])})
    assert c.cvss is None and c.epss == 0.1 and not c.kev
    assert evaluate(c, asset())
    assert normalize_configurations("not json") == []
    assert normalize_configurations(None) == []
    assert normalize_configurations([{"nodes": []}]) == [{"nodes": []}]


@pytest.mark.parametrize("src,conf,vs", [
    ("nmap", None, VersionSource.NMAP), ("banner-grab", None, VersionSource.BANNER),
    ("httpx", "low", VersionSource.HTTPX), ("wappalyzer", None, VersionSource.HTTPX),
    ("nuclei-template", None, VersionSource.FINGERPRINT), ("verified", None, VersionSource.VERIFIED),
    ("guess", None, VersionSource.INFERRED), ("", "high", VersionSource.BANNER),
    ("", "medium", VersionSource.FINGERPRINT), ("", 0.2, VersionSource.INFERRED), ("", None, VersionSource.UNKNOWN),
])
def test_map_version_source(src, conf, vs):
    assert map_version_source(src, conf) == vs


def test_adapter_asset_mapping_and_context():
    tech = {"id": 7, "host": "a.example.com", "cpe": APACHE, "version": "2.4.49", "source": "nmap", "scan_id": 3}
    a = to_p4_asset(tech, {"host": "a.example.com", "internet_facing": 0, "cdn": "cloudflare", "criticality": "HIGH"}, [OPENSSL])
    assert a.version_source == VersionSource.NMAP and not a.internet_facing and a.behind_cdn
    assert a.criticality == "high" and a.platform_cpes == [OPENSSL] and a.scan_id == 3 and a.technology_id == 7
    n = to_p4_asset({"host": "h", "cpe": APACHE, "version": None, "source": "nmap"})
    assert n.version_source == VersionSource.UNKNOWN and n.internet_facing is True


def test_build_assets_platforms_from_same_host():
    techs = [{"host": "h", "cpe": APACHE, "version": "1"}, {"host": "h", "cpe": OPENSSL, "version": "1"},
             {"host": "z", "cpe": OPENSSL, "version": "1"}, {"host": "z", "cpe": "", "version": "1"}]
    out = build_assets(techs)
    assert len(out) == 3
    assert out[0].platform_cpes == [OPENSSL] and out[2].platform_cpes == []
