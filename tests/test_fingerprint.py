from marsadix.web import fingerprint as fp


def test_parse_tech_splits_name_and_version():
    assert fp.parse_tech(["Python:3.12.3", "SimpleHTTP:0.6", "HSTS", "Google Font API", "Bootstrap:3.3.7"]) == [
        ("Python", "3.12.3"), ("SimpleHTTP", "0.6"), ("HSTS", None), ("Google Font API", None), ("Bootstrap", "3.3.7")]


def test_parse_tech_only_cuts_a_version_that_starts_with_a_digit():
    # a colon inside a name must not turn the tail into a "version"
    assert fp.parse_tech(["Foo:Bar", "Ruby on Rails:7.0.4"]) == [("Foo:Bar", None), ("Ruby on Rails", "7.0.4")]


def test_parse_tech_ignores_empty_and_missing_input():
    assert fp.parse_tech(None) == [] and fp.parse_tech(["", "  "]) == []


def test_parse_server_header():
    assert fp.parse_server_header("nginx/1.18.0 (Ubuntu)") == [("nginx", "1.18.0")]
    assert fp.parse_server_header("SimpleHTTP/0.6 Python/3.12.3") == [("SimpleHTTP", "0.6"), ("Python", "3.12.3")]
    assert fp.parse_server_header("Apache") == [("Apache", None)]
    assert fp.parse_server_header("Apache/2.4.58 (Unix) OpenSSL/3.0.2") == [("Apache", "2.4.58"), ("OpenSSL", "3.0.2")]
    assert fp.parse_server_header(None) == [] and fp.parse_server_header("") == []


def test_merge_drops_repeats_regardless_of_case():
    merged = fp.merge_technologies([("Nginx", "1.18.0"), ("PHP", None)], [("nginx", "1.18.0"), ("nginx", "1.20")])
    assert merged == [("Nginx", "1.18.0"), ("PHP", None), ("nginx", "1.20")]


def test_cpe_for_known_products():
    assert fp.cpe_for("Nginx", "1.18.0") == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
    assert fp.cpe_for("PHP") == "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
    assert fp.cpe_for("Apache HTTP Server", "2.4.58") == "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"


def test_cpe_for_unknown_product_is_none_not_a_guess():
    assert fp.cpe_for("SomeInternalFramework", "1.0") is None


def test_cpe_version_with_special_characters_falls_back_to_wildcard():
    assert fp.cpe_for("nginx", "1.0:beta*") == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


def test_category_for():
    assert fp.category_for("nginx") == "web-server" and fp.category_for("WordPress") == "cms"
    assert fp.category_for("HSTS") is None


def test_normalize_cpe_22_to_23():
    assert fp.normalize_cpe("cpe:/a:python:simplehttpserver:0.6") == \
        "cpe:2.3:a:python:simplehttpserver:0.6:*:*:*:*:*:*:*"
    assert fp.normalize_cpe("cpe:/a:openbsd:openssh:8.9p1:::en") == \
        "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:en:*:*:*:*"


def test_normalize_cpe_keeps_23_and_rejects_junk():
    c = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
    assert fp.normalize_cpe(c) == c
    assert fp.normalize_cpe(None) is None and fp.normalize_cpe("nonsense") is None
