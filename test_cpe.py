import pytest
from marsadix.matching.cpe import CPE, CPEParseError, parse_cpe


def test_nist_22_packed_edition():
    c = parse_cpe("cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:online~win2003~x64~")
    assert (c.part, c.vendor, c.product, c.version, c.update) == ("a", "hp", "insight_diagnostics", "7.4.0.1570", "-")
    assert c.edition == "online" and c.sw_edition == "win2003" and c.target_sw == "x64"
    assert c.target_hw == "" and c.other == ""


def test_22_packed_with_leading_tilde():
    c = parse_cpe("cpe:/a:v:p:1::~ed~sw~tsw~thw~oth")
    assert (c.edition, c.sw_edition, c.target_sw, c.target_hw, c.other) == ("ed", "sw", "tsw", "thw", "oth")


def test_23_basic_any_na():
    c = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert c.version == "2.4.49" and c.update == "*" and c.other == "*"
    assert parse_cpe("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*").version == "-"


def test_truncated():
    c = parse_cpe("cpe:2.3:a:apache:http_server")
    assert c.version == "*" and c.target_sw == "*"
    assert parse_cpe("cpe:/a:apache:http_server").version == ""


def test_escapes():
    c = parse_cpe(r"cpe:2.3:a:ven\:dor:prod\\uct:1.0\-beta:*:*:*:*:*:*:*")
    assert c.vendor == "ven:dor" and c.product == "prod\\uct" and c.version == "1.0-beta"
    again = parse_cpe(c.to_string())
    assert again.normalized() == c.normalized()


@pytest.mark.parametrize("bad", [
    "", "   ", "nope", "cpe:2.3:", "cpe:2.3:x:v:p", "cpe:/x:v:p", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*:extra",
    "cpe:/a:v:p:1:u:e:l:extra", "cpe:2.3:a:v:p\\", "cpe:/", "cpe:2.3:a:v:p v", None, 123,
    "cpe:/a:v:p:1::~1~2~3~4~5~6",
])
def test_malformed_raises_parse_error(bad):
    with pytest.raises(CPEParseError):
        parse_cpe(bad)


@pytest.mark.parametrize("s", [
    "cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:online~win2003~x64~",
    "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*",
    "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
    r"cpe:2.3:a:a\:b:c\\d:1.0\-x:*:*:*:*:node.js:*:*",
])
def test_round_trip(s):
    c = parse_cpe(s)
    assert parse_cpe(c.to_string()).normalized() == c.normalized()
    assert parse_cpe(c.to_uri()).normalized() == c.normalized()


def test_key_lowercase():
    assert parse_cpe("cpe:2.3:a:Apache:HTTP_Server:1:*:*:*:*:*:*:*").key == ("a", "apache", "http_server")
