"""WhatWeb output -> technologies, and how the results of several tools are merged."""

import asyncio
import json

from marsadix.web import fingerprint, probe

SAMPLE = [{
    "target": "https://www.example.com/",
    "http_status": 200,
    "plugins": {
        "HTTPServer": {"string": ["nginx/1.18.0 (Ubuntu)"]},
        "X-Powered-By": {"string": ["PHP/8.1.2"]},
        "jQuery": {"version": ["3.6.0"]},
        "WordPress": {"version": ["6.4.2"]},
        "Bootstrap": {},
        "HTML5": {},
        "Title": {"string": ["Example"]},
        "Country": {"string": ["UNITED STATES"], "module": ["US"]},
        "IP": {"string": ["93.184.216.34"]},
        "UncommonHeaders": {"string": ["x-cache"]},
    },
}]


def test_whatweb_json_array_is_parsed():
    rows = probe.parse_whatweb_output(json.dumps(SAMPLE))
    assert len(rows) == 1
    assert rows[0]["url"] == "https://www.example.com/" and rows[0]["status_code"] == 200
    assert rows[0]["ip"] == "93.184.216.34"


def test_whatweb_one_object_per_line_is_parsed_too():
    text = "[\n" + json.dumps(SAMPLE[0]) + ",\n" + json.dumps(dict(SAMPLE[0], target="https://b.example.com/")) + "\n]\n"
    assert [r["url"] for r in probe.parse_whatweb_output(text)] == ["https://www.example.com/", "https://b.example.com/"]


def test_garbage_and_incomplete_whatweb_output_is_ignored():
    assert probe.parse_whatweb_output("") == []
    assert probe.parse_whatweb_output("ERROR: no route to host") == []
    assert probe.parse_whatweb_output(json.dumps([{"target": "https://a/"}, "x", {"plugins": {}}])) == []


def test_only_technologies_are_kept_from_the_plugins():
    found = fingerprint.parse_whatweb(SAMPLE[0]["plugins"])
    assert ("nginx", "1.18.0") in found and ("PHP", "8.1.2") in found
    assert ("jQuery", "3.6.0") in found and ("WordPress", "6.4.2") in found
    assert ("Bootstrap", None) in found                      # a product Marsadix knows, no version printed
    names = {n.lower() for n, _ in found}
    assert not names & {"title", "country", "ip", "html5", "uncommonheaders"}


def test_the_same_technology_from_two_tools_is_one_entry_with_both_sources():
    merged = fingerprint.merge_sourced({"httpx": [("nginx", "1.18.0"), ("PHP", None)],
                                        "whatweb": [("nginx", "1.18.0"), ("jQuery", "3.6.0")]})
    by_name = {n: (v, set(s)) for n, v, s in merged}
    assert by_name["nginx"] == ("1.18.0", {"httpx", "whatweb"})
    assert by_name["jQuery"] == ("3.6.0", {"whatweb"})
    assert by_name["PHP"] == (None, {"httpx"})


def test_a_version_from_one_tool_replaces_the_versionless_entry_of_the_other():
    merged = fingerprint.merge_sourced({"httpx": [("Nginx", None)], "whatweb": [("nginx", "1.18.0")]})
    assert [(n.lower(), v, set(s)) for n, v, s in merged] == [("nginx", "1.18.0", {"httpx", "whatweb"})]


def test_two_entries_of_the_same_tool_are_not_folded():
    merged = fingerprint.merge_sourced({"httpx": [("nginx", None), ("nginx", "1.18.0")]})
    assert len(merged) == 2


def test_whatweb_is_skipped_when_it_is_not_installed(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert asyncio.run(probe.run_whatweb(["https://a.example.com"])) == []


def test_only_http_urls_reach_the_command_line(monkeypatch):
    """A target that starts with '-' must never become a whatweb option."""
    monkeypatch.setattr("shutil.which", lambda name: None)       # nothing is started; the filter runs first
    assert asyncio.run(probe.run_whatweb(["--log-json=/tmp/x", "ftp://a", "-a 4"])) == []
