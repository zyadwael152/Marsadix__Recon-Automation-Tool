"""CertStream message handling without a live websocket."""

from marsadix.recon.ct_monitor import _new_hosts_from_message


def _msg(domains):
    return {"message_type": "certificate_update",
            "data": {"leaf_cert": {"all_domains": domains}}}


def test_only_in_scope_hosts_are_returned_and_deduplicated():
    seen = set()
    data = _msg(["*.api.example.com", "example.com", "example.com",
                 "notexample.com", "other.org", "*.example.com"])

    assert _new_hosts_from_message(data, "example.com", seen) == [
        "api.example.com", "example.com"]
    assert _new_hosts_from_message(data, "example.com", seen) == []


def test_malformed_messages_do_not_raise():
    for data in ([], "text", {}, {"message_type": "heartbeat"},
                 {"message_type": "certificate_update", "data": None},
                 {"message_type": "certificate_update", "data": {"leaf_cert": None}},
                 {"message_type": "certificate_update",
                  "data": {"leaf_cert": {"all_domains": "not-a-list"}}},
                 {"message_type": "certificate_update",
                  "data": {"leaf_cert": {"all_domains": [None, 42, ""]}}}):
        assert _new_hosts_from_message(data, "example.com", set()) == []
