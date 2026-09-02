"""Regression test: an include target that resolves but publishes no SPF
record is a PermError, not a void lookup.

RFC 7208 section 5.2: the include mechanism runs a recursive check_host(),
and a result of "none" -- which is what you get when the target resolves and
has no SPF record -- makes the including record permerror. The code filed it
as a void lookup at warning severity, with text saying "a third may trigger a
PermError", so one broken include read as a minor cleanup item when it in
fact breaks SPF outright for every message.

Asserts on the transformed SPF card, not on the raw check dict.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer
from conftest import FakeZone, fake_dns

DOMAIN = "permerror.example.test"
RECORD = "v=spf1 include:nospf.example.test ip4:198.51.100.0/24 -all"

ZONE = {
    DOMAIN: {"TXT": [RECORD]},
    # Resolves, publishes TXT, but nothing that starts with v=spf1.
    "nospf.example.test": {"TXT": ["google-site-verification=nope"]},
}


def test_include_target_with_no_spf_record_is_an_immediate_permerror():
    with fake_dns(FakeZone(ZONE)):
        raw = audit_engine._raw_check_spf(DOMAIN)
    card = result_transformer.transform_spf(raw, has_mx=True)

    assert raw["void_lookup_count"] == 0, (
        f"The target resolves, so nothing here is a void lookup. "
        f"Got {raw['void_lookup_count']}"
    )

    severities = {
        i["severity"] for i in raw["issues"]
        if "nospf.example.test" in i.get("issue", "")
    }
    assert severities == {"error"}, (
        f"RFC 7208 5.2 makes this an immediate PermError, so it must be "
        f"reported at error severity. Got {severities!r}"
    )

    assert card["status"] == "fail", (
        f"One include with no SPF record breaks the whole record; the card "
        f"must fail. Got {card['status']!r}"
    )

    detail_texts = " ".join(d.get("text", "") for d in card.get("details", []))
    assert "publishes no SPF record" in detail_texts, (
        f"Card must name the broken include; got: {detail_texts!r}"
    )
    assert "a third may trigger" not in detail_texts.lower(), (
        f"This is not a void-lookup-budget problem; got: {detail_texts!r}"
    )
