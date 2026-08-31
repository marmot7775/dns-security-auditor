"""Regression test: a:, mx: and exists: targets are actually resolved, so a
dead one is counted as the void lookup it is.

RFC 7208 section 4.6.4 defines a void lookup as a query that returns NXDOMAIN
or an empty answer, and allows two. The counter only ever incremented for
include targets with no SPF record; a:, mx: and exists: targets were counted
towards the ten-lookup limit but never queried, so

    v=spf1 a:no1... a:no2... a:no3... -all

reported void_lookup_count 0 and a clean card while an enforcing receiver
returns PermError on the third void lookup.

Asserts on the transformed SPF card, not on the raw check dict.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer
from conftest import FakeZone, fake_dns

DOMAIN = "voidmech.example.test"
DEAD_RECORD = (
    "v=spf1 a:no1.example.test a:no2.example.test a:no3.example.test -all"
)
LIVE_RECORD = "v=spf1 a:live.example.test mx:live.example.test -all"

DEAD_ZONE = {DOMAIN: {"TXT": [DEAD_RECORD]}}
LIVE_ZONE = {
    DOMAIN: {"TXT": [LIVE_RECORD]},
    "live.example.test": {"A": ["198.51.100.10"], "MX": [(10, "mail.example.test")]},
}


def _run(zone, record):
    with fake_dns(FakeZone(zone)):
        raw = audit_engine._raw_check_spf(DOMAIN)
    return raw, result_transformer.transform_spf(raw, has_mx=True)


def test_dead_a_targets_are_counted_as_void_lookups():
    raw, card = _run(DEAD_ZONE, DEAD_RECORD)

    assert raw["void_lookup_count"] == 3, (
        f"Three a: targets that do not exist are three void lookups per "
        f"RFC 7208 4.6.4. Got {raw['void_lookup_count']}"
    )
    assert card["status"] == "fail", (
        f"Three void lookups exceeds the limit of two, so receivers return "
        f"PermError and the card must fail. Got {card['status']!r}"
    )

    detail_texts = " ".join(d.get("text", "") for d in card.get("details", []))
    assert "void lookup" in detail_texts.lower(), (
        f"Card must name the void lookup problem; got: {detail_texts!r}"
    )


def test_live_a_and_mx_targets_are_not_void():
    raw, card = _run(LIVE_ZONE, LIVE_RECORD)

    assert raw["void_lookup_count"] == 0, (
        f"Both targets resolve, so neither is a void lookup. "
        f"Got {raw['void_lookup_count']}"
    )
    assert card["status"] == "pass", (
        f"A record whose mechanisms all resolve, inside the lookup limit, "
        f"must pass. Got {card['status']!r}"
    )
