"""Regression test for discarded SPF void-lookup findings.

Bug: _raw_check_spf only pulled spf_recursive_result["total_lookups"] out
of the recursive resolver and dropped spf_recursive_result["issues"]
entirely. Every void-lookup finding (an include: pointing at a domain with
no SPF record) was silently discarded, and RFC 7208 section 4.6.4's
two-void-lookup limit was never enforced -- a record with four broken
includes was reported as "4 DNS lookups, well within the limit" instead of
an error.

Test asserts on the transformed SPF card (transform_spf output), not on
the raw check dict.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine
import spf_recursive
import result_transformer

DOMAIN = "voidlookups.example.com"
RECORD = (
    "v=spf1 include:gone1.com include:gone2.com include:gone3.com "
    "include:gone4.com ip4:1.2.3.4 -all"
)

# Only the four "gone" includes have no SPF record; everything else does.
SPF_RECORDS = {DOMAIN: RECORD}


def _fake_get_spf_record(domain):
    return SPF_RECORDS.get(domain)


def _run_spf_check():
    with patch.object(audit_engine, "_lookup_txt", return_value=[RECORD]), \
         patch.object(audit_engine, "_lookup_ttl", return_value=None), \
         patch.object(spf_recursive, "_get_spf_record", side_effect=_fake_get_spf_record):
        raw = audit_engine._raw_check_spf(DOMAIN)
    return result_transformer.transform_spf(raw, has_mx=True)


def test_four_void_lookups_fails_the_card():
    card = _run_spf_check()

    assert card["status"] == "fail", (
        f"Four void lookups (four includes with no SPF record) must fail "
        f"the SPF card per RFC 7208 4.6.4; got status={card['status']!r}"
    )

    detail_texts = " ".join(d.get("text", "") for d in card.get("details", []))
    assert "well within the limit" not in detail_texts.lower()
    assert "void" in detail_texts.lower(), (
        f"Card details must mention the void lookup problem; got: {detail_texts!r}"
    )


def test_void_lookup_count_at_limit_does_not_fail():
    """Two void lookups is within the RFC limit -- must not fail the card
    on void-lookup grounds alone."""
    record = "v=spf1 include:gone1.com include:gone2.com ip4:1.2.3.4 -all"
    records = {DOMAIN: record}

    with patch.object(audit_engine, "_lookup_txt", return_value=[record]), \
         patch.object(audit_engine, "_lookup_ttl", return_value=None), \
         patch.object(spf_recursive, "_get_spf_record", side_effect=lambda d: records.get(d)):
        raw = audit_engine._raw_check_spf(DOMAIN)

    assert raw["void_lookup_count"] == 2
    card = result_transformer.transform_spf(raw, has_mx=True)
    assert card["status"] != "fail", (
        f"Exactly 2 void lookups is within the RFC 7208 limit and must not "
        f"fail the card; got status={card['status']!r}"
    )
