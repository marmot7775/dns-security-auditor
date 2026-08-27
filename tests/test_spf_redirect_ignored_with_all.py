"""Regression test for redirect= being counted and recursed into even
when the tool itself says it is ignored.

Bug: RFC 7208 6.1 says a redirect modifier MUST be ignored if an 'all'
mechanism appears anywhere in the record, and 5.1 says terms after 'all'
are never evaluated. audit_engine._raw_check_spf already warns about the
first case, but spf_recursive._count_recursive recursed into the
redirect target anyway, and did not stop counting at 'all' either.

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


def _build_card(domain, records):
    with patch.object(audit_engine, "_lookup_txt", return_value=[records[domain]]), \
         patch.object(audit_engine, "_lookup_ttl", return_value=None), \
         patch.object(spf_recursive, "_get_spf_record", side_effect=lambda d: records.get(d)):
        raw = audit_engine._raw_check_spf(domain)
    return raw, result_transformer.transform_spf(raw, has_mx=True)


def test_redirect_ignored_when_all_present_is_not_counted():
    domain = "redirectall.example.com"
    records = {
        domain: "v=spf1 include:a.com redirect=big.com -all",
        "a.com": "v=spf1 -all",
        "big.com": (
            "v=spf1 include:x1.com include:x2.com include:x3.com include:x4.com "
            "include:x5.com include:x6.com include:x7.com include:x8.com "
            "include:x9.com include:x10.com -all"
        ),
    }

    raw, card = _build_card(domain, records)

    assert raw["lookup_count"] == 1, (
        f"redirect=big.com must be ignored per RFC 7208 6.1 because -all is "
        f"present; only include:a.com should count. Got {raw['lookup_count']}"
    )

    detail_texts = " ".join(d.get("text", "") for d in card.get("details", []))
    assert "exceeds the 10-lookup limit" not in detail_texts.lower(), (
        f"Card must not report an over-limit error beneath its own "
        f"redirect-is-ignored warning; got details: {detail_texts!r}"
    )
    assert "well within the 10-lookup limit" in detail_texts, (
        f"1 lookup should be reported as well within the limit; got: {detail_texts!r}"
    )
    assert card["status"] != "fail", (
        f"1 lookup is well within the limit; card must not fail. "
        f"status={card['status']!r} details={detail_texts!r}"
    )


def test_mechanisms_after_all_are_never_counted():
    domain = "afterall.example.com"
    includes_after_all = " ".join(f"include:x{i}.com" for i in range(1, 12))
    records = {
        domain: f"v=spf1 ip4:1.2.3.4 -all {includes_after_all}",
    }

    raw, card = _build_card(domain, records)

    assert raw["lookup_count"] == 0, (
        f"RFC 7208 5.1: mechanisms after 'all' are never evaluated, so the "
        f"11 includes after -all must not count. Got {raw['lookup_count']}"
    )
    assert card["status"] != "fail"
