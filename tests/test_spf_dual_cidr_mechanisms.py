"""Regression test for dual-cidr-length 'a' and 'mx' mechanisms rejected
as unknown SPF mechanisms.

Bug: KNOWN_MECHANISMS in audit_engine._raw_check_spf holds bare names
("a", "mx", ...), and the bare-token branch compared the whole token
against that set. RFC 7208 5.3 dual-cidr-length lets a bare 'a' or 'mx'
carry a cidr suffix (a/24, mx//64, mx/24//64), so 'a/24' and 'mx/24'
never matched and were flagged as unrecognized mechanisms.
spf_recursive._parse_spf_mechanisms already parsed these correctly, so
the two SPF parsers in the same audit disagreed.

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

DOMAIN = "dualcidr.example.com"


def _build_card(record):
    with patch.object(audit_engine, "_lookup_txt", return_value=[record]), \
         patch.object(audit_engine, "_lookup_ttl", return_value=None), \
         patch.object(spf_recursive, "_lookup_spf",
                      return_value={"record": record,
                                    "status": spf_recursive.SPF_FOUND,
                                    "error": None}), \
         patch.object(spf_recursive, "_mechanism_lookup_status",
                      return_value="ok"):
        raw = audit_engine._raw_check_spf(DOMAIN)
    return result_transformer.transform_spf(raw, has_mx=True)


def test_bare_dual_cidr_a_and_mx_produce_no_issues():
    record = "v=spf1 a/24 mx/24 include:_spf.google.com -all"
    card = _build_card(record)

    detail_texts = " ".join(d.get("text", "") for d in card.get("details", []))
    assert "not a recognized SPF mechanism" not in detail_texts, (
        f"a/24 and mx/24 are valid RFC 7208 5.3 dual-cidr-length forms; "
        f"got details: {detail_texts!r}"
    )
    assert card["status"] != "fail", (
        f"Record is fully valid; card must not fail. Got status={card['status']!r}, "
        f"details={detail_texts!r}"
    )


def test_colon_form_and_full_dual_cidr_and_ip6_only_form_produce_no_issues():
    record = (
        "v=spf1 a:mail.example.com/24 mx:mail.example.com/24//64 "
        "a//64 mx/24//64 -all"
    )
    card = _build_card(record)

    detail_texts = " ".join(d.get("text", "") for d in card.get("details", []))
    assert "not a recognized SPF mechanism" not in detail_texts, (
        f"a:host/24, mx:host/24//64, and bare ip6-only dual-cidr forms are "
        f"all valid; got details: {detail_texts!r}"
    )
    assert card["status"] != "fail"
