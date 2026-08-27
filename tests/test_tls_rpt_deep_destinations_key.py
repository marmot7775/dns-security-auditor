"""Regression test for TLS-RPT deep destinations always being empty.

Bug 43: _build_tls_rpt_deep read raw["destinations"], but the check emits
"report_destinations", which transform_tls_rpt four lines away uses
correctly. tls_rpt_deep["destinations"] came back as [] for every domain,
however many rua targets the record listed.

Consumed by the JSON API only today.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from result_transformer import transform_tls_rpt


def _raw(record, destinations):
    return {
        "status": "ok",
        "record": record,
        "report_destinations": destinations,
        "issues": [],
        "ttl": 3600,
    }


def test_mailto_destination_reaches_the_deep_section():
    card = transform_tls_rpt(
        _raw("v=TLSRPTv1; rua=mailto:tls@example.com", ["mailto:tls@example.com"]),
        "example.com",
    )
    dests = card["tls_rpt_deep"]["destinations"]
    assert dests == [{"type": "mailto", "value": "mailto:tls@example.com"}]


def test_mixed_destinations_are_classified():
    card = transform_tls_rpt(
        _raw(
            "v=TLSRPTv1; rua=mailto:tls@example.com,https://tls.example.com/r",
            ["mailto:tls@example.com", "https://tls.example.com/r"],
        ),
        "example.com",
    )
    dests = card["tls_rpt_deep"]["destinations"]
    assert [d["type"] for d in dests] == ["mailto", "https"]


def test_deep_and_card_agree_on_the_destination_count():
    # The card summary and the deep section read the same field, so they can
    # never disagree again.
    destinations = ["mailto:a@example.com", "mailto:b@example.com"]
    card = transform_tls_rpt(
        _raw("v=TLSRPTv1; rua=mailto:a@example.com,mailto:b@example.com", destinations),
        "example.com",
    )
    assert "2 destinations" in card["verdict"]
    assert len(card["tls_rpt_deep"]["destinations"]) == 2
