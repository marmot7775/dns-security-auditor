"""Regression test for pct=0 on a p=reject DMARC record.

Bug: the p=quarantine branch of transform_dmarc appended "(pct=N)" to the
verdict when pct was below 100, but the p=reject branch never did, and
_build_attack_surface never read pct at all. A record with p=reject;
pct=0 (which rejects nothing) was reported as full protection: the
executive attack-surface vector "Direct Domain Spoofing" showed
"protected", contradicting the card's own detail line noting pct=0 applies
to none of the failing messages.

Test asserts on the transformed DMARC card (transform_dmarc output: verdict
and attack_surface), not on the raw check dict.
"""
import os
import sys
from unittest.mock import patch

import dns.exception

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_engine import _raw_check_dmarc
import result_transformer

DOMAIN = "pctzero.example.com"


def _build_card(record):
    with patch("audit_engine._lookup_txt", return_value=[record]), \
         patch("audit_engine._lookup_ttl", return_value=300), \
         patch("audit_engine._get_resolver", side_effect=dns.exception.DNSException):
        raw = _raw_check_dmarc(DOMAIN)
    return result_transformer.transform_dmarc(raw)


def test_pct_zero_reject_exposes_direct_spoofing_vector():
    card = _build_card("v=DMARC1; p=reject; pct=0; rua=mailto:r@example.com")

    vectors = {v["name"]: v for v in card["attack_surface"]["vectors"]}
    direct = vectors["Direct Domain Spoofing"]
    assert direct["status"] == "exposed", (
        f"pct=0 rejects nothing; Direct Domain Spoofing must be exposed, "
        f"got status={direct['status']!r} summary={direct['summary']!r}"
    )

    assert "pct=0" in card["verdict"], (
        f"Verdict must surface pct=0 the way the quarantine branch does; "
        f"got: {card['verdict']!r}"
    )


def test_pct_100_reject_still_fully_protects():
    """Control: pct=100 (or absent) is full enforcement, unchanged by the fix."""
    card = _build_card("v=DMARC1; p=reject; rua=mailto:r@example.com")
    vectors = {v["name"]: v for v in card["attack_surface"]["vectors"]}
    assert vectors["Direct Domain Spoofing"]["status"] == "protected"
    assert "pct=" not in card["verdict"]


def test_pct_50_reject_is_partial_not_protected():
    card = _build_card("v=DMARC1; p=reject; pct=50; rua=mailto:r@example.com")
    vectors = {v["name"]: v for v in card["attack_surface"]["vectors"]}
    assert vectors["Direct Domain Spoofing"]["status"] == "partial"
    assert "pct=50" in card["verdict"]
