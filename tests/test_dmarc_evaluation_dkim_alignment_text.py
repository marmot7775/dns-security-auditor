"""Regression test for the DMARC evaluation explanation describing DKIM
alignment using the SPF alignment tag.

Bug: build_dmarc_evaluation's explanation always read spf_alignment_mode
(derived from aspf=) regardless of which mechanism(s) it was actually
describing, so a domain with no SPF record and DKIM configured under
adkim=r (relaxed) but aspf=s (strict) was told "DKIM is configured with
strict alignment" -- contradicting the dkim_alignment_mode the same
function returns.

Test asserts on build_dmarc_evaluation's own return value, which is the
user-facing object placed directly into the audit result as
"dmarc_eval" (no separate result_transformer step for this feature).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spf_execution_engine import build_dmarc_evaluation


def test_dkim_only_alignment_uses_adkim_not_aspf():
    raw_dmarc = {
        "record": "v=DMARC1; p=reject; adkim=r; aspf=s",
        "policy": "reject",
        "adkim": "r",
        "aspf": "s",
    }
    raw_spf = {"record": None, "lookup_count": 0}
    raw_dkim = {"found_selectors": ["selector1"]}

    result = build_dmarc_evaluation(raw_dmarc, raw_spf, raw_dkim, tree_walk=None)

    assert result is not None
    assert result["dkim_alignment_mode"] == "relaxed"
    assert result["spf_alignment_mode"] == "strict"
    assert result["dkim_aligned"] is True
    assert result["spf_aligned"] is False

    assert "strict alignment" not in result["explanation"], (
        f"Only DKIM (relaxed, adkim=r) is configured; the explanation must "
        f"not borrow SPF's strict (aspf=s) mode. Got: {result['explanation']!r}"
    )
    assert "relaxed alignment" in result["explanation"], (
        f"Expected the explanation to describe DKIM's own relaxed alignment; "
        f"got: {result['explanation']!r}"
    )


def test_spf_only_alignment_still_uses_aspf():
    """Control: SPF-only configuration is unaffected by the fix."""
    raw_dmarc = {
        "record": "v=DMARC1; p=reject; adkim=r; aspf=s",
        "policy": "reject",
        "adkim": "r",
        "aspf": "s",
    }
    raw_spf = {"record": "v=spf1 -all", "lookup_count": 0}
    raw_dkim = {"found_selectors": []}

    result = build_dmarc_evaluation(raw_dmarc, raw_spf, raw_dkim, tree_walk=None)

    assert result is not None
    assert result["spf_aligned"] is True
    assert result["dkim_aligned"] is False
    assert "strict alignment" in result["explanation"]


def test_both_configured_with_different_modes_mentions_both():
    raw_dmarc = {
        "record": "v=DMARC1; p=reject; adkim=r; aspf=s",
        "policy": "reject",
        "adkim": "r",
        "aspf": "s",
    }
    raw_spf = {"record": "v=spf1 -all", "lookup_count": 0}
    raw_dkim = {"found_selectors": ["selector1"]}

    result = build_dmarc_evaluation(raw_dmarc, raw_spf, raw_dkim, tree_walk=None)

    assert result is not None
    assert "strict" in result["explanation"]
    assert "relaxed" in result["explanation"]
