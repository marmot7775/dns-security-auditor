"""Regression tests for the BIMI DMARC prerequisite check.

Bug 1: check_bimi's guard was `if dmarc_enforcing_override is not None:
dmarc_found = True`. The audit orchestrator (audit_engine.py) always
passes a bool for dmarc_enforcing_override, never None, so dmarc_found was
forced True even when there was no DMARC record at all -- the correct
"BIMI requires DMARC, but no DMARC record found" error branch was dead
code in production, and the card said DMARC was "likely 'none'" (implying
a record exists) instead.

Bug 2: the DMARC enforcement check substring-matched the record
("p=reject" in record), so sp=reject satisfied the p= enforcement check
even on a p=none record.

Tests assert on the transformed BIMI card (transform_bimi output), not on
check_bimi's raw dict.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import checks_extra
import result_transformer

BIMI_RECORD = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"


def _bimi_card_via_override(dmarc_raw):
    """Mirror how audit_engine derives the overrides it passes to
    check_bimi from raw_results["dmarc"], and run the real production
    call path (override, not direct DNS lookup)."""
    dmarc_found = bool(dmarc_raw.get("record")) or bool(dmarc_raw.get("inherited_policy"))
    dmarc_enforcing = (
        (dmarc_raw.get("policy") or "").lower() in ("quarantine", "reject")
        or (dmarc_raw.get("inherited_policy") or "").lower() in ("quarantine", "reject")
    )

    with patch.object(checks_extra, "_lookup_txt", return_value=[BIMI_RECORD]), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", False):
        raw = checks_extra.check_bimi(
            "example.com",
            dmarc_enforcing_override=dmarc_enforcing,
            dmarc_found_override=dmarc_found,
        )
    return result_transformer.transform_bimi(raw, "example.com", has_mx=True)


def test_bimi_with_no_dmarc_record_fails_not_warns():
    """BIMI published, _dmarc.example.com completely empty."""
    card = _bimi_card_via_override({"record": None, "policy": None, "inherited_policy": None})

    assert card["status"] == "fail", (
        f"No DMARC record at all must fail the BIMI card, not warn as if "
        f"a p=none record exists; got status={card['status']!r}"
    )
    texts = " ".join(d.get("text", "") for d in card["details"])
    assert "likely" not in texts.lower(), (
        f"Must not claim a DMARC policy exists ('likely none') when there "
        f"is no DMARC record at all; got: {texts!r}"
    )
    assert "dmarc" in texts.lower()


def test_bimi_with_enforcing_dmarc_does_not_fail_on_dmarc_prereq():
    """Control: DMARC present and enforcing must not trigger either DMARC issue."""
    card = _bimi_card_via_override({"record": "v=DMARC1; p=reject", "policy": "reject"})
    texts = " ".join(d.get("text", "") for d in card["details"])
    assert "requires dmarc" not in texts.lower()
    assert "not at enforcement" not in texts.lower()


def test_sp_reject_does_not_satisfy_p_enforcement_check():
    """checks_extra.py substring match: 'p=reject' in 'v=DMARC1; p=none;
    sp=reject' was True. Direct-lookup path (no override), so this
    exercises the tag parser fix directly."""
    dmarc_record = "v=DMARC1; p=none; sp=reject; rua=mailto:r@example.com"

    def _fake_lookup(name):
        if name == "default._bimi.example.com":
            return [BIMI_RECORD]
        if name == "_dmarc.example.com":
            return [dmarc_record]
        return []

    with patch.object(checks_extra, "_lookup_txt", side_effect=_fake_lookup), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", False):
        raw = checks_extra.check_bimi("example.com")

    card = result_transformer.transform_bimi(raw, "example.com", has_mx=True)
    texts = " ".join(d.get("text", "") for d in card["details"])
    assert "not at enforcement" in texts.lower() or "likely" in texts.lower(), (
        f"p=none must NOT be treated as enforcing just because sp=reject "
        f"appears later in the record; got details: {texts!r}"
    )
