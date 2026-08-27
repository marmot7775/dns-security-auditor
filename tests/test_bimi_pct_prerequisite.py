"""Regression test for the missing BIMI pct prerequisite check.

Bug: `grep -n pct checks_extra.py` returned nothing. BIMI requires the
DMARC policy at enforcement with pct absent or 100 (a partial-percentage
DMARC policy means most messages that fail authentication are not
actually rejected/quarantined, so mailbox providers won't display the
BIMI logo). A record like `v=DMARC1; p=reject; pct=20` passed the BIMI
card clean with no warning, telling the operator their logo would
display when it would not.

Tests both the audit-engine override path (dmarc_pct_override, mirroring
how audit_engine.py derives it from raw_results["dmarc"]["pct"]) and the
standalone direct-DNS-lookup path.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import checks_extra

BIMI_RECORD = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"


def _pct_texts(issues):
    return " ".join(f"{i.get('issue', '')} {i.get('plain_english', '')}" for i in issues).lower()


def test_override_path_pct_below_100_disqualifies_bimi():
    with patch.object(checks_extra, "_lookup_txt", return_value=[BIMI_RECORD]), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", False):
        raw = checks_extra.check_bimi(
            "example.com",
            dmarc_enforcing_override=True,
            dmarc_found_override=True,
            dmarc_pct_override=20,
        )

    texts = _pct_texts(raw["issues"])
    assert "pct" in texts and "disqualif" in texts, (
        f"pct=20 on an enforcing DMARC policy must warn that BIMI is "
        f"disqualified; got issues: {raw['issues']!r}"
    )


def test_override_path_pct_100_does_not_warn():
    with patch.object(checks_extra, "_lookup_txt", return_value=[BIMI_RECORD]), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", False):
        raw = checks_extra.check_bimi(
            "example.com",
            dmarc_enforcing_override=True,
            dmarc_found_override=True,
            dmarc_pct_override=100,
        )

    texts = _pct_texts(raw["issues"])
    assert "disqualif" not in texts


def test_override_path_pct_none_defaults_to_no_warning():
    """No pct override supplied (e.g. older caller) must not spuriously warn."""
    with patch.object(checks_extra, "_lookup_txt", return_value=[BIMI_RECORD]), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", False):
        raw = checks_extra.check_bimi(
            "example.com",
            dmarc_enforcing_override=True,
            dmarc_found_override=True,
        )

    texts = _pct_texts(raw["issues"])
    assert "disqualif" not in texts


def test_standalone_path_pct_below_100_disqualifies_bimi():
    dmarc_record = "v=DMARC1; p=reject; pct=20; rua=mailto:r@example.com"

    def _fake_lookup(name):
        if name == "default._bimi.example.com":
            return [BIMI_RECORD]
        if name == "_dmarc.example.com":
            return [dmarc_record]
        return []

    with patch.object(checks_extra, "_lookup_txt", side_effect=_fake_lookup), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", False):
        raw = checks_extra.check_bimi("example.com")

    texts = _pct_texts(raw["issues"])
    assert "pct" in texts and "disqualif" in texts, (
        f"pct=20 in a directly-looked-up DMARC record must warn that BIMI "
        f"is disqualified; got issues: {raw['issues']!r}"
    )


def test_standalone_path_pct_absent_does_not_warn():
    dmarc_record = "v=DMARC1; p=reject; rua=mailto:r@example.com"

    def _fake_lookup(name):
        if name == "default._bimi.example.com":
            return [BIMI_RECORD]
        if name == "_dmarc.example.com":
            return [dmarc_record]
        return []

    with patch.object(checks_extra, "_lookup_txt", side_effect=_fake_lookup), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", False):
        raw = checks_extra.check_bimi("example.com")

    texts = _pct_texts(raw["issues"])
    assert "disqualif" not in texts
