"""
Prompt 25: a TXT record that fails a record type's version gate must be
reported as a present-but-invalid record, never as "no record found".

DMARC's _raw_check_dmarc took the "no record" early-return whenever every
TXT record at _dmarc failed the version gate (e.g. lowercase v=dmarc1),
discarding the syntax_errors it had already computed and telling the
operator to publish a record they already published. Fixed by mirroring
the malformed_record pattern check_mta_sts/check_tls_rpt already use.

These tests assert on the transformed card (what the user sees), not the
raw dict, per the prompt: the raw result was already correct here and the
card is where it went wrong.
"""

import sys
import os
import unittest
from unittest.mock import patch

import dns.exception

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_engine import _raw_check_dmarc
from checks_extra import check_mta_sts, check_tls_rpt, check_bimi
from result_transformer import (
    transform_dmarc,
    transform_mta_sts,
    transform_tls_rpt,
    transform_bimi,
)


def _dmarc_card(records):
    with patch("audit_engine._lookup_txt", return_value=list(records)), \
         patch("audit_engine._lookup_ttl", return_value=300), \
         patch("audit_engine._get_resolver", side_effect=dns.exception.DNSException):
        raw = _raw_check_dmarc("example.com")
    return raw, transform_dmarc(raw)


class TestDmarcVersionGateRejection(unittest.TestCase):
    """A present-but-invalid DMARC record must not be reported as absent."""

    def test_lowercase_record_card_does_not_claim_absence(self):
        raw, card = _dmarc_card(["v=dmarc1; p=reject; rua=mailto:d@example.com"])

        self.assertEqual(card["status"], "fail")
        verdict_and_explanation = (card["verdict"] + card["explanation"]).lower()
        self.assertNotIn("no dmarc policy published", verdict_and_explanation)
        self.assertNotIn("no dmarc record", verdict_and_explanation)

        # The record itself must be visible on the card, quoted.
        self.assertIn("v=dmarc1", card["record"])

        # The fix must name the correction, not tell the user to publish one.
        self.assertIn("v=DMARC1", card["fix"])
        self.assertNotIn("Publish a DMARC", card["fix"])

    def test_lowercase_record_engine_result_unaffected(self):
        """The raw engine result keeps reporting record=None; only the card
        that is built from it changes. Guards the contract the fix relies on."""
        raw, _card = _dmarc_card(["v=dmarc1; p=reject"])
        self.assertIsNone(raw["record"])
        self.assertEqual(raw["status"], "error")
        self.assertEqual(raw["malformed_record"], "v=dmarc1; p=reject")

    def test_genuinely_no_record_is_still_reported_as_absent(self):
        """No TXT at _dmarc at all is a real absence and must say so."""
        _raw, card = _dmarc_card([])
        self.assertEqual(card["status"], "fail")
        self.assertIn("No DMARC policy published", card["verdict"])
        self.assertIn("Publish a DMARC", card["fix"])

    def test_valid_record_alongside_a_stray_lowercase_one_is_unaffected(self):
        """A domain with one valid v=DMARC1 record and a leftover lowercase
        one still gets its real policy read; that path was never broken."""
        raw, card = _dmarc_card(["v=DMARC1; p=reject", "v=dmarc1; p=none"])
        self.assertEqual(raw["record"], "v=DMARC1; p=reject")
        self.assertIn("p=reject", card["verdict"])


class TestMtaStsAndTlsRptAlreadyFixed(unittest.TestCase):
    """Prompt 24 already gave these the malformed_record treatment; guard
    against a regression rather than re-deriving the fix."""

    def test_mta_sts_lowercase_record_card_does_not_claim_absence(self):
        with patch("checks_extra._lookup_txt", return_value=["v=stsv1; id=1"]), \
             patch("checks_extra._lookup_ttl", return_value=300):
            raw = check_mta_sts("example.com")
        card = transform_mta_sts(raw, "example.com")

        self.assertEqual(card["status"], "fail")
        self.assertNotIn("No MTA-STS record found", card["verdict"])
        self.assertIn("v=stsv1", card["record"])
        self.assertIn("v=STSv1", card["fix"])

    def test_tls_rpt_lowercase_record_card_does_not_claim_absence(self):
        with patch("checks_extra._lookup_txt",
                    return_value=["v=tlsrptv1; rua=mailto:d@example.com"]), \
             patch("checks_extra._lookup_ttl", return_value=300):
            raw = check_tls_rpt("example.com")
        card = transform_tls_rpt(raw, "example.com")

        self.assertEqual(card["status"], "fail")
        self.assertNotIn("No TLS-RPT", card["verdict"])
        self.assertIn("v=tlsrptv1", card["record"])
        self.assertIn("v=TLSRPTv1", card["fix"])


class TestBimiHasNoVersionGateToFail(unittest.TestCase):
    """BIMI's version tag is intentionally case insensitive and whitespace
    tolerant (BIMI draft S4.2, unlike DMARC/MTA-STS/TLS-RPT there is no %s
    prefix), so there is no near-miss family that falls into this hole.
    This locks in that a case-varied record is read as the real record
    rather than silently reproducing the DMARC bug."""

    def test_mixed_case_record_is_read_not_dropped(self):
        # No l= tag: keeps the test out of the logo-fetch path entirely,
        # which is unrelated to what this test checks.
        with patch("checks_extra._lookup_txt", return_value=["V=bimi1"]), \
             patch("checks_extra._lookup_ttl", return_value=300):
            raw = check_bimi(
                "example.com",
                dmarc_found_override=True,
                dmarc_enforcing_override=True,
                dmarc_pct_override=100,
                dmarc_policy_override="reject",
            )
        card = transform_bimi(raw, "example.com")

        self.assertIsNotNone(raw["record"])
        self.assertNotIn("No BIMI", card.get("verdict", ""))


if __name__ == "__main__":
    unittest.main()
