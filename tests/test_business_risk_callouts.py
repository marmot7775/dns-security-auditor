"""Tests for business_risk callout attachment in SPF/DMARC/DKIM checks.

The audit engine attaches a plain-English business-impact sentence to
selected top-level findings via issue["business_risk"]. These tests pin:

  - Top-level findings (no record, p=none, no rua, no SPF) carry
    business_risk that matches the BUSINESS_RISK vocabulary.
  - Healthy records do not produce business_risk callouts.
  - Findings without an explicit business_risk_key do not include
    a "business_risk" key in the issue dict.
"""
import os
import sys
import unittest
from unittest.mock import patch

import dns.exception

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_engine import BUSINESS_RISK, _raw_check_dmarc, _raw_check_spf


def _patch_dmarc_lookup(records):
    return [
        patch("audit_engine._lookup_txt", return_value=list(records)),
        patch("audit_engine._lookup_ttl", return_value=300),
        patch("audit_engine._get_resolver", side_effect=dns.exception.DNSException),
    ]


def _run_dmarc(records):
    patches = _patch_dmarc_lookup(records)
    for p in patches:
        p.start()
    try:
        return _raw_check_dmarc("example.com")
    finally:
        for p in patches:
            p.stop()


def _patch_spf_lookup(records):
    return [
        patch("audit_engine._lookup_txt", return_value=list(records)),
        patch("audit_engine._lookup_ttl", return_value=300),
        # count_spf_lookups talks to DNS internally; stub to a healthy result.
        patch(
            "audit_engine.count_spf_lookups",
            return_value={"total_lookups": 1, "chain": []},
        ),
    ]


def _run_spf(records):
    patches = _patch_spf_lookup(records)
    for p in patches:
        p.start()
    try:
        return _raw_check_spf("example.com")
    finally:
        for p in patches:
            p.stop()


def _find_issue_by_substring(result, fragment):
    for issue in result.get("issues", []):
        if fragment.lower() in issue.get("issue", "").lower():
            return issue
    return None


class DMARCBusinessRiskTests(unittest.TestCase):
    def test_no_dmarc_record_attaches_no_record_risk(self):
        result = _run_dmarc([])
        issue = _find_issue_by_substring(result, "No DMARC record")
        self.assertIsNotNone(issue, "expected 'No DMARC record found' issue")
        self.assertEqual(
            issue.get("business_risk"),
            BUSINESS_RISK["DMARC_NO_RECORD"],
        )

    def test_p_none_attaches_p_none_risk(self):
        record = "v=DMARC1; p=none; rua=mailto:reports@example.com"
        result = _run_dmarc([record])
        issue = _find_issue_by_substring(result, "policy is none")
        self.assertIsNotNone(issue, "expected p=none warning")
        self.assertEqual(
            issue.get("business_risk"),
            BUSINESS_RISK["DMARC_P_NONE"],
        )

    def test_no_rua_attaches_no_rua_risk(self):
        # p=none with no rua at all
        record = "v=DMARC1; p=none"
        result = _run_dmarc([record])
        issue = _find_issue_by_substring(result, "No aggregate reporting")
        self.assertIsNotNone(issue, "expected missing rua warning")
        self.assertEqual(
            issue.get("business_risk"),
            BUSINESS_RISK["DMARC_NO_RUA"],
        )

    def test_healthy_dmarc_has_no_callouts(self):
        # Strong DMARC: p=reject with rua present.
        record = "v=DMARC1; p=reject; rua=mailto:reports@example.com"
        result = _run_dmarc([record])
        risks = [i for i in result.get("issues", []) if i.get("business_risk")]
        self.assertEqual(
            risks,
            [],
            f"healthy DMARC should not produce business_risk callouts, got {risks}",
        )

    def test_issue_without_key_has_no_business_risk_field(self):
        # A single rua address missing mailto: is a low-severity syntax-style
        # warning. The brief specifies these should NOT carry business_risk.
        record = "v=DMARC1; p=none; rua=reports@example.com"
        result = _run_dmarc([record])
        bare_rua_issue = _find_issue_by_substring(result, "missing 'mailto:' prefix")
        self.assertIsNotNone(bare_rua_issue, "expected missing-mailto warning")
        self.assertNotIn(
            "business_risk",
            bare_rua_issue,
            "low-severity findings must not include business_risk key",
        )


class SPFBusinessRiskTests(unittest.TestCase):
    def test_no_spf_record_attaches_no_record_risk(self):
        result = _run_spf([])
        issue = _find_issue_by_substring(result, "No SPF record")
        self.assertIsNotNone(issue, "expected 'No SPF record found' issue")
        self.assertEqual(
            issue.get("business_risk"),
            BUSINESS_RISK["SPF_NO_RECORD"],
        )

    def test_plus_all_attaches_plus_all_risk(self):
        result = _run_spf(["v=spf1 ip4:192.0.2.1 +all"])
        issue = _find_issue_by_substring(result, "+all")
        self.assertIsNotNone(issue, "expected +all error")
        self.assertEqual(
            issue.get("business_risk"),
            BUSINESS_RISK["SPF_PLUS_ALL"],
        )

    def test_healthy_spf_has_no_callouts(self):
        result = _run_spf(["v=spf1 ip4:192.0.2.1 -all"])
        risks = [i for i in result.get("issues", []) if i.get("business_risk")]
        self.assertEqual(
            risks,
            [],
            f"healthy SPF should not produce business_risk callouts, got {risks}",
        )


class VocabularyConstraintsTests(unittest.TestCase):
    """Sanity checks on the BUSINESS_RISK vocabulary itself."""

    def test_no_em_dashes_or_double_hyphens(self):
        for key, text in BUSINESS_RISK.items():
            self.assertNotIn("—", text, f"em-dash in {key}")
            self.assertNotIn(" -- ", text, f"double-hyphen in {key}")

    def test_per_sentence_word_count_under_25(self):
        for key, text in BUSINESS_RISK.items():
            # Split on sentence-ending punctuation, drop empties.
            sentences = [s.strip() for s in text.replace("?", ".").replace("!", ".").split(".") if s.strip()]
            for sentence in sentences:
                words = sentence.split()
                self.assertLessEqual(
                    len(words),
                    25,
                    f"{key} sentence exceeds 25 words: '{sentence}' ({len(words)} words)",
                )


if __name__ == "__main__":
    unittest.main()
