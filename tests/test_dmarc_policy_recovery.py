"""Tests for RFC 9989 §4.10.1 policy recovery.

Verbatim from §4.10.1 (the rule under test):

    If a retrieved DMARC Policy Record does not contain a valid "p"
    tag, or contains an "sp" or "np" tag that is not valid, then:

    *  If a "rua" tag is present and contains at least one
       syntactically valid reporting URI, the Mail Receiver MUST
       act as if a record containing "p=none" was retrieved and
       continue processing;

    *  Otherwise, the Mail Receiver applies no DMARC processing to
       this message.

The rule covers all four trigger conditions: missing p, invalid p,
invalid sp, invalid np. Recovery applies only when rua= contains at
least one syntactically valid mailto: URI. This file pins that
behavior so future edits can't silently regress.
"""
import os
import sys
import unittest
from unittest.mock import patch

import dns.exception

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_engine import _is_rua_syntactically_valid, _raw_check_dmarc


def _patch_dmarc_lookup(records):
    return [
        patch("audit_engine._lookup_txt", return_value=list(records)),
        patch("audit_engine._lookup_ttl", return_value=300),
        patch("audit_engine._get_resolver", side_effect=dns.exception.DNSException),
    ]


def _run(record):
    patches = _patch_dmarc_lookup([record])
    for p in patches:
        p.start()
    try:
        return _raw_check_dmarc("example.com")
    finally:
        for p in patches:
            p.stop()


def _has_warning_about(result, fragment):
    return any(
        i.get("severity") == "warning"
        and fragment.lower() in (i.get("issue", "") + i.get("plain_english", "")).lower()
        for i in result.get("issues", [])
    )


def _has_error_about(result, fragment):
    f = fragment.lower()
    in_issues = any(
        i.get("severity") == "error"
        and f in (i.get("issue", "") + i.get("plain_english", "")).lower()
        for i in result.get("issues", [])
    )
    in_syntax = any(
        f in (e.get("issue", "") + e.get("plain_english", "")).lower()
        for e in result.get("syntax_errors", [])
    )
    return in_issues or in_syntax


class TestRuaSyntacticValidator(unittest.TestCase):
    """The helper that codifies 'at least one syntactically valid
    reporting URI'."""

    def test_single_valid_mailto_passes(self):
        self.assertTrue(_is_rua_syntactically_valid("mailto:reports@example.com"))

    def test_uppercase_mailto_passes(self):
        self.assertTrue(_is_rua_syntactically_valid("MAILTO:reports@example.com"))

    def test_size_modifier_is_stripped(self):
        # RFC 6068 size modifier: mailto:addr!10m
        self.assertTrue(_is_rua_syntactically_valid("mailto:reports@example.com!10m"))

    def test_at_least_one_valid_in_list_passes(self):
        # First URI broken, second valid -> True per spec wording.
        self.assertTrue(
            _is_rua_syntactically_valid("garbage, mailto:reports@example.com")
        )

    def test_all_invalid_fails(self):
        self.assertFalse(_is_rua_syntactically_valid("not-a-uri"))
        self.assertFalse(_is_rua_syntactically_valid("https://example.com/reports"))
        self.assertFalse(_is_rua_syntactically_valid("mailto:not-an-email"))

    def test_empty_string_fails(self):
        self.assertFalse(_is_rua_syntactically_valid(""))

    def test_whitespace_in_list_is_tolerated(self):
        self.assertTrue(
            _is_rua_syntactically_valid(" mailto:a@b.com , mailto:c@d.com ")
        )


class TestPolicyRecoveryRule(unittest.TestCase):
    """End-to-end: _raw_check_dmarc must apply §4.10.1 policy recovery
    for missing p, invalid p, invalid sp, and invalid np when rua= is
    syntactically valid; otherwise it must treat the record as if no
    DMARC was published."""

    # ── Recovery cases (rua= valid) ─────────────────────────────────

    def test_invalid_p_with_valid_rua_recovers_to_none(self):
        out = _run("v=DMARC1; p=invalid; rua=mailto:r@example.com")
        self.assertTrue(out.get("policy_recovery_applied"))
        self.assertEqual(out.get("policy"), "none")
        # Existing syntax error must still fire (constraint #4).
        self.assertTrue(_has_error_about(out, "invalid policy value"))
        # Spec-recovery warning must surface the interop split.
        self.assertTrue(_has_warning_about(out, "spec recovery"))
        self.assertTrue(_has_warning_about(out, "rfc 7489"))

    def test_missing_p_with_valid_rua_recovers_to_none(self):
        out = _run("v=DMARC1; rua=mailto:r@example.com")
        self.assertTrue(out.get("policy_recovery_applied"))
        self.assertEqual(out.get("policy"), "none")
        self.assertTrue(_has_warning_about(out, "missing p="))

    def test_invalid_sp_with_valid_rua_recovers_to_none(self):
        out = _run("v=DMARC1; p=none; sp=invalid; rua=mailto:r@example.com")
        self.assertTrue(out.get("policy_recovery_applied"))
        self.assertEqual(out.get("policy"), "none")
        self.assertTrue(_has_error_about(out, "invalid subdomain policy"))
        self.assertTrue(_has_warning_about(out, "invalid sp= value"))

    def test_invalid_np_with_valid_rua_recovers_to_none(self):
        out = _run("v=DMARC1; p=reject; np=garbage; rua=mailto:r@x.com")
        self.assertTrue(out.get("policy_recovery_applied"))
        # When np is the trigger, p=reject is overridden to p=none.
        self.assertEqual(out.get("policy"), "none")
        self.assertTrue(_has_error_about(out, "invalid non-existent subdomain policy"))
        self.assertTrue(_has_warning_about(out, "invalid np= value"))

    # ── No-recovery cases (rua= missing or invalid) ─────────────────

    def test_invalid_p_without_rua_yields_no_dmarc(self):
        out = _run("v=DMARC1; p=invalid")
        self.assertFalse(out.get("policy_recovery_applied"))
        self.assertTrue(_has_error_about(out, "no valid rua"))
        # The original invalid-p syntax error is still emitted.
        self.assertTrue(_has_error_about(out, "invalid policy value"))

    def test_missing_p_without_rua_yields_no_dmarc(self):
        out = _run("v=DMARC1")
        self.assertFalse(out.get("policy_recovery_applied"))
        self.assertTrue(_has_error_about(out, "missing required policy tag"))

    def test_invalid_p_with_unparseable_rua_does_not_recover(self):
        # rua present but no syntactically valid URI -> no recovery.
        out = _run("v=DMARC1; p=invalid; rua=not-a-uri")
        self.assertFalse(out.get("policy_recovery_applied"))
        self.assertTrue(_has_error_about(out, "no valid rua"))

    # ── Boundary: valid record must not trigger recovery ────────────

    def test_valid_record_does_not_trigger_recovery(self):
        out = _run("v=DMARC1; p=reject; rua=mailto:r@example.com")
        self.assertFalse(out.get("policy_recovery_applied"))
        self.assertEqual(out.get("policy"), "reject")
        self.assertFalse(_has_warning_about(out, "spec recovery"))


if __name__ == "__main__":
    unittest.main()
