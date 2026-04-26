"""
Tests for RFC 7489 S6.3 case-sensitive validation of the DMARC version tag.

The version tag value 'DMARC1' is case-sensitive. A record published as
v=dmarc1 is NOT a valid DMARC record and must not be honored. The audit
engine must:
  - exclude lowercase v=dmarc1 records from the valid-record count
  - emit a syntax error explaining the lowercase variant
  - still treat well-formed v=DMARC1 (with or without further tags) as valid
"""

import sys
import os
import unittest
from unittest.mock import patch

import dns.exception

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_engine import _raw_check_dmarc


def _patch_dmarc_lookup(records):
    """Patch _raw_check_dmarc's DNS dependencies to return given TXT records.

    Suppresses CNAME lookup and TTL lookup so the test focuses purely on
    the version-tag parsing path.
    """
    return [
        patch("audit_engine._lookup_txt", return_value=list(records)),
        patch("audit_engine._lookup_ttl", return_value=300),
        patch("audit_engine._get_resolver", side_effect=dns.exception.DNSException),
    ]


class TestDmarcVersionTagCaseSensitivity(unittest.TestCase):
    """Version tag must be uppercase v=DMARC1 (RFC 7489 S6.3)."""

    def _run(self, records):
        patches = _patch_dmarc_lookup(records)
        for p in patches:
            p.start()
        try:
            return _raw_check_dmarc("example.com")
        finally:
            for p in patches:
                p.stop()

    def _has_syntax_error(self, result, fragment):
        return any(
            fragment.lower() in (e.get("issue", "") + e.get("plain_english", "")).lower()
            for e in result.get("syntax_errors", [])
        )

    def test_uppercase_v_dmarc1_is_valid(self):
        """Bare v=DMARC1 must be accepted as a valid record."""
        result = self._run(["v=DMARC1"])
        assert result["record"] == "v=DMARC1"
        assert not self._has_syntax_error(result, "lowercase v=dmarc1")

    def test_lowercase_v_dmarc1_is_invalid(self):
        """Lowercase v=dmarc1 must NOT be counted as a valid record and MUST
        produce a syntax error explaining the lowercase variant."""
        result = self._run(["v=dmarc1; p=reject"])

        # The record was excluded from the valid count -> "no DMARC" path.
        assert result["status"] == "error"
        assert result["record"] is None

        # The syntax error must be present even though the record was filtered.
        assert self._has_syntax_error(result, "lowercase v=dmarc1"), (
            f"Expected lowercase syntax error in {result.get('syntax_errors')}"
        )

    def test_uppercase_v_dmarc1_with_policy_is_valid(self):
        """v=DMARC1; p=none is the canonical minimal valid record."""
        result = self._run(["v=DMARC1; p=none"])
        assert result["record"] == "v=DMARC1; p=none"
        assert result["policy"] == "none"
        assert not self._has_syntax_error(result, "lowercase v=dmarc1")


if __name__ == "__main__":
    unittest.main()
