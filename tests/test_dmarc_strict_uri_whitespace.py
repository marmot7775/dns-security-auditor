"""Pin: dmarcbis-41 §4.8 ABNF allows *WSP around the comma in
dmarc-urilist, so the strict validator must not flag whitespace.

Verbatim ABNF (line 1274 of draft-ietf-dmarc-dmarcbis-41):

    dmarc-urilist = (dmarc-uri / obs-dmarc-uri)
                    *(*WSP "," *WSP (dmarc-uri / obs-dmarc-uri))

`*WSP` on both sides means whitespace before AND after the comma is
spec-conformant. Two old checks (URI_WHITESPACE fail, URI_SPACE_AFTER_COMMA
warn) flagged conformant records; this file ensures they stay gone.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_engine import _validate_dmarc_strict


class TestStrictAllowsWhitespaceAroundComma(unittest.TestCase):

    def _codes(self, record):
        result = _validate_dmarc_strict(record)
        return [c["code"] for c in result["checks"]]

    def test_space_after_comma_does_not_warn_or_fail(self):
        record = "v=DMARC1; p=none; rua=mailto:a@x.com, mailto:b@y.com"
        codes = self._codes(record)
        self.assertNotIn("URI_WHITESPACE", codes)
        self.assertNotIn("URI_SPACE_AFTER_COMMA", codes)
        self.assertIn("RUA_VALID", codes)

    def test_space_before_comma_does_not_warn_or_fail(self):
        record = "v=DMARC1; p=none; rua=mailto:a@x.com ,mailto:b@y.com"
        codes = self._codes(record)
        self.assertNotIn("URI_WHITESPACE", codes)
        self.assertNotIn("URI_SPACE_AFTER_COMMA", codes)
        self.assertIn("RUA_VALID", codes)

    def test_space_both_sides_of_comma_does_not_warn_or_fail(self):
        record = "v=DMARC1; p=none; rua=mailto:a@x.com , mailto:b@y.com"
        codes = self._codes(record)
        self.assertNotIn("URI_WHITESPACE", codes)
        self.assertNotIn("URI_SPACE_AFTER_COMMA", codes)
        self.assertIn("RUA_VALID", codes)

    def test_ruf_with_whitespace_also_accepted(self):
        record = "v=DMARC1; p=none; rua=mailto:a@x.com; ruf=mailto:a@x.com , mailto:b@y.com"
        codes = self._codes(record)
        self.assertNotIn("URI_WHITESPACE", codes)
        self.assertNotIn("URI_SPACE_AFTER_COMMA", codes)
        self.assertIn("RUF_VALID", codes)

    def test_non_mailto_uri_still_fails(self):
        # Removing whitespace checks must not weaken URI_NO_MAILTO.
        record = "v=DMARC1; p=none; rua=https://example.com/reports"
        codes = self._codes(record)
        self.assertIn("URI_NO_MAILTO", codes)

    def test_invalid_email_in_mailto_still_fails(self):
        # Removing whitespace checks must not weaken URI_BAD_EMAIL.
        record = "v=DMARC1; p=none; rua=mailto:not-an-email"
        codes = self._codes(record)
        self.assertIn("URI_BAD_EMAIL", codes)


if __name__ == "__main__":
    unittest.main()
