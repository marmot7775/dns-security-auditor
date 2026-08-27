"""Pin: RFC 9989 §C.4 removes the rua/ruf !size modifier.

Verbatim spec text the warning is grounded in:

§C.4 (Reporting):
    "the ability to specify a maximum report size in the DMARC URI
    has been removed"

§4.8 (formal definition, line 1246):
    obs-dmarc-uri = dmarc-uri obs-dmarc-report-size
                  ; Obsolete syntax, reporters should ignore the
                  ; obs-dmarc-report-size if it is found in a DMARC
                  ; Policy Record.

The strict validator emits URI_SIZE_MODIFIER_OBSOLETE (warn) per
modifier-bearing URI; _raw_check_dmarc emits an info-level issue
with source="spec_required" and spec_reference="RFC 9989 §C.4 / §4.8".

Warn (not fail), because §4.8 keeps obs-dmarc-uri in the ABNF — the
modifier is obsolete, not forbidden.
"""
import os
import sys
import unittest
from unittest.mock import patch

import dns.exception

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_engine import _raw_check_dmarc, _validate_dmarc_strict


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


def _strict_checks(record):
    return _validate_dmarc_strict(record).get("checks", [])


class TestStrictValidatorEmitsObsoleteWarn(unittest.TestCase):

    def test_rua_with_size_modifier_emits_warn(self):
        checks = _strict_checks("v=DMARC1; p=none; rua=mailto:r@example.com!10m")
        size = [c for c in checks if c["code"] == "URI_SIZE_MODIFIER_OBSOLETE"]
        self.assertEqual(len(size), 1)
        self.assertEqual(size[0]["status"], "warn")
        self.assertIn("!10m", size[0]["message"])
        self.assertIn("§C.4", size[0]["message"])
        self.assertIn("§4.8", size[0]["message"])
        # Email part is still validated as a proper email — no URI_BAD_EMAIL.
        self.assertFalse(any(c["code"] == "URI_BAD_EMAIL" for c in checks))
        # Strict still considers the URI valid overall (warn does not flip all_valid).
        self.assertTrue(any(c["code"] == "RUA_VALID" for c in checks))

    def test_ruf_with_size_modifier_emits_warn(self):
        checks = _strict_checks("v=DMARC1; p=none; ruf=mailto:r@example.com!1g")
        size = [c for c in checks if c["code"] == "URI_SIZE_MODIFIER_OBSOLETE"]
        self.assertEqual(len(size), 1)
        self.assertEqual(size[0]["status"], "warn")
        self.assertIn("!1g", size[0]["message"])
        self.assertTrue(any(c["code"] == "RUF_VALID" for c in checks))

    def test_no_modifier_no_finding(self):
        checks = _strict_checks("v=DMARC1; p=none; rua=mailto:r@example.com")
        self.assertFalse(any(c["code"] == "URI_SIZE_MODIFIER_OBSOLETE" for c in checks))

    def test_multiple_uris_warns_once_per_modifier_bearing_uri(self):
        record = (
            "v=DMARC1; p=none; "
            "rua=mailto:a@x.com!10m, mailto:b@y.com, mailto:c@z.com!500k"
        )
        checks = _strict_checks(record)
        size = [c for c in checks if c["code"] == "URI_SIZE_MODIFIER_OBSOLETE"]
        self.assertEqual(len(size), 2)
        messages = " ".join(c["message"] for c in size)
        self.assertIn("a@x.com", messages)
        self.assertIn("c@z.com", messages)
        self.assertNotIn("b@y.com", messages)


class TestRawCheckEmitsSpecRequiredInfo(unittest.TestCase):

    def _size_infos(self, result):
        return [
            i for i in result.get("issues", [])
            if i.get("severity") == "info"
            and "size modifier" in i.get("issue", "").lower()
        ]

    def test_rua_with_modifier_emits_spec_required_info(self):
        out = _run("v=DMARC1; p=none; rua=mailto:r@example.com!10m")
        infos = self._size_infos(out)
        self.assertEqual(len(infos), 1)
        info = infos[0]
        self.assertEqual(info["source"], "spec_required")
        self.assertEqual(info["spec_reference"], "RFC 9989 §C.4 / §4.8")
        self.assertIn("!10m", info["plain_english"])
        self.assertIn("rua=", info["fix"])

    def test_no_modifier_no_info(self):
        out = _run("v=DMARC1; p=none; rua=mailto:r@example.com")
        self.assertEqual(self._size_infos(out), [])

    def test_multiple_uris_emits_one_info_per_modifier_bearing_uri(self):
        record = (
            "v=DMARC1; p=none; "
            "rua=mailto:a@x.com!10m, mailto:b@y.com, mailto:c@z.com!500k"
        )
        out = _run(record)
        infos = self._size_infos(out)
        self.assertEqual(len(infos), 2)
        joined = " ".join(i["plain_english"] for i in infos)
        self.assertIn("a@x.com", joined)
        self.assertIn("c@z.com", joined)
        self.assertNotIn("b@y.com", joined)

    def test_ruf_with_modifier_emits_spec_required_info(self):
        out = _run("v=DMARC1; p=none; ruf=mailto:r@example.com!1g")
        infos = self._size_infos(out)
        self.assertEqual(len(infos), 1)
        info = infos[0]
        self.assertEqual(info["source"], "spec_required")
        self.assertEqual(info["spec_reference"], "RFC 9989 §C.4 / §4.8")
        self.assertIn("ruf=", info["fix"])

    def test_modifier_does_not_escalate_status(self):
        # The modifier finding is severity=info; it must not flip a record's
        # status compared to the same record without the modifier. (Other
        # issues like p=none warnings still fire either way.)
        without = _run("v=DMARC1; p=reject; rua=mailto:r@example.com")
        with_mod = _run("v=DMARC1; p=reject; rua=mailto:r@example.com!10m")
        self.assertEqual(without.get("status"), with_mod.get("status"))


if __name__ == "__main__":
    unittest.main()
