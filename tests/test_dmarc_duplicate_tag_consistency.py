"""Regression test for duplicate DMARC tags resolving differently in
the two parsers that run over the same record.

Bug: _raw_check_dmarc resolved duplicate tags last-wins
(tags[key] = value on every occurrence), while _validate_dmarc_strict
and _validate_dmarc_legacy build a tag_dict that keeps only the
first-seen value. Both outputs land in the same report: the DMARC card
verdict came from the last occurrence, while the strict/legacy
validation panels described the first occurrence, so a single report
could say "Policy p=reject" right next to strict output declaring
"p=none is a valid policy value".

Fix: _raw_check_dmarc now also resolves first-wins, matching both
validators. The duplicate tag remains its own finding (a "Duplicate
tag" syntax error from _raw_check_dmarc, and a DUPLICATE_TAG check from
_validate_dmarc_strict) independent of which value is chosen.

Test asserts on the transformed DMARC card (transform_dmarc output)
together with the raw strict_validation panel it carries, since that's
where the contradiction was user-visible.
"""
import os
import sys
from unittest.mock import patch

import dns.exception

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_engine import _raw_check_dmarc
import result_transformer

DOMAIN = "duptag.example.com"
RECORD = "v=DMARC1; p=none; p=reject; rua=mailto:d@x.example"


def _build():
    with patch("audit_engine._lookup_txt", return_value=[RECORD]), \
         patch("audit_engine._lookup_ttl", return_value=300), \
         patch("audit_engine._get_resolver", side_effect=dns.exception.DNSException):
        raw = _raw_check_dmarc(DOMAIN)
    card = result_transformer.transform_dmarc(raw)
    return raw, card


def test_duplicate_p_tag_agrees_between_card_and_strict_validation():
    raw, card = _build()

    assert raw["policy"] == "none", (
        f"First occurrence of a duplicate tag must win; got policy={raw['policy']!r}"
    )
    assert "p=reject" not in card["verdict"], (
        f"Card verdict must not describe the discarded second occurrence; "
        f"got: {card['verdict']!r}"
    )

    strict_messages = " ".join(
        c["message"] for c in raw["strict_validation"]["checks"]
    )
    assert "p=reject is a valid policy value" not in strict_messages
    assert "p=none is a valid policy value" in strict_messages, (
        f"Strict validation should describe the same first-occurrence value "
        f"the card uses; got: {strict_messages!r}"
    )


def test_duplicate_tag_is_still_its_own_finding():
    raw, card = _build()

    syntax_texts = " ".join(e["issue"] for e in raw["syntax_errors"])
    assert "duplicate" in syntax_texts.lower() and "'p'" in syntax_texts.lower(), (
        f"A duplicated tag must still be flagged as its own finding; "
        f"got syntax_errors: {raw['syntax_errors']!r}"
    )

    strict_codes = [c["code"] for c in raw["strict_validation"]["checks"]]
    assert "DUPLICATE_TAG" in strict_codes
