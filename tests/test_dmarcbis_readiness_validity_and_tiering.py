"""Regression test for DMARCbis readiness claiming invalid records are
valid, and for its tiering being inverted.

Bug: _assess_dmarcbis_readiness hardcoded "Your DMARC record is valid
and works under both RFC 7489 and DMARCbis" with no check on the
record's actual validity, and _build_dmarcbis_card_data unconditionally
emitted a "Valid DMARC record found: pass" checklist item. Separately,
the readiness-tier if/elif chain let has_deprecated and has_np both
being true fall into the "compatible" bucket instead of "needs_update":
a record still carrying a spec-required removal (pct/rf/ri) got a
clean bill of health just because it also set np.

Test asserts on the transformed DMARC card (transform_dmarc output:
dmarcbis_readiness), not on the raw check dict.
"""
import os
import sys
from unittest.mock import patch

import dns.exception

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_engine import _raw_check_dmarc
import result_transformer

DOMAIN = "dmarcbis.example.com"


def _build_card(record):
    with patch("audit_engine._lookup_txt", return_value=[record]), \
         patch("audit_engine._lookup_ttl", return_value=300), \
         patch("audit_engine._get_resolver", side_effect=dns.exception.DNSException):
        raw = _raw_check_dmarc(DOMAIN)
    return result_transformer.transform_dmarc(raw)


def test_invalid_record_is_not_claimed_valid_under_either_spec():
    card = _build_card("v=DMARC1; p=bogus; rua=mailto:a@b.com")

    assert card["status"] == "fail", (
        f"p=bogus must fail the DMARC card; got status={card['status']!r}"
    )

    readiness = card["dmarcbis_readiness"]
    assert readiness is not None

    checklist_texts = " ".join(
        f"{c.get('label', '')} {c.get('detail') or ''}" for c in readiness["checklist"]
    )
    assert readiness["status"] != "compliant", (
        f"An invalid record must not be marked DMARCbis-compliant; "
        f"got readiness={readiness!r}"
    )
    valid_item = next(c for c in readiness["checklist"] if c["label"] == "Valid DMARC record found")
    assert valid_item["status"] != "pass", (
        f"The DMARC record is syntactically invalid (p=bogus); the readiness "
        f"checklist must not claim it is valid. Got: {valid_item!r}"
    )


def test_deprecated_tag_with_np_stays_needs_update_not_compatible():
    without_np = _build_card("v=DMARC1; p=reject; pct=50; rua=mailto:d@x.example")
    with_np = _build_card("v=DMARC1; p=reject; pct=50; np=reject; rua=mailto:d@x.example")

    readiness_without = without_np["dmarcbis_readiness"]
    readiness_with = with_np["dmarcbis_readiness"]

    assert readiness_without["status"] == "non_compliant", (
        f"pct=50 is a spec-required removal; must be needs_update/non_compliant. "
        f"Got {readiness_without!r}"
    )
    assert readiness_with["status"] == "non_compliant", (
        f"Adding np=reject does not remove the still-outstanding pct tag; "
        f"this must stay needs_update/non_compliant, not move to compatible. "
        f"Got {readiness_with!r}"
    )
