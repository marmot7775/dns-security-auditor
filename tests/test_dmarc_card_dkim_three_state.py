"""The DMARC card must not assert a DKIM absence the DKIM card refuses to.

The DKIM check learned in e733705 that probing cannot establish absence: it
reports "could not be confirmed by probing" rather than "no DKIM". The DMARC
alignment cross-check kept its own boolean:

    _xc_has_dkim = bool(_xc_dkim.get("found_selectors"))

which is the fourth copy of an expression already corrected in
remediation_planner, _check_domain_features and the resilience section. It is
wrong in both directions at once:

  - Revoked-only counts as "has DKIM". A selector publishing an empty p= is a
    retired key (RFC 6376 3.6.1). google.com's five retired selectors made
    this True.
  - Unconfirmed counts as "no DKIM". proton.me publishes three live 2048-bit
    keys behind a CNAME that the probe never reaches, and the DMARC card said
    "no DKIM keys were detected. DMARC can only pass via SPF alignment."

Absence is only assertable when the operator supplied a selector and it did
not resolve, which is the one path where this audit actually settled the
question.
"""
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import FakeZone

DOMAIN = "xc.test"
REVOKED = "v=DKIM1; k=rsa; p="


def _live_key():
    der = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


LIVE = _live_key()


def _zone(selectors):
    rec = {
        DOMAIN: {"MX": [(10, f"m.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.1"], "NS": [f"ns1.{DOMAIN}"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; adkim=s; rua=mailto:r@{DOMAIN}"]},
        f"m.{DOMAIN}": {"A": ["203.0.113.2"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
    }
    for name, value in (selectors or {}).items():
        rec[f"{name}._domainkey.{DOMAIN}"] = {"TXT": [value]}
    return FakeZone(rec)


def _dmarc_text(audit, selectors, **kw):
    result = audit(_zone(selectors), DOMAIN, scope="email_full", **kw)
    card = next(c for c in result["checks"] if c["name"] == "DMARC")
    return card, " ".join(d["text"] for d in card["details"])


def test_unconfirmed_dkim_is_not_reported_as_absent(audit):
    card, text = _dmarc_text(audit, {})

    assert "no dkim keys were detected" not in text.lower()
    assert "could not confirm" in text.lower(), (
        f"the card must say what it could not establish: {text!r}"
    )
    assert card["status"] != "fail"


def test_revoked_only_is_not_has_dkim_and_not_confirmed_absent(audit):
    """Both errors at once: the old boolean said True here."""
    card, text = _dmarc_text(audit, {"google": REVOKED})

    # Not treated as a working key...
    assert "relies solely on dkim" not in text.lower()
    # ...and not asserted absent either.
    assert "no dkim keys were detected" not in text.lower()
    assert "could not confirm" in text.lower()


def test_a_live_key_raises_no_alignment_complaint(audit):
    card, text = _dmarc_text(audit, {"google": LIVE})

    assert "could not confirm" not in text.lower()
    assert "strict dkim alignment" not in text.lower()
    assert card["status"] == "pass"


def test_a_supplied_selector_that_does_not_resolve_is_a_real_absence(audit):
    """The one path where this audit settles the question, so it may say so."""
    card, text = _dmarc_text(audit, {}, dkim_selector="nosuch")

    assert "could not confirm" not in text.lower(), (
        "the operator named the selector; probing was not involved"
    )
    assert "publishes no key" in text.lower(), (
        f"strict alignment against a named selector with no key is a real "
        f"finding and must still be made: {text!r}"
    )
