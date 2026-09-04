"""A truncated RSA public key must never be graded as a healthy key.

Bug: _decode_rsa_key_bits read the modulus length out of the ASN.1 header and
returned `mod_len * 8` without checking that many bytes were actually there.
A DER length is a claim about what follows, not a guarantee, so a 2048-bit key
cut short by a DNS provider still declared 2048 and the decoder believed it.
Sixty characters of a 392-character key reported "RSA key: 2048 bits (good)"
and the card rendered green, while every signature that key made failed
verification at receivers.

Second half of the same bug: when the decode did fail, _check_key fell back to
_estimate_key_bits_fallback, which buckets on base64 string length. A key
truncated to 40 characters came back as a confident "1024-bit RSA key,
deprecated, rotate to 2048-bit" about a 1024-bit key that does not exist, and
the actual problem, an unparseable key, was never mentioned.

Key material is generated with `cryptography` rather than pasted, so the
truncations are of a genuinely valid key and the test cannot drift from what
a real 2048-bit SubjectPublicKeyInfo looks like.
"""
import base64
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import result_transformer
from audit_engine import BUSINESS_RISK
from dkim_formatter import analyze_dkim_key_strength
from dkim_tag_analyzer import _decode_rsa_key_bits, validate_dkim


def _b64_2048():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(spki).decode("ascii")


# One key, reused by every case below. The truncation lengths are multiples of
# four so base64 decoding succeeds and the ASN.1 bounds check is what has to
# catch the problem, which is exactly the case the old code got wrong.
FULL_B64 = _b64_2048()
TRUNCATIONS = (60, 100, 200)


def _card_for_record(record):
    raw = {
        "domain": "example.com",
        "found_selectors": [
            {"selector": "sel", "record": record, "fqdn": "sel._domainkey.example.com"},
        ],
        "tested_count": 1,
    }
    return result_transformer.transform_dkim(raw, "example.com", has_mx=True)


def test_full_key_is_the_expected_length():
    """Guard the fixture: the truncations have to be truncations."""
    assert len(FULL_B64) == 392
    assert _decode_rsa_key_bits(FULL_B64) == 2048


@pytest.mark.parametrize("n", TRUNCATIONS)
def test_truncated_key_does_not_decode(n):
    assert _decode_rsa_key_bits(FULL_B64[:n]) is None, (
        f"{n} characters of a 392-character key still decoded to a key size; "
        f"the declared modulus length was trusted over the bytes present"
    )


@pytest.mark.parametrize("n", TRUNCATIONS + (40,))
def test_truncated_key_never_reports_a_size_or_passes(n):
    report = validate_dkim("example.com", "sel", record=f"v=DKIM1; k=rsa; p={FULL_B64[:n]}")

    assert report["status"] != "PASS", (
        f"a key truncated to {n} characters was graded {report['status']}; "
        f"every signature it makes fails verification"
    )
    assert report["key_bits"] != 2048, (
        f"a key truncated to {n} characters reported 2048 bits"
    )
    assert report["key_bits"] != 1024, (
        f"a key truncated to {n} characters reported 1024 bits, which is the "
        f"base64 length estimate guessing at a key that does not exist"
    )
    assert report["key_bits"] is None, (
        f"no size can be confirmed for an unparseable key; got {report['key_bits']!r}"
    )

    titles = " ".join(i["title"] for i in report["issues"]).lower()
    assert "rsa subjectpublickeyinfo" in titles, (
        f"the unparseable key must be named as the problem; got issues {titles!r}"
    )
    assert "rotate to 2048" not in " ".join(
        (i.get("fix") or "") for i in report["issues"]
    ), "operator told to rotate a key that was never published"


@pytest.mark.parametrize("n", TRUNCATIONS)
def test_card_fails_and_explains_a_truncation_not_a_revocation(n):
    """Item 6: 'invalid' is not always a revocation, and the callout must say so."""
    card = _card_for_record(f"v=DKIM1; k=rsa; p={FULL_B64[:n]}")

    assert card["status"] == "fail", (
        f"card for a {n}-character key fragment is {card['status']!r}"
    )
    risks = [d.get("business_risk") for d in card["details"] if d.get("business_risk")]
    assert BUSINESS_RISK["DKIM_UNDECODABLE_KEY"] in risks, (
        f"an undecodable key must be explained as one; got {risks!r}"
    )
    assert BUSINESS_RISK["DKIM_REVOKED_KEY"] not in risks, (
        "an undecodable key was explained as a revoked key, which tells the "
        "operator to look at the wrong thing"
    )


def test_revoked_key_still_gets_the_revocation_callout():
    """Control: the one condition that really is a revocation still reads as one."""
    card = _card_for_record("v=DKIM1; k=rsa; p=")
    risks = [d.get("business_risk") for d in card["details"] if d.get("business_risk")]
    assert BUSINESS_RISK["DKIM_REVOKED_KEY"] in risks
    assert BUSINESS_RISK["DKIM_UNDECODABLE_KEY"] not in risks


def test_complete_key_still_passes():
    """Control: the bounds checks must not reject a valid key."""
    record = f"v=DKIM1; k=rsa; p={FULL_B64}"

    assert analyze_dkim_key_strength(record)["key_bits"] == 2048
    assert validate_dkim("example.com", "sel", record=record)["status"] == "PASS"
    assert _card_for_record(record)["status"] == "pass"


def test_both_modules_agree_about_a_truncated_key():
    """dkim_formatter and dkim_tag_analyzer must not contradict each other."""
    record = f"v=DKIM1; k=rsa; p={FULL_B64[:100]}"

    formatter = analyze_dkim_key_strength(record)
    validator = validate_dkim("example.com", "sel", record=record)

    assert formatter["status"] == "invalid"
    assert formatter["reason"] == "undecodable"
    assert validator["status"] == "FAIL"
    assert validator["key_bits"] is None
