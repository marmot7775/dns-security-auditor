"""Regression test for guessed-vs-decoded DKIM RSA key size.

Bug: dkim_formatter.analyze_dkim_key_strength guessed key size from base64
string length with a "< 200 chars => 1024-bit" threshold. A real 1024-bit
RSA SubjectPublicKeyInfo is 162 DER bytes, which base64-encodes to 216
characters -- above the 200-char cutoff -- so real 1024-bit keys landed in
the 2048-bit "strong" bucket instead of the weak bucket. 3072-bit keys were
mislabelled 4096-bit the same way.

This test generates a real RSA key with the `cryptography` library (not a
synthetic base64 string of a particular length) and asserts on the
transformed DKIM card (transform_dkim output), not on the raw analyzer
dict.
"""
import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import result_transformer


def _dkim_record_for_key_size(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    spki_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    b64 = base64.b64encode(spki_der).decode("ascii")
    return f"v=DKIM1; k=rsa; p={b64}"


def test_real_1024_bit_key_is_reported_weak():
    record = _dkim_record_for_key_size(1024)

    raw = {
        "domain": "example.com",
        "found_selectors": [
            {"selector": "s1", "record": record, "fqdn": "s1._domainkey.example.com"},
        ],
        "tested_count": 1,
    }
    card = result_transformer.transform_dkim(raw, "example.com", has_mx=True)

    assert card["status"] == "warn", (
        f"A real 1024-bit RSA key must warn the card as weak; "
        f"got status={card['status']!r}"
    )
    detail_texts = " ".join(d.get("text", "") for d in card["details"])
    assert "1024-bit" in detail_texts, (
        f"Card detail must report the real 1024-bit size, not a guessed "
        f"2048-bit; got: {detail_texts!r}"
    )
    assert "2048-bit" not in detail_texts.split("upgrade")[0]


def test_real_2048_bit_key_is_reported_strong():
    """Control: a real 2048-bit key must not be flagged weak."""
    record = _dkim_record_for_key_size(2048)
    raw = {
        "domain": "example.com",
        "found_selectors": [
            {"selector": "s1", "record": record, "fqdn": "s1._domainkey.example.com"},
        ],
        "tested_count": 1,
    }
    card = result_transformer.transform_dkim(raw, "example.com", has_mx=True)
    assert card["status"] == "pass"
    detail_texts = " ".join(d.get("text", "") for d in card["details"])
    assert "2048-bit" in detail_texts
