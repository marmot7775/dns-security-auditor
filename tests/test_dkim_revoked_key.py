"""Regression test for a revoked DKIM key (empty p=) being misread.

Doc 15 revised what "correctly handled" means here. A revoked key is a
retired key, published the way RFC 6376 says to retire one, so the card must
not grade it as a failure of the domain. What it still must not do is what
this test was written for: read an empty p= as a working key. Between those
two, a revoked-only card is neither pass nor fail. It reports retired keys
and says no live key was found by probing, which is all the probe established.

The original bug: per RFC 6376 §3.6.1, an empty p= tag means the key is
revoked. Three things conspired to hide this:
  - dkim_formatter's Ed25519 shortcut returned "strong" before ever
    checking whether p= was empty.
  - For RSA, analyze_dkim_key_strength's "No public key found" check used
    a regex requiring 1+ base64 chars, so an empty p= slipped past it
    without being flagged.
  - transform_dkim only branched on "weak" and "strong" status, so the
    "invalid" status analyze_dkim_key_strength returns for a revoked key
    fell into the neutral info-only else branch, leaving the card at
    status "pass".

Test asserts on the transformed DKIM card (transform_dkim output), not on
analyze_dkim_key_strength's raw dict.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import result_transformer


def _card_for_record(record):
    raw = {
        "domain": "example.com",
        "found_selectors": [
            {"selector": "sel", "record": record, "fqdn": "sel._domainkey.example.com"},
        ],
        "tested_count": 1,
    }
    return result_transformer.transform_dkim(raw, "example.com", has_mx=True)


def test_revoked_rsa_key_does_not_pass_the_card():
    card = _card_for_record("v=DKIM1; k=rsa; p=")
    assert card["status"] != "pass", (
        f"An empty p= (revoked key, RFC 6376 3.6.1) publishes no usable key, "
        f"so the card cannot pass; got status={card['status']!r}"
    )
    assert card["status"] == "unavailable", (
        f"Doc 15: a retired key is not a failure of the domain, and no live "
        f"key was found, so the card is neither pass nor finding; got "
        f"status={card['status']!r}"
    )
    detail_texts = " ".join(d.get("text", "") for d in card["details"])
    assert "revoked" in detail_texts.lower() or "retired" in detail_texts.lower()


def test_revoked_ed25519_key_does_not_pass_the_card():
    card = _card_for_record("v=DKIM1; k=ed25519; p=")
    assert card["status"] != "pass", (
        f"An empty p= on an Ed25519 record is still revoked per RFC 6376; "
        f"the Ed25519 shortcut must not bypass the p= check. "
        f"got status={card['status']!r}"
    )
    assert card["status"] == "unavailable"


# A real Ed25519 public key, generated with cryptography and pinned here.
# RFC 8463 section 3 publishes the 32 raw bytes; some generators publish the
# 44-byte SubjectPublicKeyInfo wrapper instead, so both shapes are tested.
ED25519_RAW_B64 = "dyMJ7DdtTSPtJ+HfL1+E1ksPw+24+sn1Fu4RA8SiE94="
ED25519_SPKI_B64 = "MCowBQYDK2VwAyEAdyMJ7DdtTSPtJ+HfL1+E1ksPw+24+sn1Fu4RA8SiE94="


def test_valid_ed25519_key_still_passes():
    """Control: a real (non-empty) Ed25519 key must still pass."""
    card = _card_for_record(f"v=DKIM1; k=ed25519; p={ED25519_RAW_B64}")
    assert card["status"] == "pass"


def test_valid_ed25519_spki_key_still_passes():
    """The SPKI-wrapped form of the same key is equally valid."""
    card = _card_for_record(f"v=DKIM1; k=ed25519; p={ED25519_SPKI_B64}")
    assert card["status"] == "pass"


def test_malformed_ed25519_key_does_not_report_a_bit_length():
    """A k=ed25519 record whose p= is not a key must FAIL, not report 256 bits.

    The previous fixture for the control test above was
    "p=MC4CAQAwBQYDK2VwBCIEIBEZ", which is 18 bytes: the truncated head of a
    PKCS#8 *private* key, not a public key of any length. It passed only
    because the Ed25519 branch returned 256 bits on the presence of the k= tag
    without ever decoding p=, which is the same defect the RSA path was fixed
    for. Four bytes of junk rendered a green card claiming a 256-bit key while
    every signature it made failed verification.
    """
    for label, p_value in (
        ("junk", "anVuaw=="),
        ("truncated pkcs8 private key", "MC4CAQAwBQYDK2VwBCIEIBEZ"),
        ("one byte short", ED25519_RAW_B64[:-8]),
    ):
        card = _card_for_record(f"v=DKIM1; k=ed25519; p={p_value}")
        assert card["status"] == "fail", (
            f"{label}: a k=ed25519 record carrying {p_value!r} is not a valid "
            f"key and must fail; got status={card['status']!r}"
        )
        texts = " ".join(d.get("text", "") for d in card["details"])
        assert "256-bit" not in texts, (
            f"{label}: the card reported a bit length for a key that does not "
            f"parse: {texts!r}"
        )


def test_ed25519_tag_with_rsa_key_data_is_named_as_a_mismatch():
    """k=ed25519 carrying an RSA SPKI is a type mismatch, not an odd size."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import base64

    der = (rsa.generate_private_key(public_exponent=65537, key_size=2048)
           .public_key()
           .public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))
    card = _card_for_record(
        "v=DKIM1; k=ed25519; p=" + base64.b64encode(der).decode()
    )
    assert card["status"] == "fail"
    texts = " ".join(d.get("text", "") for d in card["details"]).lower()
    assert "rsa" in texts and "ed25519" in texts, (
        f"the mismatch should name both key types; got {texts!r}"
    )
