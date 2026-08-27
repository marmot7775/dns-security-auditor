"""Regression test for a revoked DKIM key (empty p=) passing as valid.

Bug: per RFC 6376 §3.6.1, an empty p= tag means the key is revoked. Three
things conspired to hide this:
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


def test_revoked_rsa_key_fails_the_card():
    card = _card_for_record("v=DKIM1; k=rsa; p=")
    assert card["status"] == "fail", (
        f"An empty p= (revoked key, RFC 6376 3.6.1) must fail the DKIM "
        f"card; got status={card['status']!r}"
    )
    detail_texts = " ".join(d.get("text", "") for d in card["details"])
    assert "revoked" in detail_texts.lower() or "invalid" in detail_texts.lower()


def test_revoked_ed25519_key_fails_the_card():
    card = _card_for_record("v=DKIM1; k=ed25519; p=")
    assert card["status"] == "fail", (
        f"An empty p= on an Ed25519 record is still revoked per RFC 6376; "
        f"the Ed25519 shortcut must not bypass the p= check. "
        f"got status={card['status']!r}"
    )


def test_valid_ed25519_key_still_passes():
    """Control: a real (non-empty) Ed25519 key must still pass."""
    card = _card_for_record("v=DKIM1; k=ed25519; p=MC4CAQAwBQYDK2VwBCIEIBEZ")
    assert card["status"] == "pass"
