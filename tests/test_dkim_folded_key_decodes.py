"""Folding whitespace inside p= must not break the key.

Bug: dkim_formatter extracted the public key with

    re.search(r'p=([A-Za-z0-9+/=]*)', dkim_record)

whose character class excludes whitespace, so the match stopped at the first
space inside the base64. RFC 6376 §3.6.1 permits folding whitespace there and
long keys are routinely published folded, one quoted chunk per line, so a
perfectly valid 2048-bit key was cut to whatever preceded the fold and then
reported as "Could not decode RSA public key" on a failed DKIM card.

DKIMValidator._check_key already stripped whitespace before decoding, so the
two modules disagreed about the same record.

The fix parses p= by splitting the record on ';' the way _parse_tags does and
strips whitespace from the value. Widening the regex character class would
have papered over the wrong parsing strategy: the tag value runs to the next
semicolon, not to the next character outside a hand-written class.
"""
import base64
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import result_transformer
from dkim_formatter import analyze_dkim_key_strength
from dkim_tag_analyzer import validate_dkim


def _b64(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(spki).decode("ascii")


FULL_B64 = _b64(2048)
UNFOLDED = f"v=DKIM1; k=rsa; p={FULL_B64}"


def _folded_at(*positions):
    """The same key with a space at each given offset inside the base64."""
    out = []
    last = 0
    for pos in positions:
        out.append(FULL_B64[last:pos])
        last = pos
    out.append(FULL_B64[last:])
    return "v=DKIM1; k=rsa; p=" + " ".join(out)


# 101 is deliberately not a multiple of four: a fold there leaves a fragment
# that cannot even be base64 decoded, which is how the bug surfaced in the
# wild. 100 is, which is how it hid behind the truncation bug.
FOLDS = {
    "space at 100": _folded_at(100),
    "space at 101": _folded_at(101),
    "one fold per 255-byte chunk": _folded_at(255),
    "newline style, several folds": _folded_at(64, 128, 192, 256, 320),
}


@pytest.mark.parametrize("label", sorted(FOLDS))
def test_folded_key_decodes_to_the_same_size_as_unfolded(label):
    folded = analyze_dkim_key_strength(FOLDS[label])
    unfolded = analyze_dkim_key_strength(UNFOLDED)

    assert folded["key_bits"] == unfolded["key_bits"] == 2048, (
        f"{label}: folded key decoded to {folded['key_bits']} bits, unfolded "
        f"to {unfolded['key_bits']}; folding whitespace is legal per RFC 6376"
    )
    assert folded["status"] == unfolded["status"] == "strong"
    assert folded["warning"] is None


@pytest.mark.parametrize("label", sorted(FOLDS))
def test_folded_key_does_not_render_a_failed_card(label):
    raw = {
        "domain": "example.com",
        "found_selectors": [
            {"selector": "sel", "record": FOLDS[label],
             "fqdn": "sel._domainkey.example.com"},
        ],
        "tested_count": 1,
    }
    card = result_transformer.transform_dkim(raw, "example.com", has_mx=True)

    assert card["status"] == "pass", (
        f"{label}: a valid folded key rendered a {card['status']!r} card"
    )
    detail_texts = " ".join(d.get("text", "") for d in card["details"]).lower()
    assert "could not decode" not in detail_texts
    assert "2048-bit" in detail_texts


@pytest.mark.parametrize("label", sorted(FOLDS))
def test_both_modules_agree_about_a_folded_key(label):
    """The validator always handled folding. The formatter now matches it."""
    formatter = analyze_dkim_key_strength(FOLDS[label])
    validator = validate_dkim("example.com", "sel", record=FOLDS[label])

    assert formatter["key_bits"] == validator["key_bits"] == 2048, (
        f"{label}: dkim_formatter says {formatter['key_bits']} bits, "
        f"dkim_tag_analyzer says {validator['key_bits']}"
    )
    assert validator["status"] == "PASS"


def test_a_tag_after_a_folded_key_is_not_swallowed():
    """The p= value ends at the semicolon, not at the end of the record."""
    record = _folded_at(100) + "; t=s"
    assert analyze_dkim_key_strength(record)["key_bits"] == 2048


def test_revoked_key_with_trailing_space_is_still_revoked():
    """An all-whitespace p= carries no key, so it is still a revocation."""
    result = analyze_dkim_key_strength("v=DKIM1; k=rsa; p= ; t=s")
    assert result["status"] == "invalid"
    assert result["reason"] == "revoked"
