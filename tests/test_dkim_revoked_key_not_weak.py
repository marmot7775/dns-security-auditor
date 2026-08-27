"""Regression test for revoked DKIM keys being reported as weak keys.

Follow-up to bug 17. Normalizing the discovery path so every selector carries
key_bits meant revoked selectors started arriving with key_bits == 0, and
_has_weak_dkim_keys compared that against `bits <= 1024` and matched. A live
audit of google.com, whose four discovered selectors all publish an empty p=,
came back with the DKIM card reporting four revoked keys and the plan telling
the user "One or more of your DKIM selectors use 1024-bit RSA keys, rotate to
2048-bit keys", which is not what is wrong with them.

0 bits means revoked or undecodable, not short, so only a positive key size
below the threshold counts as weak now. Both paths emit key_bits after the
bug 17 normalization, so both needed this. The older key_size shape was
immune by accident: `sel.get("key_size") or sel.get("key_bits")` collapses a
0 to None and fell through to the key_analysis branch.

There is no remediation step for a revoked key today. The card carries that
finding, so the fix here is not to describe it as something else.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from dkim_formatter import analyze_dkim_key_strength
from remediation_planner import build_remediation_plan
from result_transformer import transform_dkim

DOMAIN = "example.com"
WEAK_STEP = "Replace Weak DKIM Keys"
REVOKED = "v=DKIM1; k=rsa; p="


def _rsa_record(bits):
    spki = rsa.generate_private_key(
        public_exponent=65537, key_size=bits
    ).public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode("ascii")


RSA_1024 = _rsa_record(1024)


def _selector(name, record):
    analysis = analyze_dkim_key_strength(record)
    return {
        "selector": name,
        "record": record,
        "key_type": analysis["key_type"],
        "key_bits": analysis["key_bits"],
        "vendor": None,
    }


def _raw(*selectors):
    return {"domain": DOMAIN, "found_selectors": list(selectors), "tested_count": 200}


def _titles(raw):
    plan = build_remediation_plan(checks=[], raw_results={"dkim": raw}, has_mx=True)
    return {s["title"] for tier in plan.values() for s in tier}


def _card_text(card):
    return " ".join(d.get("text", "") for d in card.get("details", []))


def test_revoked_keys_do_not_produce_the_weak_key_step():
    """The google.com shape: every discovered selector publishes an empty p=."""
    raw = _raw(*(_selector(s, REVOKED) for s in ("20230601", "20221208", "20210112")))
    card = transform_dkim(raw, DOMAIN, has_mx=True)

    text = _card_text(card)
    assert "revoked" in text.lower()
    assert "1024-bit" not in text
    assert card["status"] == "fail"

    assert WEAK_STEP not in _titles(raw)


def test_a_real_weak_key_alongside_a_revoked_one_is_still_flagged():
    raw = _raw(_selector("dead", REVOKED), _selector("old", RSA_1024))
    assert WEAK_STEP in _titles(raw)


def test_older_key_size_shape_with_a_revoked_key():
    """Selector dicts still carrying the pre-17 key_size field must read the
    same way, rather than relying on `0 or None` collapsing to None."""
    assert WEAK_STEP not in _titles(
        {"found_selectors": [{"selector": "dead", "record": REVOKED, "key_size": 0}]}
    )
