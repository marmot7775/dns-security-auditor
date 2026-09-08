"""Regression test for doc 18 item 4: 2048-bit RSA is a SHOULD, not a MUST.

RFC 8301 section 3.2: "Signers MUST use RSA keys of at least 1024 bits ...
Signers SHOULD use RSA keys of at least 2048 bits." The fix text and
business-risk copy called 2048 bits "the minimum" and said a weak key (which
covers the whole 1024-2047 range, not just exactly 1024 bits) "can be
factored", both of which overstate a 1536-bit key's actual exposure.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer


def _rsa_key_record(bits):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    der = (rsa.generate_private_key(public_exponent=65537, key_size=bits)
           .public_key()
           .public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


def test_weak_key_fix_says_recommended_not_minimum():
    card = result_transformer.transform_dkim(
        {"found_selectors": [{"selector": "s1", "record": _rsa_key_record(1536)}],
         "tested_count": 1}, "example.com")
    assert "recommended 2048 bits" in card["fix"]
    assert "2048-bit minimum" not in card["fix"]


def test_weak_key_business_risk_does_not_overstate_a_1536_bit_key():
    card = result_transformer.transform_dkim(
        {"found_selectors": [{"selector": "s1", "record": _rsa_key_record(1536)}],
         "tested_count": 1}, "example.com")
    risk = card["details"][0].get("business_risk", "")
    assert "1024-bit" not in risk
    assert "factored" not in risk.lower()
    assert "cracked" not in risk.lower()


def test_roadmap_dkim_weak_key_impact_does_not_overstate():
    roadmap = result_transformer.build_security_roadmap([
        result_transformer.transform_dkim(
            {"found_selectors": [{"selector": "s1", "record": _rsa_key_record(1536)}],
             "tested_count": 1}, "example.com"),
    ])
    dkim_items = [i for i in roadmap["items"] if i["protocol"] == "DKIM"
                  and "Rotate weak" in i["action"]]
    assert len(dkim_items) == 1
    assert "factored" not in dkim_items[0]["impact"].lower()
