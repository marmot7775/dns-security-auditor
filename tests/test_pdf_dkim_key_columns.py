"""Regression test for the PDF's DKIM Bits and Rotation columns being blank.

Bug 41: _dkim_deep_section read k["key_bits"] and k["rotation_status"], but
_build_dkim_key_analysis emits "bits" and published no per-key rotation
field at all (rotation guidance was a single string at the top level, which
the per-key loop below the table also failed to find). static/app.js:2626
reads k.bits correctly, so only the PDF was affected and both columns had
always rendered empty.

The two sides are checked against each other here rather than against a
hardcoded shape, so a future rename on either side fails this test.
"""
import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from result_transformer import _build_dkim_key_analysis
from pdf_report import _dkim_deep_section, _styles


def _dkim_record(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    spki_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(spki_der).decode("ascii")


_RSA_2048 = _dkim_record(2048)
_RSA_1024 = _dkim_record(1024)
_REVOKED = "v=DKIM1; k=rsa; p="


def _deep(selectors):
    return _build_dkim_key_analysis({
        "found_selectors": [
            {"selector": name, "record": record, "vendor": None}
            for name, record in selectors
        ]
    })


def test_builder_emits_the_fields_the_pdf_reads():
    deep = _deep([("google", _RSA_2048)])
    key = deep["keys"][0]
    assert "bits" in key
    assert key["bits"] > 0
    assert key.get("rotation_status"), "the PDF's Rotation column needs a per-key value"


def test_pdf_table_rows_carry_bits_and_rotation():
    deep = _deep([("google", _RSA_2048), ("weak", _RSA_1024), ("dead", _REVOKED)])
    key_by_selector = {k["selector"]: k for k in deep["keys"]}

    els = _dkim_deep_section(deep, _styles())
    rendered = " ".join(
        getattr(e, "text", "") for e in _flatten(els)
    )

    for selector, key in key_by_selector.items():
        if key["bits"]:
            assert str(key["bits"]) in rendered, f"Bits missing for {selector}"
        assert key["rotation_status"] in rendered, f"Rotation missing for {selector}"

    # The shared guidance string is rendered once, not looked up per key.
    assert deep["rotation_guidance"][:30] in rendered


def test_revoked_key_reads_as_revoked_and_weak_key_as_rotate():
    deep = _deep([("dead", _REVOKED), ("weak", _RSA_1024), ("good", _RSA_2048)])
    status = {k["selector"]: k["rotation_status"] for k in deep["keys"]}
    assert status["dead"] == "Revoked"
    assert status["weak"] == "Rotate"
    assert status["good"] == "Current"


def _flatten(els):
    """Yield every flowable, descending into Table cells."""
    for e in els:
        yield e
        rows = getattr(e, "_cellvalues", None)
        if rows:
            for row in rows:
                yield from _flatten(row)
