"""Regression test for the k=ed25519 / RSA key data mismatch never firing.

Bug 20: the algorithm mismatch check sat below the RSA branch of _check_key,
but every key_type == "ed25519" path returned before reaching it, so no
k=ed25519 record ever got there. The classic key type migration mistake,
`v=DKIM1; k=ed25519; p=<RSA SPKI>`, was reported as P1 "Unusual Ed25519 key
size (294 bytes)" and the record graded WARNING, when the record is broken
and every signature under that selector fails.

The check now lives inside the Ed25519 branch, where a k=ed25519 record can
actually reach it, and the dead copy below the RSA branch is gone.
"""
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

import dkim_tag_analyzer
from dkim_tag_analyzer import DKIMTagAnalyzer, validate_dkim

DOMAIN = "example.com"
SELECTOR = "sel"
MISMATCH = "Key type / key data mismatch"


def _rsa_spki_b64(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")


def _ed25519_spki_b64():
    return base64.b64encode(
        ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")


MISLABELLED = "v=DKIM1; k=ed25519; p=" + _rsa_spki_b64(2048)
GENUINE_ED25519 = "v=DKIM1; k=ed25519; p=" + _ed25519_spki_b64()
GENUINE_RSA = "v=DKIM1; k=rsa; p=" + _rsa_spki_b64(2048)


@pytest.fixture
def report(monkeypatch):
    """validate_dkim against a stubbed DNS answer."""

    def _run(record):
        def _fake_lookup(domain, selector, timeout=5):
            return {
                "fqdn": f"{selector}._domainkey.{domain}",
                "txt_records": [record],
                "cname_target": None,
                "error": None,
                "nxdomain": False,
            }

        monkeypatch.setattr(dkim_tag_analyzer, "_dns_lookup_dkim", _fake_lookup)
        return validate_dkim(DOMAIN, SELECTOR)

    return _run


def _titles(rep):
    return [i["title"] for i in rep["issues"]]


def test_ed25519_declared_with_rsa_key_data_is_a_critical_mismatch(report):
    rep = report(MISLABELLED)

    assert MISMATCH in _titles(rep)
    mismatch = next(i for i in rep["issues"] if i["title"] == MISMATCH)
    assert mismatch["tag"] == "k"
    assert "2048-bit RSA" in mismatch["detail"]
    assert mismatch["severity"] == "critical"

    # A P0 grades the record FAIL, not the WARNING the P1 size note produced.
    assert rep["status"] == "FAIL"
    assert rep["summary"]["critical"] >= 1
    assert rep["key_bits"] == 2048

    # The misleading size note is not raised alongside it.
    assert not any(t.startswith("Unusual Ed25519 key size") for t in _titles(rep))


def test_genuine_ed25519_key_is_still_clean(report):
    rep = report(GENUINE_ED25519)

    assert MISMATCH not in _titles(rep)
    assert rep["key_bits"] == 256
    assert rep["summary"]["critical"] == 0
    assert rep["status"] != "FAIL"
    assert "Ed25519 key - 256-bit (strong)" in _titles(rep)


def test_genuine_rsa_key_is_still_clean(report):
    rep = report(GENUINE_RSA)

    assert MISMATCH not in _titles(rep)
    assert rep["key_bits"] == 2048
    assert rep["summary"]["critical"] == 0


def test_mismatch_reaches_the_offline_analyzer_wrapper():
    """DKIMTagAnalyzer is the no-DNS entry point and shares _check_key."""
    result = DKIMTagAnalyzer(MISLABELLED).analyze()

    assert result["status"] == "FAIL"
    messages = [i["message"] for i in result["issues"]]
    assert MISMATCH in messages
    mismatch = next(i for i in result["issues"] if i["message"] == MISMATCH)
    assert mismatch["severity"] == "critical"


def test_ed25519_with_data_that_is_neither_still_reports_an_odd_size(report):
    """Key data that is not Ed25519-sized and does not decode as RSA keeps the
    original P1 note rather than being mislabelled a mismatch."""
    rep = report("v=DKIM1; k=ed25519; p=" + base64.b64encode(b"\x01" * 64).decode())

    assert MISMATCH not in _titles(rep)
    assert any(t.startswith("Unusual Ed25519 key size") for t in _titles(rep))
