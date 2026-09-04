"""A selector holding a verification token beside the key must still be found.

One root cause, two opposite failures, one on each DKIM lookup path.

Manual selector (audit_engine._run_dkim_direct) joined every record at the
name into a single string:

    txt = "".join(s.decode() if isinstance(s, bytes) else s
                  for rdata in answers for s in rdata.strings)

The inner loop is right, that is how a TXT value over 255 bytes is
reassembled. The outer loop is not: it welds a domain verification token, or a
second key mid rotation, onto the front of the key, p= then fails to decode,
and the card reads "Could not decode RSA public key".

Auto-discovery (spf_intelligence._test_selector) read `answers[0]` and nothing
else. If the token happened to come first the p= check failed, the selector
was dropped without a word, and the domain was reported as having no DKIM at
all.

The same expression carried a second defect: `s.decode()` takes no errors
argument, so one non-UTF-8 byte raised UnicodeDecodeError, which
`except dns.exception.DNSException` does not catch, and the whole DKIM check
died rather than degrading.
"""
import base64
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

import spf_intelligence


def _rsa_record(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode("ascii")


DOMAIN = "example.com"
SELECTOR = "google"
FQDN = f"{SELECTOR}._domainkey.{DOMAIN}"
KEY_RECORD = _rsa_record()
TOKEN = "google-site-verification=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd"


def _zone(records_at_selector):
    """A minimal sending domain with the given TXT records at the selector."""
    return FakeZone({
        DOMAIN: {
            "TXT": ["v=spf1 include:_spf.google.com -all"],
            "MX": [(10, "aspmx.l.google.com")],
        },
        "aspmx.l.google.com": {"A": ["203.0.113.10"]},
        "_spf.google.com": {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"]},
        FQDN: {"TXT": records_at_selector},
    })


# Both orderings, because which record a resolver returns first is not
# something the domain owner controls.
ORDERINGS = {
    "token first": [TOKEN, KEY_RECORD],
    "key first": [KEY_RECORD, TOKEN],
}


# ---------------------------------------------------------------
# Manual selector path
# ---------------------------------------------------------------

@pytest.mark.parametrize("label", sorted(ORDERINGS))
def test_manual_selector_finds_the_key_beside_a_token(audit, label):
    result = audit(_zone(ORDERINGS[label]), DOMAIN, scope="dmarc",
                   dkim_selector=SELECTOR)

    dkim = next(c for c in result["checks"] if c["name"] == "DKIM")
    detail_texts = " ".join(d.get("text", "") for d in dkim["details"]).lower()

    assert dkim["status"] == "pass", (
        f"{label}: a valid 2048-bit key sharing its name with a verification "
        f"token produced a {dkim['status']!r} card: {detail_texts!r}"
    )
    assert "could not decode" not in detail_texts, (
        f"{label}: the token was concatenated into the key: {detail_texts!r}"
    )
    assert "2048-bit" in detail_texts


def test_manual_selector_warns_when_two_keys_share_a_selector(audit):
    """Two keys mid rotation is a real configuration and worth saying out loud."""
    second_key = _rsa_record()
    result = audit(_zone([KEY_RECORD, second_key]), DOMAIN, scope="dmarc",
                   dkim_selector=SELECTOR)

    dkim = next(c for c in result["checks"] if c["name"] == "DKIM")
    detail_texts = " ".join(d.get("text", "") for d in dkim["details"]).lower()

    assert "could not decode" not in detail_texts, (
        f"two keys at one selector were concatenated: {detail_texts!r}"
    )
    assert "2 dkim keys" in detail_texts or "2 txt records" in detail_texts, (
        f"no warning that the selector publishes more than one key: {detail_texts!r}"
    )


def test_manual_selector_survives_a_non_utf8_byte(audit, monkeypatch):
    """A bare s.decode() raised UnicodeDecodeError past the DNSException handler."""
    zone = _zone([KEY_RECORD])

    class _RawRdata:
        # A TXT value is bytes on the wire. Nothing guarantees it is UTF-8,
        # and 0xff is not a valid UTF-8 start byte.
        strings = [b"\xffgarbage-from-a-misconfigured-record"]

        def __str__(self):
            return '"\\255garbage"'

    real_resolve = zone.resolve

    def _resolve(name, rdtype="A", *args, **kwargs):
        answer = real_resolve(name, rdtype, *args, **kwargs)
        if str(name).rstrip(".").lower() == FQDN and str(rdtype).upper() == "TXT":
            answer.insert(0, _RawRdata())
        return answer

    zone.resolve = _resolve

    result = audit(zone, DOMAIN, scope="dmarc", dkim_selector=SELECTOR)

    dkim = next(c for c in result["checks"] if c["name"] == "DKIM")
    detail_texts = " ".join(d.get("text", "") for d in dkim["details"]).lower()
    assert dkim["status"] == "pass", (
        f"one undecodable byte at the selector took the whole DKIM check "
        f"down: {dkim['status']!r} / {detail_texts!r}"
    )
    assert "2048-bit" in detail_texts


# ---------------------------------------------------------------
# Auto-discovery path
# ---------------------------------------------------------------

@pytest.mark.parametrize("label", sorted(ORDERINGS))
def test_discovery_finds_the_key_beside_a_token(monkeypatch, label):
    zone = _zone(ORDERINGS[label])
    monkeypatch.setattr("dns.resolver.Resolver.resolve",
                        lambda self, name, rdtype="A", *a, **k: zone.resolve(name, rdtype))
    monkeypatch.setattr("dns.resolver.resolve", zone.resolve)

    result = spf_intelligence.smart_dkim_check(
        DOMAIN, spf_record="v=spf1 include:_spf.google.com -all"
    )

    found = {f["selector"]: f for f in result["found_selectors"]}
    assert SELECTOR in found, (
        f"{label}: the selector was dropped because a verification token "
        f"shared its name; found {sorted(found)!r}"
    )
    assert found[SELECTOR]["key_bits"] == 2048, (
        f"{label}: discovered the wrong record at the selector: "
        f"{found[SELECTOR]['record']!r}"
    )
    assert TOKEN not in found[SELECTOR]["record"]


@pytest.mark.parametrize("label", sorted(ORDERINGS))
def test_discovered_card_reports_the_key(audit, label):
    """End to end on the discovery path: the card the user reads."""
    result = audit(_zone(ORDERINGS[label]), DOMAIN, scope="dmarc")

    dkim = next(c for c in result["checks"] if c["name"] == "DKIM")
    assert dkim["status"] == "pass", (
        f"{label}: domain reported as {dkim['status']!r} despite publishing "
        f"a valid key at {FQDN}"
    )
    assert SELECTOR in str(dkim)


def test_discovery_ignores_a_selector_with_only_a_token(monkeypatch):
    """Control: a name with no key at all is still not a DKIM selector."""
    zone = _zone([TOKEN])
    monkeypatch.setattr("dns.resolver.Resolver.resolve",
                        lambda self, name, rdtype="A", *a, **k: zone.resolve(name, rdtype))
    monkeypatch.setattr("dns.resolver.resolve", zone.resolve)

    result = spf_intelligence.smart_dkim_check(
        DOMAIN, spf_record="v=spf1 include:_spf.google.com -all"
    )
    assert [f["selector"] for f in result["found_selectors"]] == []
