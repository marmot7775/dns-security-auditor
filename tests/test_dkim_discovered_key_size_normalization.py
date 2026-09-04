"""Regression test for weak DKIM keys never reaching the remediation plan.

Bug 17: _has_weak_dkim_keys (remediation_planner.py) looks for key_size,
key_bits or key_analysis.key_bits on each found selector. The default
discovery path is smart_dkim_check (spf_intelligence.py), whose selector
dicts carried only a key_type string like "RSA 1024-bit", so none of those
keys existed and a weak key never produced the short term "Replace Weak DKIM
Keys" step on the path most audits take. Only the manual selector path set
key_size. One report could say roadmap HIGH "rotate weak DKIM keys", card
warn "1024-bit, upgrade recommended", and plan long term "Schedule Regular
DKIM Key Rotation", a step gated on there being no weak key.

Bug 17b, the same normalization: that key_type string was guessed from the
base64 length, `len > 300 => 'RSA 2048-bit'`, so 3072-bit and 4096-bit keys
both read as 2048. dkim_formatter.analyze_dkim_key_strength already decodes
the DER SubjectPublicKeyInfo through dkim_tag_analyzer._decode_rsa_key_bits;
the discovery path now calls it instead of keeping a second, wrong copy of
the size logic.

The assertions are on the transformed card the user sees and on the plan
built from the same audit, not on raw check output, and the two are checked
against each other so they cannot drift apart again.
"""
import base64
import os
import sys

import dns.exception
import dns.resolver
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import spf_intelligence
from remediation_planner import build_remediation_plan
from result_transformer import transform_dkim
from spf_intelligence import smart_dkim_check

DOMAIN = "example.com"
SELECTOR = "google"
SPF = "v=spf1 include:_spf.google.com ~all"
WEAK_STEP = "Replace Weak DKIM Keys"
ROTATION_STEP = "Schedule Regular DKIM Key Rotation"


def _rsa_record(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode("ascii")


def _ed25519_record():
    spki = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=ed25519; p=" + base64.b64encode(spki).decode("ascii")


# Generating RSA keys is the slow part, so each size is built once.
RECORDS = {bits: _rsa_record(bits) for bits in (1024, 2048, 3072, 4096)}


class _FakeAnswer:
    """Mimics a dnspython TXT rdata, split into 255-char strings.

    Real rdata carries the split as a `strings` list of bytes and renders it
    as quoted chunks from `__str__`. Both are modelled here: reading the
    record by munging `str()` and reading it from `strings` are different
    code paths, and a fake that offers only the first cannot tell whether the
    caller reassembled the record correctly.
    """

    def __init__(self, txt):
        chunks = [txt[i:i + 255] for i in range(0, len(txt), 255)]
        self.strings = [c.encode("utf-8") for c in chunks] or [b""]
        self._rendered = " ".join('"%s"' % c for c in chunks)

    def __str__(self):
        return self._rendered


@pytest.fixture
def discover(monkeypatch):
    """Run smart_dkim_check against a single selector serving `record`."""

    def _run(record):
        fqdn = f"{SELECTOR}._domainkey.{DOMAIN}"

        class _FakeResolver:
            lifetime = 3

            def resolve(self, name, rdtype):
                if name == fqdn:
                    return [_FakeAnswer(record)]
                raise dns.exception.DNSException("no such name")

        def _no_answer(*args, **kwargs):
            # The wildcard canary lookup must miss, or discovery bails out.
            raise dns.exception.DNSException("no such name")

        monkeypatch.setattr(dns.resolver, "Resolver", _FakeResolver)
        monkeypatch.setattr(dns.resolver, "resolve", _no_answer)
        return smart_dkim_check(DOMAIN, SPF)

    return _run


def _plan_for(raw):
    return build_remediation_plan(checks=[], raw_results={"dkim": raw}, has_mx=True)


def _titles(plan):
    return {s["title"] for tier in plan.values() for s in tier}


def _card_text(card):
    return " ".join(d.get("text", "") for d in card.get("details", []))


def test_discovery_reports_the_real_modulus_size(discover):
    """17b: the base64 length thresholds could not tell 2048, 3072 and 4096 apart."""
    for bits, record in RECORDS.items():
        raw = discover(record)
        found = raw["found_selectors"]
        assert len(found) == 1, f"{bits}-bit selector was not discovered"
        assert found[0]["key_bits"] == bits
        assert found[0]["key_type"] == "RSA"


def test_discovered_weak_key_reaches_the_remediation_plan(discover):
    """17: a discovered 1024-bit key has to produce the weak key step."""
    raw = discover(RECORDS[1024])
    plan = _plan_for(raw)
    titles = _titles(plan)

    assert WEAK_STEP in titles
    assert {s["title"] for s in plan["short_term"]} >= {WEAK_STEP}
    # The rotation step is gated on there being no weak key, so the two must
    # never appear together.
    assert ROTATION_STEP not in titles


def test_card_and_plan_agree_at_every_key_size(discover):
    for bits, record in RECORDS.items():
        raw = discover(record)
        card = transform_dkim(raw, DOMAIN, has_mx=True)
        titles = _titles(_plan_for(raw))

        text = _card_text(card)
        assert f"{bits}-bit RSA key" in text, f"card does not name {bits} bits"

        card_says_weak = "upgrade recommended" in text
        plan_says_weak = WEAK_STEP in titles
        assert card_says_weak == plan_says_weak, (
            f"{bits}-bit: card weak={card_says_weak} but plan weak={plan_says_weak}"
        )
        assert card_says_weak == (bits < 2048)
        assert card["status"] == ("warn" if bits < 2048 else "pass")


def test_manual_and_discovered_selectors_share_one_shape(discover):
    """Both discovery paths have to emit the same keys, or the planner reads
    a field that is only ever present on one of them."""
    from dkim_formatter import analyze_dkim_key_strength

    record = RECORDS[1024]
    discovered = discover(record)["found_selectors"][0]

    # The shape audit_engine._run_dkim_direct builds for a manual selector.
    analysis = analyze_dkim_key_strength(record)
    manual = {
        "selector": SELECTOR,
        "record": record,
        "key_type": analysis.get("key_type"),
        "key_bits": analysis.get("key_bits"),
    }

    for field in ("selector", "record", "key_type", "key_bits"):
        assert discovered[field] == manual[field], f"{field} differs between paths"

    assert WEAK_STEP in _titles(_plan_for({"found_selectors": [manual]}))


def test_ed25519_key_is_not_reported_as_rsa(discover):
    raw = discover(_ed25519_record())
    found = raw["found_selectors"][0]
    assert found["key_type"] == "Ed25519"
    assert found["key_bits"] == 256
