"""Regression test for DMARC report-authorization enrichment running after
the card was already built.

Bug: inside run_full_audit, transform_dmarc() ran immediately after
_raw_check_dmarc()/​_enrich_dmarc_inheritance(), building the DMARC card
from a snapshot of raw_dmarc. The report_destinations and
report_auth_issues fields were only attached to that same raw_dmarc dict
a few lines later, by the DMARC Report Authorization block. Since the
card had already been built, result_transformer.py's
`raw.get("report_destinations")` branch was always empty in production --
an rua pointing at an unauthorized third party still showed "aggregate
reporting is configured" with a pass.

This must be caught by actually exercising run_full_audit's real
execution order, not by calling the raw-check functions and
transform_dmarc in whatever order the test chooses (that would pass
trivially and prove nothing about the orchestrator). So this test mocks
every DNS entry point at the dnspython layer (dns.resolver.Resolver.resolve
and the module-level dns.resolver.resolve, which together cover every
lookup made by every module run_full_audit touches) and drives the real
function end to end, then asserts on the transformed DMARC card in the
result -- not on any raw check dict.
"""
import os
import sys
from unittest.mock import patch

import dns.resolver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine

DOMAIN = "reportauth-order.test"
# p=quarantine, not p=reject: this domain has no MX records, which alone
# counts as one "defensive DNS domain" signal (see run_full_audit's
# is_defensive detection). p=reject would add a second signal and trigger
# a *second*, later transform_dmarc() call once is_defensive is known --
# that second call runs after the report-auth enrichment and would build
# a correct card by accident, masking the ordering bug this test targets.
DMARC_RECORD = "v=DMARC1; p=quarantine; rua=mailto:reports@unrelated-vendor.test"

# Only these TXT names resolve to anything. Everything else (MX, A, AAAA,
# CNAME, DNSKEY, DS, NS, CAA, TLSA, SOA, PTR, and any other TXT name --
# including the RFC 7489 S7.1 authorization record, which must NOT exist)
# is NXDOMAIN, so every other check in the "dmarc" scope (spf, dkim, mx
# dependency) resolves to "not found" quickly instead of hitting real DNS.
TXT_RECORDS = {
    f"_dmarc.{DOMAIN}": DMARC_RECORD,
}


class _FakeRRset:
    def __init__(self, ttl):
        self.ttl = ttl


class _FakeRdata:
    def __init__(self, text):
        self.strings = [text.encode("utf-8")]


class _FakeAnswer(list):
    def __init__(self, text, ttl=300):
        super().__init__([_FakeRdata(text)])
        self.rrset = _FakeRRset(ttl)


def _fake_resolve(name, rdtype="A", *args, **kwargs):
    qname = str(name).rstrip(".").lower()
    rtype = str(rdtype).upper()
    if rtype == "TXT" and qname in TXT_RECORDS:
        return _FakeAnswer(TXT_RECORDS[qname])
    raise dns.resolver.NXDOMAIN()


def _fake_resolve_method(self, name, rdtype="A", *args, **kwargs):
    return _fake_resolve(name, rdtype, *args, **kwargs)


def test_unauthorized_third_party_rua_fails_the_dmarc_card():
    with patch("dns.resolver.Resolver.resolve", _fake_resolve_method), \
         patch("dns.resolver.resolve", _fake_resolve):
        result = audit_engine.run_full_audit(DOMAIN, scope="dmarc")

    dmarc_card = next(c for c in result["checks"] if c["name"] == "DMARC")

    detail_texts = " ".join(d.get("text", "") for d in dmarc_card.get("details", []))
    assert "not authorized" in detail_texts.lower(), (
        f"An rua pointing at an unauthorized third party must surface in "
        f"the card's own details; got: {detail_texts!r}"
    )
    assert "aggregate reporting (rua) is configured" not in detail_texts.lower(), (
        f"Must not claim reporting is cleanly configured when the "
        f"destination is unauthorized; got: {detail_texts!r}"
    )
    assert dmarc_card["status"] == "fail", (
        f"An unauthorized external report destination (RFC 7489 S7.1) must "
        f"fail the DMARC card; got status={dmarc_card['status']!r}"
    )
