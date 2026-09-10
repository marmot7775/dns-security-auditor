"""A check that did not run must not report pass.

B2. Two of the thirteen checks structurally cannot complete from where this
audit runs:

  - Spamhaus refuses DNSBL queries from public and cloud resolvers. Querying
    dbl.spamhaus.org from the droplet returns 127.255.255.254, Spamhaus's
    documented "query refused" code, on every request. It is not rate
    limiting that will pass.
  - Certificate Transparency reads crt.sh, which is frequently down. It was
    502ing across two consecutive deploy checks.

Certificate Transparency answered `status: "pass"` with pill "Skipped" for
this, which is the worst available option: a green card for a check that
assessed nothing about the domain. Blocklist answered "warn", which reads as
a finding against the domain rather than a gap in the tool.

Both now answer "unavailable", a status that is neither a pass nor a finding,
and both say plainly that the check did not run. The counts in the PDF and
the executive summary tally pass/warn/fail, so an unavailable check drops out
of all three rather than inflating any of them.
"""
import os
import sys

import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "unavail.test"

BASE = {
    DOMAIN: {
        "MX": [(10, "mail.unavail.test")],
        "TXT": ["v=spf1 mx -all"],
        "A": ["203.0.113.70"],
        "NS": ["ns1.unavail.test"],
    },
    f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@unavail.test"]},
    "mail.unavail.test": {"A": ["203.0.113.71"]},
    "ns1.unavail.test": {"A": ["203.0.113.53"]},
}


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)




def test_ct_without_a_reachable_log_service_is_not_a_pass(audit):
    """No ct_certs supplied, so the crt.sh call fails the way it does in
    production when the service is down."""
    result = audit(FakeZone(dict(BASE)), DOMAIN)
    card = _card(result, "Certificate Transparency")

    assert card["status"] == "unavailable", (
        "a check that never reached its data source cannot be a pass"
    )
    assert card["pill_label"] == "Not checked"
    assert "not assessed" in card["explanation"].lower()




def test_an_unavailable_check_counts_as_neither_pass_warn_nor_fail(audit):
    """The PDF cover and the executive summary tally these three. An
    unavailable check must fall outside all of them rather than pad one."""
    result = audit(FakeZone(dict(BASE)), DOMAIN)
    checks = result["checks"]

    counted = sum(1 for c in checks if c["status"] in ("pass", "warn", "fail"))
    unavailable = [c["name"] for c in checks if c["status"] == "unavailable"]

    # DKIM joined Certificate Transparency under Doc 15, by a different route:
    # its lookups complete and still cannot settle the question, because
    # selectors are not enumerable from DNS. Blocklist left the set entirely
    # under Doc 17 item 7, along with the check itself.
    assert set(unavailable) == {"Certificate Transparency", "DKIM"}
    assert counted == len(checks) - len(unavailable)


# ---------------------------------------------------------------
# Doc 20: a failed DNSSEC or CAA lookup is not a negative answer
# ---------------------------------------------------------------
#
# NoAnswer and NXDOMAIN are real answers: no DNSKEY/CAA published. A
# SERVFAIL or a timeout on every attempt means the query never completed,
# and reporting it the same way as a real negative answer told a signed
# and anchored domain, or one with a working CAA policy, that it had
# neither.

def test_dnssec_servfail_is_not_reported_as_not_configured(audit):
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "DNSKEY").fail(DOMAIN, "DS")
    result = audit(zone, DOMAIN)
    card = _card(result, "DNSSEC")

    assert card["status"] == "unavailable", (
        f"a DNSKEY query that never completed cannot report a configuration "
        f"state: got status={card['status']!r} pill={card.get('pill_label')!r}"
    )
    assert card["pill_label"] == "Not confirmed"
    assert "not configured" not in card["verdict"].lower()
    texts = " ".join(d.get("text", "") for d in card.get("details", []))
    assert "no dnskey" not in texts.lower(), (
        f"a bullet still asserts DNSSEC is absent from a failed lookup: {texts!r}"
    )


def test_dnssec_double_timeout_is_not_reported_as_not_configured(audit):
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "DNSKEY", dns.resolver.LifetimeTimeout())
    result = audit(zone, DOMAIN)
    card = _card(result, "DNSSEC")

    assert card["status"] == "unavailable", (
        f"a DNSKEY query timing out on both attempts cannot report a "
        f"configuration state: got status={card['status']!r}"
    )
    assert card["pill_label"] == "Not confirmed"
    assert "not configured" not in card["verdict"].lower()


def test_caa_servfail_at_every_level_is_not_reported_as_no_records(audit):
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "CAA")
    result = audit(zone, DOMAIN)
    card = _card(result, "CAA")

    assert card["status"] == "unavailable", (
        f"a CAA query that never completed at any level of the tree cannot "
        f"say the tree published nothing: got status={card['status']!r} "
        f"pill={card.get('pill_label')!r} verdict={card['verdict']!r}"
    )
    assert "no caa records" not in card["verdict"].lower()
    assert card.get("fix") is None, (
        "a card that asserted nothing about the domain must not hand out a fix"
    )


def test_nameservers_nonameservers_is_not_reported_as_missing(audit):
    """Doc 27 item 4: _raw_check_nameservers's generic DNSException handler
    set status "error" with no lookup_failed flag, so a SERVFAIL,
    NoNameservers, or a timeout was indistinguishable from a real negative
    answer. The DNSSEC and CAA cards were already fixed for this in 28c644c;
    nameservers reached the same failure mode through a different handler
    and was missed."""
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "NS")
    result = audit(zone, DOMAIN)
    card = _card(result, "Nameservers")

    assert card["status"] == "unavailable", (
        f"an NS lookup that never completed cannot report a configuration "
        f"state: got status={card['status']!r} pill={card.get('pill_label')!r}"
    )
    assert "no nameservers found" not in card["verdict"].lower()
    assert card.get("fix") is None, (
        "a card that asserted nothing about the domain must not hand out a fix"
    )


def test_signed_unanchored_dnssec_reaches_the_dane_card_correctly(audit):
    """DNSKEY published, no DS at the parent: a real, common mid-deployment
    state, not a lookup failure. The DNSSEC and DANE cards must agree, and
    DANE's fix must point at the DS record, not at DNSSEC itself."""
    zone = FakeZone(dict(BASE))
    zone.add(DOMAIN, "DNSKEY", 13)
    zone.add("_25._tcp.mail.unavail.test", "TLSA", (3, 1, 1, "aa" * 32))
    # No DS record declared for DOMAIN -> NXDOMAIN -> a real negative answer.

    result = audit(zone, DOMAIN)
    dnssec = _card(result, "DNSSEC")
    dane = _card(result, "DANE")

    assert "unanchored" in dnssec["verdict"].lower()
    assert dane["status"] == "warn"
    assert "unanchored" in dane["verdict"].lower(), (
        f"DANE still describes this as DNSSEC being missing rather than "
        f"unanchored: {dane['verdict']!r}"
    )
    fix = (dane.get("fix") or "").lower()
    assert "ds record" in fix, (
        f"DANE's fix does not point at the DS record: {fix!r}"
    )
    assert "enable dnssec" not in fix, (
        f"DANE told the operator to enable DNSSEC, which is already done: {fix!r}"
    )






