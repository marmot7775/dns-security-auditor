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

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "unavail.test"

# Spamhaus's refusal code. 127.255.255.x means "your query was rejected",
# never "this domain is listed".
SPAMHAUS_REFUSED = "127.255.255.254"

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


def _zone_with_spamhaus_refusal():
    zone = FakeZone(dict(BASE))
    zone.add(f"{DOMAIN}.dbl.spamhaus.org", "A", [SPAMHAUS_REFUSED])
    return zone


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)


def test_spamhaus_refusal_is_not_reported_as_clean(audit):
    """A refused query says nothing about the domain, so it must not read as
    a clean bill of health."""
    result = audit(_zone_with_spamhaus_refusal(), DOMAIN)
    card = _card(result, "Blocklist")

    assert card["status"] == "unavailable"
    assert card["status"] != "pass"
    assert card["pill_label"] == "Not checked"
    assert "not assessed" in card["explanation"].lower()

    body = (card["verdict"] + " " + card["explanation"]).lower()
    assert "listed" not in card["verdict"].lower()
    assert "clean" not in body or "does not mean it is clean" in body


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


def test_unavailable_checks_are_framed_as_a_tool_gap_not_a_domain_finding(audit):
    result = audit(_zone_with_spamhaus_refusal(), DOMAIN)

    for name in ("Blocklist", "Certificate Transparency"):
        card = _card(result, name)
        explanation = card["explanation"].lower()
        assert "this audit" in explanation or "cannot complete here" in explanation, (
            f"{name}: the card must say the audit did not run the check, "
            f"rather than implying something about the domain"
        )
        # No fix can be offered for something the domain did not do wrong.
        assert not card.get("fix")


def test_an_unavailable_check_counts_as_neither_pass_warn_nor_fail(audit):
    """The PDF cover and the executive summary tally these three. An
    unavailable check must fall outside all of them rather than pad one."""
    result = audit(_zone_with_spamhaus_refusal(), DOMAIN)
    checks = result["checks"]

    counted = sum(1 for c in checks if c["status"] in ("pass", "warn", "fail"))
    unavailable = [c["name"] for c in checks if c["status"] == "unavailable"]

    assert set(unavailable) == {"Blocklist", "Certificate Transparency"}
    assert counted == len(checks) - len(unavailable)


def test_a_real_listing_still_fails(audit):
    """The refusal handling must not swallow a genuine Spamhaus listing."""
    zone = FakeZone(dict(BASE))
    zone.add(f"{DOMAIN}.dbl.spamhaus.org", "A", ["127.0.1.2"])  # spam domain

    card = _card(audit(zone, DOMAIN), "Blocklist")
    assert card["status"] == "fail"
    assert "listed" in card["verdict"].lower()


def test_a_clean_lookup_still_passes(audit):
    """And a domain that is genuinely absent from the list still passes."""
    card = _card(audit(FakeZone(dict(BASE)), DOMAIN), "Blocklist")
    assert card["status"] == "pass"
    assert card["pill_label"] == "Clean"
