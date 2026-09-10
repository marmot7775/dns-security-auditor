"""A lookup that never completed must not become an all clear.

Prompt 08 stopped the checks themselves from inventing a finding when a DNS
query failed: they return status "unavailable" instead of a false "Missing".
The summary layer above the cards was never taught the third state. Every
gate in it tests for status == "fail", so an unavailable check read as
"nothing wrong here" and the report issued an explicit all clear about
records it had not read:

    verdict:        Your domain has email authentication configured.
    deliverability: Your configuration looks solid. SPF, DKIM, and DMARC are
                    properly set up, giving you the best chance of reaching
                    inboxes.
    resilience:     spf/dmarc "missing", "No SPF record found."

That is worse than the bug Prompt 08 fixed. A false "you have no DMARC
record" hands the operator a fix for a problem they may not have; a false
"your configuration looks solid" tells them to stop looking. The verdict is
also the first line printed on the PDF cover, which is the artifact that
gets emailed to a client.

These tests run a real audit against a zone whose apex TXT and _dmarc TXT
both fail the way a broken server fails (NoNameservers, what dnspython
raises when every nameserver for a zone returns SERVFAIL), and assert the
report says so rather than drawing a conclusion from silence.
"""
import os
import sys

import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "example.com"


@pytest.fixture
def dead_apex():
    """A domain that resolves, but whose TXT lookups never complete.

    MX answers so the domain is treated as a sending domain, which is the
    case where a false all clear does the most damage.
    """
    return (
        FakeZone({
            DOMAIN: {"MX": [(10, "mail.example.com")]},
            "mail.example.com": {"A": ["203.0.113.10"]},
        })
        .fail(DOMAIN, "TXT")
        .fail("_dmarc." + DOMAIN, "TXT")
    )


def _summary(result):
    return result.get("executive_summary") or {}


# ---------------------------------------------------------------
# Item 1: the executive summary
# ---------------------------------------------------------------

def test_verdict_does_not_claim_authentication_is_configured(audit, dead_apex):
    verdict = _summary(audit(dead_apex, DOMAIN))["verdict"].lower()

    assert "has email authentication configured" not in verdict, (
        f"both apex lookups failed and the verdict still claims the domain is "
        f"configured: {verdict!r}"
    )
    assert "not assessed" in verdict or "did not" in verdict, (
        f"the verdict does not say the lookups failed: {verdict!r}"
    )


def test_deliverability_does_not_claim_the_configuration_looks_solid(audit, dead_apex):
    deliv = _summary(audit(dead_apex, DOMAIN))["deliverability_summary"].lower()

    assert "looks solid" not in deliv, (
        f"the audit never read SPF, DKIM or DMARC and still called the "
        f"configuration solid: {deliv!r}"
    )
    assert "properly set up" not in deliv, (
        f"the audit named records it never read as properly set up: {deliv!r}"
    )
    assert "not be assessed" in deliv or "did not complete" in deliv, (
        f"the deliverability sentence does not say what went unread: {deliv!r}"
    )


def test_unread_protocols_leave_the_coverage_denominator(audit, dead_apex):
    """8 of 8 rather than 8 of 9. A protocol nobody could read is not a
    protocol the domain declined to publish, and scoring it as one prints a
    red ring on the cover for a fact never established."""
    pc = _summary(audit(dead_apex, DOMAIN))["protocol_coverage"]

    assert pc["total"] < 9, (
        f"an unavailable protocol stayed in the denominator: {pc!r}"
    )
    assert pc["configured"] <= pc["total"]


def test_spoofing_and_readiness_are_neutral_not_red(audit, dead_apex):
    """Red is a verdict. These two are computed entirely from the DMARC
    record, so with no DMARC record read there is nothing to be red about."""
    es = _summary(audit(dead_apex, DOMAIN))

    assert es["spoofing_protection"]["color"] == "neutral", (
        f"spoofing protection printed a colour verdict: {es['spoofing_protection']!r}"
    )
    assert es["dmarcbis_readiness"]["color"] == "neutral", (
        f"readiness printed a colour verdict: {es['dmarcbis_readiness']!r}"
    )
    assert es["spoofing_protection"]["label"] != "None"


def test_biggest_risk_does_not_promote_a_nicety(audit, dead_apex):
    """The roadmap gates on "fail" too, so no item is generated for an unread
    record and some minor item floats to the top. Printing that under "your
    biggest risk right now" implies the real ones were weighed."""
    risk = _summary(audit(dead_apex, DOMAIN))["biggest_risk"].lower()

    assert "could not read" in risk or "not assessed" in risk, (
        f"biggest risk was drawn from an audit that read neither record: {risk!r}"
    )


# ---------------------------------------------------------------
# Item 2: the resilience section
# ---------------------------------------------------------------

def test_resilience_does_not_state_the_records_are_absent(audit, dead_apex):
    mechs = audit(dead_apex, DOMAIN)["resilience"]["mechanisms"]

    for name in ("spf", "dmarc"):
        assert mechs[name]["status"] != "missing", (
            f"{name} was never read and the resilience section reports it "
            f"missing: {mechs[name]!r}"
        )
        assert mechs[name]["status"] == "inconclusive", (
            f"{name} should be inconclusive, got {mechs[name]['status']!r}"
        )
        note = mechs[name]["note"].lower()
        assert "no spf record found" not in note
        assert "no dmarc record found" not in note
        assert "did not complete" in note, (
            f"{name} note does not say the lookup failed: {note!r}"
        )


def test_resilience_does_not_hand_out_a_plan_for_an_unread_record(audit, dead_apex):
    res = audit(dead_apex, DOMAIN)["resilience"]

    assert res["level"] == "inconclusive", (
        f"a resilience level was derived from records never read: {res['level']!r}"
    )
    risk = res["risk"].lower()
    assert "publishing a dmarc record is the single most impactful step" not in risk, (
        f"the operator was told to publish a record that may already exist: {risk!r}"
    )
    assert "publish an spf record" not in risk, (
        f"the operator was told to publish a record that may already exist: {risk!r}"
    )


# ---------------------------------------------------------------
# The guard rail: no false all clear anywhere in the summary layer
# ---------------------------------------------------------------

def test_no_part_of_the_summary_claims_the_domain_is_healthy(audit, dead_apex):
    result = audit(dead_apex, DOMAIN)
    es = _summary(result)
    res = result["resilience"]

    prose = " ".join([
        es["verdict"], es["deliverability_summary"], es["biggest_risk"],
        res["summary"], res["risk"],
    ] + [m["note"] for m in res["mechanisms"].values()]).lower()

    for claim in ("looks solid", "properly set up", "authentication configured",
                  "no spf record found", "no dmarc record found",
                  "well-protected"):
        assert claim not in prose, (
            f"the summary layer claims {claim!r} about a domain whose apex and "
            f"_dmarc lookups both failed"
        )


# ---------------------------------------------------------------
# Doc 20: a failed DNSSEC or CAA lookup must not read as a finding
# one level up either, in the roadmap and the coverage denominator
# ---------------------------------------------------------------

DNSSEC_DOMAIN = "dnssec-summary.test"
_DNSSEC_BASE = {
    DNSSEC_DOMAIN: {
        "MX": [(10, "mail." + DNSSEC_DOMAIN)],
        "TXT": ["v=spf1 mx -all"],
        "A": ["203.0.113.80"],
        "NS": ["ns1." + DNSSEC_DOMAIN],
    },
    f"_dmarc.{DNSSEC_DOMAIN}": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@" + DNSSEC_DOMAIN]},
    "mail." + DNSSEC_DOMAIN: {"A": ["203.0.113.81"]},
    "ns1." + DNSSEC_DOMAIN: {"A": ["203.0.113.53"]},
}


def _plan_items(result):
    plan = result.get("remediation_plan") or {}
    return plan.get("immediate", []) + plan.get("short_term", []) + plan.get("long_term", [])


def test_dnssec_servfail_gets_no_remediation_item_and_leaves_the_denominator(audit):
    zone = FakeZone(dict(_DNSSEC_BASE)).fail(DNSSEC_DOMAIN, "DNSKEY").fail(DNSSEC_DOMAIN, "DS")
    result = audit(zone, DNSSEC_DOMAIN)

    dnssec_items = [i["title"] for i in _plan_items(result) if i.get("check") == "DNSSEC"]
    assert dnssec_items == [], (
        f"a failed DNSSEC lookup produced a remediation task: {dnssec_items!r}"
    )
    pc = _summary(result)["protocol_coverage"]
    assert pc["total"] < 9, (
        f"DNSSEC stayed in the coverage denominator despite the lookup failing: {pc!r}"
    )


def test_dnssec_double_timeout_gets_no_remediation_item(audit):
    zone = FakeZone(dict(_DNSSEC_BASE)).fail(DNSSEC_DOMAIN, "DNSKEY", dns.resolver.LifetimeTimeout())
    result = audit(zone, DNSSEC_DOMAIN)

    dnssec_items = [i["title"] for i in _plan_items(result) if i.get("check") == "DNSSEC"]
    assert dnssec_items == [], (
        f"a DNSKEY query timing out on both attempts produced a remediation task: {dnssec_items!r}"
    )


def test_caa_servfail_at_every_level_leaves_the_coverage_denominator(audit):
    zone = FakeZone(dict(_DNSSEC_BASE)).fail(DNSSEC_DOMAIN, "CAA")
    result = audit(zone, DNSSEC_DOMAIN)

    pc = _summary(result)["protocol_coverage"]
    assert pc["total"] < 9, (
        f"CAA stayed in the coverage denominator despite every level of the "
        f"tree walk failing: {pc!r}"
    )


def test_signed_unanchored_dane_does_not_read_as_dnssec_missing_in_the_summary(audit):
    zone = FakeZone(dict(_DNSSEC_BASE))
    zone.add(DNSSEC_DOMAIN, "DNSKEY", 13)
    zone.add("_25._tcp.mail." + DNSSEC_DOMAIN, "TLSA", (3, 1, 1, "aa" * 32))
    # No DS record for DNSSEC_DOMAIN -> a real signed_unanchored answer.

    result = audit(zone, DNSSEC_DOMAIN)
    es = _summary(result)
    prose = " ".join([es["verdict"], es["deliverability_summary"], es["biggest_risk"]]).lower()

    assert "dnssec is not enabled" not in prose, (
        f"a signed but unanchored zone is being described as having no "
        f"DNSSEC in the executive summary: {prose!r}"
    )


# ---------------------------------------------------------------
# Doc 27 item 3: a scoped audit must not assert findings from checks
# it never ran
# ---------------------------------------------------------------
#
# scope=dns_infra and scope=transport never run DMARC, SPF or DKIM at all,
# so those checks are absent from check_map entirely rather than marked
# "unavailable". build_executive_summary's _unavailable() only tested
# status == "unavailable", so an absent check fell through to the same
# "Your domain has email authentication configured" verdict a check that
# ran and found nothing clean would get, from a check that never queried
# DNS.

SCOPED_DOMAIN = "scoped-summary.test"
_SCOPED_BASE = {
    SCOPED_DOMAIN: {
        "MX": [(10, "mail." + SCOPED_DOMAIN)],
        "A": ["203.0.113.90"],
        "NS": ["ns1." + SCOPED_DOMAIN],
    },
    "mail." + SCOPED_DOMAIN: {"A": ["203.0.113.91"]},
    "ns1." + SCOPED_DOMAIN: {"A": ["203.0.113.53"]},
}


def test_dns_infra_scope_does_not_assert_email_authentication_is_configured(audit):
    result = audit(FakeZone(dict(_SCOPED_BASE)), SCOPED_DOMAIN, scope="dns_infra")
    es = _summary(result)

    verdict = es["verdict"].lower()
    assert "has email authentication configured" not in verdict, (
        f"a scope that never queried DMARC, SPF or DKIM still claims email "
        f"authentication is configured: {verdict!r}"
    )
    assert "not assessed" in verdict or "did not" in verdict, (
        f"the verdict does not say email authentication was out of scope: {verdict!r}"
    )
    assert es["spoofing_protection"]["color"] == "neutral", (
        f"spoofing protection printed a colour verdict for a scope that never "
        f"ran DMARC: {es['spoofing_protection']!r}"
    )
    assert es["dmarcbis_readiness"]["label"] != "Action Needed", (
        f"a DMARC check that never ran must not read as 'Action Needed': "
        f"{es['dmarcbis_readiness']!r}"
    )
    assert es["dmarcbis_readiness"]["color"] == "neutral"


def test_transport_scope_does_not_assert_email_authentication_is_configured(audit):
    result = audit(FakeZone(dict(_SCOPED_BASE)), SCOPED_DOMAIN, scope="transport")
    verdict = _summary(result)["verdict"].lower()

    assert "has email authentication configured" not in verdict, (
        f"scope=transport never runs DMARC, SPF or DKIM either: {verdict!r}"
    )
