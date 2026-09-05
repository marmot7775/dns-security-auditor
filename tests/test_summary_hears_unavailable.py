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
