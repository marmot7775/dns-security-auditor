"""A DNS query that never completed is not a domain with no record.

_lookup_txt has taken a raise_on_failure flag since it was written, and its
docstring spells out the hazard: by default every DNS outcome collapses to an
empty list, so NXDOMAIN ("no record published") and SERVFAIL ("the lookup
failed") arrive at the caller as the same value. Only the report
authorization path passed the flag. The apex TXT lookup, the _dmarc lookup,
and the org domain lookup behind policy inheritance did not.

One SERVFAIL from a domain's authoritative nameserver therefore produced

    DMARC | fail | Missing | "No DMARC policy published"
    SPF   | fail | Missing | "No SPF record published"

with fix text telling the operator to publish records they already have, and
nothing anywhere in the report saying the query had not completed. A retry
thirty seconds later showed a different answer with no explanation for the
difference.

Both checks now report status "unavailable", which is neither a pass nor a
finding, and say plainly that the lookup did not complete.
"""
import os
import sys

import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "servfail.test"
SUB = "mail.servfail.test"

BASE = {
    DOMAIN: {
        "MX": [(10, "mx.servfail.test")],
        "TXT": ["v=spf1 ip4:198.51.100.0/24 -all"],
        "A": ["203.0.113.10"],
        "NS": ["ns1.servfail.test"],
    },
    f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@servfail.test"]},
    "mx.servfail.test": {"A": ["203.0.113.11"]},
    "ns1.servfail.test": {"A": ["203.0.113.53"]},
}


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)


def _text(card):
    parts = [card.get("verdict") or "", card.get("explanation") or "", card.get("fix") or ""]
    parts += [d.get("text", "") for d in card.get("details") or []]
    return " ".join(parts)


# ------------------------------------------------------------------
# The two cards
# ------------------------------------------------------------------

def test_servfail_on_the_dmarc_lookup_does_not_report_a_missing_record(audit):
    zone = FakeZone(dict(BASE)).fail(f"_dmarc.{DOMAIN}", "TXT")
    card = _card(audit(zone, DOMAIN), "DMARC")

    assert card["status"] == "unavailable", (
        f"the _dmarc query never completed, so the tool does not know whether "
        f"a policy exists. Got status={card['status']!r} "
        f"verdict={card['verdict']!r}"
    )
    assert card["pill_label"] == "Not checked"
    assert "No DMARC policy published" not in _text(card)
    assert "did not complete" in card["explanation"]


def test_servfail_on_the_apex_txt_lookup_does_not_report_a_missing_spf_record(audit):
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "TXT")
    card = _card(audit(zone, DOMAIN), "SPF")

    assert card["status"] == "unavailable", (
        f"the apex TXT query never completed. Got status={card['status']!r} "
        f"verdict={card['verdict']!r}"
    )
    assert card["pill_label"] == "Not checked"
    assert "No SPF record" not in _text(card)
    assert "did not complete" in card["explanation"]


def test_one_servfail_at_the_apex_takes_out_both_cards(audit):
    """The apex TXT lookup feeds SPF and the _dmarc lookup feeds DMARC, but a
    nameserver that SERVFAILs one usually SERVFAILs both, which is the case
    that produced two false "Missing" cards in a single report."""
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "TXT").fail(f"_dmarc.{DOMAIN}", "TXT")
    result = audit(zone, DOMAIN)

    for name in ("SPF", "DMARC"):
        card = _card(result, name)
        assert card["status"] == "unavailable", f"{name}: {card['verdict']!r}"
        assert "Missing" != card["pill_label"]


@pytest.mark.parametrize("exc", [
    dns.resolver.NoNameservers(),
    dns.exception.Timeout(),
])
def test_every_incomplete_outcome_is_treated_the_same(audit, exc):
    """SERVFAIL from every nameserver and a plain timeout are both "we could
    not ask", and neither is an answer about the domain."""
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "TXT", exc)
    assert _card(audit(zone, DOMAIN), "SPF")["status"] == "unavailable"


# ------------------------------------------------------------------
# Absence is still reported as absence
# ------------------------------------------------------------------

def test_a_genuinely_absent_record_is_still_a_finding(audit):
    """NXDOMAIN is an answer. The fix must not turn "no record" into
    "not checked" and silence a real finding."""
    zone = dict(BASE)
    zone[DOMAIN] = dict(zone[DOMAIN])
    del zone[DOMAIN]["TXT"]
    zone.pop(f"_dmarc.{DOMAIN}")

    result = audit(FakeZone(zone), DOMAIN)
    spf = _card(result, "SPF")
    dmarc = _card(result, "DMARC")

    assert spf["status"] == "fail"
    assert spf["pill_label"] == "Missing"
    assert dmarc["status"] == "fail"
    assert dmarc["pill_label"] == "Missing"


def test_a_record_that_resolves_is_unaffected(audit):
    result = audit(FakeZone(dict(BASE)), DOMAIN)
    assert _card(result, "SPF")["status"] == "pass"
    assert _card(result, "DMARC")["status"] == "pass"


# ------------------------------------------------------------------
# Inherited policy
# ------------------------------------------------------------------

def test_a_failed_org_domain_lookup_does_not_claim_the_subdomain_has_no_policy(audit):
    """The subdomain publishes no record of its own, so the card depends
    entirely on the org domain lookup behind policy inheritance. When that
    query fails, "No DMARC policy published" is a claim about the parent that
    this audit never established."""
    zone = {
        SUB: {"TXT": ["v=spf1 -all"], "A": ["203.0.113.12"]},
        DOMAIN: dict(BASE[DOMAIN]),
        "ns1.servfail.test": {"A": ["203.0.113.53"]},
    }
    fake = FakeZone(zone).fail(f"_dmarc.{SUB}", "TXT").fail(f"_dmarc.{DOMAIN}", "TXT")

    card = _card(audit(fake, SUB, scope="dmarc"), "DMARC")
    assert card["status"] == "unavailable", (
        f"neither the subdomain nor the org domain answered. Got "
        f"status={card['status']!r} verdict={card['verdict']!r}"
    )
    assert "No DMARC policy published" not in _text(card)


def test_inheritance_still_works_when_the_org_domain_answers(audit):
    """Control: the PSL fallback path still finds the parent's policy."""
    zone = {
        SUB: {"TXT": ["v=spf1 -all"], "A": ["203.0.113.12"]},
        DOMAIN: dict(BASE[DOMAIN]),
        f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@servfail.test"]},
        "ns1.servfail.test": {"A": ["203.0.113.53"]},
    }
    card = _card(audit(FakeZone(zone), SUB, scope="dmarc"), "DMARC")
    assert card["status"] == "pass"
    assert card["pill_label"] == "Inherited"


# ------------------------------------------------------------------
# The rest of the report must not contradict the card
# ------------------------------------------------------------------

def test_an_unavailable_check_is_neither_pass_warn_nor_fail(audit):
    """The PDF cover and the executive summary tally those three. A check
    that never ran must fall outside all of them."""
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "TXT").fail(f"_dmarc.{DOMAIN}", "TXT")
    checks = audit(zone, DOMAIN)["checks"]

    unavailable = {c["name"] for c in checks if c["status"] == "unavailable"}
    assert {"SPF", "DMARC"} <= unavailable

    counted = sum(1 for c in checks if c["status"] in ("pass", "warn", "fail"))
    assert counted == len([c for c in checks if c["status"] != "unavailable"])


def test_no_part_of_the_report_tells_the_operator_to_publish_spf(audit):
    """The card is not the only place the report speaks. The remediation
    plan, the anomaly list and the DMARC cross-check all read an empty
    record field as "no record", and each one would state as a finding
    something the failed lookup never established."""
    zone = FakeZone(dict(BASE)).fail(DOMAIN, "TXT")
    result = audit(zone, DOMAIN)

    plan = result.get("remediation_plan") or {}
    titles = [
        item.get("title", "")
        for bucket in plan.values() if isinstance(bucket, list)
        for item in bucket
    ]
    assert "Publish SPF Record" not in titles, (
        "the plan tells the operator to publish a record the audit could not read"
    )

    anomalies = [a.get("title", "") for a in result.get("anomalies") or []]
    assert "DMARC enforcement without SPF" not in anomalies

    # The cross-check injects its findings as details on the DMARC card.
    # Matched on its own sentence, not the phrase alone: the card's standing
    # explanation of how DMARC evaluates also says "neither SPF nor DKIM".
    dmarc_text = _text(_card(result, "DMARC"))
    assert "no SPF record found" not in dmarc_text.lower()
    assert "neither SPF nor DKIM is configured" not in dmarc_text
    assert "aspf=s is set but no SPF record found" not in dmarc_text


def test_no_vendor_spf_suggestion_is_built_from_a_record_that_could_not_be_read(audit):
    """The suggestion builder treats an empty current record as "nothing
    published" and offers one from scratch. Against a record the audit failed
    to read, that is the lossy suggestion the builder exists to refuse."""
    zone = dict(BASE)
    zone[DOMAIN] = dict(zone[DOMAIN])
    zone[DOMAIN]["MX"] = [(10, "aspmx.l.google.com")]
    zone["aspmx.l.google.com"] = {"A": ["203.0.113.25"]}

    fake = FakeZone(zone).fail(DOMAIN, "TXT")
    card = _card(audit(fake, DOMAIN), "SPF")

    assert not card.get("fix"), (
        f"a check that read nothing must not propose a replacement record: "
        f"{card.get('fix')!r}"
    )
