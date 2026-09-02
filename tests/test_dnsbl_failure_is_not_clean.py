"""A blocklist query that failed is not a domain that is not listed.

_dnsbl_lookup collapsed every DNS outcome to a nullable string:

    except (NXDOMAIN, NoAnswer, NoNameservers):
        return None
    except dns.exception.DNSException:
        return None

and the caller read `listed = return_code is not None`. NXDOMAIN genuinely
means the domain is not on the list. A timeout or a SERVFAIL querying
dbl.spamhaus.org means nothing at all, and both arrived as the same None, so
a failed query rendered as a clean bill of health. Spamhaus rate limits
queries from busy resolvers, which makes this the expected path rather than
a rare one.

The lookup now reports three states, listed / not listed / unknown, and an
unknown rolls into the card as a check that did not run.

The empty-results branch of the card is covered in
tests/test_unavailable_checks_never_pass.py, which is where the rule that an
incomplete check never reports pass already lives.
"""
import os
import sys

import dns.exception
import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "dnsbl.test"
DBL = f"{DOMAIN}.dbl.spamhaus.org"

BASE = {
    DOMAIN: {
        "MX": [(10, "mail.dnsbl.test")],
        "TXT": ["v=spf1 mx -all"],
        "A": ["203.0.113.80"],
        "NS": ["ns1.dnsbl.test"],
    },
    f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@dnsbl.test"]},
    "mail.dnsbl.test": {"A": ["203.0.113.81"]},
    "ns1.dnsbl.test": {"A": ["203.0.113.53"]},
}


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)


@pytest.mark.parametrize("exc", [
    dns.exception.Timeout(),
    dns.resolver.NoNameservers(),
])
def test_a_failed_dnsbl_query_does_not_produce_a_clean_verdict(audit, exc):
    zone = FakeZone(dict(BASE)).fail(DBL, "A", exc)
    card = _card(audit(zone, DOMAIN), "Blocklist")

    assert card["status"] != "pass", (
        f"the query never completed, so nothing is known about this domain's "
        f"blocklist status. Got status={card['status']!r} "
        f"verdict={card['verdict']!r}"
    )
    assert card["status"] == "unavailable"
    assert card["pill_label"] == "Not checked"
    assert "clean" not in card["verdict"].lower()


def test_a_failed_query_is_framed_as_a_gap_in_the_audit(audit):
    zone = FakeZone(dict(BASE)).fail(DBL, "A")
    card = _card(audit(zone, DOMAIN), "Blocklist")

    assert "not assessed" in card["explanation"].lower()
    # Nothing for the operator to fix: the domain did nothing wrong.
    assert not card.get("fix")


def test_a_failed_query_does_not_count_as_a_listing(audit):
    """The mirror image of the bug: an unknown must not become a finding
    against the domain either."""
    zone = FakeZone(dict(BASE)).fail(DBL, "A")
    result = audit(zone, DOMAIN)
    card = _card(result, "Blocklist")

    assert "listed" not in card["verdict"].lower()
    assert not any(d.get("type") == "error" for d in card.get("details") or [])

    # And it stays out of the priority fixes the report leads with.
    fixes = [str(f).lower() for f in result.get("priority_fixes") or []]
    assert not any("blocklist" in f or "delist" in f for f in fixes)


def test_nxdomain_still_means_not_listed(audit):
    """NXDOMAIN is the protocol's answer for "not on this list". It is a real
    result and must keep passing."""
    card = _card(audit(FakeZone(dict(BASE)), DOMAIN), "Blocklist")
    assert card["status"] == "pass"
    assert card["pill_label"] == "Clean"


def test_a_real_listing_still_fails(audit):
    zone = FakeZone(dict(BASE))
    zone.add(DBL, "A", ["127.0.1.2"])  # Spamhaus DBL: spam domain
    card = _card(audit(zone, DOMAIN), "Blocklist")

    assert card["status"] == "fail"
    assert "listed" in card["verdict"].lower()


def test_an_unknown_blocklist_result_is_not_tallied_as_a_pass(audit):
    zone = FakeZone(dict(BASE)).fail(DBL, "A")
    checks = audit(zone, DOMAIN)["checks"]

    blocklist = next(c for c in checks if c["name"] == "Blocklist")
    assert blocklist["status"] not in ("pass", "warn", "fail")
