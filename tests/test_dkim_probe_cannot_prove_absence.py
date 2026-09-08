"""Doc 15: DKIM presence cannot be proven by probing.

Two things were collapsed into one verdict.

A selector publishing an empty p= is revoked, per RFC 6376 section 3.6.1,
which states that an empty value means the public key has been revoked. That
is the correct way to retire a key: the record stays published so a receiver
meeting a delayed or replayed message gets an explicit revocation rather than
a missing record. It is not a failure of the domain and must not be graded as
one.

Selector probing cannot establish absence either. DNS offers no way to
enumerate the names under _domainkey; a selector is chosen by the sending
service and is learned from the s= tag of a signed message. A probe that
finds no live key has established only that the names it guessed did not
resolve.

google.com is the first domain anyone tries, and it is both cases at once. It
publishes four selectors, all with an empty p=, and no live key at any name in
the probe list. The report graded that as a DKIM failure and told the operator
to publish a key.

Three outcomes now, one test each:

  A. A live key was found. Graded as before.
  B. Only revoked selectors were found. Reported as correctly retired keys
     with no live key found by probing. Not a failure.
  C. Nothing was found. Reported as not confirmed, naming the limitation and
     the two things that settle it.

The revoked case uses google.com's four real selector names and the exact
record strings it publishes, rather than an invented shape. The zone is fake
because this suite is offline by design (conftest's no_network fixture fails
any test that opens a socket), but the records in it are the live ones.
"""
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import FakeZone

DOMAIN = "google.com"

# Verified live on 2026-09-07 with `dig +short TXT <selector>._domainkey.google.com`.
# All four are at indices 5 to 8 of COMPREHENSIVE_DKIM_SELECTORS, so every
# audit of this domain probes all of them. 20161025 carries no v= tag, which is
# legal: RFC 6376 section 3.6.1 makes v= RECOMMENDED in a key record, defaulting
# to DKIM1, unlike the DMARC record where it is mandatory and must come first.
GOOGLE_REVOKED = {
    "20161025": "k=rsa; p=",
    "20210112": "v=DKIM1; k=rsa; p=",
    "20221208": "v=DKIM1; k=rsa; p=",
    "20230601": "v=DKIM1; k=rsa; p=",
}


def _live_key():
    spki = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode("ascii")


LIVE_KEY = _live_key()

BASE = {
    DOMAIN: {
        "MX": [(10, "smtp.google.com")],
        "TXT": ["v=spf1 include:_spf.google.com ~all"],
        "A": ["142.250.72.206"],
        "NS": ["ns1.google.com"],
    },
    "_spf.google.com": {"TXT": ["v=spf1 ip4:209.85.128.0/17 ~all"]},
    f"_dmarc.{DOMAIN}": {
        "TXT": ["v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"]
    },
    "smtp.google.com": {"A": ["142.250.72.229"]},
    "ns1.google.com": {"A": ["216.239.32.10"]},
}


def _zone(selectors=None):
    zone = FakeZone(dict(BASE))
    for selector, record in (selectors or {}).items():
        zone.add(f"{selector}._domainkey.{DOMAIN}", "TXT", [record])
    return zone


def _card(result, name="DKIM"):
    return next(c for c in result["checks"] if c["name"] == name)


def _text(card):
    return " ".join(
        [card.get("verdict", ""), card.get("explanation", "")]
        + [d.get("text", "") for d in card.get("details", [])]
    ).lower()


# ---------------------------------------------------------------
# Outcome A: a live key was found
# ---------------------------------------------------------------

def test_a_live_key_is_still_graded(audit):
    """The grading path is untouched. Nothing below may soften it."""
    card = _card(audit(_zone({"google": LIVE_KEY}), DOMAIN, scope="email_full"))

    assert card["status"] == "pass"
    assert card["verdict"] == "1 DKIM public key published in DNS"
    assert "2048-bit" in _text(card)


def test_a_retired_selector_alongside_a_live_one_does_not_fail_the_card(audit):
    """Rotating away from a key leaves exactly this shape behind. The old
    selector is the rotation advice having been followed, not a defect."""
    zone = _zone({"google": LIVE_KEY, "20230601": GOOGLE_REVOKED["20230601"]})
    card = _card(audit(zone, DOMAIN, scope="email_full"))

    assert card["status"] == "pass", (
        f"a retired selector next to a live key must not fail the card; got "
        f"{card['status']!r} / {card['verdict']!r}"
    )
    assert card["verdict"] == "1 DKIM public key published in DNS", (
        "the count is of live keys: a retired selector is not a key anyone can "
        "verify a signature against"
    )
    text = _text(card)
    assert "retired" in text
    assert "20230601" in text


# ---------------------------------------------------------------
# Outcome B: only revoked selectors, google.com's real shape
# ---------------------------------------------------------------

@pytest.fixture
def google_result(audit):
    return audit(_zone(GOOGLE_REVOKED), DOMAIN, scope="email_full")


def test_google_com_revoked_selectors_are_not_a_failure(google_result):
    card = _card(google_result)

    assert card["status"] != "fail", (
        f"four keys retired the way RFC 6376 says to retire a key are not a "
        f"failure of the domain; got {card['status']!r} / {card['verdict']!r}"
    )
    assert card["status"] == "unavailable", (
        "neither a pass nor a finding: the keys are correctly published and no "
        "live key was established either way"
    )
    assert card["pill_label"] == "Not confirmed"


def test_google_com_card_says_the_keys_are_correctly_retired(google_result):
    text = _text(_card(google_result))

    assert "retired" in text
    assert "revoked" in text
    assert "3.6.1" in text or "section 3.6.1" in text
    for selector in GOOGLE_REVOKED:
        assert selector in text, f"{selector} is not named on the card"
    assert "no live key" in text


def test_google_com_card_does_not_tell_the_operator_to_publish_a_key(google_result):
    card = _card(google_result)

    assert not card.get("fix"), (
        f"advice to publish a DKIM record for a domain that may already sign "
        f"under an unguessed selector: {card.get('fix')!r}"
    )
    text = _text(card)
    for claim in ("no dkim", "dkim is not configured", "misconfigured"):
        assert claim not in text.replace("nothing here is misconfigured", ""), (
            f"the card asserts {claim!r} about something it did not establish"
        )


def test_google_com_gets_no_dkim_remediation_step(google_result):
    """Both roadmaps. A key rotation step needs a key to rotate, and BIMI
    needs a live signing key."""
    plan = google_result.get("remediation_plan") or {}
    titles = {s["title"] for tier in plan.values() for s in tier}
    assert "Schedule Regular DKIM Key Rotation" not in titles
    assert "Add BIMI Record" not in titles

    roadmap_actions = " ".join(
        i.get("action", "") for i in google_result["security_roadmap"]["items"]
    ).lower()
    assert "dkim" not in roadmap_actions, (
        f"a DKIM action was raised for four correctly retired keys: "
        f"{roadmap_actions!r}"
    )


def test_google_com_drops_out_of_the_pass_warn_fail_tallies(google_result):
    checks = google_result["checks"]
    counted = [c["name"] for c in checks if c["status"] in ("pass", "warn", "fail")]
    assert "DKIM" not in counted

    coverage = google_result["executive_summary"]["protocol_coverage"]
    assert coverage["configured"] <= coverage["total"]
    assert coverage["total"] == len(
        [c for c in checks
         if c["name"] in ("DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT",
                          "DANE", "DNSSEC", "BIMI", "CAA")
         and c["status"] != "unavailable"]
    )


def test_google_com_resilience_does_not_claim_broad_dkim_coverage(google_result):
    dkim = google_result["resilience"]["mechanisms"]["dkim"]

    assert dkim["status"] == "inconclusive", (
        f"four retired keys read as detected DKIM: {dkim!r}"
    )
    note = dkim["note"].lower()
    assert "broad coverage" not in note
    assert "4 dkim selectors detected" not in note
    assert "empty p=" in note


# ---------------------------------------------------------------
# The operator named the selector: no probing happened
# ---------------------------------------------------------------

def test_a_named_selector_that_is_retired_does_not_hedge_about_probing(audit):
    """Doc 15 carves the manual path out because the operator asserted the
    name. That cuts both ways: nothing was probed and nothing was guessed, so
    the not-enumerable hedge is as false here as the old "publish a DKIM
    record" advice was. This audit did settle the question for the name it was
    given."""
    zone = _zone({"20230601": GOOGLE_REVOKED["20230601"]})
    card = _card(audit(zone, DOMAIN, scope="email_full", dkim_selector="20230601"))

    text = _text(card)
    assert "probing" not in text, f"nothing was probed: {text!r}"
    assert "did not guess" not in text, f"nothing was guessed: {text!r}"
    assert "cannot be enumerated" not in text

    assert card["status"] == "warn", (
        f"the record is correctly published, so not a fail; the question was "
        f"answered, so not unconfirmed; got {card['status']!r}"
    )
    assert card["pill_label"] == "Retired"
    assert "20230601" in card["verdict"]
    assert "fails dkim" in text, (
        "the consequence for mail still signed with this selector is the whole "
        "point of answering a named selector"
    )
    assert "s=" in card["fix"], "the fix must point at the header that settles it"


def test_a_named_selector_that_does_not_resolve_is_unchanged(audit):
    """The carve-out in the doc: this path keeps its existing handling."""
    card = _card(audit(_zone(GOOGLE_REVOKED), DOMAIN, scope="email_full",
                       dkim_selector="nosuch"))

    assert card["status"] == "fail"
    assert card["pill_label"] == "Not found"
    assert "nosuch" in card["verdict"]


# ---------------------------------------------------------------
# Outcome C: nothing found
# ---------------------------------------------------------------

@pytest.fixture
def nothing_found(audit):
    return audit(_zone(), DOMAIN, scope="email_full")


def test_nothing_found_is_not_stated_as_an_absence(nothing_found):
    card = _card(nothing_found)

    assert card["status"] == "unavailable"
    assert card["pill_label"] == "Not confirmed"
    assert card["verdict"] == "DKIM could not be confirmed by probing"
    assert not card.get("fix")


def test_nothing_found_names_the_limitation_and_both_ways_to_settle_it(nothing_found):
    text = _text(_card(nothing_found))

    assert "enumerate" in text, (
        "the card must say why probing cannot answer this, not merely that it "
        "did not"
    )
    assert "enter your selector" in text, "the direct-lookup path is not offered"
    assert "s=" in text and "dkim-signature" in text, (
        "the header path is not offered: the s= tag of a DKIM-Signature or "
        "Authentication-Results header is the other thing that settles it"
    )
    assert "authentication-results" in text


# ---------------------------------------------------------------
# Both B and C: "unavailable" must not be read as a broken lookup
# ---------------------------------------------------------------

@pytest.mark.parametrize("selectors", [GOOGLE_REVOKED, {}], ids=["retired", "nothing"])
def test_the_summary_does_not_say_the_dkim_lookup_failed(audit, selectors):
    """DKIM reaches "unavailable" by a second route, and the prose above the
    cards was written for the first one. Every DKIM lookup here completed and
    answered NXDOMAIN, so saying the nameservers did not respond would trade
    one false statement for another."""
    result = audit(_zone(selectors), DOMAIN, scope="email_full")
    es = result["executive_summary"]

    prose = " ".join([
        es["verdict"], es["deliverability_summary"], es["biggest_risk"],
        result["security_roadmap"]["summary"],
    ]).lower()

    assert "did not complete" not in prose, (
        f"the DKIM lookups completed and returned answers: {prose!r}"
    )
    assert "did not answer" not in prose
    assert "nameserver" not in prose


@pytest.mark.parametrize("selectors", [GOOGLE_REVOKED, {}], ids=["retired", "nothing"])
def test_the_summary_does_not_issue_an_all_clear_covering_dkim(audit, selectors):
    """The other direction. DKIM was not established either way, so the
    deliverability line must not fold it into a clean bill of health."""
    result = audit(_zone(selectors), DOMAIN, scope="email_full")
    deliv = result["executive_summary"]["deliverability_summary"].lower()

    assert "spf, dkim, and dmarc are properly set up" not in deliv
    assert "could not be confirmed by probing" in deliv
    assert "outside the scope" not in deliv, (
        "DKIM was in scope and did run. Saying it was outside the scope trades "
        "one wrong statement for another."
    )
