"""A tree walk that could not read a level must not state the policy above it.

dmarc_tree_walk._query_dmarc caught every exception and returned None, so a
SERVFAIL, REFUSED or timeout at one level was indistinguishable from that level
publishing no record. The walk then climbed past it and reported whatever it
found higher up as the effective policy.

RFC 9989 section 4.10.1 draws exactly this line, in a parenthetical that exists
for it:

    "If the set produced by the DNS Tree Walk contains no DMARC Policy Record
    (i.e., any indication that there is no such record as opposed to a
    transient DNS error), Mail Receivers MUST NOT apply the DMARC mechanism to
    the message."

Handling of the error itself is left to receiver discretion by the same
section, but the distinction is not optional, and for an auditing tool it
settles the question: do not report a policy you could not establish. The
unread level is precisely where a different policy would live, so the direction
of the error is not safe either way. A subdomain whose parent could not be read
was told "Inherited: none (from example.com)" when the parent may publish
p=reject, and the mirror case tells an operator they are protected when they
are not.

The card's own _dmarc lookup was never the problem: it uses raise_on_failure
and already reported "unavailable" when the Author Domain's own query failed.
Only an intermediate level going unread produced a confident wrong answer.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import dmarc_tree_walk
from conftest import FakeZone

DOMAIN = "a.b.walk.test"
MID = "_dmarc.b.walk.test"


def _zone(fail_middle):
    z = FakeZone({
        DOMAIN: {"A": ["203.0.113.2"], "TXT": ["v=spf1 -all"], "NS": ["ns1.walk.test"]},
        "b.walk.test": {"A": ["203.0.113.3"]},
        "walk.test": {"A": ["203.0.113.1"]},
        "_dmarc.walk.test": {"TXT": ["v=DMARC1; p=none; rua=mailto:r@walk.test"]},
        "ns1.walk.test": {"A": ["203.0.113.53"]},
    })
    return z.fail(MID, "TXT") if fail_middle else z


def _dmarc_card(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


# ---------------------------------------------------------------
# The walk itself
# ---------------------------------------------------------------

def test_a_failed_level_is_marked_and_not_reported_as_absent(audit_zone):
    walk = audit_zone(_zone(True), lambda: dmarc_tree_walk.dmarc_tree_walk(DOMAIN))

    assert walk["walk_incomplete"] is True
    failed = [s for s in walk["steps"] if s.get("lookup_failed")]
    assert [s["query"] for s in failed] == [MID], (
        f"exactly the unread level must be marked; got "
        f"{[(s['query'], s.get('lookup_failed')) for s in walk['steps']]}"
    )


def test_a_complete_walk_is_not_flagged(audit_zone):
    walk = audit_zone(_zone(False), lambda: dmarc_tree_walk.dmarc_tree_walk(DOMAIN))

    assert walk["walk_incomplete"] is False
    assert not any(s.get("lookup_failed") for s in walk["steps"])
    assert walk["effective_policy"] == "none"


def test_absence_and_failure_are_different_at_the_query(audit_zone):
    """NXDOMAIN and NoAnswer are answers. Everything else is not."""
    absent = audit_zone(_zone(False), lambda: dmarc_tree_walk._query_dmarc("nothing.walk.test"))
    failed = audit_zone(_zone(True), lambda: dmarc_tree_walk._query_dmarc("b.walk.test"))

    assert absent is None
    assert failed is dmarc_tree_walk.LOOKUP_FAILED
    assert failed is not None, "the sentinel must be distinguishable from absence"


# ---------------------------------------------------------------
# What the reader is told
# ---------------------------------------------------------------

def test_an_unread_level_does_not_produce_an_inherited_policy(audit):
    card = _dmarc_card(audit(_zone(True), DOMAIN, scope="dmarc"))

    assert card["status"] == "unavailable", (
        f"a policy was stated across a level the walk could not read: "
        f"{card['status']!r} / {card['verdict']!r}"
    )
    assert "inherited" not in card["verdict"].lower()
    assert "none" not in card["verdict"].lower() or "not checked" in card["verdict"].lower()


def test_the_control_still_inherits(audit):
    """The fix must not suppress a real inherited policy."""
    card = _dmarc_card(audit(_zone(False), DOMAIN, scope="dmarc"))

    assert card["status"] != "unavailable"
    assert "inherited" in card["verdict"].lower()
    assert "walk.test" in card["verdict"]


def test_the_summary_layers_do_not_claim_a_policy_either(audit):
    result = audit(_zone(True), DOMAIN, scope="dmarc")

    assert result["resilience"]["mechanisms"]["dmarc"]["status"] == "inconclusive"
    prose = " ".join([
        result["executive_summary"]["verdict"],
        result["executive_summary"]["deliverability_summary"],
    ]).lower()
    assert "p=none" not in prose
    assert "monitoring" not in prose
