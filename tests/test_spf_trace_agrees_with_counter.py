"""Regression test: the execution trace must agree with the lookup count
printed beside it.

_walk_tree did not apply the two rules the counter applies: RFC 7208
section 6.1 (a redirect is ignored when an 'all' mechanism is present) and
section 5.1 (terms after 'all' are never evaluated). On

    v=spf1 include:a.com redirect=big.com -all

one call produced total_lookups 1 and a final flat step whose running_total
was 2, both rendered on the same screen, with the redirect shown as a live
lookup the tool elsewhere correctly reports as ignored.

The second defect was in the same function: child nodes were paired to
mechanisms by position, which assumes every include and redirect produced
one. A suppressed redirect breaks that assumption, so on

    v=spf1 redirect=b.com include:a.com -all

the include target's mechanisms rendered nested under the redirect and the
include rendered as an empty leaf.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spf_execution_engine
import spf_recursive
from conftest import FakeZone, fake_dns

ZONE_EXTRAS = {
    "a.com": {"TXT": ["v=spf1 ip4:198.51.100.1 -all"]},
    "b.com": {"TXT": ["v=spf1 ip4:203.0.113.1 -all"]},
    "big.com": {"TXT": ["v=spf1 include:x1.com -all"]},
    "x1.com": {"TXT": ["v=spf1 -all"]},
}


def _trace(domain, record):
    zone = dict(ZONE_EXTRAS)
    zone[domain] = {"TXT": [record]}
    with fake_dns(FakeZone(zone)):
        result = spf_recursive.count_spf_lookups(domain)
        trace = spf_execution_engine.build_spf_execution_trace(
            result, result["record"]
        )
    return result, trace


def test_total_and_final_running_total_agree_with_a_redirect_and_an_all():
    result, trace = _trace(
        "traceall.example.test", "v=spf1 include:a.com redirect=big.com -all"
    )

    assert result["total_lookups"] == 1, (
        f"redirect=big.com is ignored per RFC 7208 6.1 because -all is "
        f"present; only include:a.com counts. Got {result['total_lookups']}"
    )

    finals = [s["running_total"] for s in trace["flat_steps"]]
    assert finals[-1] == trace["total_lookups"], (
        f"The trace's last running_total must equal the total printed above "
        f"it. total={trace['total_lookups']} steps="
        f"{[(s['mechanism'], s['running_total']) for s in trace['flat_steps']]}"
    )
    assert max(finals) <= trace["total_lookups"], (
        f"No step may claim more lookups than the record consumes; got "
        f"{[(s['mechanism'], s['running_total']) for s in trace['flat_steps']]}"
    )

    mechanisms = [s["mechanism"] for s in trace["flat_steps"]]
    assert "redirect=big.com" not in mechanisms, (
        f"An ignored redirect must not appear in the trace as a live lookup; "
        f"got {mechanisms}"
    )


def test_terms_after_all_are_not_traced():
    result, trace = _trace(
        "afterall.example.test", "v=spf1 ip4:192.0.2.1 -all include:a.com"
    )

    assert result["total_lookups"] == 0
    mechanisms = [s["mechanism"] for s in trace["flat_steps"]]
    assert "include:a.com" not in mechanisms, (
        f"RFC 7208 5.1: nothing after 'all' is evaluated, so nothing after "
        f"it belongs in the trace; got {mechanisms}"
    )
    assert trace["flat_steps"][-1]["running_total"] == trace["total_lookups"]


def test_subtree_is_paired_with_the_include_that_opened_it():
    result, trace = _trace(
        "pairing.example.test", "v=spf1 redirect=b.com include:a.com -all"
    )

    assert result["total_lookups"] == 1

    steps = trace["flat_steps"]
    parents = [s for s in steps if s["type"] in ("include", "redirect")]
    assert [s["mechanism"] for s in parents] == ["include:a.com"], (
        f"The redirect is ignored, so include:a.com is the only parent step; "
        f"got {[s['mechanism'] for s in steps]}"
    )

    include_idx = steps.index(parents[0])
    nested = [s for s in steps[include_idx + 1:] if s["depth"] == 1]
    assert [s["mechanism"] for s in nested] == ["ip4:198.51.100.1", "-all"], (
        f"a.com's own mechanisms must render under include:a.com, not under "
        f"the suppressed redirect; got "
        f"{[(s['depth'], s['mechanism']) for s in steps]}"
    )
    assert steps[-1]["running_total"] == trace["total_lookups"]
