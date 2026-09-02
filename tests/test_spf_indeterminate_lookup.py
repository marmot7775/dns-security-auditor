"""Regression test: a transient DNS failure on an include target is not the
same answer as "that domain has no SPF record".

_get_spf_record swallowed every exception and returned None, so NXDOMAIN,
SERVFAIL and a timeout were indistinguishable downstream. One SERVFAIL made
the tool advise removing a live include, and silently dropped that subtree's
lookups from the count -- a record that really needs 15 lookups could report
5 and pass.

Asserts on the transformed SPF card and the raw issue list.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer
import spf_recursive

DOMAIN = "servfail.example.test"
RECORD = "v=spf1 include:flaky.example.test ip4:198.51.100.0/24 -all"


def _lookup(domain):
    if domain == DOMAIN:
        return {"record": RECORD, "status": spf_recursive.SPF_FOUND, "error": None}
    return {
        "record": None,
        "status": spf_recursive.SPF_INDETERMINATE,
        "error": f"DNS lookup for {domain} did not complete (NoNameservers)",
    }


def _run():
    with patch.object(audit_engine, "_lookup_txt", return_value=[RECORD]), \
         patch.object(audit_engine, "_lookup_ttl", return_value=None), \
         patch.object(spf_recursive, "_lookup_spf", side_effect=_lookup):
        raw = audit_engine._raw_check_spf(DOMAIN)
    return raw, result_transformer.transform_spf(raw, has_mx=True)


def test_servfail_is_not_reported_as_a_missing_spf_record():
    raw, card = _run()

    issue_texts = " ".join(i.get("issue", "") for i in raw["issues"])
    assert "did not complete" in issue_texts, (
        f"A SERVFAIL must be reported as an incomplete lookup; got: "
        f"{issue_texts!r}"
    )
    assert "has no SPF record" not in issue_texts, (
        f"We do not know that; the query never answered. Got: {issue_texts!r}"
    )
    assert raw["void_lookup_count"] == 0, (
        f"A query that never answered is not an NXDOMAIN or empty answer, so "
        f"it is not a void lookup. Got {raw['void_lookup_count']}"
    )


def test_indeterminate_lookup_suppresses_removal_advice_and_the_pass_verdict():
    raw, card = _run()

    fixes = " ".join(i.get("fix", "") for i in raw["issues"])
    assert "Remove the include for flaky.example.test" not in fixes, (
        f"Never advise removing a live include on the strength of one "
        f"transient DNS failure. Got: {fixes!r}"
    )

    assert card["status"] != "pass", (
        f"The lookup count is unknown, so the card cannot report a clean "
        f"pass. Got {card['status']!r}"
    )
