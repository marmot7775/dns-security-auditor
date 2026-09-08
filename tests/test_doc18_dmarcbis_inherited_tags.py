"""Regression tests for doc 18 item 3: np/sp inherit, they are not gaps.

A DMARC record's np and sp tags are both OPTIONAL (RFC 9989). An absent
tag inherits its value from p=, so a record without them is fully
compliant, not "not fully RFC 9989-ready". _calculate_dmarcbis_health
used to gate the green "Ready" verdict on np being present, and listed
"sp= not set (inherits correctly)" as a reason under "Compatible", both
of which penalized a record for a gap that does not exist.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import result_transformer


def test_enforcing_record_without_np_or_sp_is_fully_ready():
    tags = {"v": "DMARC1", "p": "reject", "rua": "mailto:reports@example.com"}
    health = result_transformer._calculate_dmarcbis_health(tags, "reject", [])
    assert health["status"] == "ready"
    assert health["reasons"] == []


def test_sp_absent_produces_no_reason_even_when_record_is_only_compatible():
    # t=y (testing mode) keeps this out of "Ready" for an unrelated reason,
    # so the Compatible reasons list is exercised without sp or np hiding
    # the assertion.
    tags = {"v": "DMARC1", "p": "reject", "rua": "mailto:reports@example.com", "t": "y"}
    health = result_transformer._calculate_dmarcbis_health(tags, "reject", [])
    assert health["status"] == "compatible"
    assert not any("sp" in r for r in health["reasons"])
    assert not any("np" in r for r in health["reasons"])


def test_deprecated_tags_still_block_ready_and_still_appear_as_a_reason():
    tags = {"v": "DMARC1", "p": "reject", "rua": "mailto:reports@example.com", "pct": "50"}
    health = result_transformer._calculate_dmarcbis_health(tags, "reject", [])
    assert health["status"] == "compatible"
    assert any("Deprecated tags" in r for r in health["reasons"])


def _roadmap_checks(dmarc_record):
    return [{
        "name": "DMARC",
        "status": "pass",
        "pill_label": "Pass",
        "record": dmarc_record,
        "tag_breakdown": {},
    }]


def test_np_suggestion_is_low_priority_and_only_at_enforcement():
    checks = _roadmap_checks("v=DMARC1; p=reject; rua=mailto:reports@example.com")
    roadmap = result_transformer.build_security_roadmap(checks)
    np_items = [i for i in roadmap["items"] if i["protocol"] == "DMARC" and "np=" in i["action"]]
    assert len(np_items) == 1
    assert np_items[0]["priority"] == "low"


def test_np_suggestion_absent_when_policy_is_not_enforcing():
    checks = _roadmap_checks("v=DMARC1; p=none; rua=mailto:reports@example.com")
    roadmap = result_transformer.build_security_roadmap(checks)
    np_items = [i for i in roadmap["items"] if i["protocol"] == "DMARC" and "np=" in i["action"]]
    assert np_items == []


def test_np_suggestion_absent_when_np_is_already_set():
    checks = _roadmap_checks("v=DMARC1; p=reject; np=reject; rua=mailto:reports@example.com")
    roadmap = result_transformer.build_security_roadmap(checks)
    np_items = [i for i in roadmap["items"] if i["protocol"] == "DMARC" and "np=" in i["action"]]
    assert np_items == []
