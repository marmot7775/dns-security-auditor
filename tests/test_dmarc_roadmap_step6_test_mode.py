"""Regression test for roadmap step 6 completing while t=y is published.

Bug 40: step6_complete looked only at policy and pct, ignoring the t tag
that step 5 exists for. "v=DMARC1; p=quarantine; t=y" showed steps 1
through 6 complete, when test mode drops the effective policy one level
and makes the record behave as p=none. Step 6 is literally "remove t=y to
fully enforce quarantine", so it cannot be complete while t=y is there.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spf_execution_engine import build_dmarc_roadmap


def _roadmap(record, policy, t):
    raw_dmarc = {
        "record": record,
        "policy": policy,
        "pct": None,
        "rua": "mailto:reports@example.com",
        "adkim": "r",
        "aspf": "r",
        "t": t,
        "domain": "example.com",
    }
    raw_spf = {"record": "v=spf1 -all", "lookup_count": 0, "all_mechanism": "-all"}
    raw_dkim = {"found_selectors": ["selector1"]}
    return build_dmarc_roadmap(
        raw_dmarc, raw_spf, raw_dkim,
        tree_walk=None, has_mx=True, is_defensive=False,
    )


def _step(roadmap, stage):
    return next(s for s in roadmap["steps"] if s["stage"] == stage)


def test_quarantine_with_test_mode_leaves_step6_current():
    roadmap = _roadmap("v=DMARC1; p=quarantine; t=y", "quarantine", "y")
    assert _step(roadmap, 5)["status"] == "complete"
    assert _step(roadmap, 6)["status"] == "current", (
        "t=y is still published, so 'remove t=y' is the current step"
    )
    # The step 6 record to publish is the one without t=y.
    assert "t=y" not in (_step(roadmap, 6)["dns_record"] or "")


def test_reject_with_test_mode_leaves_step6_current():
    roadmap = _roadmap("v=DMARC1; p=reject; t=y", "reject", "y")
    assert _step(roadmap, 6)["status"] == "current"
    assert _step(roadmap, 7)["status"] != "complete"


def test_quarantine_without_test_mode_still_completes_step6():
    roadmap = _roadmap("v=DMARC1; p=quarantine", "quarantine", None)
    assert _step(roadmap, 6)["status"] == "complete"


def test_reject_without_test_mode_still_completes_step6():
    roadmap = _roadmap("v=DMARC1; p=reject", "reject", None)
    assert _step(roadmap, 6)["status"] == "complete"


def test_no_step_completes_above_an_incomplete_step6():
    # A roadmap that shows step 7 done while step 6 is still current is
    # self-contradictory.
    roadmap = _roadmap("v=DMARC1; p=reject; t=y", "reject", "y")
    statuses = {s["stage"]: s["status"] for s in roadmap["steps"]}
    assert statuses[6] != "complete"
    assert statuses[7] != "complete"


def test_test_mode_lowers_completion_percentage():
    with_t = _roadmap("v=DMARC1; p=quarantine; t=y", "quarantine", "y")
    without_t = _roadmap("v=DMARC1; p=quarantine", "quarantine", None)
    assert with_t["progress_pct"] < without_t["progress_pct"]
