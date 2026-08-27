"""Regression test for build_dmarc_roadmap raising on any real DMARC
record without a t= tag.

Bug: raw_dmarc.get("t", "").lower() -- but audit_engine._raw_check_dmarc
always initializes the "t" key to None in its result dict (whether or
not the record has a t= tag), so dict.get's default of "" never
applies. Every real DMARC record without the new t= tag hit
AttributeError: 'NoneType' object has no attribute 'lower', losing the
whole roadmap.

build_dmarc_roadmap has no in-repo caller yet, so there is no
transformed card to assert against; the regression is exercised at the
function boundary instead, using the exact dict shape
_raw_check_dmarc produces (t explicitly set to None).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spf_execution_engine import build_dmarc_roadmap


def test_roadmap_builds_when_t_tag_absent():
    raw_dmarc = {
        "record": "v=DMARC1; p=reject; adkim=r; aspf=s",
        "policy": "reject",
        "pct": None,
        "rua": "mailto:reports@example.com",
        "adkim": "r",
        "aspf": "s",
        "t": None,  # matches _raw_check_dmarc's default when t= is absent
        "domain": "example.com",
    }
    raw_spf = {"record": "v=spf1 -all", "lookup_count": 0, "all_mechanism": "-all"}
    raw_dkim = {"found_selectors": ["selector1"]}

    roadmap = build_dmarc_roadmap(
        raw_dmarc, raw_spf, raw_dkim,
        tree_walk=None, has_mx=True, is_defensive=False,
    )

    assert roadmap is not None, "A p=reject record must produce a roadmap, not None"
    assert roadmap["current_stage"] == "full_reject"
    step5 = next(s for s in roadmap["steps"] if s["stage"] == 5)
    assert step5["status"] == "complete"
