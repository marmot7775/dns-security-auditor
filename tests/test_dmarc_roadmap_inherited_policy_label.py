"""Regression test for the inherited-policy label not naming the policy.

Finding E: build_dmarc_roadmap computed inherited_policy from the tree
walk's effective_policy and then never used it, so a subdomain covered by
its organizational domain's record always showed the generic "Inherited
policy". Every other stage label names what it found ("Monitoring
(p=none)", "Full Reject (p=reject)"), and the value needed to do the same
here was already sitting in an unused local.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spf_execution_engine import build_dmarc_roadmap


def _roadmap(tree_walk):
    raw_dmarc = {
        "record": None,
        "policy": None,
        "pct": None,
        "rua": None,
        "t": None,
        "domain": "mail.example.com",
    }
    raw_spf = {"record": "v=spf1 -all", "lookup_count": 0, "all_mechanism": "-all"}
    raw_dkim = {"found_selectors": []}
    return build_dmarc_roadmap(
        raw_dmarc, raw_spf, raw_dkim,
        tree_walk=tree_walk, has_mx=True, is_defensive=False,
    )


def test_label_names_the_inherited_policy():
    roadmap = _roadmap({
        "policy_source": "example.com",
        "is_subdomain": True,
        "effective_policy": "reject",
    })
    assert roadmap["current_stage"] == "inherited"
    assert roadmap["current_stage_label"] == "Inherited policy (p=reject)"


def test_quarantine_inheritance_named_too():
    roadmap = _roadmap({
        "policy_source": "example.com",
        "is_subdomain": True,
        "effective_policy": "quarantine",
    })
    assert roadmap["current_stage_label"] == "Inherited policy (p=quarantine)"


def test_falls_back_to_the_generic_label_when_policy_is_unknown():
    roadmap = _roadmap({
        "policy_source": "example.com",
        "is_subdomain": True,
        "effective_policy": None,
    })
    assert roadmap["current_stage_label"] == "Inherited policy"


def test_non_inherited_stage_labels_are_untouched():
    raw_dmarc = {
        "record": "v=DMARC1; p=none",
        "policy": "none",
        "pct": None,
        "rua": None,
        "t": None,
        "domain": "example.com",
    }
    raw_spf = {"record": "v=spf1 -all", "lookup_count": 0, "all_mechanism": "-all"}
    roadmap = build_dmarc_roadmap(
        raw_dmarc, raw_spf, {"found_selectors": []},
        tree_walk=None, has_mx=True, is_defensive=False,
    )
    assert roadmap["current_stage_label"] == "Monitoring (p=none)"
