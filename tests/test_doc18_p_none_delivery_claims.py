"""Regression tests for doc 18 item 7: claims the tool cannot source.

p=none (and the unselected fraction of pct<100) requests no receiver
action. Each receiver's own filtering still applies independently, and a
message failing authentication at p=none is routinely filtered anyway.
The audit cannot know what any given receiver actually did with a
message, so it must not assert that spoofed mail "is still delivered" or
"reaches inboxes" -- only that no DMARC action was requested.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import remediation_planner
import result_transformer

_FORBIDDEN = ("still delivered", "still reach", "delivered normally", "delivered to recipients")


def _assert_no_delivery_claim(text):
    lowered = text.lower()
    for phrase in _FORBIDDEN:
        assert phrase not in lowered, f"unsourced delivery claim {phrase!r} in: {text!r}"


def test_dmarc_card_verdict_for_monitoring_makes_no_delivery_claim():
    card = result_transformer.transform_dmarc({
        "domain": "example.com",
        "record": "v=DMARC1; p=none; rua=mailto:a@example.com",
        "policy": "none", "rua": "mailto:a@example.com", "issues": [],
    })
    _assert_no_delivery_claim(card["verdict"])
    _assert_no_delivery_claim(card["explanation"])


def test_dmarc_card_explanation_drops_the_unsourced_pre_deployment_claim():
    card = result_transformer.transform_dmarc({
        "domain": "example.com",
        "record": "v=DMARC1; p=none; rua=mailto:a@example.com",
        "policy": "none", "rua": "mailto:a@example.com", "issues": [],
    })
    assert "pre-deployment" not in card["explanation"].lower()


def test_roadmap_monitoring_impact_makes_no_delivery_claim():
    roadmap = result_transformer.build_security_roadmap([{
        "name": "DMARC", "status": "warn", "pill_label": "Not enforcing",
        "tag_breakdown": {"health": {"status": "monitoring"}},
    }])
    monitoring_items = [i for i in roadmap["items"]
                         if "monitoring" in i.get("action", "").lower()
                         or "enforcement" in i.get("action", "").lower()]
    assert monitoring_items
    for item in monitoring_items:
        _assert_no_delivery_claim(item["impact"])


def test_deliverability_summary_for_p_none_drops_unsourced_client_behavior_claim():
    checks = [
        {"name": "DMARC", "status": "warn", "pill_label": "Not enforcing", "record": "v=DMARC1; p=none"},
        {"name": "SPF", "status": "pass", "record": "v=spf1 -all"},
        {"name": "DKIM", "status": "pass"},
    ]
    summary = result_transformer.build_executive_summary(checks, {"items": []})
    text = summary.get("deliverability_summary", "") or ""
    assert "gmail, yahoo, and outlook may treat" not in text.lower()


def test_audit_engine_p_none_issue_makes_no_delivery_claim():
    import inspect
    src = inspect.getsource(audit_engine)
    assert "failed emails still reach inboxes" not in src.lower()
    assert "are still delivered normally" not in src.lower()


def test_remediation_planner_p_none_makes_no_delivery_claim():
    import inspect
    src = inspect.getsource(remediation_planner)
    assert "unauthenticated mail is still delivered" not in src.lower()
