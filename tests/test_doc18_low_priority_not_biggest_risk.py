"""Regression test: a low-priority-only roadmap must not fill the
biggest-risk slot.

Discovered live on google.com after adding the low-priority np= roadmap
suggestion (doc 18 item 3): with no critical/high/medium items, that one
low-priority item became roadmap_items[0], and the executive summary
showed "YOUR BIGGEST RISK RIGHT NOW: Purely optional. Subdomains already
inherit your enforcing policy without it." -- a risk box calling its own
contents optional. An empty roadmap already had the honest fallback
("No urgent risks found"); a roadmap containing only low-priority items
needs the same fallback, not whichever item happens to be first.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import result_transformer


def test_low_priority_only_roadmap_does_not_become_biggest_risk():
    checks = [{
        "name": "DMARC", "status": "pass", "pill_label": "Pass",
        "record": "v=DMARC1; p=reject; rua=mailto:a@example.com",
    }]
    roadmap = result_transformer.build_security_roadmap(checks)
    assert all(i["priority"] == "low" for i in roadmap["items"])
    assert roadmap["items"], "expected the np= suggestion to be present for this fixture"

    summary = result_transformer.build_executive_summary(checks, roadmap)
    assert "purely optional" not in summary["biggest_risk"].lower()
    assert "no urgent risks found" in summary["biggest_risk"].lower()
    assert summary["biggest_risk_severity"] == "none"


def test_medium_priority_item_still_wins_over_low():
    checks = [
        {"name": "DMARC", "status": "pass", "pill_label": "Pass",
         "record": "v=DMARC1; p=reject; rua=mailto:a@example.com"},
        {"name": "MTA-STS", "status": "warn", "pill_label": "Not configured"},
    ]
    roadmap = result_transformer.build_security_roadmap(checks)
    summary = result_transformer.build_executive_summary(checks, roadmap)
    assert summary["biggest_risk_severity"] == "medium"
    assert "mta-sts" in summary["biggest_risk"].lower() or "encryption" in summary["biggest_risk"].lower()
