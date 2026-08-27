"""Regression test for the executive summary protocol coverage ring.

Bug: build_executive_summary counted every "warn" status card as configured,
with the pill-label filter (excluding "Not configured"/"Missing") applied
only to "fail". Since a not-configured protocol is rendered as
status="warn", pill_label="Not configured" (see transform_mta_sts and
friends), a domain with zero protocols configured showed a green 7/9 ring
instead of 0/9 red.

Test asserts on the transformed executive-summary card (protocol_coverage),
not on any raw check output.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import result_transformer


def _not_configured_card(name):
    """Shape matches real "not configured" cards, e.g. transform_mta_sts."""
    return {"name": name, "status": "warn", "pill_label": "Not configured"}


def test_zero_configured_protocols_gives_zero_of_nine_red():
    protocol_names = [
        "DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT",
        "DANE", "DNSSEC", "BIMI", "CAA",
    ]
    checks = [_not_configured_card(name) for name in protocol_names]

    summary = result_transformer.build_executive_summary(checks, {"items": []})

    coverage = summary["protocol_coverage"]
    assert coverage["configured"] == 0, (
        f"Expected 0/9 configured for an all-'Not configured' domain, "
        f"got {coverage['configured']}"
    )
    assert coverage["color"] == "red"


def test_actually_configured_warn_card_still_counts():
    """A warn card that IS configured (e.g. a real config warning, not a
    missing one) must still count -- the fix must not just zero out warn."""
    checks = [
        {"name": "DMARC", "status": "warn", "pill_label": "Needs attention"},
        {"name": "SPF", "status": "pass", "pill_label": "Configured"},
    ]
    summary = result_transformer.build_executive_summary(checks, {"items": []})
    assert summary["protocol_coverage"]["configured"] == 2
