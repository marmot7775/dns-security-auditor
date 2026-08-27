"""Regression test for the MTA-STS vs MX coverage check never running.

Bug: build_consistency_findings read detail.get("host", "") out of
mx_details entries, but mx_check.py:291 produces those entries with a
"hostname" key, not "host" -- every entry in mx_details there uses
"hostname". So actual_mx was always empty, the "if mta_sts_mx and
actual_mx" guard never passed, and a mail-breaking MTA-STS/MX mismatch
was never surfaced.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from result_transformer import build_consistency_findings


def test_mta_sts_coverage_gap_is_detected():
    raw_results = {
        "mta_sts": {"policy_mx": ["mail.example.com"]},
        "mx": {
            "mx_details": [
                {"hostname": "mail.example.com"},
                {"hostname": "backup.other-host.net"},
            ]
        },
    }

    findings = build_consistency_findings(raw_results, checks=[])

    assert findings is not None, (
        "MTA-STS policy missing backup.other-host.net must be reported, "
        "not silently dropped"
    )
    titles = [f["title"] for f in findings]
    assert "MTA-STS policy does not cover all MX hosts" in titles
    coverage_finding = next(
        f for f in findings if f["title"] == "MTA-STS policy does not cover all MX hosts"
    )
    assert "backup.other-host.net" in coverage_finding["detail"]
    assert "mail.example.com" not in coverage_finding["detail"]


def test_full_coverage_produces_no_finding():
    raw_results = {
        "mta_sts": {"policy_mx": ["mail.example.com", "backup.other-host.net"]},
        "mx": {
            "mx_details": [
                {"hostname": "mail.example.com"},
                {"hostname": "backup.other-host.net"},
            ]
        },
    }

    findings = build_consistency_findings(raw_results, checks=[])

    titles = [f["title"] for f in (findings or [])]
    assert "MTA-STS policy does not cover all MX hosts" not in titles
