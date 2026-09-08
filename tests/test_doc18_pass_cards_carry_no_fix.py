"""Regression tests for doc 18 item 1: a pass card must carry no fix.

CAA, Nameservers, and MTA-STS each had a status override that forced "pass"
(or a top-level fix) independent of whether a real, unresolved problem was
still being reported in the same card.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import result_transformer


# ---------------------------------------------------------------------------
# CAA: an optional improvement (missing iodef/issuewild) must not surface
# as a top-level fix on an otherwise-passing card.
# ---------------------------------------------------------------------------

def test_caa_pass_with_only_optional_suggestions_carries_no_fix():
    raw = {
        "status": "warning",
        "record_count": 1,
        "records": [{"raw": '0 issue "pki.goog"'}],
        "authorized_cas": ["pki.goog"],
        "wildcard_cas": [],
        "has_issue": True,
        "has_issuewild": False,
        "has_iodef": False,
        "iodef_destinations": [],
        "issues": [{
            "severity": "info",
            "issue": "No iodef",
            "plain_english": "Without an iodef record, you will not be notified.",
            "fix": 'Add a CAA record: 0 iodef "mailto:security@example.com".',
        }],
    }
    card = result_transformer.transform_caa(raw, "example.com")
    assert card["status"] == "pass"
    assert card["fix"] is None


def test_caa_fail_still_carries_its_fix():
    raw = {
        "status": "error",
        "record_count": 1,
        "records": [{"raw": '0 issue "pki.goog"'}],
        "authorized_cas": ["pki.goog"],
        "wildcard_cas": [],
        "has_issue": True,
        "has_issuewild": False,
        "has_iodef": False,
        "iodef_destinations": [],
        "issues": [{
            "severity": "error",
            "issue": "Malformed CAA record",
            "plain_english": "A CAA record could not be parsed.",
            "fix": "Fix the malformed CAA record.",
        }],
    }
    card = result_transformer.transform_caa(raw, "example.com")
    assert card["status"] == "fail"
    assert card["fix"] == "Fix the malformed CAA record."


# ---------------------------------------------------------------------------
# Nameservers: single-provider is an optional resilience suggestion, not a
# reason to attach a top-level fix to a passing card.
# ---------------------------------------------------------------------------

def test_nameservers_pass_with_single_provider_suggestion_carries_no_fix():
    raw = {
        "status": "ok",
        "ns_count": 4,
        "nameservers": [
            {"hostname": f"ns{i}.google.com", "ipv4": ["216.239.3{}.10".format(i)],
             "ipv6": [], "resolves": True, "authoritative": True, "response_time_ms": 30}
            for i in range(4)
        ],
        "providers": ["Google Cloud DNS"],
        "networks": ["216.239.32.0", "216.239.34.0", "216.239.36.0", "216.239.38.0"],
        "soa_serials_consistent": True,
        "soa_serial": 12345,
        "issues": [{
            "severity": "info",
            "issue": "All nameservers with a single provider (Google Cloud DNS)",
            "plain_english": "All nameservers are hosted by Google Cloud DNS.",
            "fix": "Consider adding a secondary DNS provider for maximum resilience.",
        }],
    }
    card = result_transformer.transform_nameservers(raw, "google.com")
    assert card["status"] == "pass"
    assert card["fix"] is None
    assert any("hosted by Google Cloud DNS" in d["text"] for d in card["details"])


# ---------------------------------------------------------------------------
# MTA-STS: enforce mode with a real MX pattern mismatch is a warn, not a
# pass, and the pass path must not carry a fix.
# ---------------------------------------------------------------------------

def _mta_sts_raw(policy_mx, actual_note=""):
    return {
        "status": "warning",
        "txt_record": "v=STSv1; id=20240101",
        "policy_mode": "enforce",
        "issues": [{
            "severity": "warning",
            "issue": "MTA-STS mx pattern doesn't match actual MX records",
            "plain_english": f"Actual MX records are: {actual_note}.",
            "fix": "Update the mx lines to match your actual MX hostnames.",
        }],
    }


def test_mta_sts_enforce_with_real_mx_mismatch_is_not_a_pass():
    raw = _mta_sts_raw(["*.example.com"], "smtp.google.com")
    card = result_transformer.transform_mta_sts(raw, "google.com")
    assert card["status"] != "pass"
    assert card["fix"] == "Update the mx lines to match your actual MX hostnames."


def test_mta_sts_enforce_with_no_issues_is_a_pass():
    raw = {
        "status": "ok",
        "txt_record": "v=STSv1; id=20240101",
        "policy_mode": "enforce",
        "issues": [],
    }
    card = result_transformer.transform_mta_sts(raw, "example.com")
    assert card["status"] == "pass"
    assert card["fix"] is None
