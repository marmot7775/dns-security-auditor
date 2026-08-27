"""Regression test for MTA-STS max-age analysis never being emitted.

Bug 42: _build_mta_sts_deep read raw["max_age"], but check_mta_sts
publishes the parsed policy fields under a policy_ prefix and sets
result["policy_max_age"] (checks_extra.py). There is no bare "max_age" key
on the check result, so max_age_note and max_age_level were never set and
the "very short cache" warning never fired for any domain.

The adjacent policy_file local read "policy_file_content", a key nothing in
the repo produces, and was never used; it is gone.

Consumed by the JSON API only today, so there is no UI or PDF assertion to
make.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from result_transformer import _build_mta_sts_deep
import checks_extra


def _deep(max_age):
    return _build_mta_sts_deep(
        {"policy_mode": "enforce", "policy_max_age": max_age},
        "example.com",
    )


def test_short_max_age_produces_a_warning():
    deep = _deep(300)
    assert deep["max_age_level"] == "warning"
    assert "300s" in deep["max_age_note"]
    assert "Very short cache" in deep["max_age_note"]


def test_good_max_age_passes():
    deep = _deep(604800)
    assert deep["max_age_level"] == "pass"


def test_long_max_age_is_info():
    deep = _deep(31536000)
    assert deep["max_age_level"] == "info"


def test_absent_max_age_emits_nothing():
    deep = _build_mta_sts_deep({"policy_mode": "enforce"}, "example.com")
    assert "max_age_note" not in deep
    assert "max_age_level" not in deep


def test_reads_the_key_the_check_actually_publishes():
    # Guards against the rename that caused the bug: build the raw dict the
    # way check_mta_sts does, from the policy parser's own output, rather
    # than hardcoding a key that only looks right.
    policy, _ = checks_extra._validate_mta_sts_policy(
        "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 300\n",
        "example.com",
    )
    raw = {
        "policy": policy,
        "policy_mode": policy.get("mode"),
        "policy_mx": policy.get("mx_patterns", []),
        "policy_max_age": policy.get("max_age"),
    }
    assert raw["policy_max_age"] == 300
    assert _build_mta_sts_deep(raw, "example.com")["max_age_level"] == "warning"
