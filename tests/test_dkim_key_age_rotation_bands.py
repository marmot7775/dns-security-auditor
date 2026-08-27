"""Regression test for the rotation schedule being an exact-match lookup.

Bug 36: analyze_key picked its rotation advice with
`ROTATION_SCHEDULE.get(key_size, ROTATION_SCHEDULE[2048])`. ROTATION_SCHEDULE
is keyed by 1024, 2048 and 4096, so any other size fell through to the 2048
default. A 512-bit or 768-bit key, weaker than the 1024-bit key the table
rates CRITICAL, was handed the STANDARD schedule and told "Industry standard
rotation period" with 12 months to act. 3072-bit and 8192-bit keys were
misfiled the same way, less dangerously.

The lookup is banded now. dkim_key_age.py has no caller in the audit path,
so there is no transformed card to assert against here: the assertions are on
analyze_key's returned dict and on generate_rotation_report, the rendered
text this module exists to produce.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dkim_key_age import DKIMKeyAgeAnalyzer

RECORD = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest"


def _analyze(key_size, selector="sel"):
    analyzer = DKIMKeyAgeAnalyzer("example.com")
    return analyzer.analyze_key(selector, RECORD, key_size)


@pytest.mark.parametrize("bits", [256, 512, 768, 1024])
def test_keys_at_or_below_1024_get_the_critical_schedule(bits):
    result = _analyze(bits)
    assert result["urgency"] == "CRITICAL", (
        f"{bits}-bit is weaker than 1024 and must not be filed as STANDARD"
    )
    assert DKIMKeyAgeAnalyzer._rotation_schedule_for(bits)["max_age_months"] == 3


@pytest.mark.parametrize("bits", [2048, 3072])
def test_keys_between_1024_and_4096_get_the_standard_schedule(bits):
    assert _analyze(bits)["urgency"] == "STANDARD"


@pytest.mark.parametrize("bits", [4096, 8192])
def test_keys_at_or_above_4096_get_the_low_schedule(bits):
    result = _analyze(bits)
    assert result["urgency"] == "LOW"
    assert DKIMKeyAgeAnalyzer._rotation_schedule_for(bits)["max_age_months"] == 24


@pytest.mark.parametrize("bits", [0, None, -1, "2048"])
def test_unknown_or_unusable_sizes_fall_back_to_standard(bits):
    """A revoked key has 0 bits. Nothing is known about it, so it must not be
    graded CRITICAL on the strength of a size that was never read."""
    assert DKIMKeyAgeAnalyzer._rotation_schedule_for(bits)["urgency"] == "STANDARD"


def test_the_critical_reason_does_not_claim_a_size_it_was_not_given():
    """The band covers everything at or below 1024, so its text cannot say
    the key is 1024-bit."""
    reason = DKIMKeyAgeAnalyzer._rotation_schedule_for(512)["reason"]
    assert "1024 bits or fewer" in reason


def test_report_gives_a_512_bit_key_the_urgent_advice():
    analyzer = DKIMKeyAgeAnalyzer("example.com")
    analyzer.analyze_key("v2", RECORD, 512)
    report = analyzer.generate_rotation_report()

    assert "Industry standard rotation period" not in report
    assert "every 1 months" in report
