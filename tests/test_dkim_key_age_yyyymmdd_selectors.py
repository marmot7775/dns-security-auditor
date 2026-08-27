"""Regression test for YYYYMMDD selectors being unreadable, and UNKNOWN
scoring better than OVERDUE.

Bug 37: SELECTOR_PATTERNS['date_based'] covered YYYYMM, YYYY-MM and YYMM but
not YYYYMMDD, which is Google Workspace's own rotating selector format. A
selector like 20230601 fell through every pattern and came back "Unknown
age", so the module could not read the date format it is most likely to meet.

The scoring half made the miss actively rewarding: UNKNOWN scored 50 and
OVERDUE scored 30, so a domain whose old selectors could not be parsed
graded higher than one whose equally old selectors were read correctly.
Failing to understand a key must not improve the hygiene grade.

dkim_key_age.py has no caller in the audit path, so there is no transformed
card to assert against: the assertions are on analyze_key and on
get_security_hygiene_score, the two results this module produces.
"""
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dkim_key_age import DKIMKeyAgeAnalyzer

RECORD = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest"


def _analyze(selector, bits=2048):
    return DKIMKeyAgeAnalyzer("example.com").analyze_key(selector, RECORD, bits)


def _age_months(result):
    assert result["estimated_age"], "no age was estimated"
    return int(result["estimated_age"].lstrip("~").split()[0])


def test_yyyymmdd_selector_reads_the_same_as_the_yyyymm_form():
    """20230601 is the Google Workspace format and must land on the same date
    as 202306, which the old patterns already handled."""
    full = _analyze("20230601")
    short = _analyze("202306")

    assert full["estimated_age"] != "Unknown age"
    assert full["age_confidence"] == "HIGH"
    assert abs(_age_months(full) - _age_months(short)) <= 1
    assert full["rotation_status"] == short["rotation_status"]


def test_a_recent_yyyymmdd_selector_is_not_reported_overdue():
    now = datetime.now()
    month, year = now.month - 1, now.year
    if month <= 0:
        month += 12
        year -= 1
    recent = _analyze(f"{year}{month:02d}15")

    assert recent["age_confidence"] == "HIGH"
    assert recent["rotation_status"] == "CURRENT"


def test_an_impossible_date_does_not_become_a_bogus_age():
    """20230230 is not a date. It must fall through, not resolve."""
    assert _analyze("20230230")["estimated_age"] == "Unknown age"


def test_the_other_date_formats_still_parse():
    for selector in ("202306", "2023-06", "2306"):
        result = _analyze(selector)
        assert result["age_confidence"] == "HIGH", f"{selector} stopped parsing"


def test_unparsed_selectors_do_not_outscore_identified_overdue_keys():
    """The scoring half of the bug: UNKNOWN scored 50 against OVERDUE's 30."""
    unknown = DKIMKeyAgeAnalyzer("unknown.example")
    unknown.analyze_key("mail", RECORD, 2048)
    unknown.analyze_key("smtp", RECORD, 2048)

    overdue = DKIMKeyAgeAnalyzer("overdue.example")
    overdue.analyze_key("202001", RECORD, 2048)
    overdue.analyze_key("202002", RECORD, 2048)

    assert {k["rotation_status"] for k in unknown.keys_analyzed} == {"UNKNOWN"}
    assert {k["rotation_status"] for k in overdue.keys_analyzed} == {"OVERDUE"}

    assert unknown.get_security_hygiene_score()["score"] <= (
        overdue.get_security_hygiene_score()["score"]
    ), "not reading a key must not beat reading it and finding it overdue"


def test_the_google_selector_that_motivated_the_bug_now_grades_honestly():
    """Before the fix, four unreadable Google selectors graded F-with-50s as
    a C. They are old keys and must not grade above the overdue band."""
    analyzer = DKIMKeyAgeAnalyzer("example.com")
    for selector in ("20230601", "20221208", "20210112", "20161025"):
        analyzer.analyze_key(selector, RECORD, 2048)

    assert all(k["rotation_status"] == "OVERDUE" for k in analyzer.keys_analyzed)
    score = analyzer.get_security_hygiene_score()
    assert score["overdue"] == 4
    assert score["grade"] == "F"
