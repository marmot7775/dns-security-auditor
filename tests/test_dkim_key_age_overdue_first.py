"""Regression test for overdue DKIM keys being listed last in the report.

Bug 38: generate_rotation_report sorted with

    key=lambda x: (urgency_order.get(x['urgency'], 3),
                   x['rotation_status'] == 'OVERDUE')

The second element is a bare equality test, so it is False (0) for a key that
is fine and True (1) for one that is overdue. An ascending sort therefore put
every healthy key ahead of the overdue ones inside each urgency band, which
is backwards for a report whose whole purpose is to surface the keys that
need rotating. The summary counted them correctly, so the numbers at the
bottom disagreed with the order above them.

dkim_key_age.py has no caller in the audit path, so there is no transformed
card to assert against: the assertions are on generate_rotation_report, the
rendered text this module exists to produce.
"""
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dkim_key_age import DKIMKeyAgeAnalyzer

RECORD = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest"

# A YYYYMM selector the age estimator reads as roughly three months old, so
# the test does not go stale as the calendar moves.
_now = datetime.now()
_month = _now.month - 3
_year = _now.year
if _month <= 0:
    _month += 12
    _year -= 1
RECENT = f"{_year}{_month:02d}"
ANCIENT = "202001"


def _position(report, selector):
    marker = f"Selector: {selector}"
    assert marker in report, f"{selector} missing from the report"
    return report.index(marker)


def test_the_fixture_selectors_still_mean_what_the_test_assumes():
    analyzer = DKIMKeyAgeAnalyzer("example.com")
    assert analyzer.analyze_key(ANCIENT, RECORD, 2048)["rotation_status"] == "OVERDUE"
    assert analyzer.analyze_key(RECENT, RECORD, 2048)["rotation_status"] == "CURRENT"


def test_overdue_key_is_listed_before_a_healthy_one_in_the_same_band():
    analyzer = DKIMKeyAgeAnalyzer("example.com")
    # Added healthy-first on purpose: the sort is stable, so a sort that does
    # nothing useful would leave the overdue key second and pass by accident.
    analyzer.analyze_key(RECENT, RECORD, 2048)
    analyzer.analyze_key(ANCIENT, RECORD, 2048)

    report = analyzer.generate_rotation_report()
    assert _position(report, ANCIENT) < _position(report, RECENT)


def test_report_order_agrees_with_the_summary_counts():
    analyzer = DKIMKeyAgeAnalyzer("example.com")
    analyzer.analyze_key(RECENT, RECORD, 2048)
    analyzer.analyze_key(ANCIENT, RECORD, 2048)

    report = analyzer.generate_rotation_report()
    assert "Overdue: 1" in report
    # The one key the summary calls overdue is the first one listed.
    first_listed = min(
        (ANCIENT, RECENT), key=lambda s: _position(report, s)
    )
    assert first_listed == ANCIENT


def test_urgency_still_outranks_overdue_across_bands():
    """A weak key that is not yet overdue stays above a strong overdue one:
    the fix reorders inside each urgency band, it does not replace it."""
    analyzer = DKIMKeyAgeAnalyzer("example.com")
    analyzer.analyze_key(ANCIENT, RECORD, 2048)   # STANDARD, OVERDUE
    analyzer.analyze_key(RECENT, RECORD, 1024)    # CRITICAL, not overdue

    report = analyzer.generate_rotation_report()
    assert _position(report, RECENT) < _position(report, ANCIENT)
