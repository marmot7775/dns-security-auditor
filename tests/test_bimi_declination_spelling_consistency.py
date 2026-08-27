"""Regression test for the two spellings of a BIMI declination record
getting different verdicts.

Bug: "l" and "a" are both optional with an empty default, so
`v=BIMI1; l=; a=;` and `v=BIMI1;` assert the same thing -- the domain
declines to publish a logo indicator. The bare form ("l" absent) hit
the "warning" branch, dragging the whole card to warn, while the empty
form ("l=") hit the "info" branch and left the card at ok. Both must
produce the same status and the same message.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from checks_extra import _validate_bimi_record


def _l_tag_issues(issues):
    return [i for i in issues if "logo" in i.get("issue", "").lower() or "'l'" in i.get("issue", "")]


def test_empty_and_absent_l_tag_produce_identical_verdict():
    empty_tags, empty_issues = _validate_bimi_record("v=BIMI1; l=; a=;")
    absent_tags, absent_issues = _validate_bimi_record("v=BIMI1;")

    empty_l = _l_tag_issues(empty_issues)
    absent_l = _l_tag_issues(absent_issues)

    assert len(empty_l) == 1 and len(absent_l) == 1
    assert empty_l[0]["severity"] == absent_l[0]["severity"] == "info", (
        f"Both spellings must be an info-level declination, not a warning; "
        f"got empty={empty_l[0]['severity']!r} absent={absent_l[0]['severity']!r}"
    )
    assert empty_l[0]["issue"] == absent_l[0]["issue"]
