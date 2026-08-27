"""Regression test for a DMARC policy downgrade being classified as an
improvement.

Bug: in _classify_change, the policy-rank rule correctly set
is_improvement=False and a "Policy downgraded" description for p=reject
-> p=none. But the later "rua added" rule unconditionally overwrote both
change["description"] and change["is_improvement"] whenever rua was newly
present, with no check for whether an earlier rule had already decided the
verdict. A p=reject -> p=none downgrade that also added rua= was rendered
as "Added aggregate reporting (rua=)" with a green improvement check,
hiding the regression.

Test asserts on the transformed change-detection card
(build_change_detection output), not on _classify_change's raw dict.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import result_transformer


def _dmarc_history(old_record, new_record):
    return {
        "dmarc": [
            {"record_value": new_record, "record_hash": "new", "timestamp": "2026-08-26T00:00:00Z"},
            {"record_value": old_record, "record_hash": "old", "timestamp": "2026-08-19T00:00:00Z"},
        ]
    }


def test_policy_downgrade_with_rua_added_is_a_regression():
    history = _dmarc_history(
        "v=DMARC1; p=reject",
        "v=DMARC1; p=none; rua=mailto:x@y.com",
    )
    result = result_transformer.build_change_detection({}, history, first_seen="2026-08-19T00:00:00Z")

    dmarc_changes = [c for c in result["changes"] if c["record_type"] == "dmarc"]
    assert len(dmarc_changes) == 1
    change = dmarc_changes[0]

    assert change["is_improvement"] is False, (
        f"p=reject -> p=none is a regression even though rua was added; "
        f"got is_improvement={change['is_improvement']!r} "
        f"description={change['description']!r}"
    )
    assert "downgrad" in change["description"].lower(), (
        f"Description must reflect the policy downgrade, not the rua "
        f"addition; got: {change['description']!r}"
    )


def test_rua_added_alone_is_still_an_improvement():
    """Control: with no policy change, rua= being added must still count
    as an improvement (the fix must not just always suppress the rua
    rule)."""
    history = _dmarc_history(
        "v=DMARC1; p=reject",
        "v=DMARC1; p=reject; rua=mailto:x@y.com",
    )
    result = result_transformer.build_change_detection({}, history, first_seen="2026-08-19T00:00:00Z")
    dmarc_changes = [c for c in result["changes"] if c["record_type"] == "dmarc"]
    assert len(dmarc_changes) == 1
    change = dmarc_changes[0]
    assert change["is_improvement"] is True
    assert "aggregate reporting" in change["description"].lower()


def test_policy_upgrade_with_rua_removed_is_still_an_upgrade():
    """Control: an upgrade rule set first must not be clobbered by a
    later regression-flavored rule (rua removed) either."""
    history = _dmarc_history(
        "v=DMARC1; p=none; rua=mailto:x@y.com",
        "v=DMARC1; p=reject",
    )
    result = result_transformer.build_change_detection({}, history, first_seen="2026-08-19T00:00:00Z")
    dmarc_changes = [c for c in result["changes"] if c["record_type"] == "dmarc"]
    assert len(dmarc_changes) == 1
    change = dmarc_changes[0]
    assert change["is_improvement"] is True
    assert "upgrad" in change["description"].lower()
