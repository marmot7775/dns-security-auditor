"""Regression test for recently-expired certificates never being displayed.

Finding D: transform_ct read raw["expired_recent"] into a local named
`expired` and never used it. The CT check has always collected
certificates that expired within the last 90 days, and nothing anywhere
showed them, so the collection was pure dead weight.

They now appear as info details, alongside the expiring-soon warnings.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from result_transformer import transform_ct


def _raw(expired_recent, **over):
    raw = {
        "status": "info",
        "total_certs": 5,
        "active_certs": 2,
        "issuers": [{"name": "Let's Encrypt", "count": 5}],
        "wildcards": [],
        "expiring_soon": [],
        "expired_recent": expired_recent,
        "subdomains_found": [],
        "caa_mismatches": [],
        "issues": [],
    }
    raw.update(over)
    return raw


def _texts(card):
    return [d["text"] for d in card["details"]]


def test_recently_expired_cert_appears_in_details():
    card = transform_ct(
        _raw([{"common_name": "old.example.com", "not_after": "2026-06-01T00:00:00"}]),
        "example.com",
    )
    assert any("old.example.com" in t for t in _texts(card))
    assert any("Expired in the last 90 days" in t for t in _texts(card))


def test_no_expired_certs_adds_nothing():
    card = transform_ct(_raw([]), "example.com")
    assert not any("Expired in the last 90 days" in t for t in _texts(card))


def test_long_expired_list_is_truncated_with_a_count():
    expired = [
        {"common_name": f"host{i}.example.com", "not_after": "2026-06-01T00:00:00"}
        for i in range(7)
    ]
    card = transform_ct(_raw(expired), "example.com")
    texts = _texts(card)

    named = [t for t in texts if t.startswith("Expired in the last 90 days")]
    assert len(named) == 3
    assert any("4 further certificates expired" in t for t in texts)


def test_expired_certs_do_not_change_the_card_status():
    # An expired cert is history, not a live problem, so it stays info-level.
    card = transform_ct(
        _raw([{"common_name": "old.example.com", "not_after": "2026-06-01T00:00:00"}]),
        "example.com",
    )
    assert card["status"] == "pass"
    expired_details = [
        d for d in card["details"] if "Expired in the last 90 days" in d["text"]
    ]
    assert all(d["type"] == "info" for d in expired_details)
