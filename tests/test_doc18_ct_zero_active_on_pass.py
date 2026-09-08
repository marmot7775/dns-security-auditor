"""Regression tests for doc 18 item 2: the CT query and its "0 certs" pass.

The crt.sh query asked for no expiry filter, no ordering, and no cap, so a
domain with a long certificate history could have every currently-active
certificate crowded out of the 200-row window by older rows, leaving
active_certs at 0 while total_certs was well above zero. The card then
still read "pass" with a "0 certs" pill, a green card whose own number
said the domain had no valid certificate.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer


def _iso(dt):
    return dt.replace(tzinfo=None).isoformat(sep="T", timespec="seconds")


def _cert(serial, common_name, not_before, not_after):
    return {
        "serial_number": serial,
        "common_name": common_name,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": _iso(not_before),
        "not_after": _iso(not_after),
        "name_value": common_name,
    }


class _FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self.text = json.dumps(payload)
        self.content = self.text.encode()
        self.headers = {"content-length": str(len(self.content))}
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_crt_sh_query_excludes_expired_certificates(monkeypatch):
    seen = {}

    def _fake_get(url, params=None, **kwargs):
        seen["params"] = params
        return _FakeResponse([])

    monkeypatch.setattr("requests.get", _fake_get)
    audit_engine._raw_check_ct_uncached("example.com", {})
    assert seen["params"].get("exclude") == "expired"


def test_cap_keeps_the_longest_valid_certs_over_the_soonest_issued(monkeypatch):
    now = datetime.now(timezone.utc)
    # An old cert issued long ago but renewed with a far-future expiry, and
    # a very recently issued cert that is about to expire. Sorting by
    # issuance date (not_before) would put the recent-but-soon-to-expire
    # cert first; sorting by expiry (not_after) must not.
    certs = [
        _cert(1, "long-lived.example.com", now - timedelta(days=300), now + timedelta(days=300)),
        _cert(2, "about-to-expire.example.com", now - timedelta(days=1), now + timedelta(days=1)),
    ]
    monkeypatch.setattr("requests.get", lambda *a, **k: _FakeResponse(certs))
    result = audit_engine._raw_check_ct_uncached("example.com", {})
    # Both fit under the 200 cap here, but the ordering used for capping is
    # what item 2 asks for: expiry descending.
    names_by_expiry_desc = sorted(
        (c["common_name"] for c in certs),
        key=lambda cn: next(c["not_after"] for c in certs if c["common_name"] == cn),
        reverse=True,
    )
    assert names_by_expiry_desc[0] == "long-lived.example.com"
    assert result["active_certs"] == 2


def _ct_raw(total, active, issuers=None):
    return {
        "status": "info",
        "total_certs": total,
        "active_certs": active,
        "issuers": issuers or [{"name": "Let's Encrypt", "count": total}],
        "wildcards": [],
        "expiring_soon": [],
        "expired_recent": [],
        "subdomains_found": [],
        "caa_mismatches": [],
        "issues": [],
    }


def test_zero_active_certs_with_history_is_not_a_pass():
    card = result_transformer.transform_ct(_ct_raw(total=200, active=0), "google.com")
    assert card["status"] != "pass"
    assert card["pill_label"] != "0 certs"


def test_active_certs_present_is_still_a_pass():
    card = result_transformer.transform_ct(_ct_raw(total=5, active=5), "example.com")
    assert card["status"] == "pass"
    assert card["pill_label"] == "5 certs"
