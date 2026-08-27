"""Regression test for not-yet-valid certificates counting as active.

Finding A: is_active was `not_after and not_after > now`, which ignores
not_before entirely. A certificate issued with a future start date, which
CT logs carry routinely for scheduled renewals, was counted in
active_certs and could be reported as "expiring soon" before it had ever
been valid. The unused not_before_str local was the leftover from whoever
meant to handle this.

The "recently expired" bucket keyed off `not is_active`, which now also
means "not yet valid", so it tests the expiry directly instead.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine


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
    """Minimal stand-in for the crt.sh requests.Response."""

    status_code = 200

    def __init__(self, payload):
        self._payload = payload
        self.text = json.dumps(payload)
        self.content = self.text.encode()
        self.headers = {"content-length": str(len(self.content))}

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _run(certs, monkeypatch):
    # _raw_check_ct_uncached imports requests inside the function body.
    monkeypatch.setattr("requests.get", lambda *a, **k: _FakeResponse(certs))
    return audit_engine._raw_check_ct_uncached("example.com", {})


def test_not_yet_valid_cert_is_not_active(monkeypatch):
    now = datetime.now(timezone.utc)
    result = _run([
        _cert(1, "example.com", now - timedelta(days=10), now + timedelta(days=80)),
        _cert(2, "future.example.com", now + timedelta(days=30), now + timedelta(days=120)),
    ], monkeypatch)

    assert result["total_certs"] == 2
    assert result["active_certs"] == 1, "the future-dated cert is not active yet"


def test_not_yet_valid_cert_is_not_reported_expiring_soon(monkeypatch):
    now = datetime.now(timezone.utc)
    # Starts in 10 days, ends in 20: inside the 30-day window, but not valid yet.
    result = _run([
        _cert(1, "future.example.com", now + timedelta(days=10), now + timedelta(days=20)),
    ], monkeypatch)

    assert result["active_certs"] == 0
    assert result["expiring_soon"] == []


def test_not_yet_valid_cert_is_not_reported_recently_expired(monkeypatch):
    now = datetime.now(timezone.utc)
    result = _run([
        _cert(1, "future.example.com", now + timedelta(days=10), now + timedelta(days=20)),
    ], monkeypatch)

    assert result["expired_recent"] == []


def test_genuinely_expired_cert_still_reported(monkeypatch):
    now = datetime.now(timezone.utc)
    result = _run([
        _cert(1, "old.example.com", now - timedelta(days=400), now - timedelta(days=30)),
    ], monkeypatch)

    assert result["active_certs"] == 0
    assert [c["common_name"] for c in result["expired_recent"]] == ["old.example.com"]


def test_currently_valid_cert_expiring_soon_still_reported(monkeypatch):
    now = datetime.now(timezone.utc)
    result = _run([
        _cert(1, "example.com", now - timedelta(days=80), now + timedelta(days=10)),
    ], monkeypatch)

    assert result["active_certs"] == 1
    assert [c["common_name"] for c in result["expiring_soon"]] == ["example.com"]
