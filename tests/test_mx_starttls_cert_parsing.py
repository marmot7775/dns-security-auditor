"""Regression test for expired-certificate detection on MX hosts being
dead code.

Bug: mx_check._check_starttls built its TLS context with
verify_mode = ssl.CERT_NONE. With CERT_NONE, ssl refuses to hand back
peer certificate data: getpeercert(binary_form=False) always returns
{}, so `if cert:` was always false and cert_subject, cert_issuer,
cert_expiry and cert_valid stayed None on every scan. The downstream
"Expired cert on ..." finding in check_mx's deep scan was unreachable.

Fix: CERT_OPTIONAL still skips verification (self-signed MX certs are
common and this is a posture scan, not a trust decision) but does
parse and return the certificate.

Verified against a local STARTTLS server with a self-signed cert, since
this is only observable against a server that actually completes
STARTTLS.
"""
import datetime
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _starttls_test_server import LocalStarttlsServer, generate_self_signed_cert

import mx_check


def test_valid_cert_returns_real_subject_and_expiry():
    key_pem, cert_pem = generate_self_signed_cert(common_name="mail.example.com")
    with LocalStarttlsServer(cert_pem, key_pem) as srv:
        result = mx_check._check_starttls("127.0.0.1", port=srv.port, timeout=5)

    assert result["error"] is None
    assert result["cert_subject"] == "mail.example.com"
    assert result["cert_expiry"] is not None
    assert result["cert_valid"] is True


class _FakeExchange:
    def __init__(self, name):
        self._name = name

    def __str__(self):
        return self._name


class _FakeRdata:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = _FakeExchange(exchange)


class _FakeMxAnswers:
    def __init__(self, rdatas):
        self._rdatas = rdatas
        self.rrset = None

    def __iter__(self):
        return iter(self._rdatas)


def test_expired_cert_marks_invalid_and_check_mx_surfaces_the_finding():
    now = datetime.datetime.now(datetime.timezone.utc)
    key_pem, cert_pem = generate_self_signed_cert(
        common_name="mail.example.com",
        not_before=now - datetime.timedelta(days=30),
        not_after=now - datetime.timedelta(days=1),
    )

    with LocalStarttlsServer(cert_pem, key_pem) as srv:
        direct_result = mx_check._check_starttls("127.0.0.1", port=srv.port, timeout=5)

    assert direct_result["error"] is None
    assert direct_result["cert_valid"] is False
    assert direct_result["cert_expiry"] is not None

    # check_mx's deep-scan path always probes port 25, which this test
    # cannot bind without root. Delegate to the real _check_starttls
    # (exercising the actual cert-parsing fix) but redirect the port to a
    # fresh local server carrying the same expired cert, so the wiring
    # between a real expired-cert result and the "Expired cert on ..."
    # finding is still exercised end-to-end. (LocalStarttlsServer serves a
    # single connection, so it can't be reused for the direct call above.)
    with LocalStarttlsServer(cert_pem, key_pem) as srv2:
        real_check_starttls = mx_check._check_starttls

        def _redirect_to_local_server(hostname, port=25, timeout=10.0):
            # hostname is "mail.example.com" here, which does not resolve.
            # check_mx only uses its own mx_detail["hostname"] for the
            # issue text it builds, not this function's return value, so
            # redirecting to the loopback address the local server is
            # actually bound to is safe.
            return real_check_starttls("127.0.0.1", port=srv2.port, timeout=timeout)

        fake_mx_answers = _FakeMxAnswers([_FakeRdata(10, "mail.example.com.")])
        fake_resolver = type("FakeResolver", (), {"resolve": staticmethod(lambda name, rtype: fake_mx_answers)})()

        with patch.object(mx_check, "_get_resolver", return_value=fake_resolver), \
             patch.object(mx_check, "_resolve_host", return_value={"a": ["127.0.0.1"], "aaaa": [], "resolved": True}), \
             patch.object(mx_check, "_check_ptr", return_value={"ip": "127.0.0.1", "ptr": None, "fcrdns": False}), \
             patch.object(mx_check, "_check_starttls", side_effect=_redirect_to_local_server):
            raw = mx_check.check_mx("example.com", deep_scan=True)

    titles = [i["issue"] for i in raw["issues"]]
    assert "Expired cert on mail.example.com" in titles, (
        f"An expired MX cert must produce the 'Expired cert on ...' finding; "
        f"got issues: {titles!r}"
    )
