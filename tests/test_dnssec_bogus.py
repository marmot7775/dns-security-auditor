"""Tests for DNSSEC four-state classification.

States: secure, signed_unanchored, insecure, bogus.

Covers:
  (a) DNSKEY query fails AND probe finds SERVFAIL/NOERROR mismatch -> bogus.
  (b) DNSKEY query fails AND probe sees consistent answers -> insecure.
  (c) DNSKEY succeeds AND DS found at parent -> secure.
  (d) DNSKEY succeeds AND DS absent at parent -> signed_unanchored.
  (e) Bogus signal takes priority over has_ds presence.

Probe internals are exercised directly: dns.query.udp is patched to dispatch
by destination IP, so 9.9.9.9 (validating) and 8.8.4.4 (unvalidating) can
return different responses for the same domain.
"""
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.rcode
import dns.resolver

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine


class _FakeRdata:
    def __init__(self, algorithm=13):
        self.algorithm = algorithm


class _FakeAnswer(list):
    """Mimics dnspython's Answer: iterable of rdata + .response.flags."""
    def __init__(self, items, ad_flag=False):
        super().__init__(items)
        self.response = MagicMock()
        self.response.flags = dns.flags.AD if ad_flag else 0


def _make_response(rcode_value, answer_count=0):
    """Build a fake dns.message.Message-shaped response."""
    r = MagicMock()
    r.rcode.return_value = rcode_value
    r.answer = [MagicMock() for _ in range(answer_count)]
    return r


def _make_udp_dispatcher(*, validating_response, unvalidating_response):
    """Return a dns.query.udp side_effect that routes by destination IP."""
    def _udp(query_message, ns_ip, **kwargs):
        if ns_ip == "9.9.9.9":
            return validating_response
        if ns_ip == "8.8.4.4":
            return unvalidating_response
        # Anything else (parent NS in DS Method 2) — refuse so the
        # probe isn't accidentally exercised via that path.
        raise dns.exception.DNSException(f"udp blocked for {ns_ip}")
    return _udp


def test_bogus_state_when_validating_servfails_and_unvalidating_succeeds():
    """DNSKEY fails + validating SERVFAIL + unvalidating NOERROR -> bogus."""
    resolver = MagicMock()
    resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

    udp = _make_udp_dispatcher(
        validating_response=_make_response(dns.rcode.SERVFAIL, 0),
        unvalidating_response=_make_response(dns.rcode.NOERROR, 1),
    )

    with patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver), \
         patch("dns.query.udp", side_effect=udp), \
         patch("dns.query.tcp", side_effect=dns.exception.DNSException("tcp blocked")), \
         patch("audit_engine._lookup_ttl", return_value=None):
        result = audit_engine._raw_check_dnssec("bogus.example")

    assert result["has_dnssec"] is False
    assert result["dnssec_state"] == "bogus"
    bogus_issues = [i for i in result["issues"] if "BOGUS" in i.get("issue", "")]
    assert bogus_issues, f"expected BOGUS error issue, got: {result['issues']}"
    assert bogus_issues[0]["severity"] == "error"


def test_insecure_state_for_unsigned_zone():
    """DNSKEY fails + both resolvers NOERROR -> insecure (normal unsigned)."""
    resolver = MagicMock()
    resolver.resolve.side_effect = dns.resolver.NoAnswer()

    udp = _make_udp_dispatcher(
        validating_response=_make_response(dns.rcode.NOERROR, 1),
        unvalidating_response=_make_response(dns.rcode.NOERROR, 1),
    )

    with patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver), \
         patch("dns.query.udp", side_effect=udp), \
         patch("dns.query.tcp", side_effect=dns.exception.DNSException("tcp blocked")), \
         patch("audit_engine._lookup_ttl", return_value=None):
        result = audit_engine._raw_check_dnssec("plain.example")

    assert result["has_dnssec"] is False
    assert result["dnssec_state"] == "insecure"
    bogus_issues = [i for i in result["issues"] if "BOGUS" in i.get("issue", "")]
    assert bogus_issues == [], (
        f"unsigned zone must not trigger BOGUS issue. Got: {result['issues']}"
    )


def test_secure_state_for_signed_zone():
    """DNSKEY succeeds -> dnssec_state=secure, no probe needed."""
    dnskey = _FakeAnswer([_FakeRdata(13)], ad_flag=True)
    ds = _FakeAnswer([_FakeRdata(13)])

    resolver = MagicMock()

    def _resolve(name, qtype):
        if qtype == "DNSKEY":
            return dnskey
        if qtype == "DS":
            return ds
        if qtype == "NS":
            raise dns.exception.DNSException("not exercised")
        raise dns.exception.DNSException(f"unexpected qtype {qtype}")

    resolver.resolve.side_effect = _resolve

    # Probe must not be reachable when DNSKEY succeeds — assert by raising
    # if dns.query.udp is hit (parent-NS path is blocked above).
    with patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver), \
         patch("dns.query.udp", side_effect=dns.exception.DNSException("udp blocked")), \
         patch("dns.query.tcp", side_effect=dns.exception.DNSException("tcp blocked")), \
         patch("audit_engine._lookup_ttl", return_value=None):
        result = audit_engine._raw_check_dnssec("signed.example")

    assert result["has_dnssec"] is True
    assert result["dnssec_state"] == "secure"


def test_signed_unanchored_state_when_dnskey_present_but_no_ds():
    """DNSKEY succeeds + DS absent at parent -> dnssec_state=signed_unanchored.

    Mocks: DNSKEY resolves; DS (Method 1) raises NoAnswer; parent NS
    lookup (Method 2) raises so the parent-NS path is a no-op. The bogus
    probe must NOT be reachable when DNSKEY succeeded.
    """
    dnskey = _FakeAnswer([_FakeRdata(13)], ad_flag=False)

    resolver = MagicMock()

    def _resolve(name, qtype):
        if qtype == "DNSKEY":
            return dnskey
        if qtype == "DS":
            raise dns.resolver.NoAnswer()
        if qtype == "NS":
            raise dns.exception.DNSException("NS lookup blocked")
        if qtype == "A":
            raise dns.exception.DNSException("A lookup blocked")
        raise dns.exception.DNSException(f"unexpected qtype {qtype}")

    resolver.resolve.side_effect = _resolve

    with patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver), \
         patch("dns.query.udp", side_effect=dns.exception.DNSException("udp blocked")), \
         patch("dns.query.tcp", side_effect=dns.exception.DNSException("tcp blocked")), \
         patch("audit_engine._lookup_ttl", return_value=None):
        result = audit_engine._raw_check_dnssec("unanchored.example")

    assert result["has_dnssec"] is True
    assert result["has_ds"] is False
    assert result["dnssec_state"] == "signed_unanchored"

    # Existing "no DS at parent" warning must still fire (state for
    # machines, issue for humans — both should coexist).
    warnings = [i for i in result["issues"]
                if i.get("severity") == "warning"
                and "no ds record found at parent" in i.get("issue", "").lower()]
    assert warnings, (
        f"signed_unanchored must still surface the 'no DS at parent' warning. "
        f"Got: {result['issues']}"
    )


def test_bogus_takes_priority_over_has_ds():
    """is_bogus=True wins even when DS would otherwise be observable.

    A bogus zone may technically have DS at the parent (orphaned,
    mismatched key tag, etc.). The bogus signal is strictly more
    informative, so dnssec_state must resolve to 'bogus' regardless of
    has_ds. Forced via mocking: DNSKEY raises (so the bogus probe runs),
    the probe returns True, and DS Method 1 returns records.
    """
    resolver = MagicMock()
    ds = _FakeAnswer([_FakeRdata(13)])

    def _resolve(name, qtype):
        if qtype == "DNSKEY":
            raise dns.resolver.NoAnswer()
        if qtype == "DS":
            return ds
        if qtype == "NS":
            raise dns.exception.DNSException("not exercised")
        raise dns.exception.DNSException(f"unexpected qtype {qtype}")

    resolver.resolve.side_effect = _resolve

    udp = _make_udp_dispatcher(
        validating_response=_make_response(dns.rcode.SERVFAIL, 0),
        unvalidating_response=_make_response(dns.rcode.NOERROR, 1),
    )

    with patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver), \
         patch("dns.query.udp", side_effect=udp), \
         patch("dns.query.tcp", side_effect=dns.exception.DNSException("tcp blocked")), \
         patch("audit_engine._lookup_ttl", return_value=None):
        result = audit_engine._raw_check_dnssec("bogus-with-ds.example")

    assert result["has_ds"] is True
    assert result["dnssec_state"] == "bogus", (
        f"bogus must take priority over has_ds. Got state={result['dnssec_state']}"
    )


def test_probe_returns_false_on_validating_resolver_exception():
    """Probe fails closed when the validating query raises."""
    with patch("dns.query.udp", side_effect=dns.exception.DNSException("network")):
        assert audit_engine._probe_dnssec_bogus("any.example") is False


def test_probe_returns_false_when_unvalidating_also_servfails():
    """Probe rejects ambiguous evidence — both servfailing isn't bogus."""
    udp = _make_udp_dispatcher(
        validating_response=_make_response(dns.rcode.SERVFAIL, 0),
        unvalidating_response=_make_response(dns.rcode.SERVFAIL, 0),
    )
    with patch("dns.query.udp", side_effect=udp):
        assert audit_engine._probe_dnssec_bogus("ambiguous.example") is False
