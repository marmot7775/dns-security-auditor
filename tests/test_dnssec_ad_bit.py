"""Tests for DNSSEC AD-bit handling in audit_engine._raw_check_dnssec.

Three scenarios cover the new behaviour:
  (a) Method 1 (direct DS query) succeeds: has_ds=True, no info annotation.
  (b) Methods 1+2 fail, AD bit set: has_ds=False, info annotation emitted.
  (c) Methods 1+2 fail, AD bit clear: has_ds=False, existing warning emitted.

The check makes many DNS calls so we patch _get_dnssec_resolver to return a
controllable mock and patch dns.query.udp/tcp to neutralise Method 2's
parent-NS path.
"""
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags

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


def _build_resolver(*, dnskey_answer, ds_result, ns_result):
    """Build a fake resolver. ds_result/ns_result may be an answer or an Exception."""
    resolver = MagicMock()

    def _resolve(name, qtype):
        if qtype == "DNSKEY":
            return dnskey_answer
        if qtype == "DS":
            if isinstance(ds_result, BaseException):
                raise ds_result
            return ds_result
        if qtype == "NS":
            if isinstance(ns_result, BaseException):
                raise ns_result
            return ns_result
        if qtype == "A":
            raise dns.exception.DNSException("test: A lookup not exercised")
        raise dns.exception.DNSException(f"test: unexpected qtype {qtype}")

    resolver.resolve.side_effect = _resolve
    return resolver


def test_method_1_finds_ds_no_info_issue():
    """has_dnssec=True, Method 1 returns DS -> has_ds=True, no AD-bit info issue."""
    dnskey = _FakeAnswer([_FakeRdata(13)], ad_flag=True)
    ds = _FakeAnswer([_FakeRdata(13)])
    resolver = _build_resolver(
        dnskey_answer=dnskey,
        ds_result=ds,
        ns_result=dns.exception.DNSException("not exercised"),
    )

    with patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver), \
         patch("audit_engine._lookup_ttl", return_value=None):
        result = audit_engine._raw_check_dnssec("example.com")

    assert result["has_dnssec"] is True
    assert result["has_ds"] is True
    info_issues = [i for i in result["issues"]
                   if i.get("severity") == "info"
                   and "AD bit" in i.get("issue", "")]
    assert info_issues == [], (
        f"Method 1 succeeded; no AD-bit annotation should be emitted. "
        f"Got: {result['issues']}"
    )


def test_methods_fail_ad_set_emits_info_annotation():
    """has_dnssec=True, Methods 1+2 fail, AD set -> has_ds=False, info issue present."""
    dnskey = _FakeAnswer([_FakeRdata(13)], ad_flag=True)
    resolver = _build_resolver(
        dnskey_answer=dnskey,
        ds_result=dns.exception.DNSException("simulated DS lookup failure"),
        ns_result=dns.exception.DNSException("simulated NS lookup failure"),
    )

    with patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver), \
         patch("dns.query.udp", side_effect=dns.exception.DNSException("udp blocked")), \
         patch("dns.query.tcp", side_effect=dns.exception.DNSException("tcp blocked")), \
         patch("audit_engine._lookup_ttl", return_value=None):
        result = audit_engine._raw_check_dnssec("example.com")

    assert result["has_dnssec"] is True
    assert result["has_ds"] is False
    assert result["validated_by_resolver"] is True

    info_issues = [i for i in result["issues"]
                   if i.get("severity") == "info"
                   and "AD bit" in i.get("issue", "")]
    assert info_issues, (
        f"Methods 1+2 failed but AD is set; expected info annotation. "
        f"Got: {result['issues']}"
    )

    bare_warnings = [i for i in result["issues"]
                     if i.get("severity") == "warning"
                     and "no ds record found at parent" in i.get("issue", "").lower()]
    assert bare_warnings == [], (
        f"AD bit is set; should emit info instead of bare warning. "
        f"Got: {result['issues']}"
    )


def test_methods_fail_ad_clear_emits_warning():
    """has_dnssec=True, Methods 1+2 fail, AD clear -> has_ds=False, existing warning kept."""
    dnskey = _FakeAnswer([_FakeRdata(13)], ad_flag=False)
    resolver = _build_resolver(
        dnskey_answer=dnskey,
        ds_result=dns.exception.DNSException("simulated DS lookup failure"),
        ns_result=dns.exception.DNSException("simulated NS lookup failure"),
    )

    with patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver), \
         patch("dns.query.udp", side_effect=dns.exception.DNSException("udp blocked")), \
         patch("dns.query.tcp", side_effect=dns.exception.DNSException("tcp blocked")), \
         patch("audit_engine._lookup_ttl", return_value=None):
        result = audit_engine._raw_check_dnssec("example.com")

    assert result["has_dnssec"] is True
    assert result["has_ds"] is False
    assert result["validated_by_resolver"] is False

    warnings = [i for i in result["issues"]
                if i.get("severity") == "warning"
                and "no ds record found at parent" in i.get("issue", "").lower()]
    assert warnings, (
        f"Methods 1+2 failed, AD clear: existing warning must still fire. "
        f"Got: {result['issues']}"
    )

    info_issues = [i for i in result["issues"]
                   if i.get("severity") == "info"
                   and "AD bit" in i.get("issue", "")]
    assert info_issues == [], (
        f"AD bit clear; should not emit AD-bit info. Got: {result['issues']}"
    )
