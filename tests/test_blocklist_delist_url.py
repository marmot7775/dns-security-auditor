"""Regression test for blocklist issues shipping without a delisting link.

Finding B: delist_url was unpacked from the DOMAIN_LISTS tuple in both
loops and then discarded, so _add_issue was always called with its default
fix=None. A domain listed on Spamhaus DBL got told it was listed and
nothing about how to get off the list, even though the URL was sitting in
the table two lines up.

The tier2_listings branch was also unreachable: DOMAIN_LISTS holds exactly
one tier-1 entry. Severity is now derived from the entry's tier in a
single loop, so a tier-2 entry works without a branch that no data can
reach.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine


class _Rdata:
    def __init__(self, value):
        self._value = value

    def __str__(self):
        return self._value


class _Resolver:
    """Answers every DNSBL query with a listing."""

    def __init__(self, response):
        self._response = response

    def resolve(self, name, rdtype):
        return [_Rdata(self._response)]


def _run(monkeypatch, response="127.0.1.2"):
    monkeypatch.setattr(
        audit_engine, "_get_resolver", lambda *a, **k: _Resolver(response)
    )
    return audit_engine._raw_check_blacklist("example.com", {})


def test_listing_issue_carries_the_delisting_url(monkeypatch):
    result = _run(monkeypatch)

    assert result["status"] == "error"
    assert result["total_listings"] == 1
    issue = result["issues"][0]
    assert issue["fix"], "a listed domain must be told how to get delisted"
    assert "https://check.spamhaus.org/" in issue["fix"]


def test_clean_domain_produces_no_issue(monkeypatch):
    class _Clean:
        def resolve(self, name, rdtype):
            raise audit_engine.dns.resolver.NXDOMAIN()

    monkeypatch.setattr(audit_engine, "_get_resolver", lambda *a, **k: _Clean())
    result = audit_engine._raw_check_blacklist("example.com", {})

    assert result["status"] == "ok"
    assert result["total_listings"] == 0
    assert result["issues"] == []


def test_spamhaus_error_response_is_not_a_listing(monkeypatch):
    result = _run(monkeypatch, response="127.255.255.254")

    assert result["total_listings"] == 0
    assert result["status"] == "ok"
