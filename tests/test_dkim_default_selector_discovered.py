"""A domain signing with default._domainkey must be reported as having DKIM.

comprehensive_selectors orders the master list service-specific first, then 358
sequential entries, then 370 date-based ones, and only then the 153 generics.
That put "default" at index 981, so smart_dkim_check's cap sliced it off every
time and any domain running OpenDKIM, cPanel or Plesk out of the box got
"DKIM | warn | no public keys found". Those domains name no vendor in SPF, so
there was nothing to prioritize them back into range either.

The generics are now unioned in on top of the cap rather than inside it.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from conftest import FakeZone

import spf_intelligence


_DKIM_KEY = (
    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
    "0ZbJmVhVjhBHmXNCzHZ5wjMmT9VqZQ1lQxhkPz8YtGqLbNvXcRfWpKdEjSaHuI"
    "oYtMnBvCxDwEzFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaB"
    "cDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkL"
    "mNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuV"
    "wXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeF"
    "gwIDAQAB"
)


def _self_hosted_zone():
    """OpenDKIM out of the box: a plain SPF naming no vendor, one key at
    default._domainkey."""
    return FakeZone({
        "example.com": {
            "TXT": ["v=spf1 ip4:203.0.113.10 -all"],
            "MX": [(10, "mail.example.com")],
        },
        "mail.example.com": {"A": ["203.0.113.10"]},
        "default._domainkey.example.com": {"TXT": [_DKIM_KEY]},
    })


def test_default_selector_is_inside_the_tested_slice():
    """The unit-level cause: default has to survive the cap."""
    from comprehensive_selectors import COMPREHENSIVE_DKIM_SELECTORS

    # No vendor in SPF, so nothing gets prioritized and the raw master order
    # is what the cap slices.
    prioritized = spf_intelligence.get_prioritized_selectors(
        "v=spf1 ip4:203.0.113.10 -all", COMPREHENSIVE_DKIM_SELECTORS
    )
    assert prioritized.index("default") > 200, (
        "fixture no longer reproduces the bug: default is already near the "
        "front of the prioritized list"
    )


def test_smart_dkim_check_finds_default_selector(monkeypatch):
    zone = _self_hosted_zone()
    monkeypatch.setattr("dns.resolver.Resolver.resolve",
                        lambda self, name, rdtype="A", *a, **k: zone.resolve(name, rdtype))
    monkeypatch.setattr("dns.resolver.resolve", zone.resolve)

    result = spf_intelligence.smart_dkim_check(
        "example.com", spf_record="v=spf1 ip4:203.0.113.10 -all"
    )

    selectors = [f["selector"] for f in result["found_selectors"]]
    assert "default" in selectors, (
        f"default._domainkey was not discovered; found {selectors!r} after "
        f"testing {result['tested_count']} selectors"
    )


def test_dkim_card_reports_the_key_for_a_self_hosted_domain(audit):
    """End to end: the card the user actually reads."""
    result = audit(_self_hosted_zone(), "example.com", scope="complete")

    dkim = next(c for c in result["checks"] if c["name"] == "DKIM")
    assert dkim["status"] != "warn" or "no public keys" not in str(dkim).lower(), (
        f"DKIM card still reports nothing found: {dkim.get('status')} / "
        f"{dkim.get('summary')}"
    )
    assert "default" in str(dkim), f"card does not mention the default selector: {dkim}"


def test_tested_count_reports_probes_that_actually_ran(monkeypatch):
    """tested_count used to be len(queued), regardless of the early break."""
    zone = _self_hosted_zone()
    monkeypatch.setattr("dns.resolver.Resolver.resolve",
                        lambda self, name, rdtype="A", *a, **k: zone.resolve(name, rdtype))
    monkeypatch.setattr("dns.resolver.resolve", zone.resolve)

    result = spf_intelligence.smart_dkim_check(
        "example.com", spf_record="v=spf1 ip4:203.0.113.10 -all"
    )
    assert result["tested_count"] > 0
    assert result["tested_count"] <= len(
        spf_intelligence.get_prioritized_selectors(
            "v=spf1 ip4:203.0.113.10 -all",
            __import__("comprehensive_selectors").COMPREHENSIVE_DKIM_SELECTORS,
        )
    )
