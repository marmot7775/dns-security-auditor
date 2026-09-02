"""Regression test for the vendor-enriched SPF suggestion dropping mechanisms.

The suggestion builder harvested `include:` terms out of the published record
with a regex and rebuilt the record from those alone, so every ip4, ip6, a,
a:, mx and exists term was discarded. A domain publishing

    v=spf1 ip4:198.51.100.0/24 ip4:203.0.113.5 a:relay.vsp.test ~all

with Google MX was told to publish

    v=spf1 include:_spf.google.com ~all

which de-authorizes the sender's own IPs and their relay host. Pasting the
suggestion is what breaks their mail, so the builder now splices the missing
includes into the operator's own term list and refuses to emit a suggestion
that authorizes less than the record it replaces.

Asserts on the SPF card produced by a real audit, not on a hand-built dict.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_engine import _build_suggested_spf, _spf_authorization_sources

DOMAIN = "vsp.test"
PUBLISHED = "v=spf1 ip4:198.51.100.0/24 ip4:203.0.113.5 a:relay.vsp.test ~all"
GOOGLE = "include:_spf.google.com"

ZONE = {
    DOMAIN: {
        "TXT": [PUBLISHED],
        "MX": [(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")],
    },
    "_dmarc." + DOMAIN: {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@vsp.test"]},
    "relay.vsp.test": {"A": ["198.51.100.9"]},
}


def _spf_card(result):
    for check in result["checks"]:
        if check.get("name") == "SPF":
            return check
    return None


def _suggested_from_fix(fix):
    """Pull the suggested record out of the fix HTML."""
    assert fix and "Suggested SPF record" in fix, f"no suggestion in fix: {fix!r}"
    body = fix.split("Suggested SPF record:</strong><br>", 1)[1]
    return body.split("<code>", 1)[1].split("</code>", 1)[0]


def test_suggested_record_keeps_every_published_authorization_source(audit):
    result = audit(ZONE, DOMAIN, scope="email_full")
    suggested = _suggested_from_fix(_spf_card(result).get("fix"))

    for ip4 in ("ip4:198.51.100.0/24", "ip4:203.0.113.5"):
        assert ip4 in suggested, (
            f"{ip4} is a sending source the domain publishes today. A "
            f"suggestion without it stops that host passing SPF. Got: "
            f"{suggested!r}"
        )
    assert "a:relay.vsp.test" in suggested, (
        f"The relay host must survive the rewrite; got {suggested!r}"
    )
    assert GOOGLE in suggested, (
        f"The detected vendor's include is the point of the suggestion; "
        f"got {suggested!r}"
    )
    assert suggested.endswith("~all"), (
        f"The operator chose a soft fail; the suggestion must not silently "
        f"harden it to -all. Got {suggested!r}"
    )
    # The whole invariant in one line: nothing published was lost.
    assert _spf_authorization_sources(PUBLISHED) <= _spf_authorization_sources(suggested)


def test_builder_appends_rather_than_rebuilds():
    suggested = _build_suggested_spf(PUBLISHED, [GOOGLE], "~all")
    assert suggested == (
        "v=spf1 ip4:198.51.100.0/24 ip4:203.0.113.5 a:relay.vsp.test "
        "include:_spf.google.com ~all"
    ), suggested


def test_builder_never_returns_a_record_weaker_than_the_original():
    records = [
        "v=spf1 ip4:198.51.100.0/24 -all",
        "v=spf1 mx a include:spf.protection.outlook.com ?all",
        "v=spf1 ip6:2001:db8::/32 exists:%{i}._spf.vsp.test ~all",
        "v=spf1 a mx",                       # no all mechanism at all
        "v=spf1 include:one.test redirect=_spf.vsp.test",
    ]
    for record in records:
        suggested = _build_suggested_spf(record, [GOOGLE], "-all")
        assert suggested is not None, record
        lost = _spf_authorization_sources(record) - _spf_authorization_sources(suggested)
        assert not lost, f"{record!r} lost {sorted(lost)} in {suggested!r}"
        assert GOOGLE in suggested


def test_builder_preserves_the_all_qualifier_and_its_position():
    assert _build_suggested_spf("v=spf1 ip4:198.51.100.1 ?all", [GOOGLE]) == (
        "v=spf1 ip4:198.51.100.1 include:_spf.google.com ?all"
    )
    # No all mechanism published means none is invented.
    assert _build_suggested_spf("v=spf1 mx", [GOOGLE]) == "v=spf1 mx include:_spf.google.com"


def test_builder_skips_records_it_cannot_parse():
    assert _build_suggested_spf("spf1 ip4:198.51.100.1 -all", [GOOGLE]) is None
    # An include already present is not a suggestion worth making.
    assert _build_suggested_spf(f"v=spf1 {GOOGLE} -all", [GOOGLE]) is None


def test_domain_with_no_spf_record_still_gets_a_starting_point():
    assert _build_suggested_spf("", [GOOGLE]) == "v=spf1 include:_spf.google.com -all"
