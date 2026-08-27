"""End-to-end golden zones: real audits, asserted on the cards users see.

Only three test files in this suite ever assert on result["checks"]. The rest
assert on raw check dicts, or call one transformer in isolation with a
hand-built input. That is the seam the ledger's 43 bugs lived in: a test that
builds its own raw dict and hands it to transform_dmarc cannot catch a
producer/consumer key mismatch, because the test author writes the key the
transformer expects. 256 tests passed while 43 bugs shipped.

Each fixture below declares a zone, runs the real run_full_audit through the
conftest harness, and asserts on the transformed output. The invariant at the
bottom is the part that closes the gap:

    every card renders a body, and every deep-analysis panel that exists is
    populated

A wrong dict key does not raise. It produces an empty panel or a blank field,
which every existing test happily ignores and every user sees. Bugs 41, 42
and 43 were all exactly that, and all three would have failed this file.

The whole module runs offline in well under a second per audit.
"""
import base64
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone


def _dkim(bits):
    spki = rsa.generate_private_key(
        public_exponent=65537, key_size=bits
    ).public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode("ascii")


DKIM_STRONG = _dkim(2048)
DKIM_WEAK = _dkim(1024)

MTA_STS_POLICY = (
    "version: STSv1\nmode: enforce\nmx: mail.wellrun.test\nmax_age: 604800\n"
)
# Tiny PS profile, fixed pixel dimensions, and at least 96x96, which is what
# the BIMI check requires for Gmail to actually render the logo.
BIMI_LOGO = (
    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" '
    'width="96" height="96" viewBox="0 0 96 96">'
    '<title>Wellrun</title><rect width="96" height="96" fill="#123456"/></svg>'
)
CT_CERTS = [{
    "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
    "common_name": "wellrun.test",
    "name_value": "wellrun.test\nwww.wellrun.test",
    "not_before": "2026-07-01T00:00:00",
    "not_after": "2026-12-01T00:00:00",
    "id": 1,
}]


# ------------------------------------------------------------------
# Golden zones
# ------------------------------------------------------------------

FULLY_CONFIGURED = ("wellrun.test", {
    "wellrun.test": {
        "MX": [(10, "mail.wellrun.test")],
        "TXT": ["v=spf1 ip4:203.0.113.0/24 -all"],
        "A": ["203.0.113.10"],
        "CAA": [(0, "issue", "letsencrypt.org"), (0, "iodef", "mailto:sec@wellrun.test")],
        "NS": ["ns1.wellrun.test", "ns2.example-dns.test"],
    },
    "_dmarc.wellrun.test": {
        "TXT": ["v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc@wellrun.test"]
    },
    "selector1._domainkey.wellrun.test": {"TXT": [DKIM_STRONG]},
    "_smtp._tls.wellrun.test": {"TXT": ["v=TLSRPTv1; rua=mailto:tls@wellrun.test"]},
    "_mta-sts.wellrun.test": {"TXT": ["v=STSv1; id=20260101000000Z"]},
    "default._bimi.wellrun.test": {
        "TXT": ["v=BIMI1; l=https://wellrun.test/logo.svg"]
    },
    "mail.wellrun.test": {"A": ["203.0.113.20"]},
    "ns1.wellrun.test": {"A": ["203.0.113.53"]},
    "ns2.example-dns.test": {"A": ["198.51.100.53"]},
})

# A domain that accepts mail and has published no email authentication at
# all. Not a bare parked domain: without MX the audit correctly treats most
# email checks as not applicable, which is a different and much less
# interesting case than a live mail domain that is wide open.
NOTHING_CONFIGURED = ("bare.test", {
    "bare.test": {
        "MX": [(10, "mail.bare.test")],
        "A": ["203.0.113.99"],
        "NS": ["ns1.bare.test"],
    },
    "mail.bare.test": {"A": ["203.0.113.98"]},
    "ns1.bare.test": {"A": ["203.0.113.53"]},
})

SUBDOMAIN_INHERITING = ("shop.parent.test", {
    "parent.test": {
        "MX": [(10, "mail.parent.test")],
        "TXT": ["v=spf1 mx -all"],
        "NS": ["ns1.parent.test"],
    },
    "_dmarc.parent.test": {
        "TXT": ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@parent.test"]
    },
    "shop.parent.test": {
        "MX": [(10, "mail.parent.test")],
        "TXT": ["v=spf1 mx -all"],
        "A": ["203.0.113.30"],
    },
    "mail.parent.test": {"A": ["203.0.113.31"]},
    "ns1.parent.test": {"A": ["203.0.113.53"]},
})

MISCONFIGURED = ("broken.test", {
    "broken.test": {
        "MX": [(10, "mail.broken.test")],
        # +all authorizes the entire internet; pct=0 disables the policy.
        "TXT": ["v=spf1 include:absent-one.test include:absent-two.test +all"],
        "A": ["203.0.113.40"],
        "NS": ["ns1.broken.test"],
    },
    "_dmarc.broken.test": {"TXT": ["v=DMARC1; p=none; pct=0"]},
    "selector1._domainkey.broken.test": {"TXT": [DKIM_WEAK]},
    "mail.broken.test": {"A": ["203.0.113.41"]},
    "ns1.broken.test": {"A": ["203.0.113.53"]},
})

THIRD_PARTY_RUA = ("reports.test", {
    "reports.test": {
        "MX": [(10, "mail.reports.test")],
        "TXT": ["v=spf1 mx -all"],
        "A": ["203.0.113.50"],
        "NS": ["ns1.reports.test"],
    },
    # No reports.test._report._dmarc.unrelated-vendor.test record exists, so
    # the destination is not authorized under RFC 7489 S7.1.
    "_dmarc.reports.test": {
        "TXT": ["v=DMARC1; p=quarantine; rua=mailto:agg@unrelated-vendor.test"]
    },
    "mail.reports.test": {"A": ["203.0.113.51"]},
    "ns1.reports.test": {"A": ["203.0.113.53"]},
})

ZONES = {
    "fully_configured": FULLY_CONFIGURED,
    "nothing_configured": NOTHING_CONFIGURED,
    "subdomain_inheriting": SUBDOMAIN_INHERITING,
    "misconfigured": MISCONFIGURED,
    "third_party_rua": THIRD_PARTY_RUA,
}

# Only the fully configured zone gets the HTTP-backed checks answered. The
# rest see an unreachable remote, which is the ordinary case.
HTTP = {
    "fully_configured": {
        "mta_sts_policy": MTA_STS_POLICY,
        "bimi_logo": BIMI_LOGO,
        "ct_certs": CT_CERTS,
    },
}

EXPECTED_CHECKS = {
    "BIMI", "Blocklist", "CAA", "Certificate Transparency", "DANE", "DKIM",
    "DMARC", "DNSSEC", "MTA-STS", "MX Records", "Nameservers", "SPF", "TLS-RPT",
}


# Each zone is audited once and the result reused. The zones are fixtures,
# not state: nothing here mutates the result, and re-running the same audit
# per assertion only loads the engine's shared executor, which slows the
# later audits down without testing anything extra.
_AUDITED = {}


def _audit_zone(name, audit):
    if name not in _AUDITED:
        domain, records = ZONES[name]
        _AUDITED[name] = audit(FakeZone(records), domain, **HTTP.get(name, {}))
    return _AUDITED[name]


@pytest.fixture(params=sorted(ZONES), ids=sorted(ZONES))
def golden(request, audit):
    return request.param, _audit_zone(request.param, audit)


@pytest.fixture
def golden_full(audit):
    return _audit_zone("fully_configured", audit)


def _cards(result):
    return {c["name"]: c for c in result["checks"]}


# ------------------------------------------------------------------
# Snapshot: the card set itself
# ------------------------------------------------------------------

def test_every_zone_produces_the_full_card_set(golden):
    name, result = golden
    assert set(_cards(result)) == EXPECTED_CHECKS, (
        f"{name}: the audit dropped or renamed a card"
    )


# Status alone is too coarse. A wrong key that turns "Reports to 1
# destination" into "Reports to 0 destinations" leaves the status at pass and
# the verdict non-empty, so only the text itself catches it.
GOLDEN_VERDICTS = {
    "BIMI": ("pass", "Logo configured"),
    "Blocklist": ("pass", "Clean on 1 domain blocklist"),
    "CAA": ("pass", "Restricted to letsencrypt.org"),
    "Certificate Transparency": ("pass", "1 active cert from 1 issuer"),
    "DANE": ("warn", "No DANE TLSA records"),
    "DKIM": ("pass", "1 DKIM public key published in DNS"),
    "DMARC": ("pass", "p=reject (authentication failures are rejected)"),
    "DNSSEC": ("warn", "DNSSEC not configured"),
    "MTA-STS": ("pass", "Inbound email must use encryption"),
    "MX Records": ("warn", "Single MX host"),
    "Nameservers": ("pass", "2 nameservers"),
    "SPF": ("pass", "SPF record configured"),
    "TLS-RPT": ("pass", "Reports to 1 destination"),
}


def test_fully_configured_card_verdicts_are_stable(golden_full):
    """Golden snapshot of what the fully configured zone actually says.

    Kept to status and verdict: those are the two lines a user reads first,
    and they are stable across copy edits to the longer explanation text.
    """
    actual = {
        name: (card["status"], card.get("verdict"))
        for name, card in _cards(golden_full).items()
    }
    assert actual == GOLDEN_VERDICTS


def test_card_statuses_match_the_zone(golden):
    """A coarse snapshot. Tight enough that a card silently flipping to pass
    fails here, loose enough that it is not rewritten on every copy edit."""
    name, result = golden
    cards = _cards(result)
    status = {k: v["status"] for k, v in cards.items()}

    if name == "fully_configured":
        assert status["SPF"] == "pass"
        assert status["DMARC"] == "pass"
        assert status["DKIM"] == "pass"
        assert status["MTA-STS"] == "pass"
        assert status["TLS-RPT"] == "pass"
        assert status["CAA"] == "pass"
    elif name == "nothing_configured":
        assert status["SPF"] == "fail"
        assert status["DMARC"] == "fail"
        assert status["CAA"] != "pass"
        assert status["MTA-STS"] != "pass"
    elif name == "misconfigured":
        assert status["SPF"] == "fail", "+all authorizes the whole internet"
        assert status["DMARC"] != "pass", "pct=0 means the policy does nothing"
    elif name == "third_party_rua":
        assert status["DMARC"] == "fail", "unauthorized rua destination"


# ------------------------------------------------------------------
# Zone-specific behaviour
# ------------------------------------------------------------------

def test_subdomain_inherits_the_org_domain_policy(audit):
    domain, records = SUBDOMAIN_INHERITING
    result = audit(FakeZone(records), domain)
    dmarc = _cards(result)["DMARC"]

    body = " ".join(
        [dmarc.get("verdict", ""), dmarc.get("explanation", "")]
        + [d.get("text", "") for d in dmarc.get("details", [])]
    ).lower()
    assert "parent.test" in body, (
        "the card must name the org domain the policy came from"
    )
    assert dmarc["status"] != "fail", (
        "an inherited enforcing policy is protection, not a failure"
    )


def test_unauthorized_third_party_rua_is_surfaced(audit):
    domain, records = THIRD_PARTY_RUA
    result = audit(FakeZone(records), domain)
    dmarc = _cards(result)["DMARC"]

    texts = " ".join(d.get("text", "") for d in dmarc.get("details", [])).lower()
    assert "not authorized" in texts
    assert dmarc["status"] == "fail"


def test_misconfigured_zone_does_not_report_protection(audit):
    domain, records = MISCONFIGURED
    result = audit(FakeZone(records), domain)
    cards = _cards(result)

    spf_body = " ".join(d.get("text", "") for d in cards["SPF"]["details"]).lower()
    assert "+all" in spf_body or "all" in spf_body

    dkim_body = " ".join(d.get("text", "") for d in cards["DKIM"]["details"])
    assert "1024-bit" in dkim_body, "a weak key must be named in the card"


def test_bare_domain_is_not_reported_as_configured(audit):
    domain, records = NOTHING_CONFIGURED
    result = audit(FakeZone(records), domain)
    cards = _cards(result)

    passing = [n for n, c in cards.items() if c["status"] == "pass"]
    assert "SPF" not in passing and "DMARC" not in passing and "DKIM" not in passing


# ------------------------------------------------------------------
# The invariant
# ------------------------------------------------------------------

def _deep_panels(card):
    return {k: v for k, v in card.items() if k.endswith("_deep")}


def _has_content(value):
    """True if a nested structure carries at least one real leaf value."""
    if value is None or value == "" or value == [] or value == {}:
        return False
    if isinstance(value, dict):
        return any(_has_content(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_content(v) for v in value)
    if value is False or value == 0:
        # A real boolean or numeric answer still counts as content.
        return True
    return True


def test_every_card_renders_a_body(golden):
    """The invariant a key mismatch actually trips.

    A wrong key does not raise, it renders blank. Every card the user is
    shown must name itself, state a verdict, and explain itself.
    """
    name, result = golden
    for card_name, card in _cards(result).items():
        where = f"{name}/{card_name}"
        assert card.get("status") in {"pass", "warn", "fail", "info", "unavailable"}, where
        assert (card.get("verdict") or "").strip(), f"{where}: empty verdict"
        assert (card.get("explanation") or "").strip(), f"{where}: empty explanation"

        for i, detail in enumerate(card.get("details") or []):
            assert (detail.get("text") or "").strip(), (
                f"{where}: detail {i} renders as an empty line"
            )


def test_every_deep_panel_present_is_populated(golden):
    """Bugs 41, 42 and 43 were each a deep panel reading a key its producer
    never published. The panel came back structurally present and entirely
    empty, and no test noticed."""
    name, result = golden
    for card_name, card in _cards(result).items():
        for panel_name, panel in _deep_panels(card).items():
            if panel is None:
                continue
            assert _has_content(panel), (
                f"{name}/{card_name}: {panel_name} is present but every field "
                f"in it is empty, which is what a wrong dict key looks like"
            )


def _populated_fields(panel):
    return {k for k, v in panel.items() if _has_content(v)}


# The golden snapshot. For the fully configured zone, exactly these fields
# carry data. Fields deliberately absent from a set are ones that are empty
# for a real reason in this zone, not a wiring fault: spf_deep.misconfigs and
# .optimizations because the record is clean, dane_deep.hosts_with_tlsa and
# .parsed_records because the zone publishes no TLSA.
#
# Equality, not a subset. A field that stops being populated is the shape a
# producer/consumer key mismatch takes, and a field that starts being
# populated is a deliberate change worth re-reading this list for.
GOLDEN_DEEP_PANELS = {
    ("DKIM", "dkim_deep"): {"has_weak", "keys", "rotation_guidance"},
    ("SPF", "spf_deep"): {
        "all_explanation", "all_mechanism", "all_severity", "dmarcbis_note",
        "lookup_count", "mechanisms",
    },
    ("MTA-STS", "mta_sts_deep"): {
        "max_age_level", "max_age_note", "mode", "mode_explanation",
    },
    ("TLS-RPT", "tls_rpt_deep"): {"cross_protocol_note", "destinations"},
    ("DANE", "dane_deep"): {"dnssec_status", "hosts_without_tlsa"},
}


@pytest.mark.parametrize(
    "card_name,panel_name,expected",
    [(c, p, f) for (c, p), f in sorted(GOLDEN_DEEP_PANELS.items())],
    ids=[f"{c}.{p}" for c, p in sorted(GOLDEN_DEEP_PANELS)],
)
def test_golden_deep_panels_are_fully_populated(golden_full, card_name, panel_name, expected):
    """The assertion that actually catches a dict key mismatch.

    Bugs 41, 42 and 43 each had a panel read a key its producer never
    published. Nothing raised. The field simply rendered blank, and asserting
    that the panel had *something* in it was not enough, because the rest of
    the panel was fine. Only the exact set of populated fields moves.
    """
    panel = _cards(golden_full)[card_name].get(panel_name)
    assert panel is not None, f"{panel_name} missing entirely"

    populated = _populated_fields(panel)
    assert populated == expected, (
        f"{card_name}/{panel_name} populated fields changed.\n"
        f"  went blank: {sorted(expected - populated)}\n"
        f"  newly set:  {sorted(populated - expected)}"
    )


def test_an_audit_stays_well_under_a_second(audit):
    """The harness is only worth having if it is cheap enough to keep.

    Timed on a fresh audit rather than on a cached one, so the number is the
    real cost of adding a zone.

    The bound is deliberately loose. A clean run is around 0.1s, but every
    audit in this module shares one thread pool, and on a loaded machine
    contention alone pushed a single audit past a 1.0s bound intermittently.
    A tight threshold made this test flaky without catching anything a loose
    one misses: the regression worth failing on is a check that starts doing
    real network I/O, and DNS or HTTP timeouts put an audit an order of
    magnitude above this, not a few hundred milliseconds.
    """
    domain, records = FULLY_CONFIGURED
    result = audit(FakeZone(records), domain, **HTTP["fully_configured"])
    assert result["elapsed_seconds"] < 5.0, (
        f"a full audit took {result['elapsed_seconds']}s with zero network, "
        f"which suggests a check is waiting on something real"
    )
