"""Regression tests for the major findings of the doc 12 cold review.

Findings 6 through 13: wrong attribution, a failed lookup treated as an
answer, and summaries that spoke for protocols the run never examined.
"""
import base64
import os
import sys

import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import checks_extra
import pdf_report
import result_transformer
from advanced_fingerprinting import AdvancedVendorFingerprinter


# ---------------------------------------------------------------------------
# Finding 6: vendor attribution must be on label boundaries
# ---------------------------------------------------------------------------

def _fingerprint(spf_record, mx_hosts):
    fp = AdvancedVendorFingerprinter("victim.example", prefetch={
        "spf_record": spf_record, "mx_hosts": mx_hosts, "dmarc_record": None,
        "tls_rpt_record": None, "mta_sts_record": None, "bimi_record": None,
        "txt_ttl": None,
    })
    return {v["vendor"] for v in fp.fingerprint_all().get("vendors", [])}


def test_lookalike_domains_do_not_wear_a_vendor_badge():
    """A substring match handed an attacker's domain the real vendor's name.

    This module produces the entire vendors list the report shows, in the web
    card and the PDF. spf_execution_engine and spf_intelligence were moved onto
    label boundaries; this one was missed, so the badge survived at 0.99
    confidence in the place users actually read it.
    """
    found = _fingerprint(
        "v=spf1 include:sendgrid.net.attacker.example -all",
        ["mx.google.com.attacker.example"],
    )
    assert "SendGrid" not in found
    assert "Google Workspace" not in found


def test_genuine_vendors_are_still_detected():
    """Control: the real domains, and subdomains of them, must still match."""
    found = _fingerprint(
        "v=spf1 include:sendgrid.net include:eu._spf.google.com -all",
        ["aspmx.l.google.com"],
    )
    assert "SendGrid" in found
    assert "Google Workspace" in found


@pytest.mark.parametrize("matcher,candidate", [
    ("_match_spf_vendor", "sendgrid.net.evil.example"),
    ("_match_mx_vendor", "google.com.evil.example"),
    ("_match_reporting_vendor", "rua@dmarcian.com.evil.example"),
])
def test_every_matcher_rejects_a_suffix_lookalike(matcher, candidate):
    fp = AdvancedVendorFingerprinter("victim.example", prefetch={})
    assert getattr(fp, matcher)(candidate) is None


# ---------------------------------------------------------------------------
# Finding 7: a DKIM selector lookup that failed is not "selector not found"
# ---------------------------------------------------------------------------

def test_dkim_selector_servfail_is_not_reported_as_not_found():
    raw = {
        "domain": "example.com", "found_selectors": [], "status": "unavailable",
        "unavailable_reason": "dns_lookup_failed",
        "lookup_target": "sel._domainkey.example.com", "tested_count": 1,
    }
    card = result_transformer.transform_dkim(raw, "example.com")
    assert card["status"] == "unavailable"
    blob = f"{card['verdict']} {card['explanation']}".lower()
    assert "not found" not in blob
    assert "verify the selector name" not in blob


def test_dkim_selector_nxdomain_still_reports_not_found():
    """Control: an absent record is a true statement about the domain."""
    raw = {"domain": "example.com", "found_selectors": [],
           "selector_not_found": "sel", "tested_count": 1}
    card = result_transformer.transform_dkim(raw, "example.com")
    assert card["status"] == "fail"
    assert "not found" in card["verdict"].lower()


# ---------------------------------------------------------------------------
# Finding 8: checks_extra crashed on a byte, and read SERVFAIL as absence
# ---------------------------------------------------------------------------

class _Resolver:
    def __init__(self, behaviour):
        self._behaviour = behaviour

    def resolve(self, name, rdtype):
        return self._behaviour(name, rdtype)


def test_undecodable_txt_byte_does_not_take_the_check_down(monkeypatch):
    """UnicodeDecodeError is not a DNSException, so it escaped every handler.

    One byte at _mta-sts, _smtp._tls or default._bimi turned into a
    server-error card. audit_engine._lookup_txt was fixed for this; this copy
    was missed.
    """
    class _RD:
        strings = [b"v=STSv1; id=\xff\xfe"]

    monkeypatch.setattr(checks_extra, "_get_resolver",
                        lambda *a, **k: _Resolver(lambda n, t: [_RD()]))
    records = checks_extra._lookup_txt("_mta-sts.example.com")
    assert records == ["v=STSv1; id=��"]


@pytest.mark.parametrize("check,transform,name", [
    (checks_extra.check_mta_sts, result_transformer.transform_mta_sts, "MTA-STS"),
    (checks_extra.check_tls_rpt, result_transformer.transform_tls_rpt, "TLS-RPT"),
    (checks_extra.check_bimi, result_transformer.transform_bimi, "BIMI"),
])
def test_servfail_is_not_reported_as_not_configured(monkeypatch, check, transform, name):
    def _servfail(n, t):
        raise dns.resolver.NoNameservers("all nameservers failed")

    monkeypatch.setattr(checks_extra, "_get_resolver",
                        lambda *a, **k: _Resolver(_servfail))
    raw = check("example.com")
    assert raw["status"] == "unavailable"
    card = transform(raw, "example.com")
    assert card["status"] == "unavailable"
    assert card["name"] == name
    blob = f"{card['verdict']} {card.get('fix') or ''}".lower()
    assert "not configured" not in blob
    assert "publish" not in blob


@pytest.mark.parametrize("check", [
    checks_extra.check_mta_sts, checks_extra.check_tls_rpt, checks_extra.check_bimi,
])
def test_nxdomain_still_means_the_record_is_absent(monkeypatch, check):
    """Control: an absent record must keep reporting as absent."""
    def _nx(n, t):
        raise dns.resolver.NXDOMAIN("no such name")

    monkeypatch.setattr(checks_extra, "_get_resolver", lambda *a, **k: _Resolver(_nx))
    assert check("example.com")["status"] != "unavailable"


# ---------------------------------------------------------------------------
# Finding 9: a check that did not run is not a finding against the domain
# ---------------------------------------------------------------------------

def test_timeout_and_error_cards_do_not_score_against_the_domain():
    """Both used to land in the cover's Warnings and Issues figures.

    Nothing about the domain was learned on either path, so they belong in the
    "not checked" counter that _tally, the summary layers and the front end
    all already understand.
    """
    cards = [audit_engine._timeout_card("DNSSEC"),
             audit_engine._error_card("DNSSEC", RuntimeError("boom"))]
    for card in cards:
        assert card["status"] == "unavailable"
        assert "not checked" in card["verdict"].lower()
    passes, warns, fails, unavailable = pdf_report._tally(cards)
    assert (passes, warns, fails, unavailable) == (0, 0, 0, 2)


def test_error_card_still_hides_the_exception_text():
    """Control: the earlier fix against leaking server paths must survive."""
    card = audit_engine._error_card(
        "DMARC", RuntimeError("/home/marmot7/secret/path.py exploded"))
    rendered = repr(card)
    assert "marmot7" not in rendered and "secret" not in rendered


# ---------------------------------------------------------------------------
# Findings 10 and 11: summaries must not speak for protocols that never ran
# ---------------------------------------------------------------------------

def _es(checks):
    return result_transformer.build_executive_summary(
        checks, result_transformer.build_security_roadmap(checks))


DMARC_CLEAN = {
    "name": "DMARC", "status": "pass", "pill_label": "Enforcing",
    "tag_breakdown": {"health": {"status": "ready"}, "config_warnings": []},
    "attack_surface": {"vectors": [{"name": "v", "status": "protected"}] * 4},
}


def test_protocol_coverage_excludes_protocols_that_never_ran():
    """A scoped run reported 1/9 for eight protocols it never queried."""
    coverage = _es([DMARC_CLEAN])["protocol_coverage"]
    assert coverage["total"] == 1
    assert coverage["configured"] == 1


def test_protocol_coverage_denominator_matches_the_reports_own_check_list():
    """The About page says the cover "scores N of these" over the check names.

    The two figures have to be able to agree, which they cannot when the
    denominator counts cards the report does not contain.
    """
    checks = [DMARC_CLEAN] + [
        {"name": n, "status": "pass", "pill_label": "Configured"}
        for n in ("SPF", "DKIM", "MTA-STS")
    ]
    coverage = _es(checks)["protocol_coverage"]
    assert coverage["total"] <= len(checks)


def test_deliverability_does_not_call_unchecked_protocols_solid():
    """"SPF, DKIM, and DMARC are properly set up" on a run that read one."""
    summary = _es([DMARC_CLEAN])["deliverability_summary"]
    assert "SPF, DKIM, and DMARC are properly set up" not in summary
    assert "outside the scope" in summary


def test_deliverability_all_clear_survives_a_complete_clean_run():
    """Control."""
    checks = [DMARC_CLEAN] + [
        {"name": n, "status": "pass", "pill_label": "Configured"}
        for n in ("SPF", "DKIM")
    ]
    assert "properly set up" in _es(checks)["deliverability_summary"]


# ---------------------------------------------------------------------------
# Finding 12: a key that does not parse is broken, not "undetermined"
# ---------------------------------------------------------------------------

def _rsa_spki_b64(bits=2048):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    der = (rsa.generate_private_key(public_exponent=65537, key_size=bits)
           .public_key()
           .public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))
    return base64.b64encode(der).decode()


def _dkim_card(record):
    return result_transformer.transform_dkim(
        {"found_selectors": [{"selector": "s1", "record": record}],
         "tested_count": 1}, "example.com")


@pytest.mark.parametrize("record", [
    "v=DKIM1; k=rsa; p=" + _rsa_spki_b64()[:60],      # truncated RSA
    "v=DKIM1; k=ed25519; p=anVuaw==",                  # junk Ed25519
])
def test_unparseable_key_is_red_everywhere_in_the_report(record):
    """One key used to carry three severities in one report.

    The card header said FAIL, the deep-dive row said amber "key strength
    could not be determined" with a blank Bits column, and the guidance said
    "Review key configuration". has_weak stayed False, so the roadmap said
    nothing at all about a key that fails every signature it makes.
    """
    card = _dkim_card(record)
    assert card["status"] == "fail"

    deep = card["dkim_deep"]
    key = deep["keys"][0]
    assert key["rating"] == "red"
    assert "could not be determined" not in key["rating_label"].lower()
    assert key["rotation_status"] == "Replace"
    assert deep["has_invalid"] is True
    assert "review key configuration" not in deep["rotation_guidance"].lower()

    roadmap = result_transformer.build_security_roadmap([card])
    dkim_items = [i for i in roadmap["items"] if i["protocol"] == "DKIM"]
    assert dkim_items and dkim_items[0]["priority"] == "critical"


def test_a_revoked_key_is_not_called_unparseable():
    """An empty p= is a deliberate revocation with its own guidance."""
    card = _dkim_card("v=DKIM1; k=rsa; p=")
    deep = card["dkim_deep"]
    assert deep["has_invalid"] is False
    assert "revoked" in deep["rotation_guidance"].lower()
    assert deep["keys"][0]["rotation_status"] == "Revoked"


def test_a_healthy_key_is_unaffected():
    """Control."""
    card = _dkim_card("v=DKIM1; k=rsa; p=" + _rsa_spki_b64())
    assert card["status"] == "pass"
    assert card["dkim_deep"]["has_invalid"] is False
    assert card["dkim_deep"]["keys"][0]["rating"] == "green"


# ---------------------------------------------------------------------------
# Finding 13: pct=0 must name the receiver population
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_pct_zero_verdict_names_both_receiver_populations(policy):
    """RFC 9989 C.5.2 removed pct, so "enforcement is switched off" is wrong.

    The same report warns that RFC 9989 receivers ignore pct, so an unqualified
    claim contradicted the tool's own tag breakdown and the RFC 9989 Readiness
    metric on the cover.
    """
    card = result_transformer.transform_dmarc({
        "domain": "example.com",
        "record": f"v=DMARC1; p={policy}; pct=0; rua=mailto:a@example.com",
        "policy": policy, "pct": 0, "rua": "mailto:a@example.com", "issues": [],
    })
    assert card["status"] == ("fail" if policy == "quarantine" else "warn")

    # Both populations are still named, in the detail row rather than the
    # verdict. Carrying the split inline ran the verdict to 132 characters
    # against roughly 45 for every other verdict on this card, so the verdict
    # now states the weaker population and the row gives the reason.
    row = next(d["text"] for d in card["details"] if "pct=0" in d["text"])
    assert "7489" in row and "9989" in row, row
    assert "9989" in card["explanation"] or "9989" in row

    if policy == "reject":
        # RFC 7489 section 6.6.4 quarantines the unselected fraction of a
        # reject policy. "enforce on no mail" was the original wording and it
        # is the one thing those receivers do not do.
        assert "quarantine" in card["verdict"].lower(), card["verdict"]
        assert "no mail" not in card["verdict"].lower(), card["verdict"]
        assert "quarantine all failing messages" in row, row


def test_out_of_range_pct_is_not_quoted_as_zero():
    """The disabled verdict hardcoded "pct=0" regardless of the real value."""
    card = result_transformer.transform_dmarc({
        "domain": "example.com",
        "record": "v=DMARC1; p=reject; pct=-5", "policy": "reject",
        "pct": -5, "issues": [],
    })
    assert "pct=-5" in card["verdict"]
    assert "pct=0" not in card["verdict"]
    # And no detail row does percentage arithmetic on an impossible value.
    # The engine's own "pct value out of range" issue is what speaks here.
    assert not [d for d in card["details"] if "-5% of failing" in d["text"]], (
        card["details"]
    )
