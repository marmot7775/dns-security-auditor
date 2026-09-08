"""Regression tests for the five critical findings of the doc 12 cold review.

Each one is a case where the report stated something the data did not support.
They are grouped here because they were found together; the fixes live in
audit_engine, result_transformer and dkim_formatter.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import pdf_report
import remediation_planner
import result_transformer


# ---------------------------------------------------------------------------
# Finding 1: the blocklist check's Phase 2 label must equal its card name
# ---------------------------------------------------------------------------

def test_blocklist_timeout_card_is_findable_by_the_pdf():
    """A timed-out blocklist check must appear in the PDF body, not just the tally.

    Phase 2 registered the check with the label "Blacklist" while
    transform_blacklist names the card "Blocklist". _timeout_card and
    _error_card take the label, so on any failure path the cover's _tally
    counted a check that _protocol_details could not look up and therefore
    never rendered.
    """
    for card in (audit_engine._timeout_card("Blocklist"),
                 audit_engine._error_card("Blocklist", RuntimeError("boom"))):
        data = {"checks": [card]}
        assert pdf_report._get_check(data, "Blocklist") == card, (
            "the PDF body looks checks up by name and could not find this one"
        )
        counted = sum(pdf_report._tally(data["checks"]))
        assert counted == 1


def test_no_check_is_counted_on_the_cover_without_a_body_section():
    """Every name _tally can count must be renderable by _protocol_details.

    Guards the invariant doc 9 established, rather than the one label that
    broke it.
    """
    body_names = {
        "Blocklist", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "DNSSEC",
        "CAA", "MX Records", "Nameservers", "BIMI", "Certificate Transparency",
        # DMARC has its own section (_dmarc_deep_dive), not a protocol card.
        "DMARC",
    }
    source = open(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "audit_engine.py")
    ).read()
    # Every label handed to Phase 2 becomes a card name on the failure paths.
    import re
    labels = set(re.findall(r'lambda raw: transform_\w+\([^)]*\),\s*\n\s*"([^"]+)"\)\)',
                            source))
    assert labels, "could not find the Phase 2 labels; update this test"
    unrenderable = labels - body_names
    assert not unrenderable, (
        f"these Phase 2 labels have no section in pdf_report._protocol_details, "
        f"so a timeout or error card for them would be counted on the cover and "
        f"rendered nowhere: {sorted(unrenderable)}"
    )


# ---------------------------------------------------------------------------
# Finding 3: a failed DNSSEC lookup must not become a DANE finding
# ---------------------------------------------------------------------------

def _dane_raw(dnssec_validated):
    return {
        "has_tlsa": True,
        "dnssec_validated": dnssec_validated,
        "mx_hosts_checked": 1,
        "mx_hosts_with_tlsa": 1,
        "tlsa_records": [{
            "mx_host": "mx.example.com", "found": True,
            "records": [{"usage_name": "DANE-EE", "selector_name": "SPKI",
                         "matching_type_name": "SHA-256"}],
        }],
        "issues": [],
    }


def test_dane_does_not_claim_dnssec_is_off_when_the_lookup_failed():
    """The hoisted DNSSEC check timing out must not produce DANE advice.

    run_full_audit hoists DNSSEC ahead of Phase 2 so DANE can read its verdict.
    On timeout it writes a stub with has_dnssec False, and DANE read that as a
    fact, telling a signed domain with working DANE to "enable DNSSEC".
    """
    card = result_transformer.transform_dane(_dane_raw(None), "example.com")
    blob = " ".join([
        card.get("verdict", ""), card.get("explanation", ""),
        card.get("fix") or "",
        " ".join(d.get("text", "") for d in card.get("details", [])),
    ]).lower()
    assert "dnssec is not enabled" not in blob
    assert "enable dnssec" not in blob
    assert "not confirmed" in card["verdict"].lower()


def test_dane_still_flags_a_genuinely_unsigned_domain():
    """Control: DNSSEC confirmed absent must still produce the finding."""
    card = result_transformer.transform_dane(_dane_raw(False), "example.com")
    assert "dnssec missing" in card["verdict"].lower()
    assert "Enable DNSSEC" in (card.get("fix") or "")


def test_dane_still_passes_a_signed_domain():
    """Control: DNSSEC confirmed present must still pass."""
    card = result_transformer.transform_dane(_dane_raw(True), "example.com")
    assert card["status"] == "pass"


def test_hoist_stubs_are_marked_as_failed_lookups():
    """The stubs run_full_audit writes on a failed hoist must carry the flag.

    Without lookup_failed, _raw_check_dane cannot tell the stub's
    has_dnssec=False from a real negative answer.
    """
    source = open(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "audit_engine.py")
    ).read()
    marker = '"check": "DNSSEC", "domain": domain, "has_dnssec": False'
    assert source.count(marker) == 2, "expected the two hoist failure stubs"
    for chunk in source.split(marker)[1:]:
        assert '"lookup_failed": True' in chunk[:400], (
            "a DNSSEC hoist failure stub is missing lookup_failed, so DANE will "
            "read its has_dnssec=False as a fact about the domain"
        )


# ---------------------------------------------------------------------------
# Finding 4: two SPF records is not "no SPF record"
# ---------------------------------------------------------------------------

def test_multiple_spf_records_are_not_reported_as_a_missing_record():
    """RFC 7208 4.5: two v=spf1 records is a PermError, not an absent record.

    _raw_check_spf detected it correctly but returned with record still None,
    and transform_spf keyed "No SPF record published" off the empty record
    field, handing the operator fix text telling them to publish the record
    they had published twice.
    """
    raw = {
        "check": "SPF", "domain": "example.com", "record": None, "status": "error",
        "multiple_records": ["v=spf1 include:_spf.google.com ~all",
                             "v=spf1 ip4:198.51.100.7 -all"],
        "issues": [{"severity": "error", "issue": "Multiple SPF records (2)",
                    "plain_english": "RFC 7208 requires exactly one.",
                    "fix": "Merge them."}],
        "syntax_errors": [], "mechanisms": [],
    }
    card = result_transformer.transform_spf(raw, has_mx=True)

    assert card["status"] == "fail"
    assert card["pill_label"] == "Multiple records"
    # The verdict and the fix are what the operator acts on. The explanation may
    # legitimately compare the effect to having no record; the verdict may not
    # say it, and the fix must not tell them to publish one.
    assert "no spf record" not in card["verdict"].lower()
    assert "publish an spf" not in (card["fix"] or "").lower()
    assert "merge" in card["fix"].lower()
    # Both records have to be visible; the operator has to know which two.
    texts = " ".join(d.get("text", "") for d in card["details"])
    assert "include:_spf.google.com" in texts and "198.51.100.7" in texts


def test_multiple_spf_records_reach_the_roadmap_as_critical():
    """The roadmap gated on pill_label "Missing", so this contributed nothing."""
    card = {"name": "SPF", "status": "fail", "pill_label": "Multiple records"}
    roadmap = result_transformer.build_security_roadmap([card])
    spf_items = [i for i in roadmap["items"] if i["protocol"] == "SPF"]
    assert spf_items, "a PermError for every message must appear in the roadmap"
    assert spf_items[0]["priority"] == "critical"


def test_multiple_spf_records_reach_every_layer_not_just_the_card():
    """Doc 16: two layers below the card still read the empty record field.

    The card and build_security_roadmap were taught that "record": None plus a
    populated multiple_records is a PermError. build_remediation_plan and the
    resilience section were not, and both key their "you have no SPF" branch
    off the same empty field. One audit of a domain publishing two records said
    all four of these at once:

        card       2 SPF records published (RFC 7208 requires exactly one)
        roadmap    Merge the duplicate SPF records into one
        plan       Publish SPF Record
        resilience missing / "No SPF record found."
    """
    raw_spf = {
        "check": "SPF", "domain": "example.com", "record": None, "status": "error",
        "multiple_records": ["v=spf1 include:_spf.google.com ~all",
                             "v=spf1 ip4:198.51.100.7 -all"],
        "issues": [], "syntax_errors": [], "mechanisms": [],
    }

    plan = remediation_planner.build_remediation_plan(
        checks=[], raw_results={"spf": raw_spf}, has_mx=True
    )
    titles = [s["title"] for tier in plan.values() for s in tier]
    assert "Publish SPF Record" not in titles, (
        f"the plan told a domain with two SPF records to publish one: {titles}"
    )
    # Suppressed, not replaced: the card and the security roadmap already tell
    # the operator to merge, and the defect here was the publish advice.
    assert not any("SPF" in t for t in titles), (
        f"the plan should stay silent on SPF rather than add a fourth copy of "
        f"the merge instruction: {titles}"
    )

    resilience = audit_engine._build_resilience_analysis(
        raw_results={"spf": raw_spf, "dmarc": {}, "dkim": {}},
        checks=[], has_mx=True, is_defensive=False,
    )
    spf_mech = resilience["mechanisms"]["spf"]
    assert spf_mech["status"] != "missing", (
        f"the resilience section reports the records absent: {spf_mech!r}"
    )
    assert spf_mech["status"] == "broken"
    assert "no spf record found" not in spf_mech["note"].lower()
    assert "7208" in spf_mech["note"]


# ---------------------------------------------------------------------------
# Finding 5: an empty roadmap is not always an all-clear
# ---------------------------------------------------------------------------

_ALL_CLEAR = "meets all current best practices"


def _clean(name):
    return {"name": name, "status": "pass", "pill_label": "Configured",
            "records_found": 1}


def test_roadmap_all_clear_requires_every_protocol_to_have_been_read():
    """Unavailable checks pass through every gate, emptying the roadmap.

    A run where the DMARC, SPF and DKIM lookups all failed printed "Your email
    security meets all current best practices across all protocols" on page 2,
    directly under a cover reading "3 not checked".
    """
    checks = [
        result_transformer._lookup_unavailable_card(n, {}, "record")
        for n in ("DMARC", "SPF", "DKIM")
    ] + [_clean(n) for n in ("MTA-STS", "TLS-RPT", "DANE", "BIMI")]

    roadmap = result_transformer.build_security_roadmap(checks)
    assert roadmap["total"] == 0, "fixture should produce no action items"
    assert _ALL_CLEAR not in roadmap["summary"]
    assert "not assessed" in roadmap["summary"]
    assert set(roadmap["unread_protocols"]) == {"DMARC", "SPF", "DKIM"}


def test_roadmap_all_clear_requires_every_protocol_to_have_run():
    """A scoped audit examines a subset and must not speak for the rest."""
    roadmap = result_transformer.build_security_roadmap(
        [{"name": "DMARC", "status": "pass", "pill_label": "Enforcing"}]
    )
    assert _ALL_CLEAR not in roadmap["summary"]
    assert "outside the scope" in roadmap["summary"]


def test_scoped_audit_gives_no_advice_about_checks_it_did_not_run():
    """Absent cards returned defaults, so every gate below Medium fired."""
    roadmap = result_transformer.build_security_roadmap(
        [{"name": "DMARC", "status": "pass", "pill_label": "Enforcing"}]
    )
    named = {i["protocol"] for i in roadmap["items"]}
    assert not named & {"MTA-STS", "TLS-RPT", "DANE", "BIMI"}, (
        f"roadmap advised on protocols that never ran: {sorted(named)}"
    )


def test_roadmap_still_gives_the_all_clear_when_everything_really_is_clean():
    """Control: the all-clear must survive for a genuinely complete clean run."""
    checks = [_clean(n) for n in
              ("DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "BIMI")]
    roadmap = result_transformer.build_security_roadmap(checks)
    assert roadmap["total"] == 0
    assert _ALL_CLEAR in roadmap["summary"]
