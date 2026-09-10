"""Regression tests for Doc 28: false or unsupported statements in app
output.

Item 1: fo= has no effect without ruf= (RFC 9989 section 4.7: "This tag's
content MUST be ignored if a ruf tag is not also specified"). No record or
target string this app generates may set fo= unless it also sets ruf=.

Item 4: the "no email authentication" verdict must gate on SPF actually
being absent (pill_label == "Missing"), not on status == "fail", which also
fires for +all, duplicate records, and syntax errors where SPF exists. The
"all attack vectors protected" verdict must be reachable; the vectors list
excludes Reporting Intelligence and holds at most three entries, so a gate
of `protected_count == 4` can never fire.

Item 8: an MTA-STS extension tag is legal under RFC 8461 section 3.1 and
must not raise a warning-severity issue.

Item 11: the PDF must not print a hardcoded all-clear line under an empty
roadmap; result_transformer's own roadmap summary already covers every
empty-roadmap case, including the not-an-all-clear ones.
"""
import io
import os
import sys

from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone
import checks_extra
import pdf_report
import result_transformer
from result_transformer import (
    _build_migration_path,
    _build_record_builder,
    build_executive_summary,
    build_security_roadmap,
)
from spf_execution_engine import build_dmarc_roadmap


# ---------------------------------------------------------------------------
# Item 1: no generated fo= without ruf=
# ---------------------------------------------------------------------------

def _assert_no_bare_fo(record, label):
    if record and "fo=" in record:
        assert "ruf=" in record, (
            f"{label} sets fo= with no ruf=, which RFC 9989 section 4.7 "
            f"requires for fo to have any effect: {record!r}"
        )


def test_record_builder_first_record_has_no_fo():
    result = _build_record_builder({}, "", "", None, [], domain="example.com")
    _assert_no_bare_fo(result["recommended_record"], "record builder (no existing record)")
    assert not any(c["tag"] == "fo" for c in result["changes"]), (
        "the change list still explains a tag that was never added"
    )


def test_record_builder_fix_mode_does_not_add_fo_without_ruf():
    tags = {"v": "DMARC1", "p": "none", "rua": "mailto:d@example.com"}
    record = "v=DMARC1; p=none; rua=mailto:d@example.com"
    result = _build_record_builder(tags, "none", "attention", record, [], domain="example.com")
    _assert_no_bare_fo(result["recommended_record"], "record builder (fix mode, no ruf)")
    assert not any(c["tag"] == "fo" for c in result["changes"])


def test_record_builder_fix_mode_sets_fo_when_ruf_present():
    """Control: when ruf already exists, fo=1 is a real, live recommendation."""
    tags = {"v": "DMARC1", "p": "none", "rua": "mailto:d@example.com",
             "ruf": "mailto:f@example.com"}
    record = "v=DMARC1; p=none; rua=mailto:d@example.com; ruf=mailto:f@example.com"
    result = _build_record_builder(tags, "none", "attention", record, [], domain="example.com")
    assert "fo=1" in result["recommended_record"]
    assert "ruf=" in result["recommended_record"]


def test_migration_path_has_no_fo_step_or_target_fo_without_ruf():
    tags = {"v": "DMARC1", "p": "none", "rua": "mailto:d@example.com"}
    path = _build_migration_path(tags, "none", "attention", domain="example.com")
    assert path is not None
    _assert_no_bare_fo(path["target_record"], "migration path target (no ruf)")
    for step in path["steps"]:
        assert "fo" not in step.get("tags_changed", []), (
            f"a migration step still recommends fo without ruf: {step!r}"
        )
        _assert_no_bare_fo(step.get("record_after"), f"migration step {step['step']}")


def test_migration_path_sets_fo_step_when_ruf_present():
    """Control: with ruf already set, the fo step is real advice."""
    tags = {"v": "DMARC1", "p": "none", "rua": "mailto:d@example.com",
             "ruf": "mailto:f@example.com"}
    path = _build_migration_path(tags, "none", "attention", domain="example.com")
    assert path is not None
    assert "fo=1" in path["target_record"]
    fo_steps = [s for s in path["steps"] if "fo" in s.get("tags_changed", [])]
    assert fo_steps, "expected a fo=1 step when ruf is already configured"


def test_dmarc_roadmap_wizard_has_no_bare_fo():
    raw_dmarc = {
        "record": None, "policy": "", "pct": None, "rua": None,
        "domain": "example.com",
    }
    raw_spf = {"record": None, "lookup_count": 0, "all_mechanism": ""}
    raw_dkim = {"found_selectors": []}

    roadmap = build_dmarc_roadmap(
        raw_dmarc, raw_spf, raw_dkim,
        tree_walk=None, has_mx=True, is_defensive=False,
    )
    assert roadmap is not None
    for step in roadmap["steps"]:
        _assert_no_bare_fo(step.get("dns_record"), f"roadmap stage {step['stage']}")


# ---------------------------------------------------------------------------
# Item 4: verdict gate and the unreachable "all vectors" branch
# ---------------------------------------------------------------------------

def _es(checks, roadmap=None):
    if roadmap is None:
        roadmap = build_security_roadmap(checks)
    return build_executive_summary(checks, roadmap)


_DKIM_ASSESSED = {"name": "DKIM", "status": "pass", "configured": True}


def test_no_dmarc_with_spf_present_but_failing_is_not_no_authentication():
    """+all means SPF exists and is badly configured, not that it is absent.
    DKIM is not consulted by this gate, so it must not be assumed absent
    either."""
    checks = [
        {"name": "DMARC", "status": "fail", "pill_label": "Missing", "configured": False},
        {"name": "SPF", "status": "fail", "pill_label": None,
         "record": "v=spf1 +all", "configured": True},
        _DKIM_ASSESSED,
    ]
    verdict = _es(checks)["verdict"]
    assert "no email authentication" not in verdict.lower(), (
        f"SPF publishes a (badly configured) record and the verdict still "
        f"claims no email authentication exists: {verdict!r}"
    )
    assert "publishes neither" not in verdict.lower(), (
        f"SPF exists, so the neither-record verdict is also wrong here: {verdict!r}"
    )


def test_no_dmarc_and_no_spf_reports_neither_record():
    checks = [
        {"name": "DMARC", "status": "fail", "pill_label": "Missing", "configured": False},
        {"name": "SPF", "status": "fail", "pill_label": "Missing", "configured": False},
        _DKIM_ASSESSED,
    ]
    verdict = _es(checks)["verdict"].lower()
    assert "publishes neither an spf record nor a dmarc record" in verdict
    assert "anyone on the internet can send email pretending to be you" not in verdict, (
        "the old sentence predicted spoofing with no supporting evidence"
    )


def test_every_vector_protected_gets_the_all_vectors_verdict():
    checks = [
        {
            "name": "DMARC", "status": "pass", "pill_label": "Enforcing", "configured": True,
            "tag_breakdown": {"health": {"status": "compatible"}, "config_warnings": []},
            "attack_surface": {"vectors": [
                {"name": "Spoofing via SPF", "status": "protected"},
                {"name": "Spoofing via DKIM", "status": "protected"},
                {"name": "Lookalike Domains", "status": "protected"},
            ]},
        },
        {"name": "SPF", "status": "pass", "pill_label": None,
         "record": "v=spf1 -all", "configured": True},
        _DKIM_ASSESSED,
    ]
    verdict = _es(checks)["verdict"]
    assert "all vectors" in verdict.lower() or "all attack vectors" in verdict.lower(), (
        f"every vector is protected but the verdict says something short of "
        f"that: {verdict!r}"
    )
    assert "most attack vectors" not in verdict.lower()


# ---------------------------------------------------------------------------
# Item 8: MTA-STS extension tags are legal, not a warning
# ---------------------------------------------------------------------------

def test_mta_sts_extension_tag_is_not_a_warning():
    tags, issues = checks_extra._validate_mta_sts_txt(
        "v=STSv1; id=20260101000000; ext-future-flag=1"
    )
    warning_issues = [i for i in issues if i["severity"] == "warning"]
    assert warning_issues == [], (
        f"RFC 8461 section 3.1 allows extension fields, but an unknown tag "
        f"still raised a warning-severity issue: {warning_issues!r}"
    )
    info_issues = [i for i in issues if i["severity"] == "info"]
    assert any("ext-future-flag" in i["issue"] for i in info_issues)


# ---------------------------------------------------------------------------
# Item 11: no hardcoded all-clear under an empty roadmap
# ---------------------------------------------------------------------------

def _pdf_text(audit_result: dict) -> str:
    pdf_bytes = pdf_report.generate_pdf(audit_result)
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


SCOPED_DOMAIN = "doc28-scoped.test"
_SCOPED_ZONE = {
    # No MX: DANE (which dns_infra does run) then reports pill "N/A" rather
    # than "Not configured", so the roadmap stays empty and this test is
    # actually exercising an empty roadmap rather than one DANE item.
    SCOPED_DOMAIN: {
        "A": ["203.0.113.90"],
        "NS": ["ns1." + SCOPED_DOMAIN],
    },
    "ns1." + SCOPED_DOMAIN: {"A": ["203.0.113.53"]},
}


def test_scoped_empty_roadmap_pdf_does_not_print_a_hardcoded_all_clear(audit):
    result = audit(FakeZone(dict(_SCOPED_ZONE)), SCOPED_DOMAIN, scope="dns_infra")
    assert result["security_roadmap"]["items"] == [], (
        "expected an empty roadmap for this fixture"
    )
    text = _pdf_text(result)

    assert "meets all current best practices" not in text, (
        "the PDF printed a hardcoded all-clear under a scoped run whose own "
        "roadmap summary says something else"
    )


def test_real_all_clear_still_reaches_the_pdf():
    """Control: a genuine all-clear (every protocol assessed, nothing to
    recommend) must still say so, just from roadmap['summary'] and not a
    second, separate hardcoded line."""
    checks = [
        {"name": "DMARC", "status": "pass", "pill_label": "Enforcing"},
        {"name": "SPF", "status": "pass", "pill_label": None, "record": "v=spf1 -all"},
        _DKIM_ASSESSED,
        {"name": "MTA-STS", "status": "pass", "record": "v=STSv1; id=1"},
        {"name": "TLS-RPT", "status": "pass", "record": "v=TLSRPTv1; rua=mailto:a@example.com"},
        {"name": "DANE", "status": "pass"},
        {"name": "BIMI", "status": "pass", "pill_label": "Not configured", "record": None},
    ]
    roadmap = build_security_roadmap(checks)
    assert roadmap["items"] == []
    assert "meets all current best practices" in roadmap["summary"].lower()

    es = build_executive_summary(checks, roadmap)
    audit_result = {
        "domain": "example.com", "checks": checks,
        "executive_summary": es, "security_roadmap": roadmap,
    }
    text = _pdf_text(audit_result)
    assert "meets all current best practices" in text.lower()
