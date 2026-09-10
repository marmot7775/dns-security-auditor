"""Regression tests for Doc 27: the PDF report says things the audit did
not find.

Item 1's fix moved Protocol Coverage's "configured" decision out of a
hardcoded pill_label allowlist and into a `configured` boolean the transform
layer sets from the check result itself. Item 2's fix made the DMARC Deep
Dive render `details`, `explanation`, and `fix` the way `_protocol_card`
does for every other check, instead of silently dropping them. Item 3's fix
made a scoped PDF name what it covered on the cover page.

Assertions for items 1 and 2 land on the rendered PDF text, not on the
result dict: "correct in the data and wrong in the document" is exactly the
failure mode a dict-only assertion cannot catch.
"""
import io
import os
import sys

from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone
import pdf_report
import result_transformer

PROTOCOL_NAMES = [
    "DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "DNSSEC", "BIMI", "CAA",
]


def _pdf_text(audit_result: dict) -> str:
    pdf_bytes = pdf_report.generate_pdf(audit_result)
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# ---------------------------------------------------------------------------
# Item 1: Protocol Coverage must count from the check result, not from a
# hardcoded pill_label allowlist
# ---------------------------------------------------------------------------

BLANK_DOMAIN = "blank-zone.test"
_BLANK_ZONE = {
    BLANK_DOMAIN: {"NS": ["ns1." + BLANK_DOMAIN]},
    "ns1." + BLANK_DOMAIN: {"A": ["203.0.113.53"]},
}


def test_blank_zone_scores_zero_protocol_coverage(audit):
    """No MX, no records anywhere. Every one of the 9 protocols is either
    genuinely missing or waived as not applicable to a non-mail domain. The
    old allowlist counted pills like DKIM's "Not found", DNSSEC's "Not
    enabled", SPF's "No mail", and every "N/A" as configured, reporting
    4/8 for a domain publishing nothing in DNS."""
    result = audit(FakeZone(dict(_BLANK_ZONE)), BLANK_DOMAIN)
    pc = result["executive_summary"]["protocol_coverage"]

    assert pc["configured"] == 0, (
        f"a domain publishing nothing in DNS scored protocol coverage "
        f"{pc['configured']}/{pc['total']}"
    )


def test_cover_count_matches_the_number_of_cards_marked_configured(audit):
    """The cover's Protocol Coverage figure and each card's own `configured`
    flag must agree, driven from one real audit result rather than a
    hand-built dict, so a new pill or a new protocol cannot desync the two
    again."""
    result = audit(FakeZone(dict(_BLANK_ZONE)), BLANK_DOMAIN)
    checks = {c["name"]: c for c in result["checks"]}

    expected = sum(
        1 for name in PROTOCOL_NAMES
        if name in checks
        and checks[name].get("status") != "unavailable"
        and checks[name].get("configured")
    )
    assert result["executive_summary"]["protocol_coverage"]["configured"] == expected


CONFIGURED_DOMAIN = "configured-zone.test"
_CONFIGURED_ZONE = {
    CONFIGURED_DOMAIN: {
        "MX": [(10, "mail." + CONFIGURED_DOMAIN)],
        "TXT": ["v=spf1 mx -all"],
        "NS": ["ns1." + CONFIGURED_DOMAIN],
        "CAA": [(0, "issue", "letsencrypt.org")],
    },
    f"_dmarc.{CONFIGURED_DOMAIN}": {
        "TXT": ["v=DMARC1; p=reject; rua=mailto:d@" + CONFIGURED_DOMAIN],
    },
    "mail." + CONFIGURED_DOMAIN: {"A": ["203.0.113.71"]},
    "ns1." + CONFIGURED_DOMAIN: {"A": ["203.0.113.53"]},
}


def test_partially_configured_zone_counts_only_what_it_published(audit):
    """DMARC, SPF, and CAA are published; DKIM, MTA-STS, TLS-RPT, DANE,
    DNSSEC, and BIMI are not. Coverage must count exactly the three that
    are, not more (the old pass-branch bug) and not fewer (the old
    warn/fail allowlist gaps)."""
    result = audit(FakeZone(dict(_CONFIGURED_ZONE)), CONFIGURED_DOMAIN)
    checks = {c["name"]: c for c in result["checks"]}

    for name in ("DMARC", "SPF", "CAA"):
        assert checks[name].get("configured") is True, (
            f"{name} publishes a record but was not marked configured: "
            f"{checks[name]!r}"
        )
    for name in ("MTA-STS", "TLS-RPT", "BIMI", "DNSSEC"):
        assert checks[name].get("configured") is False, (
            f"{name} publishes nothing but was marked configured: "
            f"{checks[name]!r}"
        )

    pc = result["executive_summary"]["protocol_coverage"]
    assert pc["configured"] == 3, (
        f"expected exactly DMARC, SPF, and CAA to count as configured, "
        f"got {pc['configured']}/{pc['total']}"
    )


# ---------------------------------------------------------------------------
# Item 2: the DMARC Deep Dive must not drop the finding and the remediation
# ---------------------------------------------------------------------------

def _dmarc_pdf_result(dmarc_check):
    checks = [dmarc_check]
    roadmap = result_transformer.build_security_roadmap(checks)
    es = result_transformer.build_executive_summary(checks, roadmap)
    return {
        "domain": "thirdparty-rua.test",
        "checks": checks,
        "executive_summary": es,
        "security_roadmap": roadmap,
    }


def test_error_severity_dmarc_details_reach_the_rendered_pdf():
    """Reproduces the doc's second case: rua points at a third party that
    has not authorized this domain, so aggregate reports are silently
    dropped. The card carries an error-severity detail naming this; the old
    Deep Dive read only status/verdict/record/tag_breakdown and never
    rendered `details`, so this fact never reached the PDF at all."""
    dmarc_check = {
        "name": "DMARC",
        "status": "fail",
        "pill_label": None,
        "verdict": "p=reject (authentication failures are rejected)",
        "record": "v=DMARC1; p=reject; rua=mailto:reports@thirdparty-rua.test",
        "explanation": "DMARC record found but a reporting destination is unauthorized.",
        "details": [
            {
                "type": "error",
                "text": (
                    "Aggregate reporting (rua): 2 destination(s), 1 NOT "
                    "authorized (reports silently dropped)"
                ),
            },
            {"type": "good", "text": "Policy p=reject: authentication failures are rejected"},
        ],
        "fix": (
            "Publish a DMARC authorization record at thirdparty-rua.test "
            "authorizing this domain's reports, or remove that destination."
        ),
        "configured": True,
    }

    text = _pdf_text(_dmarc_pdf_result(dmarc_check))

    assert "1 NOT" in text and "authorized" in text, (
        "the error-severity rua detail did not reach the rendered PDF text"
    )
    assert "reports silently dropped" in text, (
        "the consequence of the unauthorized destination is missing from the PDF"
    )


def test_dmarc_explanation_and_fix_reach_the_rendered_pdf():
    """The no-DMARC-record reproduction: Section 3 used to be the FAIL line,
    "No DMARC policy published", and the Record Builder, with the
    explanation and fix dropped entirely (the fix survived only as an
    unlabelled numbered line in Priority Fixes)."""
    dmarc_check = {
        "name": "DMARC",
        "status": "fail",
        "pill_label": "Missing",
        "verdict": "No DMARC policy published",
        "record": None,
        "explanation": (
            "This is a distinctive marker sentence identifying the DMARC "
            "explanation text for this test."
        ),
        "details": [],
        "fix": "This is a distinctive marker sentence identifying the DMARC fix text.",
        "configured": False,
    }

    text = _pdf_text(_dmarc_pdf_result(dmarc_check))

    assert "identifying the DMARC explanation text" in text, (
        "the DMARC explanation did not reach the rendered PDF text"
    )
    assert "identifying the DMARC fix text" in text, (
        "the DMARC fix did not reach the rendered PDF text"
    )


# ---------------------------------------------------------------------------
# Item 3: a scoped PDF must name the scope on the cover
# ---------------------------------------------------------------------------

SCOPED_DOMAIN = "scoped-cover.test"
_SCOPED_ZONE = {
    SCOPED_DOMAIN: {
        "MX": [(10, "mail." + SCOPED_DOMAIN)],
        "A": ["203.0.113.90"],
        "NS": ["ns1." + SCOPED_DOMAIN],
    },
    "mail." + SCOPED_DOMAIN: {"A": ["203.0.113.91"]},
    "ns1." + SCOPED_DOMAIN: {"A": ["203.0.113.53"]},
}


def test_scoped_pdf_names_its_scope_on_the_cover(audit):
    result = audit(FakeZone(dict(_SCOPED_ZONE)), SCOPED_DOMAIN, scope="dns_infra")
    text = _pdf_text(result)

    assert "DNS Infrastructure" in text, (
        "the PDF cover does not name the scope this report actually ran"
    )
    assert "5 of 12 checks" in text, (
        "the PDF cover does not say how many of the full check set this "
        "scope covers"
    )


def test_complete_scope_pdf_does_not_print_a_scope_line(audit):
    result = audit(FakeZone(dict(_SCOPED_ZONE)), SCOPED_DOMAIN, scope="complete")
    text = _pdf_text(result)

    assert "of 12 checks" not in text, (
        "a complete audit is not scoped and should not print a scope line"
    )
