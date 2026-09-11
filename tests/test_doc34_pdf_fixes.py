"""Regression tests for Doc 34 Part A: PDF rendering defects and one false
sentence on scoped reports.

The fixture zone is the one the doc was reproduced against: SPF, one DKIM
selector, DMARC p=none with pct and ri, two MX, no DNSSEC, no MTA-STS.
Rendered once complete and once with scope=dns_infra.
"""
import base64
import io
import os
import re
import sys

import pytest
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone
import pdf_report
from result_transformer import (
    _build_migration_path,
    build_executive_summary,
    build_security_roadmap,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN = "doc34-fixture.test"


def _rsa_key_record(bits=2048):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    der = (rsa.generate_private_key(public_exponent=65537, key_size=bits)
           .public_key()
           .public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


@pytest.fixture(scope="module")
def zone():
    return {
        DOMAIN: {
            "MX": [(10, "mx1." + DOMAIN), (20, "mx2." + DOMAIN)],
            "TXT": ["v=spf1 mx -all"],
            "A": ["203.0.113.34"],
            "NS": ["ns1." + DOMAIN],
        },
        f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=none; pct=100; ri=86400; rua=mailto:d@" + DOMAIN]},
        f"selector1._domainkey.{DOMAIN}": {"TXT": [_rsa_key_record()]},
        "mx1." + DOMAIN: {"A": ["203.0.113.35"]},
        "mx2." + DOMAIN: {"A": ["203.0.113.36"]},
        "ns1." + DOMAIN: {"A": ["203.0.113.53"]},
    }


def _pdf_text(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# ---------------------------------------------------------------------------
# Item 1: scoped out is not the same as DNS did not answer
# ---------------------------------------------------------------------------

def test_scoped_run_says_out_of_scope_not_that_dns_failed(audit, zone):
    result = audit(FakeZone(dict(zone)), DOMAIN, scope="dns_infra")
    es = result["executive_summary"]
    verdict = es["verdict"]
    assert "did not answer" not in verdict, verdict
    assert "did not complete" not in verdict, verdict
    assert "outside its scope" in verdict, verdict
    assert es["spoofing_protection"]["detail"] == "Not in this run's scope."
    # And the PDF carries the same sentence, not the lookup-failure one.
    text = _pdf_text(result)
    assert "did not answer" not in text
    assert "outside its scope" in text


def test_a_real_lookup_failure_keeps_the_lookup_failure_wording(audit, zone):
    z = FakeZone(dict(zone)).fail(DOMAIN, "TXT").fail("_dmarc." + DOMAIN, "TXT")
    verdict = audit(z, DOMAIN)["executive_summary"]["verdict"]
    assert "did not complete" in verdict, verdict
    assert "outside its scope" not in verdict, verdict


# ---------------------------------------------------------------------------
# Item 2: monitoring has a condition, not a calendar
# ---------------------------------------------------------------------------

_DURATION = re.compile(r"\b\d+(\s*-\s*\d+)?\s*(weeks?|days?)\b", re.IGNORECASE)


def test_no_monitoring_step_or_fix_names_a_number_of_weeks_or_days(audit, zone):
    strings = []
    for tags, policy in (({"v": "DMARC1", "p": "none", "rua": "mailto:a@x.test"}, "none"),
                         ({"v": "DMARC1", "p": "quarantine", "rua": "mailto:a@x.test"}, "quarantine")):
        path = _build_migration_path(tags, policy, "monitoring", domain=DOMAIN)
        for step in path["steps"]:
            strings.append(step.get("action", ""))
            strings.append(step.get("why", ""))
    result = audit(FakeZone(dict(zone)), DOMAIN)
    for item in result["security_roadmap"]["items"]:
        strings.append(item.get("action", ""))
        strings.append(item.get("impact", ""))
    for card in result["checks"]:
        strings.append(card.get("fix") or "")
    offenders = [s for s in strings if _DURATION.search(s)]
    assert offenders == [], offenders
    assert any("until the sender inventory is stable" in s for s in strings)


# ---------------------------------------------------------------------------
# Item 3: roadmap ordered by priority
# ---------------------------------------------------------------------------

def test_roadmap_lists_a_critical_item_before_a_high_one():
    checks = [
        # DMARC p=none with rua produces a HIGH item and is appended first.
        {"name": "DMARC", "status": "warn", "pill_label": None, "configured": True,
         "record": "v=DMARC1; p=none; rua=mailto:a@x.test",
         "tag_breakdown": {"health": {"status": "monitoring"}, "config_warnings": []}},
        {"name": "SPF", "status": "pass", "configured": True, "record": "v=spf1 -all"},
        # An unparseable DKIM key produces a CRITICAL item, appended later.
        {"name": "DKIM", "status": "fail", "configured": True,
         "dkim_deep": {"has_invalid": True, "has_weak": False}},
    ]
    items = build_security_roadmap(checks)["items"]
    priorities = [i["priority"] for i in items]
    assert "critical" in priorities and "high" in priorities
    assert priorities.index("critical") < priorities.index("high"), priorities
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert priorities == sorted(priorities, key=rank.get)


# ---------------------------------------------------------------------------
# Item 7: every icon is a character the built-in fonts can draw
# ---------------------------------------------------------------------------

_RENDERABLE = set("✓✗•!")  # check, cross, bullet, bang


def test_detail_icons_use_only_glyphs_helvetica_can_render():
    for kind, icon in pdf_report.DETAIL_ICON.items():
        chars = re.sub(r"<[^>]+>", "", icon)
        assert set(chars) <= _RENDERABLE, (kind, icon)
    with open(os.path.join(REPO_ROOT, "pdf_report.py"), encoding="utf-8") as f:
        src = f.read()
    assert "\\u26A0" not in src and "⚠" not in src, (
        "U+26A0 has no glyph in Helvetica and rendered as a black box"
    )


def test_warning_line_renders_a_bang_in_the_pdf_text():
    checks = [{
        "name": "DMARC", "status": "warn", "pill_label": None, "configured": True,
        "record": "v=DMARC1; p=none; rua=mailto:a@x.test",
        "verdict": "p=none (monitoring only, no enforcement)",
        "explanation": "", "fix": "",
        "details": [{"type": "warning", "text": "DOC34WARNMARKER monitoring only"}],
    }]
    roadmap = build_security_roadmap(checks)
    es = build_executive_summary(checks, roadmap)
    text = _pdf_text({"domain": "example.com", "checks": checks,
                      "executive_summary": es, "security_roadmap": roadmap})
    assert re.search(r"!\s+DOC34WARNMARKER", text), text[:3000]
    assert "⚠" not in text


# ---------------------------------------------------------------------------
# Item 8: the table of contents matches the sections present
# ---------------------------------------------------------------------------

def test_scoped_pdf_toc_lists_only_the_sections_it_contains(audit, zone):
    text = _pdf_text(audit(FakeZone(dict(zone)), DOMAIN, scope="dns_infra"))
    assert "1. Executive Summary" in text
    assert "2. Email Security Roadmap" in text
    assert "3. Protocol Details" in text
    assert "4. About This Report" in text
    for absent in ("DMARC Deep Dive", "Attack Surface Analysis", "Migration Path",
                   "5. Protocol Details", "7. About This Report"):
        assert absent not in text, absent


def test_complete_pdf_toc_still_lists_all_seven_in_order(audit, zone):
    text = _pdf_text(audit(FakeZone(dict(zone)), DOMAIN))
    expected = ["1. Executive Summary", "2. Email Security Roadmap", "3. DMARC Deep Dive",
                "4. Attack Surface Analysis", "5. Protocol Details", "6. Migration Path",
                "7. About This Report"]
    positions = [text.find(e) for e in expected]
    assert all(p >= 0 for p in positions), list(zip(expected, positions))
    assert positions == sorted(positions)
