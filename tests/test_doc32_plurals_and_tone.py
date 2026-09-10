"""Regression tests for Doc 32 Part B: generated text with a count of one.

One test per surface (transformer, rendered PDF text, app.js source) using a
count of exactly 1, which is the case every "{n} things" string got wrong.
Also pins the tone fixes: no card predicts what attackers will do, and the
subdomain-gap warnings name the audited domain rather than yourdomain.com.
"""
import io
import os
import re
import sys

from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report
import result_transformer
from result_transformer import (
    _detect_dangerous_combinations,
    build_executive_summary,
    build_security_roadmap,
    transform_ct,
    transform_dkim,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _texts(card):
    return " ".join(d.get("text", "") for d in card.get("details", []))


# ---------------------------------------------------------------------------
# Transformer surface
# ---------------------------------------------------------------------------

def test_dkim_with_one_supplied_selector_says_selector_not_selectors():
    raw = {
        "found_selectors": [{"selector": "s1", "record": "v=DKIM1; k=rsa; p=abc", "key_size": 2048}],
        "tested_count": 1,
        "selector_queried": "s1",
        "domain": "example.com",
    }
    card = transform_dkim(raw, "example.com")
    texts = _texts(card)
    assert "Tested 1 selector" in texts
    assert "1 selectors" not in texts


def test_dkim_nothing_found_for_supplied_selector_does_not_call_it_common():
    raw = {
        "found_selectors": [],
        "tested_count": 1,
        "selector_queried": "s1",
        "domain": "example.com",
    }
    card = transform_dkim(raw, "example.com")
    blob = _texts(card) + " " + card.get("explanation", "")
    assert "1 selectors" not in blob
    assert "1 common selector" not in blob
    assert "common selector" not in blob, (
        "the name was the one the user typed, not a common one this audit guessed"
    )


def test_ct_with_one_cert_and_one_day_left_pluralizes_on_the_count():
    raw = {
        "status": "ok",
        "total_certs": 1,
        "active_certs": 1,
        "issuers": [{"name": "Let's Encrypt", "count": 1}],
        "expiring_soon": [
            {"days_left": 1, "common_name": "one.example.com"},
            {"days_left": 0, "common_name": "zero.example.com"},
        ],
        "expired_recent": [],
        "wildcards": [],
        "caa_mismatches": [],
        "subdomains_found": [],
        "issues": [],
    }
    card = transform_ct(raw, "example.com")
    texts = _texts(card)
    assert "1 active cert from 1 issuer" in texts, texts
    assert "active certificates" not in texts
    assert "Expiring in 1 day:" in texts, texts
    assert "1 days" not in texts
    assert "Expiring today: zero.example.com" in texts, texts
    assert "0 days" not in texts


def test_clean_report_biggest_risk_has_no_marketing_words():
    checks = [
        {"name": "DMARC", "status": "pass", "pill_label": "Enforcing", "configured": True,
         "record": "v=DMARC1; p=reject; rua=mailto:a@example.com",
         "tag_breakdown": {"health": {"status": "ready"}, "config_warnings": []},
         "attack_surface": {"vectors": [{"name": "v", "status": "protected"}] * 3}},
        {"name": "SPF", "status": "pass", "configured": True, "record": "v=spf1 -all"},
        {"name": "DKIM", "status": "pass", "configured": True},
    ]
    es = build_executive_summary(checks, build_security_roadmap(checks))
    assert "optimization opportunities" not in es["biggest_risk"]
    assert "No urgent risks found" in es["biggest_risk"]


def test_no_warning_predicts_what_attackers_will_do_and_the_real_domain_is_used():
    tags = {"v": "DMARC1", "p": "reject", "sp": "none", "rua": "mailto:a@example.com"}
    warnings = _detect_dangerous_combinations(tags, "reject", domain="example.com")
    blob = " ".join(w["text"] for w in warnings)
    assert "attackers will" not in blob.lower()
    assert "yourdomain.com" not in blob
    assert "mail.example.com" in blob

    tags = {"v": "DMARC1", "p": "none", "np": "reject", "rua": "mailto:a@example.com"}
    warnings = _detect_dangerous_combinations(tags, "none", domain="example.com")
    blob = " ".join(w["text"] for w in warnings)
    assert "attackers will" not in blob.lower()
    assert "The root domain is the easier target" in blob


def test_transformer_source_has_no_attacker_predictions_left():
    with open(os.path.join(REPO_ROOT, "result_transformer.py"), encoding="utf-8") as f:
        src = f.read()
    assert not re.search(r"[Aa]ttackers will", src), (
        "a card still predicts what attackers will do"
    )
    assert "technical checkbox" not in src


# ---------------------------------------------------------------------------
# PDF surface
# ---------------------------------------------------------------------------

def _pdf_text(audit_result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(audit_result)))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_pdf_cover_with_one_check_one_issue_and_one_step_pluralizes_each():
    checks = [{
        "name": "DMARC", "status": "fail", "pill_label": None, "configured": True,
        "record": "v=DMARC1; p=none",
        "verdict": "p=none (monitoring only, no enforcement)",
        "details": [], "explanation": "", "fix": "",
        "tag_breakdown": {
            "health": {"status": "monitoring"},
            "config_warnings": [],
            "tags": [],
            "migration": {
                "status": "migration",
                "steps": [{"step": 1, "action": "Add aggregate reporting",
                           "why": "Without rua=, you have zero visibility.", "tags_changed": ["rua"]}],
                "total_steps": 1,
                "target_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            },
        },
    }]
    roadmap = build_security_roadmap(checks)
    es = build_executive_summary(checks, roadmap)
    text = _pdf_text({"domain": "example.com", "checks": checks,
                      "executive_summary": es, "security_roadmap": roadmap})
    assert "1 issues" not in text
    assert "1 checks total" not in text
    assert "1 steps to reach" not in text
    assert "1 step to reach" in text, text[:2000]


# ---------------------------------------------------------------------------
# app.js surface (a string test; the browser is not run here)
# ---------------------------------------------------------------------------

def test_app_js_share_text_and_strict_count_pluralize_on_one():
    with open(os.path.join(REPO_ROOT, "static", "app.js"), encoding="utf-8") as f:
        src = f.read()
    assert "${failCount} issues`" not in src
    assert "${failCount} issue${failCount !== 1 ? 's' : ''}" in src
    assert "found that only appear under strict" not in src, (
        "the verb did not agree with a pluralized noun on a count of 1"
    )
    assert "five minute DNS change" not in src
    assert "five-minute DNS change" in src
