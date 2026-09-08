"""Regression tests for the minor findings of the doc 12 cold review.

Findings 14 through 20: self-contradicting copy, dead PDF surface, pool
sizing, and a status code that told followers the wrong thing.
"""
import base64
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import pdf_report
import result_transformer
from config import MAX_CONCURRENT_AUDITS


def _rsa_key_record(bits):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    der = (rsa.generate_private_key(public_exponent=65537, key_size=bits)
           .public_key()
           .public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


# ---------------------------------------------------------------------------
# Finding 14: the card must not contradict itself about the key it measured
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bits", [1024, 1536])
def test_weak_key_advice_names_the_size_actually_measured(bits):
    """The fix text said "1024-bit keys" whatever the real size was.

    A card whose own detail line read "1536-bit RSA key" carried fix text
    calling it 1024-bit, and deliverability copy saying the same.
    """
    card = result_transformer.transform_dkim(
        {"found_selectors": [{"selector": "s1", "record": _rsa_key_record(bits)}],
         "tested_count": 1}, "example.com")

    assert f"{bits}-bit" in card["details"][0]["text"]
    assert f"{bits}-bit" in card["fix"]
    assert f"{bits}-bit" in card["deliverability"]
    if bits != 1024:
        assert "1024-bit" not in card["fix"]
        assert "1024-bit" not in card["deliverability"]


def test_mixed_weak_sizes_are_all_named():
    card = result_transformer.transform_dkim(
        {"found_selectors": [
            {"selector": "s1", "record": _rsa_key_record(1536)},
            {"selector": "s2", "record": _rsa_key_record(1024)},
        ], "tested_count": 2}, "example.com")
    assert "1536-bit" in card["fix"] and "1024-bit" in card["fix"]


# ---------------------------------------------------------------------------
# Finding 15: the PDF's DKIM Vendor column read a key nothing writes
# ---------------------------------------------------------------------------

def test_pdf_dkim_table_reads_the_field_the_analysis_emits():
    """_build_dkim_key_analysis emits "provider"; the table read "vendor"."""
    deep = result_transformer._build_dkim_key_analysis(
        {"found_selectors": [{"selector": "google",
                              "record": _rsa_key_record(2048)}]})
    assert "provider" in deep["keys"][0]
    assert deep["keys"][0]["provider"], "fixture should resolve a provider"

    source = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "pdf_report.py")).read()
    assert 'k.get("provider")' in source, (
        "the DKIM key table must read the field the analysis actually emits, "
        "or every Vendor cell renders as '-'"
    )


# ---------------------------------------------------------------------------
# Finding 16: the contents page must not promise absent sections
# ---------------------------------------------------------------------------

def _toc_protocols(checks):
    els = pdf_report._cover_page({"domain": "example.com", "checks": checks,
                                  "executive_summary": {}}, pdf_report._styles())
    for el in els:
        text = getattr(el, "text", "") or ""
        if text.startswith("5. Protocol Details"):
            inner = re.search(r"\((.*)\)", text)
            return [p.strip() for p in inner.group(1).split(",")] if inner else []
    raise AssertionError("no protocol details line in the contents")


def test_contents_page_lists_only_the_sections_the_body_contains():
    """A scoped audit's TOC promised all twelve protocol sections."""
    checks = [{"name": "DMARC", "status": "pass"},
              {"name": "SPF", "status": "pass"},
              {"name": "DKIM", "status": "pass"}]
    listed = _toc_protocols(checks)
    assert listed == ["SPF", "DKIM"], listed  # DMARC has its own section
    assert "BIMI" not in listed and "DANE" not in listed


def test_contents_page_still_lists_everything_on_a_complete_run():
    checks = [{"name": n, "status": "pass"}
              for n in pdf_report.PROTOCOL_SECTION_ORDER]
    listed = _toc_protocols(checks)
    assert len(listed) == len(pdf_report.PROTOCOL_SECTION_ORDER)
    assert "Blocklist" in listed and "Certificate Transparency" in listed


def test_section_order_matches_what_the_body_actually_renders():
    """The contents list and _protocol_details must not drift apart."""
    source = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "pdf_report.py")).read()
    body = source.split("def _protocol_details(")[1].split("\ndef ")[0]
    looked_up = re.findall(r'_get_check\(data, "([^"]+)"\)', body)
    assert looked_up == pdf_report.PROTOCOL_SECTION_ORDER, (
        f"PROTOCOL_SECTION_ORDER drifted from the body: "
        f"body renders {looked_up}, constant says "
        f"{pdf_report.PROTOCOL_SECTION_ORDER}"
    )


# ---------------------------------------------------------------------------
# Finding 17: "Checks performed" must not list checks that were not performed
# ---------------------------------------------------------------------------

def _about_text(checks):
    els = pdf_report._about_page({"domain": "example.com", "checks": checks,
                                  "executive_summary": {}}, pdf_report._styles())
    return " ".join(getattr(e, "text", "") or "" for e in els)


def test_unavailable_checks_are_not_listed_as_performed():
    checks = [
        {"name": "DMARC", "status": "pass"},
        {"name": "Blocklist", "status": "unavailable"},
    ]
    text = _about_text(checks)
    performed = text.split("Checks performed:")[1].split("Not checked:")[0]
    assert "DMARC" in performed
    assert "Blocklist" not in performed, (
        "a check whose lookup did not complete was listed as performed, on the "
        "same document whose cover counts it under 'not checked'"
    )
    assert "Not checked:" in text and "Blocklist" in text.split("Not checked:")[1]


def test_no_not_checked_line_when_everything_ran():
    text = _about_text([{"name": "DMARC", "status": "pass"}])
    assert "Not checked:" not in text


# ---------------------------------------------------------------------------
# Finding 18: the biggest-risk callout must not be red when there is no risk
# ---------------------------------------------------------------------------

def _severity(checks):
    roadmap = result_transformer.build_security_roadmap(checks)
    return result_transformer.build_executive_summary(
        checks, roadmap)["biggest_risk_severity"]


def test_a_clean_run_does_not_report_a_biggest_risk():
    checks = [{"name": n, "status": "pass", "pill_label": "Configured",
               "records_found": 1}
              for n in ("DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "BIMI")]
    assert _severity(checks) == "none"


def test_an_unread_run_reports_the_risk_as_unestablished():
    checks = [result_transformer._lookup_unavailable_card(n, {}, "record")
              for n in ("DMARC", "SPF", "DKIM")]
    assert _severity(checks) == "unknown"


def test_a_real_critical_finding_still_reports_critical():
    checks = [{"name": "DMARC", "status": "fail", "pill_label": "Missing"}]
    assert _severity(checks) == "critical"


@pytest.mark.parametrize("checks,expect_red", [
    ([{"name": "DMARC", "status": "fail", "pill_label": "Missing"}], True),
    ([{"name": n, "status": "pass", "pill_label": "Configured", "records_found": 1}
      for n in ("DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "BIMI")], False),
])
def test_callout_renders_without_error_in_both_states(checks, expect_red):
    """The whole report has to build, not just the severity flag."""
    roadmap = result_transformer.build_security_roadmap(checks)
    es = result_transformer.build_executive_summary(checks, roadmap)
    pdf = pdf_report.generate_pdf({
        "domain": "example.com", "checks": checks,
        "executive_summary": es, "security_roadmap": roadmap,
    })
    assert pdf[:4] == b"%PDF"
    assert (es["biggest_risk_severity"] == "critical") is expect_red


# ---------------------------------------------------------------------------
# Finding 19: the shared pool must cover the load the audit can place on it
# ---------------------------------------------------------------------------

def test_shared_pool_covers_a_full_phase_two_at_the_concurrency_cap():
    """Future.result counts queue wait, so an undersized pool times checks out.

    At 20 workers and the 8-audit cap, 8 audits times a ~10 check Phase 2 is
    80 tasks on 20 workers, and the tail exhausted the CHECK_TIMEOUT + 5 batch
    budget on queue wait alone: timeout cards for checks that never ran.
    """
    needed = MAX_CONCURRENT_AUDITS * audit_engine._PHASE2_WIDTH
    assert audit_engine._shared_executor._max_workers >= needed, (
        f"shared pool holds {audit_engine._shared_executor._max_workers} workers "
        f"but {MAX_CONCURRENT_AUDITS} concurrent audits can queue {needed} "
        f"Phase 2 tasks"
    )


def test_phase_two_width_matches_the_number_of_parallel_checks():
    """_PHASE2_WIDTH is the sizing input; it must track reality."""
    source = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "audit_engine.py")).read()
    # Distinct keys, not call sites: DKIM registers at two mutually exclusive
    # sites (a user-supplied selector, or auto-discovery) and only ever
    # contributes one task.
    keys = set(re.findall(r'_parallel_checks\.append\(\(\s*"([a-z_]+)"', source))
    assert len(keys) == audit_engine._PHASE2_WIDTH, (
        f"{len(keys)} distinct checks are registered for Phase 2 ({sorted(keys)}) "
        f"but _PHASE2_WIDTH says {audit_engine._PHASE2_WIDTH}; the shared pool is "
        f"sized off that number"
    )


def test_probe_pools_are_still_separate_from_the_shared_pool():
    """No task may submit into the pool it is running on."""
    assert audit_engine._probe_executor is not audit_engine._shared_executor
    assert audit_engine._dkim_executor is not audit_engine._shared_executor


# ---------------------------------------------------------------------------
# Finding 20: a follower must not be told the audit failed when it was busy
# ---------------------------------------------------------------------------

def test_busy_leader_hands_followers_a_retryable_status():
    source = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "server.py")).read()
    assert '"_http_status": 503' in source, (
        "the 503 path must record a status for the followers waiting on it"
    )
    assert '_status = shared.pop("_http_status", 200)' in source, (
        "the follower must honour the leader's status instead of returning 200 "
        "with a generic 'Audit could not complete'"
    )
