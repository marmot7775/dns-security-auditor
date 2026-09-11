"""Regression tests for the minor findings of the doc 12 cold review.

Findings 14 through 20: self-contradicting copy, dead PDF surface, pool
sizing, and a status code that told followers the wrong thing.
"""
import base64
import os
import re
import socket
import sys
import threading
import time

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
    # Doc 34 item 8: the contents list is built from the sections actually
    # emitted and numbered consecutively, so Protocol Details is no longer
    # always "5.". Match the title, not the number.
    toc_items, _ = pdf_report._build_sections(
        {"domain": "example.com", "checks": checks, "executive_summary": {}},
        pdf_report._styles())
    for text in toc_items:
        if re.match(r"\d+\. Protocol Details", text):
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
    assert "Certificate Transparency" in listed and "DANE" in listed


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
        {"name": "Certificate Transparency", "status": "unavailable"},
    ]
    text = _about_text(checks)
    performed = text.split("Checks performed:")[1].split("Not checked:")[0]
    assert "DMARC" in performed
    assert "Certificate Transparency" not in performed, (
        "a check whose lookup did not complete was listed as performed, on the "
        "same document whose cover counts it under 'not checked'"
    )
    assert "Not checked:" in text
    assert "Certificate Transparency" in text.split("Not checked:")[1]


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

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_every_follower_honours_the_leaders_status_not_just_the_first():
    """The follower branch must read the shared payload, never mutate it.

    Two things were wrong with how this was covered. The old test asserted the
    literal source line `_status = shared.pop("_http_status", 200)`, and that
    line was the defect: _release_inflight resolves the future once, so every
    follower awaits one dict object and the first pop removed the key for
    everyone behind it. Followers 2..n read the default 200 and returned an
    empty checks list under a success code.

    The second thing is that the defect is latent, not live. On the leader's
    path there is no await between _join_or_lead and the 503 return, so the
    event loop never yields in that window and no follower can attach to a
    leader that goes on to answer busy. Driving the endpoint normally therefore
    exercises none of this: every caller simply becomes a leader in turn and
    gets its own 503, with or without the bug.

    So the follower branch is entered directly here, by handing the endpoint an
    already-resolved future. That is the code under test, and it protects the
    invariant if an await is ever introduced above it.
    """
    import asyncio

    import httpx2 as httpx
    import uvicorn

    import server as server_module

    busy_payload = {
        "checks": [], "priority_fixes": [], "vendors": [],
        "error": "server_busy",
        "error_message": "Server is busy. Please try again in a moment.",
        "_http_status": 503,
    }

    port = _free_port()
    orig_join = server_module._join_or_lead
    orig_limit = server_module.RATE_LIMIT_MAX
    server_module.RATE_LIMIT_MAX = 10_000
    server_module._rate_limits.clear()
    server_module._cache.clear()

    holder = {}

    def _always_follower(cache_key):
        # One future, one payload dict, shared by every caller: exactly what
        # _release_inflight produces for the real followers of one leader.
        fut = holder.get("fut")
        if fut is None or fut.get_loop() is not asyncio.get_event_loop():
            fut = asyncio.get_event_loop().create_future()
            fut.set_result(busy_payload)
            holder["fut"] = fut
        return fut, False

    server_module._join_or_lead = _always_follower

    config = uvicorn.Config(server_module.app, host="127.0.0.1", port=port,
                            log_level="error")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if srv.started:
                break
            time.sleep(0.05)
        assert srv.started, "test server did not start"

        async def fire():
            async with httpx.AsyncClient(timeout=10) as c:
                return await asyncio.gather(*[
                    c.get(f"http://127.0.0.1:{port}/api/audit",
                          params={"domain": "coalesce.example.com"})
                    for _ in range(6)
                ])

        responses = asyncio.run(fire())
    finally:
        srv.should_exit = True
        thread.join(timeout=10)
        server_module._join_or_lead = orig_join
        server_module.RATE_LIMIT_MAX = orig_limit
        server_module._rate_limits.clear()

    codes = [r.status_code for r in responses]
    assert set(codes) == {503}, (
        f"every follower must get the leader's 503; got {codes}. A 200 here is "
        f"a follower that read the shared payload after another follower "
        f"mutated it, and its body carries an empty audit rather than an error."
    )
    for r in responses:
        body = r.json()
        assert "checks" not in body, (
            f"a busy response must not carry an audit body: {body!r}"
        )
        assert "busy" in body.get("detail", "").lower()
        assert r.headers.get("Retry-After") == "5"

    assert busy_payload["_http_status"] == 503, (
        "the follower branch mutated the payload every other follower still "
        "has to read"
    )
