"""Regression test for a slow subdomain batch discarding every probe.

Bug 35: _audit_subdomains ran `for future in as_completed(futures,
timeout=CHECK_TIMEOUT)`. as_completed raises its timeout from the `for`
statement, which sits outside the try that guards the loop body, so the
exception escaped _audit_subdomains. The caller wraps the call in a bare
`except Exception` and leaves subdomain_raw as None, which drops the whole
subdomain section from the report even though most probes had finished.

One slow probe must cost only that probe, not the section.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine


def test_slow_probe_keeps_completed_probes(monkeypatch):
    # Shrink both budgets so the batch gives up quickly. CHECK_TIMEOUT is the
    # name the pre-fix code read, so this exercises the old path too: without
    # the fix the timeout escapes and _audit_subdomains raises.
    monkeypatch.setattr(audit_engine, "CHECK_TIMEOUT", 0.5)
    monkeypatch.setattr(audit_engine, "_SUBDOMAIN_BATCH_TIMEOUT", 0.5, raising=False)

    hung = f"{audit_engine._SUBDOMAIN_PREFIXES[0]}.example.com"

    def fake_probe(subdomain):
        if subdomain == hung:
            time.sleep(5)  # outlives the batch budget
        return {
            "subdomain": subdomain,
            "exists": True,
            "has_mx": False,
            "has_spf": False,
            "has_dmarc": False,
            "dmarc_record": None,
            "spf_record": None,
            "mx_hosts": [],
        }

    monkeypatch.setattr(audit_engine, "_probe_subdomain", fake_probe)

    result = audit_engine._audit_subdomains("example.com")

    probes = result["probes"]
    expected = len(audit_engine._SUBDOMAIN_PREFIXES) - 1
    assert len(probes) == expected, (
        f"expected the {expected} fast probes to survive the slow one, got {len(probes)}"
    )
    assert hung not in {p["subdomain"] for p in probes}


def test_batch_budget_leaves_headroom_under_check_timeout():
    # The caller bounds _audit_subdomains with CHECK_TIMEOUT. If the batch
    # budget matched it, the caller's timeout would fire first and the partial
    # results would be discarded anyway.
    assert audit_engine._SUBDOMAIN_BATCH_TIMEOUT < audit_engine.CHECK_TIMEOUT
