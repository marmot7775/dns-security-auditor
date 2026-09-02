"""Item 1: subdomain probes must not contend with the pool that runs them.

_audit_subdomains is itself submitted to _shared_executor and then blocks on
as_completed waiting for the probes it submits. While those probes went to the
same pool, a parent held a worker hostage to the queue its own children were
sitting in. At the 8 audit concurrency cap that left 8 of 20 workers blocked
with 160 probes queued behind them; at 20 parents nothing ran at all. The
visible symptom is a truncated subdomain section, because as_completed gives
up at the batch budget and reports only what finished.

Two knobs are turned so the starvation is arithmetic rather than a race
against the wall clock:

  * the shared pool is shrunk to fewer workers than concurrent audits, so once
    the parents are in flight there is provably nothing left to run a probe on.
    Production's ratio (20 workers, 8 parents) starves the same way but only
    under enough load to fill the slack, which is not a thing a test should
    wait around for.
  * the probe batch budget is shortened, so a starved batch gives up in
    seconds instead of twelve.

Neither knob is the fix. The fix is that probes draw from a separate pool, and
once they do this passes at any ratio.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import audit_engine
from conftest import FakeZone, fake_dns

CONCURRENT_AUDITS = 8
SHARED_WORKERS = 4          # fewer than the parents that will block on them
BATCH_BUDGET = 2.0          # seconds; production uses CHECK_TIMEOUT - 3
QUERY_DELAY = 0.01          # seconds per fake DNS query


class _SlowZone(FakeZone):
    """A zone whose lookups cost real time, the way a resolver does.

    With instant answers a probe costs nothing and even a starved pool drains
    the batch before the budget notices, so the contention never shows.
    """

    def resolve(self, name, rdtype="A", *args, **kwargs):
        time.sleep(QUERY_DELAY)
        return super().resolve(name, rdtype, *args, **kwargs)


def _zone():
    return _SlowZone({
        "example.test": {
            "MX": [(10, "mail.example.test")],
            "TXT": ["v=spf1 include:_spf.example.test -all"],
            "A": ["192.0.2.1"],
            "NS": ["ns1.example.test"],
        },
        "_dmarc.example.test": {"TXT": ["v=DMARC1; p=reject; rua=mailto:a@example.test"]},
    })


def test_concurrent_audits_all_get_a_full_subdomain_probe_set(monkeypatch):
    monkeypatch.setattr(audit_engine, "_shared_executor",
                        ThreadPoolExecutor(max_workers=SHARED_WORKERS))
    monkeypatch.setattr(audit_engine, "_SUBDOMAIN_BATCH_TIMEOUT", BATCH_BUDGET)

    expected = len(audit_engine._SUBDOMAIN_PREFIXES)
    results = {}
    errors = {}

    def _one(i):
        try:
            results[i] = audit_engine.run_full_audit("example.test")
        except Exception as e:  # pragma: no cover - surfaced by the assert below
            errors[i] = e

    with fake_dns(_zone()):
        threads = [threading.Thread(target=_one, args=(i,)) for i in range(CONCURRENT_AUDITS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

    assert not errors, f"audits raised: {errors}"
    assert len(results) == CONCURRENT_AUDITS, "not every concurrent audit returned"

    probed = {}
    for i, result in results.items():
        section = result.get("subdomain_audit")
        probed[i] = section.get("total_probed") if section else 0

    starved = {i: n for i, n in sorted(probed.items()) if n != expected}
    assert not starved, (
        f"{len(starved)} of {CONCURRENT_AUDITS} concurrent audits returned a truncated "
        f"subdomain probe set (expected {expected} probes each, got {starved}); "
        "probes are queued behind the parent tasks that are blocking on them"
    )


def test_probe_pool_is_not_the_shared_pool():
    # The property the test above depends on, asserted directly so a refactor
    # that merges the pools fails here with an obvious message rather than as
    # an intermittent truncation somewhere else.
    assert audit_engine._probe_executor is not audit_engine._shared_executor
