"""run_full_audit's deadline parameter bounds the whole audit, not just one
check (Prompt 22 item 3), and the CT cache stays bounded under unbounded
distinct-domain traffic (item 4).
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import audit_engine

DOMAIN = "wallclock.test"


def _zone():
    return FakeZone({
        DOMAIN: {
            "MX": [(10, f"mail.{DOMAIN}")],
            "TXT": ["v=spf1 mx -all"],
            "A": ["203.0.113.50"],
            "NS": [f"ns1.{DOMAIN}"],
        },
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.51"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
    })


def test_expired_deadline_returns_every_check_as_unavailable_not_missing():
    with fake_dns(_zone()):
        result = audit_engine.run_full_audit(
            DOMAIN, scope="complete", deadline=time.monotonic() - 1,
        )

    names = {c["name"] for c in result["checks"]}
    expected = {"DMARC", "MX Records", "SPF", "DKIM", "MTA-STS", "TLS-RPT",
                "BIMI", "DNSSEC", "CAA", "Nameservers", "DANE",
                "Certificate Transparency"}
    assert names == expected, (
        f"a scoped-in check went missing instead of getting an unavailable "
        f"card: expected {expected}, got {names}"
    )
    assert all(c["status"] == "unavailable" for c in result["checks"])
    assert all(c["status"] not in ("pass", "warn", "fail") for c in result["checks"]), (
        "an audit that never ran must not read as a finding about the domain"
    )


def test_generous_deadline_does_not_change_a_normal_result():
    with fake_dns(_zone()):
        with_deadline = audit_engine.run_full_audit(
            DOMAIN, scope="complete", deadline=time.monotonic() + 90,
        )
    with fake_dns(_zone()):
        without_deadline = audit_engine.run_full_audit(DOMAIN, scope="complete")

    statuses_a = {c["name"]: c["status"] for c in with_deadline["checks"]}
    statuses_b = {c["name"]: c["status"] for c in without_deadline["checks"]}
    assert statuses_a == statuses_b


def test_ct_cache_is_bounded():
    original = dict(audit_engine._ct_cache)
    try:
        audit_engine._ct_cache.clear()
        for i in range(audit_engine.CT_CACHE_MAX_SIZE + 500):
            audit_engine._set_cached_ct(f"ct-cache-test-{i}.example", {"total_certs": i})
        assert len(audit_engine._ct_cache) <= audit_engine.CT_CACHE_MAX_SIZE, (
            f"CT cache grew unbounded: {len(audit_engine._ct_cache)} entries"
        )
    finally:
        audit_engine._ct_cache.clear()
        audit_engine._ct_cache.update(original)


def test_ct_cache_eviction_keeps_stale_fallback_for_survivors():
    """Eviction removes the oldest entries by size, not by TTL, so an entry
    that survives under the cap must still answer _get_stale_ct however old
    it is -- that behaviour predates the cap and must not regress."""
    original = dict(audit_engine._ct_cache)
    try:
        audit_engine._ct_cache.clear()
        audit_engine._set_cached_ct("recent.example", {"total_certs": 1})
        # Backdate it past the TTL so _get_cached_ct would refuse it, and
        # confirm _get_stale_ct still serves it.
        audit_engine._ct_cache["recent.example"]["timestamp"] -= (audit_engine.CT_CACHE_TTL + 10)
        assert audit_engine._get_cached_ct("recent.example") is None
        assert audit_engine._get_stale_ct("recent.example") == {"total_certs": 1}
    finally:
        audit_engine._ct_cache.clear()
        audit_engine._ct_cache.update(original)
