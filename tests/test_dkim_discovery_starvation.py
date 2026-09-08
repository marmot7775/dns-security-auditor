"""DKIM discovery must not starve under concurrent audits.

Prompt 22: _dkim_executor and _probe_executor were fixed at 20 workers
regardless of MAX_CONCURRENT_AUDITS, while every audit could submit up to
196 DKIM selector probes to _dkim_executor alone. At the 8-audit
concurrency cap that is up to 1568 tasks queued on 20 workers, and the
tail of that queue could exceed DKIM_DISCOVERY_TIMEOUT (15s) having never
run a real DNS query -- so whether a user learned the truth about their
own DKIM key depended on how many other domains happened to be audited at
the same moment, and the resulting card was indistinguishable from a
domain that genuinely has no DKIM key.

The first two tests drive real run_full_audit calls (not smart_dkim_check
in isolation) concurrently through one shared fake_dns patch context,
since the pools these fixes touch are process-wide singletons in
audit_engine and the bug was specifically about contention on those
shared pools.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import audit_engine

DOMAIN = "starvation.test"
SELECTOR = "sasl"  # Only in GENERIC_SELECTORS, not any vendor map: the
                    # worst case, reachable only via the fallback sweep.


def _rsa_dkim_record(bits=2048):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import base64
    der = (rsa.generate_private_key(public_exponent=65537, key_size=bits)
           .public_key()
           .public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


DKIM_RECORD = _rsa_dkim_record()


class _DelayedZone(FakeZone):
    """Adds a fixed per-query delay, standing in for real RTT the way the
    prompt's own reproduction did, so concurrent probes actually contend
    for pool workers instead of returning before contention can matter."""

    def __init__(self, *args, delay=0.02, **kwargs):
        super().__init__(*args, **kwargs)
        self._delay = delay

    def resolve(self, name, rdtype="A", *args, **kwargs):
        time.sleep(self._delay)
        return super().resolve(name, rdtype, *args, **kwargs)


def _zone():
    # 0.2s: the prompt's own reproduction found this the RTT at which 8
    # concurrent audits sharing a 20-worker pool started missing the 15s
    # DKIM_DISCOVERY_TIMEOUT (their (15.2, 109, True) row). Confirmed against
    # this harness directly: at delay=0.2 with the pool artificially pinned
    # back to a fixed ThreadPoolExecutor(max_workers=20), one of eight
    # concurrent runs of this exact test reports DKIM unavailable while the
    # other seven find the key; at the real (concurrency-scaled) pool size,
    # all eight find it in a third of the wall-clock time.
    return _DelayedZone({
        DOMAIN: {
            "MX": [(10, f"mail.{DOMAIN}")],
            "TXT": ["v=spf1 mx -all"],  # No recognized vendor include.
            "A": ["203.0.113.60"],
            "NS": [f"ns1.{DOMAIN}"],
        },
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.61"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"{SELECTOR}._domainkey.{DOMAIN}": {"TXT": [DKIM_RECORD]},
    }, delay=0.2)


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)


def test_dkim_key_is_found_alone():
    """Control: this domain's key is findable at all, run by itself."""
    zone = _zone()
    with fake_dns(zone):
        result = audit_engine.run_full_audit(DOMAIN, scope="complete")
    card = _card(result, "DKIM")
    assert card["status"] not in ("unavailable", "fail"), card["verdict"]
    found = {s["selector"] for s in (card.get("dkim_deep") or {}).get("keys", [])}
    assert SELECTOR in found or card["status"] == "pass", card


def test_dkim_key_is_found_under_concurrency():
    """The regression that matters: the same domain, audited alongside
    MAX_CONCURRENT_AUDITS - 1 others hitting the same shared DKIM pool,
    must get the same answer as it does alone."""
    from config import MAX_CONCURRENT_AUDITS

    zone = _zone()
    results = [None] * MAX_CONCURRENT_AUDITS
    errors = []

    def _worker(i):
        try:
            results[i] = audit_engine.run_full_audit(DOMAIN, scope="complete")
        except Exception as e:  # pragma: no cover - surfaced via errors list
            errors.append(e)

    # One shared fake_dns patch context for the whole run: unittest.mock.patch
    # is not thread-local, so each thread entering and exiting its own patch
    # context would race the others' patches on and off mid-audit.
    with fake_dns(zone):
        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(MAX_CONCURRENT_AUDITS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

    assert not errors, errors
    assert all(r is not None for r in results), "an audit never returned within 30s"

    cards = [_card(r, "DKIM") for r in results]
    assert all(c["status"] != "unavailable" for c in cards), (
        f"at least one of {MAX_CONCURRENT_AUDITS} concurrent audits of the same "
        f"domain reported DKIM unavailable: {[c['verdict'] for c in cards]!r}"
    )


def test_truncated_discovery_card_differs_from_no_key_card():
    """A truncated probe (timed_out=True, nothing found) must not read the
    same as a completed probe that found nothing."""
    import result_transformer as rt

    truncated = rt.transform_dkim(
        {"found_selectors": [], "tested_count": 80, "timed_out": True}, DOMAIN,
    )
    completed = rt.transform_dkim(
        {"found_selectors": [], "tested_count": 196}, DOMAIN,
    )

    assert truncated["verdict"] != completed["verdict"]
    assert "did not finish" in truncated["verdict"].lower()
    assert "did not finish" not in completed["verdict"].lower()
    assert truncated["explanation"] != completed["explanation"]
