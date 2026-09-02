"""Item 4: a failed thread start must not leak a concurrency slot.

/api/audit/stream reserves a slot, then starts a raw background thread, and
the generator whose finally releases that slot does not begin running until a
client consumes the stream. Anything that raises in between leaked the slot
permanently. Thread.start raising RuntimeError is the case that actually
happens, and it happens precisely under the thread exhaustion the shared pool
contention used to produce, so the two defects compounded: after
_MAX_CONCURRENT_AUDITS of them every user got "Server is busy" until the
service was restarted.

Modelled on tests/test_sse_disconnect_slot_release.py, which covers the other
way a slot used to be held: an abandoned connection.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import threading

from fastapi.testclient import TestClient

import server as server_module

client = TestClient(server_module.app)


def _fast_audit(domain, dkim_selector=None, scope=None, progress_callback=None):
    return {"domain": domain, "checks": [], "priority_fixes": [], "vendors": []}


class _UnstartableThread:
    """A thread that cannot start, the way the runtime behaves once the
    process is out of thread stacks."""

    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        raise RuntimeError("can't start new thread")


def _patch_audit_thread(monkeypatch):
    # Only the audit runner's thread fails. TestClient's own portal thread has
    # to keep working, so anything else is handed to the real class.
    real_thread = threading.Thread

    def _dispatch(*args, **kwargs):
        target = kwargs.get("target") or (args[0] if args else None)
        if getattr(target, "__name__", "") == "_run_audit":
            return _UnstartableThread()
        return real_thread(*args, **kwargs)

    monkeypatch.setattr(server_module.threading, "Thread", _dispatch)


def test_thread_start_failure_releases_the_slot(monkeypatch):
    monkeypatch.setattr(server_module, "run_full_audit", _fast_audit)
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "_check_rate_limit", lambda ip: True)
    monkeypatch.setattr(server_module, "_active_audits", 0)
    server_module._cache.clear()
    _patch_audit_thread(monkeypatch)

    before = server_module._active_audits

    response = client.get("/api/audit/stream", params={"domain": "threadfail.example.com"})

    assert response.status_code == 200
    assert "error" in response.text, f"no error event sent to the client: {response.text!r}"
    assert server_module._active_audits == before, (
        f"active audit count went from {before} to {server_module._active_audits} "
        "after a failed thread start; the slot was leaked"
    )


def test_repeated_thread_start_failures_do_not_exhaust_the_budget(monkeypatch):
    monkeypatch.setattr(server_module, "run_full_audit", _fast_audit)
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "_check_rate_limit", lambda ip: True)
    monkeypatch.setattr(server_module, "_active_audits", 0)
    server_module._cache.clear()
    _patch_audit_thread(monkeypatch)

    # One more failure than the whole budget. Leaking even one slot per failure
    # would have the last of these answering "Server is busy".
    for i in range(server_module._MAX_CONCURRENT_AUDITS + 1):
        response = client.get("/api/audit/stream", params={"domain": f"threadfail{i}.example.com"})
        assert "Server is busy" not in response.text, (
            f"request {i} was refused as busy after {i} failed thread starts; "
            "each failure leaked its slot"
        )

    assert server_module._active_audits == 0, (
        f"active audit count stuck at {server_module._active_audits} after "
        f"{server_module._MAX_CONCURRENT_AUDITS + 1} failed thread starts"
    )
