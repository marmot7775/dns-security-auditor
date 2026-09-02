"""
Audit-log schema: outcome, abandonment, and visitor counting.

Three things the weekly usage report could not measure before these fields
existed. A failed audit was logged as an ordinary one (checks=0, no marker),
so a week where 30% of audits broke read as 100% healthy. An abandoned SSE
stream was not logged at all, so giving up looked exactly like never
visiting. And with no per-visitor token, one heavy user and twenty light
ones were the same number.

The visitor id has to buy that last one without giving up the log's
GDPR-safe posture, so its two properties are tested directly: different
clients hash differently, and the same client hashes differently tomorrow.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import logging
import socket
import threading
import time

import httpx2 as httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from starlette.requests import Request

import server as server_module


class _CapturingHandler(logging.Handler):
    """Collect the JSON lines the audit logger writes, parsed."""

    def __init__(self):
        super().__init__()
        self.entries = []

    def emit(self, record):
        try:
            self.entries.append(json.loads(record.getMessage()))
        except ValueError:
            pass


@pytest.fixture
def audit_entries():
    handler = _CapturingHandler()
    server_module.audit_logger.addHandler(handler)
    server_module._rate_limits.clear()
    try:
        yield handler.entries
    finally:
        server_module.audit_logger.removeHandler(handler)


def _fake_request(ip="203.0.113.7", ua="pytest-agent", referer=None):
    """A real starlette Request with a chosen peer address and headers."""
    headers = [(b"user-agent", ua.encode("utf-8"))]
    if referer is not None:
        headers.append((b"referer", referer.encode("utf-8")))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/audit",
        "raw_path": b"/api/audit",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": (ip, 54321),
        "server": ("testserver", 80),
    }
    return Request(scope)


def _ok_audit(domain, dkim_selector=None, scope=None, progress_callback=None):
    return {
        "domain": domain,
        "checks": [{"id": "dmarc"}, {"id": "spf"}],
        "priority_fixes": [],
        "vendors": [],
    }


def _boom_audit(domain, dkim_selector=None, scope=None, progress_callback=None):
    raise RuntimeError("audit engine exploded")


# ------------------------------------------------------------------
# status / error
# ------------------------------------------------------------------

def test_error_audit_logs_status_error(monkeypatch, audit_entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "run_full_audit", _boom_audit)
    client = TestClient(server_module.app)

    response = client.get("/api/audit", params={"domain": "logschema-error.example.com"})

    assert response.status_code == 200
    assert response.json()["error"] == "server_error"
    assert audit_entries, "a failed audit wrote no log entry at all"
    entry = audit_entries[-1]
    assert entry["status"] == "error", (
        "a failed audit is logged as ordinary usage: %r" % entry
    )
    assert entry["error"] == "server_error"
    assert entry["checks"] == 0


def test_successful_audit_logs_status_ok_and_no_error_field(monkeypatch, audit_entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "run_full_audit", _ok_audit)
    client = TestClient(server_module.app)

    client.get("/api/audit", params={"domain": "logschema-ok.example.com"})

    entry = audit_entries[-1]
    assert entry["status"] == "ok"
    assert "error" not in entry
    assert entry["checks"] == 2
    # Every field the existing reader parses is still there, unrenamed.
    for key in ("ts", "domain", "scope", "duration_s", "checks", "ua", "source"):
        assert key in entry, "existing log field %r disappeared" % key


# ------------------------------------------------------------------
# abandonment
# ------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _slow_audit(domain, dkim_selector=None, scope=None, progress_callback=None):
    # One progress event so the client has something to read, then a long
    # block: the client gives up while the audit is still running.
    if progress_callback:
        progress_callback("start", 0, 2)
    time.sleep(10)
    return {"domain": domain, "checks": [], "priority_fixes": [], "vendors": []}


@pytest.fixture
def live_server(monkeypatch):
    """A real uvicorn server, so a client disconnect is a real TCP close."""
    monkeypatch.setattr(server_module, "run_full_audit", _slow_audit)
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "_active_audits", 0)
    server_module._rate_limits.clear()

    port = _free_port()
    config = uvicorn.Config(server_module.app, host="127.0.0.1", port=port, log_level="error")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()

    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started, "uvicorn server did not start in time"

    try:
        yield "http://127.0.0.1:%d" % port
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


def test_abandoned_sse_audit_logs_status_abandoned(live_server, audit_entries):
    domain = "logschema-abandoned.example.com"

    with httpx.stream(
        "GET", "%s/api/audit/stream" % live_server,
        params={"domain": domain}, timeout=20,
    ) as resp:
        for line in resp.iter_lines():
            if line:
                break  # one chunk read; leaving the block closes the socket

    # The server polls for the disconnect at ~0.2s intervals.
    matching = []
    deadline = time.time() + 10
    while time.time() < deadline:
        matching = [e for e in audit_entries if e.get("domain") == domain]
        if matching:
            break
        time.sleep(0.1)

    assert matching, (
        "a client that started an audit and gave up left no log entry, so "
        "abandonment is still indistinguishable from nobody visiting"
    )
    entry = matching[-1]
    assert entry["status"] == "abandoned"
    assert entry["source"] == "sse"
    assert entry["duration_s"] >= 0


# ------------------------------------------------------------------
# visitor id
# ------------------------------------------------------------------

def test_vid_differs_for_different_ips():
    same_day = "2026-08-31"
    a = server_module._visitor_id(_fake_request(ip="198.51.100.1"), day=same_day)
    b = server_module._visitor_id(_fake_request(ip="198.51.100.2"), day=same_day)

    assert a != b, "two different clients share a visitor id"
    assert len(a) == 12 and all(c in "0123456789abcdef" for c in a)
    # Same client, same day, same id -- otherwise it counts nothing.
    assert a == server_module._visitor_id(_fake_request(ip="198.51.100.1"), day=same_day)


def test_vid_for_the_same_ip_differs_across_dates():
    request = _fake_request(ip="198.51.100.1")

    monday = server_module._visitor_id(request, day="2026-08-31")
    tuesday = server_module._visitor_id(request, day="2026-09-01")

    assert monday != tuesday, (
        "the visitor id is stable across days, which makes the log a "
        "cross-day tracker rather than a daily unique count"
    )


def test_vid_does_not_leak_the_client_ip(audit_entries):
    ip = "198.51.100.77"
    server_module._log_audit(_fake_request(ip=ip), "vid.example.com", None, 1.0, 3)

    entry = audit_entries[-1]
    assert "vid" in entry
    assert ip not in json.dumps(entry), "the raw client IP reached the log"


# ------------------------------------------------------------------
# referer
# ------------------------------------------------------------------

def test_missing_referer_omits_ref(monkeypatch, audit_entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "run_full_audit", _ok_audit)
    client = TestClient(server_module.app)

    client.get("/api/audit", params={"domain": "logschema-noref.example.com"})

    entry = audit_entries[-1]
    assert "ref" not in entry, "absent Referer wrote a null field instead of nothing"


def test_referer_logs_host_only(monkeypatch, audit_entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "run_full_audit", _ok_audit)
    client = TestClient(server_module.app)

    client.get(
        "/api/audit",
        params={"domain": "logschema-ref.example.com"},
        headers={"Referer": "https://forum.example.org/private/thread-42?token=secret"},
    )

    entry = audit_entries[-1]
    assert entry["ref"] == "forum.example.org"
    assert "private" not in json.dumps(entry) and "secret" not in json.dumps(entry)
