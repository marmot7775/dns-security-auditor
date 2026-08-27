"""
Load test for bug 29: an abandoned /api/audit/stream connection must not
hold its concurrency slot until the background audit thread finishes on
its own. Uses a real uvicorn server so client disconnects are real TCP
closes, not TestClient's synthetic transport.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import socket
import threading
import time

import httpx2 as httpx
import pytest
import uvicorn

import server as server_module


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _slow_audit_no_progress(domain, dkim_selector=None, scope=None, progress_callback=None):
    # One progress checkpoint, then a long blocking span with no further
    # checkpoints -- mirrors a single slow DNS check in the real engine.
    if progress_callback:
        progress_callback("start", 0, 1)
    time.sleep(30)
    if progress_callback:
        progress_callback("done", 1, 1)
    return {"domain": domain, "checks": [], "priority_fixes": [], "vendors": []}


@pytest.fixture
def live_server(monkeypatch):
    monkeypatch.setattr(server_module, "run_full_audit", _slow_audit_no_progress)
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "_MAX_CONCURRENT_AUDITS", 8)
    monkeypatch.setattr(server_module, "_active_audits", 0)

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
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


def _abandon_after_one_chunk(base, domain):
    with httpx.stream("GET", f"{base}/api/audit/stream", params={"domain": domain}, timeout=20) as resp:
        for line in resp.iter_lines():
            if line:
                break  # got one SSE chunk; exiting the `with` closes the connection


def test_abandoned_streams_release_their_slots(live_server):
    base = live_server

    threads = [
        threading.Thread(target=_abandon_after_one_chunk, args=(base, f"loadtest{i}.example.com"))
        for i in range(9)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    # The abandoned streams' server-side generators need a moment to notice
    # the disconnect (polled at ~0.2s intervals) and release their slots.
    deadline = time.time() + 5
    while server_module._active_audits > 0 and time.time() < deadline:
        time.sleep(0.1)

    assert server_module._active_audits == 0, (
        f"active audit count stuck at {server_module._active_audits} after "
        "all clients disconnected -- slots were not released"
    )

    # A fresh client must be served, not told "Server is busy".
    with httpx.stream(
        "GET", f"{base}/api/audit/stream",
        params={"domain": "freshclient.example.com"}, timeout=20,
    ) as resp:
        first_line = next(line for line in resp.iter_lines() if line)
    assert "Server is busy" not in first_line
