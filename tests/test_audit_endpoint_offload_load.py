"""
Load test for bug 28: audit_domain/audit_pdf must not block the event loop.

Runs a real uvicorn server (not TestClient, which doesn't exercise true
concurrency) with run_full_audit patched to a slow synchronous call, then
fires concurrent requests to prove /api/health stays responsive while
audits are running, and that two concurrent audits run in parallel rather
than serializing on the event loop.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import socket
import threading
import time

import httpx
import pytest
import uvicorn

import server as server_module


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _slow_audit(domain, dkim_selector=None, scope=None, progress_callback=None):
    time.sleep(3)
    return {"domain": domain, "checks": [], "priority_fixes": [], "vendors": []}


@pytest.fixture
def live_server(monkeypatch):
    monkeypatch.setattr(server_module, "run_full_audit", _slow_audit)
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)

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


def test_health_stays_responsive_and_audits_run_concurrently(live_server):
    base = live_server

    idle_start = time.time()
    idle_resp = httpx.get(f"{base}/api/health", timeout=20)
    idle_latency = time.time() - idle_start
    assert idle_resp.status_code == 200

    results = {}

    def hit_audit(domain):
        t0 = time.time()
        r = httpx.get(f"{base}/api/audit", params={"domain": domain}, timeout=20)
        results[domain] = (time.time() - t0, r.status_code)

    def hit_health():
        time.sleep(0.5)  # let both audits get underway first
        t0 = time.time()
        r = httpx.get(f"{base}/api/health", timeout=20)
        results["health"] = (time.time() - t0, r.status_code)

    threads = [
        threading.Thread(target=hit_audit, args=("example.com",)),
        threading.Thread(target=hit_audit, args=("example.org",)),
        threading.Thread(target=hit_health),
    ]
    batch_start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    batch_elapsed = time.time() - batch_start

    health_latency, health_status = results["health"]
    audit1_latency, audit1_status = results["example.com"]
    audit2_latency, audit2_status = results["example.org"]

    assert health_status == 200
    assert audit1_status == 200
    assert audit2_status == 200

    # Health must stay near its idle latency even while two 3s audits run.
    # Today (blocking on the event loop) this jumps from ~0.10s to ~5.48s.
    assert health_latency < max(idle_latency * 2, 1.0), (
        f"health latency {health_latency:.2f}s degraded too far from "
        f"idle {idle_latency:.2f}s under audit load"
    )

    # The two audits must overlap on background threads, not serialize on
    # the event loop. Serialized, this batch takes ~6s; concurrent, ~3s.
    assert batch_elapsed < 5.0, (
        f"batch of two concurrent audits took {batch_elapsed:.2f}s, "
        "suggesting they serialized instead of running in parallel"
    )
