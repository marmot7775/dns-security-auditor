import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

import server as server_module

client = TestClient(server_module.app)


def test_undocumented_health_endpoint_removed():
    response = client.get("/health")
    assert response.status_code == 404


def test_api_health_verifies_dns_resolution(monkeypatch):
    calls = {}

    def _resolve(*args, **kwargs):
        calls["called"] = True

    monkeypatch.setattr(server_module.dns.resolver, "resolve", _resolve)

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "dns_resolution": "working"}
    assert calls.get("called") is True
