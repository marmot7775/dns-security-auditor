import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
import dns.exception

import server as server_module

client = TestClient(server_module.app)


def test_health_failure_does_not_leak_resolver_detail(monkeypatch):
    sensitive_detail = "SERVFAIL from resolver 10.0.0.53 port 53"

    def _boom(*args, **kwargs):
        raise dns.exception.DNSException(sensitive_detail)

    monkeypatch.setattr(server_module.dns.resolver, "resolve", _boom)

    response = client.get("/api/health")

    assert response.status_code == 500
    body = response.json()
    assert body == {"status": "error"}
    assert sensitive_detail not in response.text
