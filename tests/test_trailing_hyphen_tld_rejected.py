import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

import server as server_module

client = TestClient(server_module.app)


def _audit_should_not_run(*args, **kwargs):
    raise AssertionError("run_full_audit must not run for an invalid domain")


def test_trailing_hyphen_tld_rejected_with_400(monkeypatch):
    monkeypatch.setattr(server_module, "run_full_audit", _audit_should_not_run)
    server_module._rate_limits.clear()

    for domain in ("example.co-", "foo.bar-"):
        response = client.get("/api/audit", params={"domain": domain})
        assert response.status_code == 400, f"{domain} should be rejected, got {response.status_code}"
