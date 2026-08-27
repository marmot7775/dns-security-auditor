import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

import server as server_module
from config import RATE_LIMIT_MAX

client = TestClient(server_module.app)


def _fast_audit(domain, dkim_selector=None, scope=None, progress_callback=None):
    return {"domain": domain, "checks": [], "priority_fixes": [], "vendors": []}


def test_rotating_x_real_ip_from_untrusted_peer_still_rate_limited(monkeypatch):
    # TestClient's synthetic peer ("testclient") is not in TRUSTED_PROXY_IPS,
    # so every rotated X-Real-IP value here must be ignored and all 40
    # requests must be counted against the same (peer) identity.
    monkeypatch.setattr(server_module, "run_full_audit", _fast_audit)
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    server_module._rate_limits.clear()

    statuses = []
    for i in range(40):
        response = client.get(
            "/api/audit",
            params={"domain": "example.com"},
            headers={"X-Real-IP": f"1.2.3.{i}"},
        )
        statuses.append(response.status_code)

    assert 429 in statuses, "rotating X-Real-IP from an untrusted peer bypassed the rate limit"
    assert statuses.count(429) >= 40 - RATE_LIMIT_MAX
