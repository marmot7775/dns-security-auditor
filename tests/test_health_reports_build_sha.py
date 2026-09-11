"""The deployed commit has to be readable from outside the box.

The deploy is a git pull plus a systemctl restart, and the only external
fingerprint of the running code used to be the ?v= string on static assets.
That string is rewritten only when something under static/ changes, so a
Python-only commit leaves every asset URL pinned to the previous build. A
restart that never happened then looks identical to one that did, which is
exactly how a parser fix can sit in main and not be live.
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

import config
import server as server_module

client = TestClient(server_module.app)


def test_build_sha_is_a_short_commit_id():
    assert re.fullmatch(r"[0-9a-f]{7}", config.BUILD_SHA), (
        f"expected a 7 character commit id from the checkout, got "
        f"{config.BUILD_SHA!r}"
    )


def test_build_sha_matches_the_checkout():
    head = os.popen("git rev-parse --short=7 HEAD").read().strip()
    if not head:
        return  # No git available in this environment; the shape test stands.
    assert config.BUILD_SHA == head


def test_health_reports_the_running_commit(monkeypatch):
    monkeypatch.setattr(server_module.dns.resolver, "resolve", lambda *a, **k: None)

    body = client.get("/api/health").json()

    assert body["version"] == server_module.BUILD_SHA


def test_env_override_wins_over_the_checkout(monkeypatch):
    monkeypatch.setenv("BUILD_SHA", "deadbee")
    assert config._read_build_sha() == "deadbee"


def test_missing_git_directory_does_not_raise(monkeypatch, tmp_path):
    """A deploy without a working tree reports "unknown" rather than dying at
    import. The health endpoint is what a load balancer polls; it cannot be
    the thing that stops the process from starting."""
    monkeypatch.delenv("BUILD_SHA", raising=False)
    monkeypatch.setattr(config.os.path, "abspath", lambda _p: str(tmp_path / "config.py"))
    assert config._read_build_sha() == "unknown"


def test_packed_ref_is_resolved(monkeypatch, tmp_path):
    """git gc packs refs away, leaving no loose file under .git/refs."""
    monkeypatch.delenv("BUILD_SHA", raising=False)
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "packed-refs").write_text(
        "# pack-refs with: peeled fully-peeled sorted\n"
        "1234567890abcdef1234567890abcdef12345678 refs/heads/main\n"
    )
    monkeypatch.setattr(config.os.path, "abspath", lambda _p: str(tmp_path / "config.py"))
    assert config._read_build_sha() == "1234567"
