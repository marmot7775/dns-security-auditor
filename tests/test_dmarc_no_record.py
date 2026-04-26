"""Regression test for the DMARC-check crash on read-only filesystem.

Bug: tldextract's default cache lives under ~/.cache, which is read-only
on the prod systemd unit (ProtectHome=read-only). Running the DMARC
check on a domain that exists but lacks DMARC triggered a tldextract
cache write, the OSError bubbled up, and the user-facing response
leaked the server-side path and OS username via _error_card.

These tests verify:
  1. The configured tldextract instance writes its cache to a path
     under the project working directory, not under the user's home.
  2. _error_card no longer echoes raw exception text to the user.
"""

import os

import audit_engine


def test_tldextract_cache_dir_is_under_project_root():
    """tldextract instance must use a writable, project-local cache dir."""
    if audit_engine._tld_extract is None:
        # tldextract not installed in this environment; nothing to verify.
        return
    project_root = os.path.dirname(os.path.abspath(audit_engine.__file__))
    cache_dir = audit_engine._tldextract_cache_dir
    assert cache_dir.startswith(project_root), (
        f"tldextract cache_dir {cache_dir!r} must live under project root "
        f"{project_root!r} so it stays writable under ProtectHome=read-only"
    )
    assert ".cache/python-tldextract" not in cache_dir, (
        "Cache must not point at the systemd-protected ~/.cache path"
    )


def test_error_card_does_not_leak_exception_text():
    """_error_card must produce a generic message, not the raw exception."""
    leaky_exc = OSError(
        30,
        "Read-only file system",
        "/home/marmot7/.cache/python-tldextract/3.12.3.final__.venv__"
        "862318__tldextract-5.3.1/publicsuffix.org-tlds/abc.tldextract.json.lock",
    )
    card = audit_engine._error_card("DMARC", leaky_exc)

    rendered = repr(card)
    forbidden = ["/home/", "Errno", "Read-only", "tldextract", "marmot7"]
    for token in forbidden:
        assert token not in rendered, (
            f"_error_card leaked {token!r} to the user response: {rendered}"
        )

    assert card["status"] == "fail"
    assert card["pill_label"] == "Error"
    assert card["details"], "Error card must still surface an actionable message"


def test_get_org_domain_handles_real_domain_without_crash():
    """_get_org_domain must not raise OSError when tldextract refreshes.

    Smoke test: call against a real public domain. With the cache_dir
    override in place this writes to the project tree (writable in dev
    and in prod via ReadWritePaths) and returns the org domain cleanly.
    """
    result = audit_engine._get_org_domain("mail.yahoo.com")
    assert result == "yahoo.com"
