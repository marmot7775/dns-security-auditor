"""Regression tests for Doc 30: README, SECURITY.md, and stale references.

Item 2: the README's headline check count must match the check registry the
engine actually runs (audit_engine.ALL_SCOPE_CHECK_KEYS), so a check being
added or removed cannot leave the README's number stale again.

Item 1: the Blocklist check was removed (live_check.py's docstring explains
why), so it must not reappear in copy a reader could act on. The docstring
itself is exempt: it is deliberately historical, explaining a check that
used to exist.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import live_check

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def test_readme_headline_check_count_matches_the_check_registry():
    readme = _read("README.md")
    m = re.search(r"^## (\d+) Security Checks", readme, re.MULTILINE)
    assert m, "README.md is missing its '## N Security Checks' headline"
    headline_count = int(m.group(1))

    assert headline_count == len(audit_engine.ALL_SCOPE_CHECK_KEYS), (
        f"README claims {headline_count} security checks, but the engine's "
        f"own check registry (audit_engine.ALL_SCOPE_CHECK_KEYS) runs "
        f"{len(audit_engine.ALL_SCOPE_CHECK_KEYS)}: "
        f"{sorted(audit_engine.ALL_SCOPE_CHECK_KEYS)}"
    )


def _static_html_files():
    static_dir = os.path.join(REPO_ROOT, "static")
    paths = []
    for name in os.listdir(static_dir):
        if name.endswith(".html"):
            paths.append(os.path.join(static_dir, name))
    articles_dir = os.path.join(static_dir, "articles")
    if os.path.isdir(articles_dir):
        for name in os.listdir(articles_dir):
            if name.endswith(".html"):
                paths.append(os.path.join(articles_dir, name))
    return paths


def test_no_page_or_readme_mentions_the_removed_blocklist_check():
    offenders = []

    readme = _read("README.md")
    if re.search(r"blocklist", readme, re.IGNORECASE):
        offenders.append("README.md")

    for path in _static_html_files():
        with open(path, encoding="utf-8") as f:
            content = f.read()
        if re.search(r"blocklist", content, re.IGNORECASE):
            offenders.append(os.path.relpath(path, REPO_ROOT))

    assert offenders == [], (
        f"the removed Blocklist check is still mentioned in: {offenders!r}"
    )


def test_live_check_mentions_blocklist_only_in_its_docstring_not_in_card_order():
    assert "Blocklist" in (live_check.__doc__ or ""), (
        "live_check.py's docstring is expected to explain, historically, "
        "why the Blocklist check was removed"
    )
    assert "Blocklist" not in live_check.CARD_ORDER, (
        "the removed Blocklist check is still in live_check.py's live "
        "CARD_ORDER, so a run against production would look for a card "
        "that no longer exists"
    )
