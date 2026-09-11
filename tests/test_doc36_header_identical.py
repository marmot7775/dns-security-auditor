"""Doc 36: one header on every page.

The site header drifted: the homepage and the 404 page carried a plain
wordmark while the other six pages carried the terminal-window logo, a
different spelling and the accent on a different word. This test extracts
the <header> block from every static HTML page, strips the one permitted
per-page difference (which nav link carries nav-link-active) and asserts
that all eight blocks are byte-identical, so the header cannot drift again.
"""
import glob
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "static")

PAGES = sorted(
    glob.glob(os.path.join(STATIC, "*.html"))
    + glob.glob(os.path.join(STATIC, "articles", "*.html"))
)

HEADER_RE = re.compile(r'<header class="site-header">.*?</header>', re.DOTALL)


def _header(path):
    with open(path, encoding="utf-8") as f:
        html = f.read()
    blocks = HEADER_RE.findall(html)
    assert len(blocks) == 1, f"{path}: expected exactly one site header, found {len(blocks)}"
    return blocks[0]


def _normalised(path):
    return _header(path).replace(" nav-link-active", "")


def test_every_static_page_is_covered():
    names = {os.path.relpath(p, STATIC) for p in PAGES}
    assert names == {
        "404.html",
        "about.html",
        "index.html",
        "privacy.html",
        "articles/dane.html",
        "articles/dmarcbis.html",
        "articles/dnssec.html",
        "articles/index.html",
    }


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_header_is_identical_to_about(path):
    reference = _normalised(os.path.join(STATIC, "about.html"))
    assert _normalised(path) == reference, (
        f"{os.path.relpath(path, STATIC)}: site header differs from about.html "
        "beyond the nav-link-active attribute"
    )


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_header_carries_the_terminal_logo_and_wordmark(path):
    header = _header(path)
    assert '<div class="logo-terminal">' in header
    assert '<span class="logo-bin">dns-audit</span>' in header
    assert '<span class="logo-text"><span class="logo-accent">dns</span>-audit</span>' in header
    assert '<div class="header-right">' in header
    assert '<nav class="site-nav" aria-label="Main navigation">' in header
    for label in ("Home", "Articles", "About"):
        assert re.search(rf'class="nav-link(?: nav-link-active)?">{label}</a>', header), label
    assert 'id="theme-toggle"' in header


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_at_most_one_active_nav_link(path):
    assert _header(path).count("nav-link-active") <= 1


def test_active_link_matches_the_page():
    expected = {
        "index.html": "Home",
        "about.html": "About",
        "articles/index.html": "Articles",
        "articles/dane.html": "Articles",
        "articles/dmarcbis.html": "Articles",
        "articles/dnssec.html": "Articles",
    }
    for rel, label in expected.items():
        header = _header(os.path.join(STATIC, rel))
        assert f'class="nav-link nav-link-active">{label}</a>' in header, rel
