"""Regression test for Doc 31: every RFC link in an article must name a
current RFC that the article text actually discusses, and no article may
link to captaindns.com (an uncited vendor blog used as the sole source for
a claim about Google's DANE behavior that Google's own docs do not make).

Cheap on purpose: it does not verify the RFC number is *correct* for the
claim next to it, only that the number in the URL is not orphaned from the
visible text, which is the failure mode a stale or copy-pasted link
produces (link to RFC 8624 while the prose has moved on to RFC 9904, and
nothing else on the page ever names 8624).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTICLES_DIR = os.path.join(REPO_ROOT, "static", "articles")

_RFC_LINK_RE = re.compile(
    r'href="https?://(?:www\.)?(?:rfc-editor\.org|datatracker\.ietf\.org)/'
    r'[^"]*?rfc0*(\d+)[^"]*"',
    re.IGNORECASE,
)

# Links whose anchor text names the protocol rather than the RFC number
# (e.g. linking "TLS-RPT" straight to RFC 8460) are not stale citations: the
# reader sees exactly what the link is. Exempted by number so a genuinely
# orphaned link cannot hide behind this list.
_NAMED_PROTOCOL_EXEMPTIONS = {"8460"}  # TLS-RPT


def _article_files():
    return sorted(
        os.path.join(ARTICLES_DIR, name)
        for name in os.listdir(ARTICLES_DIR)
        if name.endswith(".html")
    )


def test_every_rfc_link_names_an_rfc_the_article_text_discusses():
    for path in _article_files():
        with open(path, encoding="utf-8") as f:
            content = f.read()
        rel = os.path.relpath(path, REPO_ROOT)
        for number in _RFC_LINK_RE.findall(content):
            if number in _NAMED_PROTOCOL_EXEMPTIONS:
                continue
            assert re.search(rf"RFC\s+0*{number}\b", content), (
                f"{rel} links to RFC {number} but never names it as "
                f"'RFC {number}' in the visible text, which is what a stale "
                f"or copy-pasted link looks like"
            )


def test_no_article_links_to_captaindns():
    offenders = []
    for path in _article_files():
        with open(path, encoding="utf-8") as f:
            content = f.read()
        if "captaindns.com" in content.lower():
            offenders.append(os.path.relpath(path, REPO_ROOT))
    assert offenders == [], (
        f"an article still links to captaindns.com, an uncited vendor blog: "
        f"{offenders!r}"
    )
