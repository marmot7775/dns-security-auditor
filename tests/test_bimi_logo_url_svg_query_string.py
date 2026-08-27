"""Regression test for BIMI logo URLs with a query string or fragment
being false-flagged as not being SVG files.

Bug: _validate_bimi_record checked logo_url.lower().endswith(".svg") on
the raw URL. A routine CDN cache-busting query string (?v=2) or a
fragment moves the ".svg" substring away from the end of the string,
even though the URL unambiguously points at an SVG file. The function
already computes urlparse(logo_url).path four lines earlier -- test
that instead of the raw string.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from checks_extra import _validate_bimi_record


def _issue_texts(issues):
    return " ".join(f"{i.get('issue', '')} {i.get('plain_english', '')}" for i in issues).lower()


def test_query_string_logo_url_is_not_flagged():
    record = "v=BIMI1; l=https://x.example/logo.svg?v=2; a=https://x.example/vmc.pem"
    _tags, issues = _validate_bimi_record(record)
    texts = _issue_texts(issues)
    assert "does not end in .svg" not in texts, (
        f"A cache-busting query string must not fail SVG detection; got: {issues!r}"
    )


def test_fragment_logo_url_is_not_flagged():
    record = "v=BIMI1; l=https://x.example/logo.svg#v2; a=https://x.example/vmc.pem"
    _tags, issues = _validate_bimi_record(record)
    texts = _issue_texts(issues)
    assert "does not end in .svg" not in texts, (
        f"A URL fragment must not fail SVG detection; got: {issues!r}"
    )


def test_non_svg_path_is_still_flagged():
    record = "v=BIMI1; l=https://x.example/logo.png?v=2; a=https://x.example/vmc.pem"
    _tags, issues = _validate_bimi_record(record)
    texts = _issue_texts(issues)
    assert "does not end in .svg" in texts, (
        "A genuinely non-SVG path must still be flagged"
    )
