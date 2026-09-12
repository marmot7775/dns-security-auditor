"""Smoke test for the ratio function in scripts/contrast_check.py.

The script reports the palette's contrast numbers, so the one thing it must
get right before anything it prints means anything is the ratio itself. White
on black is the defined maximum in WCAG 2.1: 21:1 exactly.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import contrast_check


def test_white_on_black_is_21():
    white = contrast_check.parse_color("#ffffff")
    black = contrast_check.parse_color("#000000")
    assert round(contrast_check.contrast_ratio(white, black), 2) == 21.00
