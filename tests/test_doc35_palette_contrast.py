"""Doc 35: the palette and type tokens hold their guarantees.

Every text and status colour clears WCAG AA (4.5:1) against every surface it
sits on, in both themes; the two light-theme token blocks (the
prefers-color-scheme one and the [data-theme="light"] one) carry identical
values; the PDF's colour constants mirror the light-theme tokens; and no
component sets a literal font-size outside the token scale, so the scale
cannot silently sprout a 0.65rem label again.
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_PATH = os.path.join(REPO_ROOT, "static", "style.css")

AA = 4.5


def _css():
    with open(CSS_PATH, encoding="utf-8") as f:
        return f.read()


def _block(css, opener):
    start = css.index(opener)
    body = css[start:css.index("}", start)]
    # Only real declarations, not a token name mentioned inside a comment.
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    return dict(re.findall(r"^\s*(--[a-z0-9-]+):\s*([^;]+);", body, flags=re.MULTILINE))


def _tokens():
    css = _css()
    dark = _block(css, ":root {")
    light_media = _block(css, ':root:where(:not([data-theme="dark"])) {')
    light_toggle = _block(css, ':root:where([data-theme="light"]) {')
    return dark, light_media, light_toggle


def _hex_to_rgb(h):
    m = re.search(r"#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b", h)
    assert m, f"not a hex colour: {h!r}"
    h = m.group(1)
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


def _luminance(rgb):
    def lin(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(fg, bg):
    l1, l2 = _luminance(_hex_to_rgb(fg)), _luminance(_hex_to_rgb(bg))
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


# (foreground token, background token) pairs that carry readable text.
TEXT_ON_GROUND = [
    (fg, bg)
    for fg in ("--text-primary", "--text-secondary", "--text-tertiary", "--text-muted",
               "--primary", "--pass", "--warn", "--fail-text", "--dmarcbis", "--rec-caution",
               "--ttl-long-text")
    for bg in ("--bg", "--bg-raised", "--surface")
] + [
    ("--text-muted-raised", "--surface"),
    ("--text-muted-raised", "--bg-raised"),
    ("--text-inverse", "--primary-solid"),
    ("--text-inverse", "--primary-solid-hover"),
    ("--text-inverse", "--pass-solid"),
    ("--text-inverse", "--fail-solid"),
    ("--warn-contrast", "--warn"),
    ("--dmarcbis-contrast", "--dmarcbis"),
]


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_every_text_and_status_colour_clears_aa_on_every_surface(theme):
    dark, light, _ = _tokens()
    tokens = dark if theme == "dark" else {**dark, **light}
    failures = []
    for fg, bg in TEXT_ON_GROUND:
        ratio = contrast(tokens[fg], tokens[bg])
        if ratio < AA:
            failures.append(f"{theme}: {fg} {tokens[fg]} on {bg} {tokens[bg]} = {ratio:.2f}:1")
    assert failures == [], "\n".join(failures)


def test_the_two_light_theme_blocks_carry_identical_values():
    _, light_media, light_toggle = _tokens()
    assert light_media == light_toggle, {
        k: (light_media.get(k), light_toggle.get(k))
        for k in set(light_media) | set(light_toggle)
        if light_media.get(k) != light_toggle.get(k)
    }


def test_pdf_colours_mirror_the_light_theme_tokens():
    _, light, _ = _tokens()
    pairs = {
        "PASS_CLR": "--pass", "WARN_CLR": "--warn", "FAIL_CLR": "--fail",
        "FIX_BORDER": "--fix-border", "BLUE_ACCENT": "--primary", "TEAL_ACCENT": "--dmarcbis",
        "TEXT_PRI": "--text-primary", "TEXT_SEC": "--text-secondary",
        "TEXT_TER": "--text-tertiary", "BORDER": "--border", "SURFACE_BG": "--bg",
    }
    mismatches = {
        const: (getattr(pdf_report, const).hexval().lower(), light[token].lower())
        for const, token in pairs.items()
        if getattr(pdf_report, const).hexval().lower().replace("0x", "#") != light[token].lower()
    }
    assert mismatches == {}, mismatches


def test_fail_red_is_no_longer_the_stock_red_500_anywhere_in_the_tokens():
    dark, light, _ = _tokens()
    for name, tokens in (("dark", dark), ("light", light)):
        for k, v in tokens.items():
            assert "ef4444" not in v.lower(), (name, k, v)


def test_no_component_sets_a_literal_font_size_outside_the_token_scale():
    css = _css()
    # Root and the brand mark are the two legitimate places for a literal.
    offenders = []
    current = ""
    for n, line in enumerate(css.split("\n"), 1):
        s = line.strip()
        if s.endswith("{"):
            current = s[:-1].strip()
        m = re.search(r"font-size:\s*[0-9.]+(rem|px)\b", line)
        if m and current != "html" and not current.startswith(":root") and "logo" not in current:
            offenders.append((n, current, m.group(0)))
    assert offenders == [], offenders


def test_root_type_size_is_16px():
    css = _css()
    m = re.search(r"html \{[^}]*font-size:\s*(\d+)px", css)
    assert m and m.group(1) == "16", m.group(0) if m else "no html font-size"
