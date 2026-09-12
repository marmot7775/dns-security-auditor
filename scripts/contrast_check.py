#!/usr/bin/env python3
"""Report WCAG 2.1 contrast ratios for the design tokens in static/style.css.

Reads the three custom-property blocks in the stylesheet, resolves each token
for the dark theme and for the light theme, and prints one table per theme for
the foreground/background pairs declared in PAIRS below.

Stdlib only. Reporting tool, not a test: it prints and exits 0 whatever the
numbers say. tests/test_doc35_palette_contrast.py is the gate that fails a
build.

Usage:
    python3 scripts/contrast_check.py            # both themes
    python3 scripts/contrast_check.py --theme dark
    python3 scripts/contrast_check.py --theme light
"""

import argparse
import os
import re
import sys

CSS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "static", "style.css",
)

# Selectors that open a custom-property block, in the order they are applied.
# The dark theme is the :root default. The light theme is the OS-preference
# copy inside @media (prefers-color-scheme: light); style.css carries an
# identical [data-theme="light"] copy for the header toggle, and
# tests/test_doc35_palette_contrast.py holds the two in step.
DARK_SELECTOR = ":root"
LIGHT_SELECTOR = ':root:where(:not([data-theme="dark"]))'

# A translucent token has to be flattened onto something before it has a
# colour at all. Status tints (--pass-bg and friends) are painted on result
# cards, whose background is var(--surface) (style.css:1233), so --surface is
# the base this script composites onto. A pair measured on a different ground
# would give a different number.
COMPOSITE_BASE = "--surface"

# (foreground token, background token). Both are resolved per theme.
PAIRS = [
    # Text ramp on each of the three grounds.
    ("--text-primary", "--bg"),
    ("--text-primary", "--bg-raised"),
    ("--text-primary", "--surface"),
    ("--text-secondary", "--bg"),
    ("--text-secondary", "--bg-raised"),
    ("--text-secondary", "--surface"),
    ("--text-tertiary", "--bg"),
    ("--text-tertiary", "--bg-raised"),
    ("--text-tertiary", "--surface"),
    ("--text-muted", "--bg"),
    ("--text-muted", "--bg-raised"),
    ("--text-muted", "--surface"),
    ("--text-muted-raised", "--bg"),
    ("--text-muted-raised", "--bg-raised"),
    ("--text-muted-raised", "--surface"),
    # Accent on the same three grounds.
    ("--primary", "--bg"),
    ("--primary", "--bg-raised"),
    ("--primary", "--surface"),
    ("--primary-light", "--bg"),
    ("--primary-light", "--bg-raised"),
    ("--primary-light", "--surface"),
    # Status colours on the page ground and on their own tint.
    ("--pass", "--bg"),
    ("--pass", "--pass-bg"),
    ("--warn", "--bg"),
    ("--warn", "--warn-bg"),
    ("--fail", "--bg"),
    ("--fail", "--fail-bg"),
    ("--fail-text", "--bg"),
    ("--fail-text", "--fail-bg"),
    ("--dmarcbis", "--bg"),
    ("--dmarcbis", "--dmarcbis-bg"),
    # Text carried on a solid status or accent fill.
    ("--warn-contrast", "--warn"),
    ("--dmarcbis-contrast", "--dmarcbis"),
    ("--text-inverse", "--primary-solid"),
    ("--text-inverse", "--pass-solid"),
    ("--text-inverse", "--fail-solid"),
]

AA_NORMAL = 4.5
AA_LARGE = 3.0


# ---------------------------------------------------------------- parsing

def read_css(path=CSS_PATH):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def strip_comments(text):
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def extract_block(text, selector):
    """Return {token: raw value} for the first block opened by `selector`.

    Matches the selector as a whole line-leading token so that, for example,
    ":root" does not also match ':root:where([data-theme="light"])'.
    """
    needle = re.escape(selector) + r"\s*\{"
    for m in re.finditer(needle, text):
        # Reject a partial match: ":root" inside ":root:where(...)".
        before = text[:m.start()]
        tail = before.rsplit("\n", 1)[-1].strip()
        if tail not in ("", "}"):
            continue
        depth = 1
        i = m.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[m.end():i - 1]
        out = {}
        for line in body.split(";"):
            dm = re.match(r"\s*(--[\w-]+)\s*:\s*(.+)\s*$", line, flags=re.DOTALL)
            if dm:
                out[dm.group(1)] = dm.group(2).strip()
        return out
    return {}


def load_themes(text=None):
    """Return (dark_tokens, light_tokens). Light inherits anything it omits."""
    text = strip_comments(read_css() if text is None else text)
    dark = extract_block(text, DARK_SELECTOR)
    light_overrides = extract_block(text, LIGHT_SELECTOR)
    light = dict(dark)
    light.update(light_overrides)
    return dark, light


# ---------------------------------------------------------------- colour

def parse_hex(value):
    v = value.strip().lstrip("#")
    if len(v) == 3:
        v = "".join(c * 2 for c in v)
    if len(v) == 8:          # #rrggbbaa
        r, g, b, a = (int(v[i:i + 2], 16) for i in (0, 2, 4, 6))
        return (r, g, b, a / 255.0)
    if len(v) != 6:
        return None
    try:
        return (int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16), 1.0)
    except ValueError:
        return None


def parse_color(value):
    """Parse a hex or rgb()/rgba() literal into (r, g, b, alpha) or None."""
    if value is None:
        return None
    value = value.strip()
    if value.startswith("#"):
        return parse_hex(value)
    m = re.match(r"rgba?\(([^)]*)\)", value, flags=re.IGNORECASE)
    if not m:
        return None
    parts = [p.strip() for p in re.split(r"[,/]", m.group(1)) if p.strip()]
    if len(parts) < 3:
        return None
    try:
        chan = []
        for p in parts[:3]:
            chan.append(round(float(p[:-1]) * 255 / 100) if p.endswith("%")
                        else int(round(float(p))))
        alpha = 1.0
        if len(parts) > 3:
            a = parts[3]
            alpha = float(a[:-1]) / 100 if a.endswith("%") else float(a)
    except ValueError:
        return None
    return (chan[0], chan[1], chan[2], alpha)


def resolve(token, tokens, _seen=None):
    """Resolve a token to (r, g, b, alpha), following one level of var()."""
    _seen = _seen or set()
    if token in _seen:
        return None
    _seen.add(token)
    raw = tokens.get(token)
    if raw is None:
        return None
    direct = parse_color(raw)
    if direct:
        return direct
    m = re.match(r"var\(\s*(--[\w-]+)\s*(?:,\s*(.+?)\s*)?\)$", raw)
    if m:
        via = resolve(m.group(1), tokens, _seen)
        if via:
            return via
        if m.group(2):
            return parse_color(m.group(2))
    return None


def composite(fg, bg):
    """Flatten a translucent colour onto an opaque one (source-over)."""
    a = fg[3]
    if a >= 1.0:
        return (fg[0], fg[1], fg[2], 1.0)
    return tuple(round(fg[i] * a + bg[i] * (1 - a)) for i in range(3)) + (1.0,)


# ---------------------------------------------------------------- WCAG 2.1

def _channel(c):
    s = c / 255.0
    return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4


def relative_luminance(rgb):
    r, g, b = (_channel(c) for c in rgb[:3])
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg, bg):
    """WCAG 2.1 contrast ratio for two opaque colours. Returns 1.0 to 21.0."""
    l1 = relative_luminance(fg)
    l2 = relative_luminance(bg)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


# ---------------------------------------------------------------- report

def evaluate(tokens):
    """Return a row per pair: (fg, bg, ratio or None, note)."""
    base = resolve(COMPOSITE_BASE, tokens)
    rows = []
    for fg_tok, bg_tok in PAIRS:
        fg = resolve(fg_tok, tokens)
        bg = resolve(bg_tok, tokens)
        missing = [t for t, v in ((fg_tok, fg), (bg_tok, bg)) if v is None]
        if missing:
            rows.append((fg_tok, bg_tok, None,
                         "unresolved: " + ", ".join(missing)))
            continue
        note = ""
        if bg[3] < 1.0:
            if base is None:
                rows.append((fg_tok, bg_tok, None,
                             "unresolved: %s (needed to flatten %s)"
                             % (COMPOSITE_BASE, bg_tok)))
                continue
            note = "bg flattened onto %s" % COMPOSITE_BASE
            bg = composite(bg, base)
        if fg[3] < 1.0:
            note = (note + "; " if note else "") + "fg flattened onto bg"
            fg = composite(fg, bg)
        rows.append((fg_tok, bg_tok, contrast_ratio(fg, bg), note))
    return rows


def print_table(theme_name, rows):
    fw = max(len(r[0]) for r in rows)
    bw = max(len(r[1]) for r in rows)
    head = ("%-*s  %-*s  %7s  %-9s  %-9s  %s"
            % (fw, "foreground", bw, "background", "ratio",
               "AA 4.5", "AA 3.0", "note"))
    print()
    print("%s theme" % theme_name)
    print("-" * len(head))
    print(head)
    print("-" * len(head))
    for fg, bg, ratio, note in rows:
        if ratio is None:
            print("%-*s  %-*s  %7s  %-9s  %-9s  %s"
                  % (fw, fg, bw, bg, "n/a", "unresolved", "unresolved", note))
            continue
        print("%-*s  %-*s  %7.2f  %-9s  %-9s  %s"
              % (fw, fg, bw, bg, ratio,
                 "PASS" if ratio >= AA_NORMAL else "FAIL",
                 "PASS" if ratio >= AA_LARGE else "FAIL", note))
    fails = [r for r in rows if r[2] is not None and r[2] < AA_NORMAL]
    unres = [r for r in rows if r[2] is None]
    print("-" * len(head))
    print("%d pairs; %d below AA normal (4.5); %d below AA large (3.0); "
          "%d unresolved"
          % (len(rows), len(fails),
             len([r for r in rows if r[2] is not None and r[2] < AA_LARGE]),
             len(unres)))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--theme", choices=("dark", "light", "both"),
                    default="both")
    args = ap.parse_args(argv)

    dark, light = load_themes()
    if args.theme in ("dark", "both"):
        print_table("dark", evaluate(dark))
    if args.theme in ("light", "both"):
        print_table("light", evaluate(light))
    return 0


if __name__ == "__main__":
    sys.exit(main())
