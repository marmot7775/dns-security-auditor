"""CLAUDE.md: never use em dashes or double hyphens in user-facing text.

The rule was being broken silently because nothing checked it. Three live
violations were shipping on the site when this test was written: two em
dashes inside DMARC syntax-error text on the card and in the PDF, and a
double hyphen in a DMARC roadmap step warning.

Scope is the modules whose strings reach a visitor's screen, plus the static
pages themselves. server.py is deliberately not in the list: its dashes are
in log format strings, which go to audit.log and the journal and are never
rendered to anyone.

Comments cannot trip this, since they are not in the AST. Docstrings are
skipped for the same reason a comment is: they are written for whoever reads
the source, not for whoever reads a card.
"""

import ast
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

ROOT = os.path.join(os.path.dirname(__file__), "..")

# Character, and what to write instead. The advice is in the failure message
# because "rewrite the sentence" is the rule, not "swap the character".
FORBIDDEN = {
    "—": "em dash",
    "–": "en dash",
    " -- ": "double hyphen",
}

# Modules that build text a visitor reads: card verdicts, explanations,
# issue text, fix instructions, roadmap steps, PDF copy.
USER_FACING_MODULES = [
    "audit_engine.py",
    "result_transformer.py",
    "checks_extra.py",
    "spf_execution_engine.py",
    "dkim_formatter.py",
    "dkim_tag_analyzer.py",
    "remediation_planner.py",
    "pdf_report.py",
    "dmarc_tree_walk.py",
    "mx_check.py",
    "advanced_fingerprinting.py",
    "anomaly_detector.py",
    "dns_tools.py",
]


def _docstring_ids(tree):
    """Every string that is a module, class or function docstring."""
    out = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        body = getattr(node, "body", None)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            out.add(id(body[0].value))
    return out


@pytest.mark.parametrize("module", USER_FACING_MODULES)
def test_no_forbidden_dashes_in_module_strings(module):
    path = os.path.join(ROOT, module)
    if not os.path.exists(path):
        pytest.skip(f"{module} no longer exists")

    with open(path, encoding="utf-8") as fh:
        source = fh.read()

    tree = ast.parse(source)
    skip = _docstring_ids(tree)

    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in skip:
            continue
        for char, name in FORBIDDEN.items():
            if char in node.value:
                found.append(f"{module}:{node.lineno} ({name}) {node.value.strip()[:70]!r}")

    assert not found, (
        "CLAUDE.md forbids em dashes and double hyphens in user-facing text. "
        "Rewrite the sentence rather than swapping the character for a comma:\n  "
        + "\n  ".join(found)
    )


def _static_pages():
    pages = []
    for sub in ("static", os.path.join("static", "articles")):
        d = os.path.join(ROOT, sub)
        if not os.path.isdir(d):
            continue
        pages += [
            os.path.join(sub, f) for f in sorted(os.listdir(d)) if f.endswith(".html")
        ]
    return pages


@pytest.mark.parametrize("page", _static_pages())
def test_no_forbidden_dashes_in_static_pages(page):
    with open(os.path.join(ROOT, page), encoding="utf-8") as fh:
        html = fh.read()
    # Strip inline script and style: their contents are code, not prose.
    html = re.sub(r"<(script|style)\b.*?</\1>", "", html, flags=re.S | re.I)

    found = [
        f"{name} in {page}" for char, name in FORBIDDEN.items() if char in html
    ]
    assert not found, (
        f"CLAUDE.md forbids em dashes and double hyphens in user-facing text: "
        f"{', '.join(found)}"
    )


def test_readme_has_no_forbidden_dashes():
    """The README is the repository's front page, so it is user-facing too."""
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        text = fh.read()
    found = [name for char, name in FORBIDDEN.items() if char in text]
    assert not found, f"README.md contains: {', '.join(found)}"
