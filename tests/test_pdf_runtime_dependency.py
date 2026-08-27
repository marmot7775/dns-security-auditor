"""Regression test for reportlab being declared as a test-only dependency.

D1: reportlab lived in requirements-dev.txt, but pdf_report.py imports it at
module scope and server.py imports pdf_report. The deploy step runs
`pip install -r requirements.txt` only, so a rebuilt VPS, a recreated venv or
a container built from requirements.txt got no reportlab, server.py's
ImportError guard set generate_pdf to None, and /api/audit/{domain}/pdf
started answering 503 with nothing in the logs to say why. It kept working on
the live host only because that venv still had reportlab from an earlier
install.

Tests always run with requirements-dev.txt installed too, so importing
reportlab here would pass either way. The declaration itself is what has to be
asserted: what a requirements.txt-only install would get.

D2: the same file pinned fpdf2==2.8.7, which nothing imports. The PDF code
moved to reportlab and the old pin was never dropped. The check below is tied
to what the sources actually import rather than to a hardcoded name, so
switching PDF libraries again moves the requirement instead of failing.
"""
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _declared(filename):
    """Distribution names declared in a requirements file, lowercased."""
    names = set()
    with open(os.path.join(_ROOT, filename), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name = re.split(r"[<>=!~\[;]", line, 1)[0].strip()
            if name:
                names.add(name.lower())
    return names


def test_reportlab_is_a_runtime_requirement():
    assert "reportlab" in _declared("requirements.txt"), (
        "pdf_report.py imports reportlab and server.py imports pdf_report, so "
        "the deploy's `pip install -r requirements.txt` has to install it"
    )


def test_reportlab_is_not_duplicated_as_a_dev_requirement():
    assert "reportlab" not in _declared("requirements-dev.txt"), (
        "reportlab is a runtime dependency now, so listing it in both files "
        "lets the two drift apart on version"
    )


def _imported_anywhere(module):
    """True if any Python source in the repo imports the named module."""
    pattern = re.compile(r"^\s*(?:import|from)\s+%s\b" % re.escape(module), re.M)
    for path in glob.glob(os.path.join(_ROOT, "*.py")) + glob.glob(
        os.path.join(_ROOT, "tests", "*.py")
    ):
        with open(path, encoding="utf-8") as fh:
            if pattern.search(fh.read()):
                return True
    return False


def test_pdf_library_declared_matches_the_one_actually_imported():
    declared = _declared("requirements.txt")
    for module, distribution in (("reportlab", "reportlab"), ("fpdf", "fpdf2")):
        if _imported_anywhere(module):
            assert distribution in declared, f"{module} is imported but unpinned"
        else:
            assert distribution not in declared, (
                f"{distribution} is pinned but nothing imports {module}"
            )


def test_pdf_generation_is_wired_up_not_silently_disabled():
    assert server.generate_pdf is not None, (
        "server.py:50 swallows the ImportError, so a missing PDF dependency "
        "shows up as a 503 at request time rather than at startup"
    )
