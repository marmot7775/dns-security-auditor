"""Tests for _build_priority_fixes after Phase 3 refactor.

Phase 3 removed security_scoring.py and rebuilt priority_fixes directly
from the checks list. This module covers the new ordering rules and
output shape consumed by static/app.js.

Function under test:
    audit_engine._build_priority_fixes(checks, raw_results, has_mx) -> List[str]

Rules verified:
- Empty / all-pass inputs return [].
- Only fail/warn checks are included; passes are dropped.
- Fails come before warnings.
- BOGUS DNSSEC is pinned to the very top, ahead of other fails.
- Output items are plain strings (frontend renders them as text).
- HTML in fix text is stripped.
- Duplicate check names are deduplicated.
- pill_label == "Error" is excluded.
- Checks with no fix text are excluded.
- Cap of 5 items.
- has_mx=False skips MAIL_ONLY_CHECKS.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine


def _check(name, status, fix="Do the thing.", pill_label=None):
    """Minimal check dict matching the shape audit_engine produces."""
    c = {"name": name, "status": status, "fix": fix}
    if pill_label is not None:
        c["pill_label"] = pill_label
    return c


def test_empty_checks_returns_empty():
    assert audit_engine._build_priority_fixes([]) == []


def test_all_passes_returns_empty():
    checks = [
        _check("SPF", "pass"),
        _check("DMARC", "pass"),
        _check("DKIM", "pass"),
    ]
    assert audit_engine._build_priority_fixes(checks) == []


def test_only_warns_and_fails_included_fails_first():
    checks = [
        _check("SPF", "pass", fix="should not appear"),
        _check("DMARC", "warn", fix="Tighten DMARC policy."),
        _check("DKIM", "fail", fix="Add DKIM key."),
        _check("MX Records", "pass", fix="should not appear"),
    ]
    fixes = audit_engine._build_priority_fixes(checks)

    assert len(fixes) == 2
    assert fixes[0] == "Add DKIM key."
    assert fixes[1] == "Tighten DMARC policy."
    assert "should not appear" not in " ".join(fixes)


def test_two_fails_order_stable():
    checks = [
        _check("SPF", "fail", fix="Fix SPF."),
        _check("DMARC", "fail", fix="Fix DMARC."),
    ]
    fixes = audit_engine._build_priority_fixes(checks)
    assert fixes == ["Fix SPF.", "Fix DMARC."]


def test_bogus_dnssec_pinned_to_top():
    """BOGUS DNSSEC sorts ahead of every other fail, regardless of input order."""
    checks = [
        _check("SPF", "fail", fix="Fix SPF."),
        _check("DMARC", "fail", fix="Fix DMARC."),
        _check("DNSSEC", "fail", fix="Resolve BOGUS DNSSEC state."),
    ]
    raw_results = {"dnssec": {"dnssec_state": "bogus"}}

    fixes = audit_engine._build_priority_fixes(checks, raw_results=raw_results)

    assert fixes[0] == "Resolve BOGUS DNSSEC state."
    assert "Fix SPF." in fixes
    assert "Fix DMARC." in fixes


def test_bogus_dnssec_not_pinned_when_state_not_bogus():
    """Without bogus state, DNSSEC follows normal fail ordering."""
    checks = [
        _check("SPF", "fail", fix="Fix SPF."),
        _check("DNSSEC", "fail", fix="Resolve DNSSEC."),
    ]
    raw_results = {"dnssec": {"dnssec_state": "insecure"}}

    fixes = audit_engine._build_priority_fixes(checks, raw_results=raw_results)
    assert fixes == ["Fix SPF.", "Resolve DNSSEC."]


def test_output_items_are_strings():
    """Frontend (static/app.js:613-624) renders each item as text via escapeHtml,
    so items must be plain strings, not dicts."""
    checks = [_check("SPF", "fail", fix="Fix SPF.")]
    fixes = audit_engine._build_priority_fixes(checks)
    assert len(fixes) == 1
    assert isinstance(fixes[0], str)


def test_html_stripped_from_fix_text():
    checks = [
        _check(
            "SPF",
            "fail",
            fix='Add an SPF record like <code>v=spf1 -all</code> to <a href="#">your DNS</a>.',
        ),
    ]
    fixes = audit_engine._build_priority_fixes(checks)
    assert fixes == ["Add an SPF record like v=spf1 -all to your DNS."]


def test_duplicate_check_names_deduplicated():
    checks = [
        _check("SPF", "fail", fix="Fix SPF."),
        _check("SPF", "fail", fix="Fix SPF differently."),
    ]
    fixes = audit_engine._build_priority_fixes(checks)
    assert fixes == ["Fix SPF."]


def test_error_pill_excluded():
    checks = [
        _check("SPF", "fail", fix="Should not appear.", pill_label="Error"),
        _check("DMARC", "fail", fix="Real fix."),
    ]
    fixes = audit_engine._build_priority_fixes(checks)
    assert fixes == ["Real fix."]


def test_check_with_no_fix_excluded():
    checks = [
        _check("SPF", "fail", fix=""),
        _check("DMARC", "fail", fix=None),
        _check("DKIM", "fail", fix="Add DKIM."),
    ]
    fixes = audit_engine._build_priority_fixes(checks)
    assert fixes == ["Add DKIM."]


def test_cap_at_five_items():
    checks = [_check(f"Check{i}", "fail", fix=f"Fix {i}.") for i in range(8)]
    fixes = audit_engine._build_priority_fixes(checks)
    assert len(fixes) == 5
    assert fixes == ["Fix 0.", "Fix 1.", "Fix 2.", "Fix 3.", "Fix 4."]


def test_has_mx_false_skips_mail_only_checks():
    """Non-mail domains shouldn't see SPF/DKIM/MX/MTA-STS/etc. fixes surfaced.
    DMARC is intentionally not skipped: a DMARC reject record is part of the
    defensive-DNS pattern for non-mail domains."""
    checks = [
        _check("SPF", "fail", fix="Fix SPF."),
        _check("DKIM", "fail", fix="Fix DKIM."),
        _check("MX Records", "fail", fix="Fix MX."),
        _check("MTA-STS", "warn", fix="Add MTA-STS."),
        _check("DANE", "fail", fix="Fix DANE."),
        _check("BIMI", "warn", fix="Add BIMI."),
        _check("TLS-RPT", "warn", fix="Add TLS-RPT."),
        _check("DNSSEC", "fail", fix="Fix DNSSEC."),
    ]
    fixes = audit_engine._build_priority_fixes(checks, has_mx=False)
    assert fixes == ["Fix DNSSEC."]


def test_has_mx_true_includes_mail_checks():
    checks = [
        _check("SPF", "fail", fix="Fix SPF."),
        _check("DNSSEC", "fail", fix="Fix DNSSEC."),
    ]
    fixes = audit_engine._build_priority_fixes(checks, has_mx=True)
    assert "Fix SPF." in fixes
    assert "Fix DNSSEC." in fixes


def test_mixed_pass_warn_fail_with_bogus_dnssec_full_ordering():
    """End-to-end: bogus DNSSEC at top, then fails in order, then warns."""
    checks = [
        _check("SPF", "warn", fix="SPF warn."),
        _check("DKIM", "pass", fix="ignore"),
        _check("DMARC", "fail", fix="DMARC fail."),
        _check("DNSSEC", "fail", fix="Resolve BOGUS DNSSEC."),
        _check("DANE", "fail", fix="DANE fail."),
        _check("MTA-STS", "warn", fix="MTA-STS warn."),
    ]
    raw_results = {"dnssec": {"dnssec_state": "bogus"}}

    fixes = audit_engine._build_priority_fixes(checks, raw_results=raw_results)

    assert fixes[0] == "Resolve BOGUS DNSSEC."
    # Remaining fails come before warns.
    dmarc_idx = fixes.index("DMARC fail.")
    dane_idx = fixes.index("DANE fail.")
    spf_idx = fixes.index("SPF warn.")
    mta_idx = fixes.index("MTA-STS warn.")
    assert dmarc_idx < spf_idx and dmarc_idx < mta_idx
    assert dane_idx < spf_idx and dane_idx < mta_idx
    assert "ignore" not in " ".join(fixes)
