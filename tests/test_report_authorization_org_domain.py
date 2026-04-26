"""Tests for _check_report_authorization Org Domain determination.

Prior code used an inline parts[-2:] heuristic in the fallback path
(when no tree_walk_result was supplied), which misidentified
example.co.uk's Org Domain as "co.uk" and falsely flagged rua=mailto:
dmarc@example.co.uk as external. The fallback now delegates to
audit_engine._get_org_domain, which is PSL-aware via tldextract with
a two-part-TLD fallback table.
"""
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine


def _stub_resolver_with_no_mx():
    """Resolver mock where MX lookups always fail (sets has_mx=False)."""
    resolver = MagicMock()
    resolver.resolve.side_effect = audit_engine.dns.exception.DNSException()
    return resolver


def _run_check(domain, raw_dmarc, tree_walk_result=None):
    """Run _check_report_authorization with DNS dependencies stubbed.

    Patches:
      - _get_resolver to return a resolver whose MX lookups all fail
        (we don't care about MX for these tests; the focus is the
        org_domain decision).
      - _lookup_txt to return [] (no authorization records exist),
        which forces the external/internal decision to drive
        is_external on its own.
    """
    with patch.object(audit_engine, "_get_resolver",
                      return_value=_stub_resolver_with_no_mx()), \
         patch.object(audit_engine, "_lookup_txt", return_value=[]):
        return audit_engine._check_report_authorization(
            domain, raw_dmarc, tree_walk_result=tree_walk_result,
        )


def test_co_uk_rua_at_same_apex_is_not_external():
    """example.co.uk with rua=mailto:dmarc@example.co.uk and no
    tree_walk_result must NOT classify the destination as external.

    The buggy inline heuristic produced org_domain="co.uk", causing
    "example.co.uk" != "co.uk" -> is_external=True. The PSL-aware
    fallback resolves org_domain="example.co.uk".
    """
    result = _run_check(
        "example.co.uk",
        {"rua": "mailto:dmarc@example.co.uk"},
        tree_walk_result=None,
    )
    assert result is not None
    dest = result["report_destinations"][0]
    assert dest["domain"] == "example.co.uk"
    assert dest["is_external"] is False, (
        f"Expected internal classification for two-part TLD; got "
        f"is_external={dest['is_external']}"
    )
    # No external -> no auth check fired -> no auth issues raised.
    auth_issues = [
        i for i in result["report_auth_issues"]
        if "External" in i.get("issue", "")
    ]
    assert auth_issues == [], (
        f"No external-auth issue should fire for same-org rua; got: "
        f"{auth_issues}"
    )


def test_com_au_rua_at_same_apex_is_not_external():
    """foo.com.au with rua=mailto:r@foo.com.au and no tree_walk_result
    must NOT classify the destination as external. Inline heuristic
    would yield org_domain="com.au".
    """
    result = _run_check(
        "foo.com.au",
        {"rua": "mailto:r@foo.com.au"},
        tree_walk_result=None,
    )
    assert result is not None
    dest = result["report_destinations"][0]
    assert dest["is_external"] is False


def test_org_za_rua_at_same_apex_is_not_external():
    """bar.org.za with rua=mailto:r@bar.org.za and no tree_walk_result
    must NOT classify the destination as external. Inline heuristic
    would yield org_domain="org.za".
    """
    result = _run_check(
        "bar.org.za",
        {"rua": "mailto:r@bar.org.za"},
        tree_walk_result=None,
    )
    assert result is not None
    dest = result["report_destinations"][0]
    assert dest["is_external"] is False


def test_third_party_rua_is_external_control():
    """Control: example.com with rua to an unrelated domain MUST be
    flagged external. Confirms the fix didn't accidentally suppress
    legitimate external-detection."""
    result = _run_check(
        "example.com",
        {"rua": "mailto:r@third-party.com"},
        tree_walk_result=None,
    )
    assert result is not None
    dest = result["report_destinations"][0]
    assert dest["is_external"] is True


def test_tree_walk_org_domain_takes_priority():
    """Control: when tree_walk_result.org_domain is supplied, the
    fallback heuristic does not run. rua at that org_domain is
    internal."""
    result = _run_check(
        "example.com",
        {"rua": "mailto:r@example.com"},
        tree_walk_result={"org_domain": "example.com"},
    )
    assert result is not None
    dest = result["report_destinations"][0]
    assert dest["is_external"] is False


def test_co_uk_subdomain_rua_at_apex_is_not_external():
    """Subdomain audit on a two-part TLD with rua at the parent apex:
    sub.example.co.uk with rua=mailto:r@example.co.uk and no tree
    walk -> org_domain should resolve to example.co.uk via PSL,
    classifying the destination as internal."""
    result = _run_check(
        "sub.example.co.uk",
        {"rua": "mailto:r@example.co.uk"},
        tree_walk_result=None,
    )
    assert result is not None
    dest = result["report_destinations"][0]
    assert dest["is_external"] is False
