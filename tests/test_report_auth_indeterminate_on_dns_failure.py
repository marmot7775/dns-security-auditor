"""Regression test for a transient DNS failure on the _report._dmarc
authorization lookup being reported as a hard "not authorized" finding.

Bug: _lookup_txt swallowed every DNS outcome -- NXDOMAIN (no record),
SERVFAIL, and timeout -- into an equally empty list, so
_check_report_authorization could not tell "the destination never
authorized us" from "we couldn't find out". A SERVFAIL or timeout on
the _report._dmarc query became authorized=False, the same hard error
shown for a destination that genuinely never published the
authorization record: "Reports sent to ... will be silently dropped."

Test patches the resolver to raise on the _report._dmarc query and
asserts on _check_report_authorization's own output (the object placed
directly into the audit result), which is the user-facing home of this
finding.
"""
import os
import sys
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine

DOMAIN = "reportauth.example.com"


def test_dns_failure_on_report_auth_query_is_indeterminate_not_hard_fail():
    raw_dmarc = {"rua": "mailto:reports@thirdparty.example.net"}

    def _fake_resolve(name, rdtype=None, *args, **kwargs):
        if rdtype == "TXT":
            raise dns.resolver.NoNameservers(request=MagicMock(), errors=[])
        raise dns.exception.Timeout()

    fake_resolver = MagicMock()
    fake_resolver.resolve.side_effect = _fake_resolve

    with patch.object(audit_engine, "_get_resolver", return_value=fake_resolver):
        result = audit_engine._check_report_authorization(DOMAIN, raw_dmarc, tree_walk_result=None)

    dest = result["report_destinations"][0]
    assert dest["is_external"] is True
    assert dest["authorized"] is None, (
        f"A failed lookup must be indeterminate (authorized=None), not a "
        f"hard False; got {dest!r}"
    )

    issue_texts = " ".join(i["issue"] for i in result["report_auth_issues"])
    assert "not authorized" not in issue_texts.lower(), (
        f"Must not claim the destination is NOT authorized when the lookup "
        f"itself failed; got issues: {result['report_auth_issues']!r}"
    )
    assert any(i["severity"] == "warning" for i in result["report_auth_issues"]), (
        f"A DNS lookup failure should surface as a warning-level indeterminate "
        f"finding; got: {result['report_auth_issues']!r}"
    )


def test_genuine_no_authorization_record_is_still_a_hard_error():
    """Control: NXDOMAIN (no record published) still fails, unchanged."""
    raw_dmarc = {"rua": "mailto:reports@thirdparty.example.net"}

    def _fake_resolve(name, rdtype=None, *args, **kwargs):
        if rdtype == "TXT":
            raise dns.resolver.NXDOMAIN()
        raise dns.exception.Timeout()

    fake_resolver = MagicMock()
    fake_resolver.resolve.side_effect = _fake_resolve

    with patch.object(audit_engine, "_get_resolver", return_value=fake_resolver):
        result = audit_engine._check_report_authorization(DOMAIN, raw_dmarc, tree_walk_result=None)

    dest = result["report_destinations"][0]
    assert dest["authorized"] is False
    issue_texts = " ".join(i["issue"] for i in result["report_auth_issues"])
    assert "not authorized" in issue_texts.lower()
