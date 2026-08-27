"""Regression test for the Org Domain returned as the public suffix
instead of the registrant domain, when the registrant has no DMARC
record of its own and its parent is a psd=y PSD.

Bug: in the "no record at the Author Domain" branch of dmarc_tree_walk,
stop_at_first_walk treated "the domain where the Tree Walk started"
(RFC 9989 4.10.2 rule 2's exclusion) as the first *walk* query target,
which per 4.10.1 paragraph 5 is already the immediate parent for
<8-label Author Domains. RFC 9989's own worked example in 4.10.2 makes
clear the excluded domain is the Author Domain itself:

    "if in the course of a Tree Walk a DMARC Policy Record is queried
    for at first '_dmarc.mail.example.com' and then '_dmarc.example.com',
    and a valid DMARC Policy Record containing the 'psd' tag set to 'y'
    is found at '_dmarc.example.com', then 'mail.example.com' is the
    domain one label below 'example.com' in the DNS hierarchy and is
    thus the Organizational Domain."

Since this branch only runs when the Author Domain has no record at
all, it is never a candidate for rule 2's exclusion, so a psd=y record
found at the immediate parent (the first walk query) must still be
treated as "other than the Author Domain" and produce an Org Domain
one label below it -- not the parent (public suffix) itself.

_walk_after_author_hit's psd=y handling already reads the exclusion
this way; only the no-author-record branch disagreed.

The actual damage: a wrong (too-short) Org Domain makes a genuinely
external rua destination on the same public suffix look internal,
so its _report._dmarc authorization is never checked (RFC 7489 7.1).

Test asserts on dmarc_tree_walk's org_domain output and on the
downstream report-authorization classification
(audit_engine._check_report_authorization), not on internal walk
bookkeeping.
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dmarc_tree_walk as tw
import audit_engine


def test_registrant_under_psd_y_suffix_gets_registrant_as_org_domain():
    domain = "example.co.uk"
    records = {
        "example.co.uk": None,
        "co.uk": "v=DMARC1; p=reject; psd=y",
    }

    with patch.object(tw, "_query_dmarc", side_effect=lambda d: records.get(d)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.co.uk", (
        f"psd=y at co.uk (the immediate parent, not the Author Domain) must "
        f"still yield the registrant one label below it as the Org Domain "
        f"per RFC 9989 4.10.2 rule 2; got {result['org_domain']!r}"
    )
    assert result["org_domain_method"] == "walked"
    assert result["psd_flag"] == "y"


def test_misclassification_is_fixed_downstream_in_report_authorization():
    domain = "example.co.uk"
    records = {
        "example.co.uk": None,
        "co.uk": "v=DMARC1; p=reject; psd=y",
    }
    with patch.object(tw, "_query_dmarc", side_effect=lambda d: records.get(d)), \
         patch.object(tw, "_domain_exists", return_value=True):
        tree_walk_result = tw.dmarc_tree_walk(domain)

    assert tree_walk_result["org_domain"] == "example.co.uk"

    raw_dmarc = {"rua": "mailto:reports@unrelated-vendor.co.uk"}

    fake_resolver = MagicMock()
    with patch.object(audit_engine, "_get_resolver", return_value=fake_resolver), \
         patch.object(audit_engine, "_lookup_txt", return_value=["v=DMARC1"]):
        result = audit_engine._check_report_authorization(domain, raw_dmarc, tree_walk_result)

    dest = result["report_destinations"][0]
    assert dest["is_external"] is True, (
        f"With org_domain correctly at example.co.uk, "
        f"reports@unrelated-vendor.co.uk must be classified external "
        f"(it shares only the public suffix, not the org domain); got {dest!r}"
    )
    assert dest["authorization_record"] == "example.co.uk._report._dmarc.unrelated-vendor.co.uk"
    assert dest["authorized"] is not None, (
        f"External destinations must have their _report._dmarc "
        f"authorization checked, not skipped; got {dest!r}"
    )
