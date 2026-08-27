"""Tests for RFC 9989 §4.10.1 ¶3 / §4.10.2 Org Domain determination
when a DMARC record is found at the Author Domain.

Spec text (verbatim, §4.10.1 paragraph 3):

    Policy discovery starts first with a query for a valid DMARC Policy
    Record at the name created by prepending the label "_dmarc" to the
    Author Domain of the message being evaluated.  If a valid DMARC
    Policy Record is found there, then this is the DMARC Policy Record
    to be applied to the message; however, this does not necessarily
    mean that the Author Domain is the Organizational Domain to be
    used in Identifier Alignment checks.  Whether this is also the
    Organizational Domain is dependent on the value of the "psd" tag,
    if present, or some conditions described in Section 4.10.2.

The audit previously assumed Author Domain == Org Domain on first-query
hit, which produced false-external-rua flags for sub-domain audits whose
parents are the actual Org Domain.
"""
import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dmarc_tree_walk as tw


def _records_lookup(records):
    def _lookup(domain):
        return records.get(domain)
    return _lookup


def test_author_hit_with_parent_dmarc_walks_and_picks_parent_as_org():
    """§4.10.1 ¶3 / §4.10.2 rule 3: subdomain has its own DMARC, parent
    also publishes DMARC -> rule 3 fewest-labels selects the parent as
    the Org Domain. Policy still comes from the Author Domain record.
    """
    domain = "mail.example.com"
    records = {
        "mail.example.com": "v=DMARC1; p=reject; rua=mailto:reports@example.com",
        "example.com": "v=DMARC1; p=none; rua=mailto:reports@example.com",
        "com": None,
    }

    queried = []

    def _qd(d):
        queried.append(d)
        return records.get(d)

    with patch.object(tw, "_query_dmarc", side_effect=_qd), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com", (
        f"Author Domain should NOT be assumed to be Org Domain; "
        f"§4.10.2 rule 3 picks fewest-labels = example.com, got "
        f"{result['org_domain']}"
    )
    assert result["org_domain_method"] == "walked"
    assert result["policy_source"] == "mail.example.com"
    assert result["effective_policy"] == "reject"
    assert result["effective_record"] == records["mail.example.com"]
    assert result["is_subdomain"] is False
    assert result["applied_tag"] == "p"
    # Walk should have queried the parent.
    assert "example.com" in queried


def test_author_hit_with_psd_n_marks_author_as_org():
    """§4.10.2 rule 1: psd=n at the Author Domain -> Author IS Org Domain.
    Walk does NOT proceed (§4.10 step 2 stops on psd=n)."""
    domain = "example.com"
    records = {
        "example.com": "v=DMARC1; p=reject; psd=n",
    }

    queried = []

    def _qd(d):
        queried.append(d)
        return records.get(d)

    with patch.object(tw, "_query_dmarc", side_effect=_qd), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com"
    assert result["org_domain_method"] == "psd_n_at_author"
    assert result["psd_flag"] == "n"
    assert result["policy_source"] == "example.com"
    assert result["effective_policy"] == "reject"
    # Only the Author Domain query should have run.
    assert queried == ["example.com"]
    assert result["query_count"] == 0


def test_author_hit_two_label_no_psd_takes_label_minimum_fast_path():
    """2-label Author Domain with no psd tag is already at the minimum
    below the TLD; skip the walk entirely."""
    domain = "example.com"
    records = {
        "example.com": "v=DMARC1; p=quarantine; rua=mailto:r@example.com",
    }

    queried = []

    def _qd(d):
        queried.append(d)
        return records.get(d)

    with patch.object(tw, "_query_dmarc", side_effect=_qd), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com"
    assert result["org_domain_method"] == "label_minimum"
    assert result["policy_source"] == "example.com"
    assert result["effective_policy"] == "quarantine"
    # No walk: only the Author Domain query.
    assert queried == ["example.com"]
    assert result["query_count"] == 0


def test_author_hit_walk_finds_psd_n_at_parent():
    """§4.10.2 rule 1 via walk: subdomain has DMARC (no psd), parent
    has psd=n -> walk runs, finds psd=n, parent is Org Domain."""
    domain = "mail.example.com"
    records = {
        "mail.example.com": "v=DMARC1; p=reject",
        "example.com": "v=DMARC1; p=none; psd=n",
    }

    queried = []

    def _qd(d):
        queried.append(d)
        return records.get(d)

    with patch.object(tw, "_query_dmarc", side_effect=_qd), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com"
    assert result["org_domain_method"] == "walked"
    assert result["psd_flag"] == "n"
    # Policy stays anchored to Author Domain (§4.10.1-6).
    assert result["policy_source"] == "mail.example.com"
    assert result["effective_policy"] == "reject"
    assert result["is_subdomain"] is False
    # Walk should have queried the parent.
    assert "example.com" in queried


def test_author_hit_psd_y_at_author_keeps_author_as_org():
    """§4.10.2 rule 2 excludes the starting target; rule 3 with one
    record makes Author the Org Domain. Walk does not proceed."""
    domain = "example.com"
    records = {
        "example.com": "v=DMARC1; p=none; psd=y",
    }

    queried = []

    def _qd(d):
        queried.append(d)
        return records.get(d)

    with patch.object(tw, "_query_dmarc", side_effect=_qd), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com"
    assert result["org_domain_method"] == "psd_y_at_author"
    assert result["psd_flag"] == "y"
    assert queried == ["example.com"]


def test_author_hit_walk_finds_no_other_records_falls_back_to_psl():
    """When the walk turns up no records other than the Author Domain,
    fall back to PSL Org Domain so subdomains whose parents do not
    publish DMARC do not get false-external-rua flags."""
    domain = "mail.example.com"
    records = {
        "mail.example.com": "v=DMARC1; p=reject; rua=mailto:r@example.com",
        # Parent has no DMARC.
        "example.com": None,
        "com": None,
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com"
    assert result["org_domain_method"] == "psl_fallback"
    assert result["policy_source"] == "mail.example.com"
    assert result["effective_policy"] == "reject"


def test_author_hit_explicit_psd_u_continues_walk():
    """psd="u" (unknown) is not psd=n or psd=y; §4.10 step 2 does not
    stop on it. Behavior matches psd-absent: walk continues."""
    domain = "mail.example.com"
    records = {
        "mail.example.com": "v=DMARC1; p=reject; psd=u",
        "example.com": "v=DMARC1; p=none",
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com"
    assert result["org_domain_method"] == "walked"
    assert result["policy_source"] == "mail.example.com"
