"""Tests for dmarcbis-41 §4.10 tree-walk conformance.

Covers behavior changes from the spec audit:
  - First-walk-query stop on psd=y (§4.10 step 2 + §4.10.2 rule 2/3).
  - Walk descends to the TLD inclusive (§4.10 step 7
    "no more labels remaining").
  - Total query budget is 8 (Author Domain query is counted; §4.10-5).
  - Org Domain when psd=y is at the starting walk target equals that
    domain (rule 2 excludes the starting target; rule 3 with one
    collected record means fewest labels = stop record).
  - Tag cascade: Author NX + no np + sp present -> p (sp does NOT
    apply when Author Domain is NXDOMAIN; §4.10.1-7).
"""
from unittest.mock import patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dmarc_tree_walk as tw


def _records_lookup(records):
    """Return a side_effect for _query_dmarc mapping domain -> record str."""
    def _lookup(domain):
        return records.get(domain)
    return _lookup


def test_eight_label_shortening_starts_at_seven_labels_and_walks_to_tld():
    """§4.10 step 4: x>=8 labels -> shorten until 7 remain.
    §4.10 step 7: walk down to 1 label inclusive.
    §4.10-5: total query cap is 8 (Author Domain + 7 walk).
    """
    domain = "a.b.c.d.e.f.g.h.i.j.mail.example.com"  # 13 labels
    queried = []

    def _qd(d):
        queried.append(d)
        return None

    with patch.object(tw, "_query_dmarc", side_effect=_qd), \
         patch.object(tw, "_domain_exists", return_value=True):
        tw.dmarc_tree_walk(domain)

    assert queried[0] == domain, "Author Domain query must come first"
    assert queried[1] == "g.h.i.j.mail.example.com", (
        f"first walk query should be at 7 labels, got {queried[1]}"
    )
    assert queried[-1] == "com", (
        f"walk should reach the TLD (1 label), last queried: {queried[-1]}"
    )
    assert len(queried) == 8, (
        f"§4.10-5 caps total queries at 8, got {len(queried)}: {queried}"
    )


def test_psd_y_at_first_walk_query_stops_and_sets_org_domain_to_that_target():
    """§4.10 step 2: psd=y at first walk query stops the walk.
    §4.10.2 rule 2 excludes the starting target; rule 3 with a single
    collected record means the starting walk domain IS the Org Domain.
    """
    domain = "alpha.example.com"
    records = {
        "alpha.example.com": None,
        "example.com": "v=DMARC1; p=reject; psd=y",
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["psd_flag"] == "y"
    assert result["org_domain"] == "example.com"
    assert result["policy_source"] == "example.com"
    walk_steps = [s for s in result["steps"] if s.get("level") == "tree_walk"]
    assert any(s.get("stop_reason") == "psd=y" for s in walk_steps), (
        f"expected psd=y stop_reason on a walk step, got: {walk_steps}"
    )
    # The walk must NOT have continued past the psd=y stop.
    assert len(walk_steps) == 1, f"walk should stop after first query, got {walk_steps}"


def test_psd_y_at_second_walk_query_org_domain_is_one_label_below():
    """§4.10.2 rule 2: psd=y at a non-starting walk target -> Org Domain
    is the name one label below the PSD."""
    domain = "a.mail.example.com"
    records = {
        "a.mail.example.com": None,
        "mail.example.com": "v=DMARC1; p=none",            # collected
        "example.com": "v=DMARC1; p=reject; psd=y",        # stop psd=y
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["psd_flag"] == "y"
    assert result["org_domain"] == "mail.example.com"
    assert result["policy_source"] == "mail.example.com"


def test_psd_n_makes_that_domain_the_org_domain():
    """§4.10.2 rule 1: psd=n identifies the Organizational Domain."""
    domain = "a.b.example.com"
    records = {
        "a.b.example.com": None,
        "b.example.com": "v=DMARC1; p=none; psd=n",
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["psd_flag"] == "n"
    assert result["org_domain"] == "b.example.com"
    assert result["policy_source"] == "b.example.com"


def test_no_psd_tags_org_domain_is_record_with_fewest_labels():
    """§4.10.2 rule 3: no psd tag anywhere -> Org Domain has fewest labels."""
    domain = "a.mail.example.com"
    records = {
        "a.mail.example.com": None,
        "mail.example.com": "v=DMARC1; p=none",
        "example.com": "v=DMARC1; p=quarantine",
        "com": None,
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com"
    assert result["policy_source"] == "example.com"


def test_tag_cascade_author_nx_no_np_falls_back_to_p_not_sp():
    """§4.10.1-7: when Author Domain is NXDOMAIN and the policy record
    has sp but no np, fall back to p; sp does NOT apply."""
    domain = "missing.example.com"
    records = {
        "missing.example.com": None,
        "example.com": "v=DMARC1; p=reject; sp=quarantine; psd=n",
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=False):
        result = tw.dmarc_tree_walk(domain)

    assert result["applied_tag"] == "p"
    assert result["effective_policy"] == "reject"


def test_tag_cascade_author_nx_uses_np_when_present():
    """§4.10.1-7: Author NX + np tag present -> np."""
    domain = "missing.example.com"
    records = {
        "missing.example.com": None,
        "example.com": "v=DMARC1; p=none; np=reject; psd=n",
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=False):
        result = tw.dmarc_tree_walk(domain)

    assert result["applied_tag"] == "np"
    assert result["effective_policy"] == "reject"


def test_tag_cascade_author_exists_uses_sp_when_present():
    """§4.10.1-7: Author Domain exists + sp tag -> sp."""
    domain = "sub.example.com"
    records = {
        "sub.example.com": None,
        "example.com": "v=DMARC1; p=reject; sp=quarantine; psd=n",
    }

    with patch.object(tw, "_query_dmarc", side_effect=_records_lookup(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["applied_tag"] == "sp"
    assert result["effective_policy"] == "quarantine"
