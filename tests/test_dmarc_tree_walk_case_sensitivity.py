"""Tests for dmarcbis-41 §4.7 case-sensitive v=DMARC1 in tree walk.

§4.7 (v tag): "The tag value is case sensitive, and the only possible
value is 'DMARC1'. ... if the value is not 'DMARC1', then the entire
record MUST be ignored."

Tree walk inheritance must honor this: a parent record published with
v=dmarc1 (or V=DMARC1) is invalid and must NOT be inherited.
"""
import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dmarc_tree_walk as tw


class _FakeRdata:
    def __init__(self, txt):
        self.strings = [txt.encode()]


class _FakeAnswers:
    def __init__(self, txts):
        self._items = [_FakeRdata(t) for t in txts]

    def __iter__(self):
        return iter(self._items)


def _resolver_for(records):
    """Return a side_effect for dns.resolver.resolve.

    `records` maps "_dmarc.<domain>" -> list of TXT strings, or to None
    to simulate NXDOMAIN/NoAnswer (raised as a generic Exception that
    _query_dmarc swallows).
    """
    def _resolve(name, rdtype):
        key = str(name)
        if key in records and records[key] is not None:
            return _FakeAnswers(records[key])
        raise Exception("no answer")
    return _resolve


def test_parent_uppercase_v_dmarc1_is_inherited():
    """Properly-cased v=DMARC1 at parent: walk inherits, policy=reject."""
    domain = "alpha.example.com"
    records = {
        "_dmarc.alpha.example.com": None,
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
        "_dmarc.com": None,
    }
    with patch("dns.resolver.resolve", side_effect=_resolver_for(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["org_domain"] == "example.com"
    assert result["policy_source"] == "example.com"
    assert result["effective_policy"] == "reject"
    assert result["is_subdomain"] is True


def test_parent_lowercase_v_dmarc1_is_skipped():
    """Lowercase v=dmarc1 at parent: walk MUST ignore it (§4.7)."""
    domain = "alpha.example.com"
    records = {
        "_dmarc.alpha.example.com": None,
        "_dmarc.example.com": ["v=dmarc1; p=reject"],
        "_dmarc.com": None,
    }
    with patch("dns.resolver.resolve", side_effect=_resolver_for(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["policy_source"] is None
    assert result["effective_policy"] is None
    assert result["effective_record"] is None
    assert result["org_domain"] is None


def test_parent_uppercase_V_dmarc1_is_skipped():
    """V=DMARC1 (uppercase tag name) does not match the literal v=DMARC1
    prefix the spec mandates: walk MUST ignore it."""
    domain = "alpha.example.com"
    records = {
        "_dmarc.alpha.example.com": None,
        "_dmarc.example.com": ["V=DMARC1; p=reject"],
        "_dmarc.com": None,
    }
    with patch("dns.resolver.resolve", side_effect=_resolver_for(records)), \
         patch.object(tw, "_domain_exists", return_value=True):
        result = tw.dmarc_tree_walk(domain)

    assert result["policy_source"] is None
    assert result["effective_policy"] is None
    assert result["effective_record"] is None
    assert result["org_domain"] is None
