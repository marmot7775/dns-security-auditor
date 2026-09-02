"""Regression test: CAA is looked up on the parent chain, not just the name.

RFC 8659 section 3 has a CA climb the name tree when the name itself has no
CAA RRset. The check stopped at the queried name -- the "check parent domain"
comment was followed by a bare pass -- so auditing mail.example.test while
example.test publishes CAA produced a headline warning that any CA in the
world could issue for it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.resolver

import audit_engine
from conftest import FakeZone, fake_dns


class CaaZone(FakeZone):
    """FakeZone, but a name with no CAA RRset answers NOERROR/no-answer.

    FakeZone returns NXDOMAIN for any undeclared (name, type), which is the
    right default for the rest of the suite. Here the two have to stay apart:
    "this name exists and publishes no CAA" is what makes a CA climb to the
    parent, while NXDOMAIN means the name is not there at all.
    """

    def resolve(self, name, rdtype="A", *args, **kwargs):
        if str(rdtype).upper() == "CAA" and self._key(name, rdtype) not in self._records:
            raise dns.resolver.NoAnswer()
        return super().resolve(name, rdtype, *args, **kwargs)

SUB = "mail.example.test"
APEX = "example.test"

INHERITED_ZONE = {
    SUB: {"A": ["198.51.100.10"]},
    APEX: {"CAA": [(0, "issue", "letsencrypt.org")]},
}

BARE_ZONE = {SUB: {"A": ["198.51.100.10"]}}


def _issues(result):
    return " ".join(i.get("issue", "") for i in result["issues"])


def test_subdomain_inherits_the_parent_caa_rrset():
    with fake_dns(CaaZone(INHERITED_ZONE)):
        result = audit_engine._raw_check_caa(SUB)

    assert result["record_count"] == 1, (
        f"The effective CAA RRset for {SUB} is the one at {APEX}. "
        f"Got {result['records']!r}"
    )
    assert result["caa_source"] == APEX, (
        f"The card has to say where the policy was found; got "
        f"{result['caa_source']!r}"
    )
    assert result["inherited"] is True
    assert result["authorized_cas"] == ["letsencrypt.org"]

    assert "No CAA records published" not in _issues(result), (
        "A false headline warning that any CA in the world can issue."
    )
    assert result["status"] != "warning"


def test_no_caa_anywhere_in_the_chain_still_warns():
    with fake_dns(CaaZone(BARE_ZONE)):
        result = audit_engine._raw_check_caa(SUB)

    assert result["record_count"] == 0
    assert result["caa_source"] is None
    assert result["inherited"] is False
    assert "No CAA records published" in _issues(result)


def test_the_climb_stops_below_the_public_suffix():
    names = audit_engine._caa_tree("a.b.example.test")

    assert names[0] == "a.b.example.test"
    assert names[-1] == "example.test", (
        f"RFC 8659 section 3 climbs to but not including the root, and "
        f"nothing above the registrable domain can publish CAA for this "
        f"name. Got {names!r}"
    )
    assert all(name.count(".") >= 1 for name in names), (
        f"A single-label name is a public suffix, never a lookup target. "
        f"Got {names!r}"
    )
