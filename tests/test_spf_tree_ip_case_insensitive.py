"""Regression test for uppercase and qualified ip4:/ip6: terms vanishing
from the SPF include tree.

Bug 39: _build_tree_node matched raw.startswith(("ip4:", "ip6:", "+ip4:",
"+ip6:")) against the unmodified mechanism text. SPF terms are
case-insensitive (RFC 7208 section 4.6.1), and the `all` check two lines
below already lowercases first, so "IP4:203.0.113.0/24" and any range
carrying a -, ~ or ? qualifier were silently dropped from the tree's ip
list.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spf_execution_engine import _build_tree_node


def _node(*raws):
    return {
        "domain": "example.com",
        "record": "v=spf1 " + " ".join(raws),
        "mechanisms": [{"type": "no_lookup", "raw": r, "value": r} for r in raws],
        "children": [],
        "lookups_here": 0,
        "total": 0,
    }


def test_uppercase_ip4_and_ip6_kept():
    node = _build_tree_node(
        _node("IP4:203.0.113.0/24", "ip6:2001:db8::/32", "-ALL"), 0, 0
    )
    assert "IP4:203.0.113.0/24" in node["ips"]
    assert "ip6:2001:db8::/32" in node["ips"]


def test_qualified_ip4_kept():
    node = _build_tree_node(
        _node("-ip4:198.51.100.0/24", "~ip4:192.0.2.0/24", "?IP6:2001:db8::/48", "-all"),
        0, 0,
    )
    # The qualifier is stripped, the range is kept.
    assert "ip4:198.51.100.0/24" in node["ips"]
    assert "ip4:192.0.2.0/24" in node["ips"]
    assert "IP6:2001:db8::/48" in node["ips"]


def test_all_is_not_collected_as_an_ip():
    node = _build_tree_node(_node("ip4:203.0.113.0/24", "-ALL"), 0, 0)
    assert node["ips"] == ["ip4:203.0.113.0/24"]
    assert node["terminal"] == "-all"
