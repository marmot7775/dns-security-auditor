"""Regression test: a macro expanded include target is not a broken include.

spf_recursive already knew macros cannot be resolved from the record alone:
_mechanism_lookup_status returns "ok" for an a:, mx: or exists: target
containing "%". The include and redirect branches skipped that guard and
recursed into the literal text, so

    v=spf1 include:%{ir}.a.example.net include:%{ir}.b.example.net
           include:%{ir}.c.example.net ip4:1.2.3.4 -all

queried three names nobody publishes, booked three NXDOMAIN results as void
lookups, and tripped the RFC 7208 section 4.6.4 two void lookup rule. The
card told the operator to remove the includes that make the record work.

Macro based includes are what reputation lookups and per recipient
authorization publish, so this is a valid record reported as broken.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer
import spf_execution_engine
import spf_recursive
from conftest import FakeZone, fake_dns

DOMAIN = "macro.example.test"
MACRO_RECORD = (
    "v=spf1 include:%{ir}.a.example.net include:%{ir}.b.example.net "
    "include:%{ir}.c.example.net ip4:1.2.3.4 -all"
)
ZONE = {DOMAIN: {"TXT": [MACRO_RECORD]}}


def _run():
    with fake_dns(FakeZone(ZONE)):
        raw = audit_engine._raw_check_spf(DOMAIN)
    return raw, result_transformer.transform_spf(raw, has_mx=True)


def test_macro_includes_produce_no_void_lookups():
    raw, card = _run()

    assert raw["void_lookup_count"] == 0, (
        f"A macro expanded target cannot be resolved from the record, so it "
        f"is neither NXDOMAIN nor a void lookup. Got "
        f"{raw['void_lookup_count']}"
    )
    assert raw["lookup_count"] == 3, (
        f"Each include still costs one DNS lookup at evaluation time. "
        f"Got {raw['lookup_count']}"
    )


def test_macro_includes_are_not_reported_as_broken():
    raw, card = _run()

    issue_texts = " ".join(
        f"{i.get('issue', '')} {i.get('fix', '')}" for i in raw["issues"]
    ).lower()
    assert "broken include" not in issue_texts, (
        f"A macro based include is valid configuration; got issues: "
        f"{[i['issue'] for i in raw['issues']]}"
    )
    assert "remove the include" not in issue_texts, (
        f"The fix text must not tell the operator to delete the includes "
        f"that make the record work; got: {issue_texts!r}"
    )
    assert "void lookup" not in issue_texts, (
        f"No void lookups happened, so none may be reported; got: "
        f"{issue_texts!r}"
    )

    assert raw["status"] == "ok", (
        f"This record is valid, so the check must not be an error or a "
        f"warning. Got {raw['status']!r} from "
        f"{[(i['severity'], i['issue']) for i in raw['issues']]}"
    )
    assert card["status"] == "pass", (
        f"A valid macro based record must pass. Got {card['status']!r}"
    )


def test_macro_targets_get_an_informational_note():
    raw, _ = _run()

    notes = [i for i in raw["issues"] if i["severity"] == "info"]
    assert len(notes) == 3, (
        f"One note per macro expanded term, explaining the lookup it costs. "
        f"Got {[(i['severity'], i['issue']) for i in raw['issues']]}"
    )
    for note in notes:
        assert "macro" in note["issue"].lower()
    assert any("%{ir}.a.example.net" in n["issue"] for n in notes), (
        f"The note must name the term it is about; got "
        f"{[n['issue'] for n in notes]}"
    )


def test_macro_include_does_not_break_child_pairing():
    """A suppressed recursion must not shift the remaining subtrees."""
    domain = "macromix.example.test"
    zone = {
        domain: {"TXT": ["v=spf1 include:%{ir}.macro.example.net "
                         "include:real.example.net -all"]},
        "real.example.net": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]},
    }
    with fake_dns(FakeZone(zone)):
        result = spf_recursive.count_spf_lookups(domain)
        viz = spf_execution_engine.build_spf_tree_viz(result)

    assert result["total_lookups"] == 2
    assert result["void_lookups"] == 0

    children = viz["root"]["children"]
    assert [c["domain"] for c in children] == ["real.example.net"], (
        f"Only the non macro include has a subtree, and it must render under "
        f"itself; got {[c['domain'] for c in children]}"
    )
