"""Regression test for unknown SPF terms being invisible in the trace.

Finding C: _walk_tree's if/elif chain handled include/redirect, a/mx/ptr/
exists and no_lookup, and fell off the end for anything else. Terms the
parser classifies as "unknown", such as the exp= modifier or a typo like
"inculde:example.com", emitted no step at all, so the visualization simply
skipped them even though audit_engine.py flags them separately.

The walk algorithm itself is deliberately untouched: it was fuzzed against
300 random zones for range contiguity and total agreement with zero
mismatches. The lookup-accounting assertions below guard that.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spf_execution_engine import build_spf_execution_trace


def _tree(mechanisms, children=None, total=0, lookups_here=0):
    return {
        "domain": "example.com",
        "mechanisms": mechanisms,
        "children": children or [],
        "total": total,
        "lookups_here": lookups_here,
    }


def _mech(mtype, raw, value=None):
    return {"type": mtype, "raw": raw, "value": value if value is not None else raw}


def _trace(tree, total_lookups):
    return build_spf_execution_trace(
        {"tree": tree, "total_lookups": total_lookups, "domain": "example.com"},
        "v=spf1 ...",
    )


def test_exp_modifier_emits_a_step():
    trace = _trace(
        _tree([
            _mech("no_lookup", "ip4:203.0.113.0/24"),
            _mech("unknown", "exp=explain.example.com"),
            _mech("no_lookup", "-all"),
        ]),
        0,
    )
    mechs = [s["mechanism"] for s in trace["flat_steps"]]
    assert "exp=explain.example.com" in mechs


def test_typo_term_emits_a_step_marked_unknown():
    trace = _trace(
        _tree([
            _mech("unknown", "inculde:_spf.example.net"),
            _mech("no_lookup", "-all"),
        ]),
        0,
    )
    step = next(s for s in trace["flat_steps"] if s["mechanism"].startswith("inculde"))
    assert step["status"] == "unknown"
    assert step["lookup_cost"] == 0
    assert step["lookup_range"] is None


def test_unknown_term_costs_no_lookup():
    with_unknown = _trace(
        _tree(
            [
                _mech("include", "include:_spf.example.net", "_spf.example.net"),
                _mech("unknown", "exp=explain.example.com"),
                _mech("no_lookup", "-all"),
            ],
            children=[_tree([_mech("no_lookup", "-all")], total=0)],
            total=1,
        ),
        1,
    )
    include_step = next(
        s for s in with_unknown["flat_steps"] if s["type"] == "include"
    )
    assert include_step["running_total"] == 1
    unknown_step = next(
        s for s in with_unknown["flat_steps"] if s["status"] == "unknown"
    )
    assert unknown_step["running_total"] == 1


def test_every_mechanism_produces_exactly_one_step():
    mechanisms = [
        _mech("include", "include:_spf.example.net", "_spf.example.net"),
        _mech("a", "a"),
        _mech("mx", "mx"),
        _mech("exists", "exists:%{i}.example.com"),
        _mech("no_lookup", "ip4:203.0.113.0/24"),
        _mech("unknown", "exp=explain.example.com"),
        _mech("no_lookup", "-all"),
    ]
    child = _tree([_mech("no_lookup", "-all")], total=0)
    trace = _trace(_tree(mechanisms, children=[child], total=4), 4)

    # Every mechanism in the tree, the include's subtree included. _walk_tree
    # used to hand the recursion a throwaway list, so nested mechanisms never
    # reached flat_steps at all and this count was len(mechanisms).
    assert len(trace["flat_steps"]) == len(mechanisms) + len(child["mechanisms"])

    nested = [s for s in trace["flat_steps"] if s["depth"] == 1]
    assert len(nested) == 1 and nested[0]["mechanism"] == "-all", (
        f"the include's own mechanisms must appear at depth 1; got "
        f"{trace['flat_steps']!r}"
    )
    assert trace["flat_steps"][0]["type"] == "include", (
        "a parent step must precede the subtree it opens"
    )


def test_lookup_accounting_is_unchanged_by_the_new_branch():
    # Contiguous ranges and a running total that agrees with the tree, which
    # is what the 300-zone fuzz established.
    trace = _trace(
        _tree(
            [
                _mech("include", "include:a.example.net", "a.example.net"),
                _mech("unknown", "exp=explain.example.com"),
                _mech("include", "include:b.example.net", "b.example.net"),
                _mech("no_lookup", "-all"),
            ],
            children=[
                _tree([_mech("a", "a")], total=1, lookups_here=1),
                _tree([_mech("mx", "mx")], total=1, lookups_here=1),
            ],
            total=4,
        ),
        4,
    )
    includes = [s for s in trace["flat_steps"] if s["type"] == "include"]
    assert [s["lookup_range"] for s in includes] == ["1-2", "3-4"]
    assert includes[-1]["running_total"] == 4
