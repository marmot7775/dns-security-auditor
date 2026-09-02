"""Regression test: two SPF records at an include target are a PermError.

RFC 7208 section 4.5 allows exactly one v=spf1 record at a name and makes
more than one a permerror for the whole evaluation. audit_engine flags this
for the audited domain, but spf_recursive._lookup_spf returned on the first
RR whose text started with v=spf1, so nothing checked include or redirect
targets.

    example.com  v=spf1 include:dup.example.net -all
    dup.example.net  v=spf1 ip4:198.51.100.1 -all
                     v=spf1 ip4:203.0.113.1 -all

came back status pass, total_lookups 1, issues []. Real receivers PermError
that record, and the tool called it fine.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer
import spf_recursive
from conftest import FakeZone, fake_dns

DOMAIN = "dupinclude.example.test"
TARGET = "dup.example.net"
ZONE = {
    DOMAIN: {"TXT": [f"v=spf1 include:{TARGET} -all"]},
    TARGET: {"TXT": [
        "v=spf1 ip4:198.51.100.1 -all",
        "v=spf1 ip4:203.0.113.1 -all",
    ]},
}


def _run():
    with fake_dns(FakeZone(ZONE)):
        raw = audit_engine._raw_check_spf(DOMAIN)
    return raw, result_transformer.transform_spf(raw, has_mx=True)


def test_duplicate_records_at_an_include_target_are_an_error():
    raw, card = _run()

    errors = [i for i in raw["issues"] if i["severity"] == "error"]
    assert errors, (
        f"Two SPF records at {TARGET} is a PermError for the whole chain and "
        f"must be reported; got issues "
        f"{[(i['severity'], i['issue']) for i in raw['issues']]}"
    )
    assert any(TARGET in i["issue"] for i in errors), (
        f"The issue has to name the domain that publishes the duplicates; "
        f"got {[i['issue'] for i in errors]}"
    )
    assert raw["status"] == "error"
    assert card["status"] == "fail", (
        f"A chain that PermErrors at every receiver cannot pass. Got "
        f"{card['status']!r}"
    )


def test_duplicates_are_not_reported_as_a_missing_record():
    raw, _ = _run()

    issue_texts = " ".join(i["issue"] for i in raw["issues"])
    assert "publishes no SPF record" not in issue_texts, (
        f"{TARGET} publishes two records, not none; got {issue_texts!r}"
    )
    assert raw.get("void_lookup_count", 0) == 0, (
        f"RFC 7208 4.5 duplicates are an immediate permerror, not a void "
        f"lookup. Got {raw['void_lookup_count']}"
    )


def test_the_target_is_reported_through_the_recursive_result():
    with fake_dns(FakeZone(ZONE)):
        result = spf_recursive.count_spf_lookups(DOMAIN)

    assert result["multiple_spf_domains"] == [TARGET]
    assert result["total_lookups"] == 1, (
        f"The include still costs its own lookup. Got "
        f"{result['total_lookups']}"
    )
    chain_entry = next(e for e in result["chain"] if e["domain"] == TARGET)
    assert chain_entry["lookup_status"] == spf_recursive.SPF_MULTIPLE


def test_a_single_record_at_the_target_is_still_fine():
    zone = {
        DOMAIN: {"TXT": [f"v=spf1 include:{TARGET} -all"]},
        TARGET: {"TXT": ["v=spf1 ip4:198.51.100.1 -all"]},
    }
    with fake_dns(FakeZone(zone)):
        raw = audit_engine._raw_check_spf(DOMAIN)
    card = result_transformer.transform_spf(raw, has_mx=True)

    assert raw["status"] == "ok"
    assert card["status"] == "pass"
