"""Regression test: the malformed record repair must not mangle a token that
merely ends in a qualified 'all'.

repair_spf_missing_spaces used (?<=\\S)([~?+\\-]all(?=\\s|$)) with no token
boundary guard, so

    v=spf1 ip4:1.2.3.4 include:mail-all ~all

became

    v=spf1 ip4:1.2.3.4 include:mail -all ~all

The include target silently lost its last label, a -all the operator never
published was injected mid record, and a perfectly valid record was reported
as malformed. "mail-all" is an ordinary hostname label.

The repair itself is worth keeping: ip4:1.2.3.4~all really is a jammed
multi string TXT record and really does need the space put back.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer
from conftest import FakeZone, fake_dns
from spf_recursive import repair_spf_missing_spaces


def test_include_ending_in_all_is_left_alone():
    record = "v=spf1 ip4:1.2.3.4 include:mail-all ~all"
    repaired, malformed = repair_spf_missing_spaces(record)

    assert repaired == record, (
        f"mail-all is a hostname label, not a jammed -all. Got {repaired!r}"
    )
    assert malformed is False, (
        "A valid record must not be reported as malformed"
    )


def test_other_tokens_ending_in_all_are_left_alone():
    for record in (
        "v=spf1 a:catch-all.example.com -all",
        "v=spf1 include:spf-all.example.net include:send-all.example.net ~all",
        "v=spf1 exists:%{i}.deny-all.example.com -all",
    ):
        repaired, malformed = repair_spf_missing_spaces(record)
        assert repaired == record, f"{record!r} became {repaired!r}"
        assert malformed is False


def test_a_genuinely_jammed_all_is_still_repaired():
    repaired, malformed = repair_spf_missing_spaces("v=spf1 ip4:1.2.3.4~all")
    assert repaired == "v=spf1 ip4:1.2.3.4 ~all"
    assert malformed is True

    repaired, malformed = repair_spf_missing_spaces(
        "v=spf1ip4:1.2.3.0/22include:example.com~all"
    )
    assert repaired == "v=spf1 ip4:1.2.3.0/22 include:example.com ~all"
    assert malformed is True


def test_the_card_does_not_call_a_mail_all_include_malformed():
    domain = "mailall.example.test"
    record = "v=spf1 ip4:1.2.3.4 include:mail-all.example.net ~all"
    zone = {
        domain: {"TXT": [record]},
        "mail-all.example.net": {"TXT": ["v=spf1 ip4:198.51.100.1 -all"]},
    }
    with fake_dns(FakeZone(zone)):
        raw = audit_engine._raw_check_spf(domain)
    card = result_transformer.transform_spf(raw, has_mx=True)

    assert raw["record"] == record, (
        f"The card must show what the domain actually publishes. Got "
        f"{raw['record']!r}"
    )
    issue_texts = " ".join(i["issue"] for i in raw["issues"]).lower()
    assert "not space-delimited" not in issue_texts, (
        f"Nothing here is jammed together; got {issue_texts!r}"
    )
    assert card["status"] == "pass"
