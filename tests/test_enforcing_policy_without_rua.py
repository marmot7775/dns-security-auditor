"""An enforcing policy with no rua is a gap, not a failing record.

rua is OPTIONAL in RFC 7489 section 6.3 and in RFC 9989. A record with
p=quarantine or p=reject and no rua is compliant, and it is doing the thing
that stops spoofing. The tool graded it FAIL, named "Add aggregate reporting"
as the domain's biggest risk at critical, and scored spoofing protection 0 of
4 on proton.me, which quarantines every failing message.

Three separate causes, all fixed here:

  - audit_engine raised the missing-rua issue at severity "error" when the
    policy was enforcing, and transform_dmarc turns any engine error into a
    fail. It is a warning at every policy now; what changes with the policy is
    the consequence, which the text states.

  - The spoofing metric counted "Reporting Intelligence" as one of its four
    vectors. That is not a spoofing vector: it describes whether you can see
    what your policy does, not whether an attacker can send as you. A missing
    rua therefore cost a spoofing point. The vector stays in the panel and is
    out of the count, which is now over the three spoofing vectors.

  - The roadmap ranked the rua item critical, so it took the biggest-risk slot
    from a domain rejecting every failing message. It is a high.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "rua.test"


def _zone(policy, rua):
    record = f"v=DMARC1; p={policy}" + (f"; rua=mailto:r@{DOMAIN}" if rua else "")
    return FakeZone({
        DOMAIN: {"MX": [(10, f"m.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.1"], "NS": [f"ns1.{DOMAIN}"]},
        f"_dmarc.{DOMAIN}": {"TXT": [record]},
        f"m.{DOMAIN}": {"A": ["203.0.113.2"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
    })


def _run(audit, policy, rua):
    return audit(_zone(policy, rua), DOMAIN, scope="dmarc")


def _card(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


@pytest.mark.parametrize("policy", ["quarantine", "reject"])
def test_an_enforcing_policy_without_rua_does_not_fail(audit, policy):
    card = _card(_run(audit, policy, rua=False))

    assert card["status"] != "fail", (
        f"p={policy} with no rua is a compliant, enforcing record. rua is "
        f"OPTIONAL in RFC 7489 6.3 and RFC 9989. Got {card['status']!r}"
    )


@pytest.mark.parametrize("policy", ["quarantine", "reject"])
def test_the_spoofing_count_does_not_move_with_rua(audit, policy):
    """The metric measures spoofing. rua is not a spoofing control."""
    with_rua = _run(audit, policy, rua=True)["executive_summary"]
    without = _run(audit, policy, rua=False)["executive_summary"]

    assert (with_rua["spoofing_protection"]["detail"]
            == without["spoofing_protection"]["detail"]), (
        f"p={policy}: the spoofing count changed with the report address. "
        f"with rua {with_rua['spoofing_protection']['detail']!r}, "
        f"without {without['spoofing_protection']['detail']!r}"
    )
    assert (with_rua["spoofing_protection"]["label"]
            == without["spoofing_protection"]["label"])


def test_the_reporting_vector_is_still_shown(audit):
    """Excluded from the count, not deleted from the panel."""
    card = _card(_run(audit, "reject", rua=False))
    names = [v["name"] for v in card["attack_surface"]["vectors"]]
    assert "Reporting Intelligence" in names


@pytest.mark.parametrize("policy", ["quarantine", "reject"])
def test_rua_does_not_take_the_biggest_risk_slot(audit, policy):
    risk = _run(audit, policy, rua=False)["executive_summary"]["biggest_risk"].lower()
    assert "aggregate reporting" not in risk, (
        f"p={policy}: a domain enforcing against spoofed mail was told its "
        f"biggest risk is the missing report address: {risk!r}"
    )


def test_the_rua_item_is_still_on_the_roadmap(audit):
    """Demoted, not dropped."""
    roadmap = _run(audit, "reject", rua=False)["security_roadmap"]
    rua_items = [i for i in roadmap["items"] if "rua" in i["action"].lower()]
    assert rua_items, "the visibility gap is real and still belongs on the roadmap"
    assert rua_items[0]["priority"] == "high"
    # The impact line has to be true at every policy it can appear under.
    assert "enforcing" not in rua_items[0]["impact"].lower()


def test_a_record_with_rua_is_unaffected(audit):
    card = _card(_run(audit, "reject", rua=True))
    assert card["status"] == "pass"
