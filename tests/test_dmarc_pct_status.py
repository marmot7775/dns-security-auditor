"""Regression test: pct= decides the DMARC card status, not just its wording.

The p=reject and p=quarantine branches of transform_dmarc read pct, appended
it to the verdict sentence, and then set status "pass" unconditionally. So a
record with enforcement switched off,

    v=DMARC1; p=reject; pct=0

rendered as a green pass reading "p=reject (authentication failures are
rejected) (pct=0)", a sentence that is false on its face, while
_build_attack_surface in the same report marked Direct Domain Spoofing
exposed. One report, two opposite answers.

pct now gates the status: pass only at pct=100, warn while it is partial,
fail at pct=0. A missing rua still does not downgrade a policy that really
is enforcing, which is what the branch was written to protect.

Asserts on the transformed card, the thing a client reads.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from result_transformer import transform_dmarc

DOMAIN = "pct.example.test"


def _raw(record, policy, pct=None, rua="mailto:d@pct.example.test"):
    raw = {
        "domain": DOMAIN,
        "status": "ok",
        "record": record,
        "policy": policy,
        "rua": rua,
        "issues": [],
    }
    if pct is not None:
        raw["pct"] = pct
    return raw


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_pct_zero_is_not_a_pass(policy):
    """Not a pass, and for reject not a fail either.

    "pct=0 applies the policy to no mail at all" was the premise here and it is
    wrong for reject. RFC 7489 section 6.6.4: mail not subject to the reject
    policy is treated "as though the 'quarantine' policy applies", so p=reject
    with pct=0 is full quarantine on RFC 7489 receivers and full reject on RFC
    9989 ones. Every failing message is acted on, which is not a failure.
    Quarantine is the policy that really does degrade to nothing, since the
    same section sends its unselected fraction to local classification.
    """
    record = f"v=DMARC1; p={policy}; pct=0; rua=mailto:d@{DOMAIN}"
    card = transform_dmarc(_raw(record, policy, pct=0))

    assert card["status"] != "pass", (
        f"a green card tells the client pct=0 is full enforcement. Got "
        f"status={card['status']!r} verdict={card['verdict']!r}"
    )
    _expected = "fail" if policy == "quarantine" else "warn"
    assert card["status"] == _expected, (
        f"p={policy} with pct=0: expected {_expected!r}, got "
        f"{card['status']!r} verdict={card['verdict']!r}"
    )
    assert "pct=0" in card["verdict"]
    # The verdict must not claim failures are rejected, and must not claim
    # enforcement is simply off either: RFC 9989 section C.5.2 removed pct, and
    # the same report warns that RFC 9989 receivers ignore it. Naming both
    # receiver populations is the only statement that is true of each.
    assert "9989" in card["verdict"] and "7489" in card["verdict"], (
        f"The verdict has to say enforcement is off rather than claim "
        f"failures are rejected; got {card['verdict']!r}"
    )


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_partial_pct_is_a_warning(policy):
    record = f"v=DMARC1; p={policy}; pct=25; rua=mailto:d@{DOMAIN}"
    card = transform_dmarc(_raw(record, policy, pct=25))

    assert card["status"] == "warn", (
        f"p={policy} at pct=25 enforces on a quarter of failing mail; got "
        f"status={card['status']!r}"
    )
    assert "pct=25" in card["verdict"]


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_full_enforcement_is_still_a_pass(policy):
    """Control: the branch's original intent, an enforcing policy passes."""
    record = f"v=DMARC1; p={policy}; rua=mailto:d@{DOMAIN}"
    card = transform_dmarc(_raw(record, policy))

    assert card["status"] == "pass"
    assert "pct=" not in card["verdict"]


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_missing_rua_is_not_graded_as_a_pct_problem(policy):
    """This file's subject is that pct decides the status. That still holds.

    It used to assert a green card, on the reasoning that the policy itself is
    correct. It is correct, and rua is OPTIONAL in RFC 7489 section 6.3 and
    RFC 9989, so this is not a failure. But the owner cannot see what their own
    enforcing policy is doing, and a green card says there is nothing to look
    at. Doc 17 item 3 settled it at amber. What must not happen, and is what
    this file guards, is the missing rua being described as a coverage problem:
    the verdict still says the policy applies to everything.
    """
    record = f"v=DMARC1; p={policy}"
    raw = _raw(record, policy, rua=None)
    raw["issues"] = [{
        "severity": "warning",
        "issue": "No aggregate reporting (rua) configured",
        "plain_english": "You have no visibility into authentication results.",
    }]
    card = transform_dmarc(raw)

    assert card["status"] == "warn"
    assert card["status"] != "fail", "an optional tag cannot fail a record"
    assert "pct" not in card["verdict"], (
        f"the verdict must not describe this as partial coverage: "
        f"{card['verdict']!r}"
    )


def test_card_and_attack_surface_agree_on_pct_zero(audit):
    """End to end: the two halves of the report gave opposite answers."""
    zone = {
        DOMAIN: {"TXT": ["v=spf1 -all"], "MX": [(10, "mail." + DOMAIN)]},
        "_dmarc." + DOMAIN: {"TXT": [f"v=DMARC1; p=reject; pct=0; rua=mailto:d@{DOMAIN}"]},
        "mail." + DOMAIN: {"A": ["198.51.100.4"]},
    }
    result = audit(zone, DOMAIN, scope="dmarc")
    card = next(c for c in result["checks"] if c.get("name") == "DMARC")

    vectors = {v["name"]: v for v in card["attack_surface"]["vectors"]}
    # "exposed" means the spoofed mail reaches the inbox. Under p=reject with
    # pct=0 that is the one outcome that cannot happen: RFC 7489 receivers
    # quarantine all of it (section 6.6.4) and RFC 9989 receivers reject all of
    # it. Partial is the honest reading, and the card must agree with it.
    assert vectors["Direct Domain Spoofing"]["status"] == "partial"
    assert card["status"] != "pass", (
        f"The attack surface panel calls direct spoofing partial. The card "
        f"above it cannot be green in the same report. Got "
        f"{card['status']!r} / {card['verdict']!r}"
    )
    assert card["status"] == "warn"
