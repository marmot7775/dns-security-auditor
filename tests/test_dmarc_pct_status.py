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
    record = f"v=DMARC1; p={policy}; pct=0; rua=mailto:d@{DOMAIN}"
    card = transform_dmarc(_raw(record, policy, pct=0))

    assert card["status"] == "fail", (
        f"pct=0 applies p={policy} to no mail at all. A green card tells the "
        f"client they are protected when nothing is enforced. Got "
        f"status={card['status']!r} verdict={card['verdict']!r}"
    )
    assert "pct=0" in card["verdict"]
    assert "switched off" in card["verdict"], (
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
def test_missing_rua_does_not_downgrade_a_fully_enforcing_policy(policy):
    """The comment the branch was written around still holds: the engine may
    flag a warning for an absent rua, but the policy itself is correct."""
    record = f"v=DMARC1; p={policy}"
    raw = _raw(record, policy, rua=None)
    raw["issues"] = [{
        "severity": "warning",
        "issue": "No aggregate reporting (rua) configured",
        "plain_english": "You have no visibility into authentication results.",
    }]
    assert transform_dmarc(raw)["status"] == "pass"


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
    assert vectors["Direct Domain Spoofing"]["status"] == "exposed"
    assert card["status"] != "pass", (
        f"The attack surface panel calls direct spoofing exposed. The card "
        f"above it cannot be green in the same report. Got "
        f"{card['status']!r} / {card['verdict']!r}"
    )
