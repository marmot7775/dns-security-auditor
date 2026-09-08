"""Absent BIMI is information. Published-but-unusable BIMI is a finding.

A warning means the domain owner can and probably should do something. BIMI
is optional brand display, not a security control, so a domain that has not
adopted it has done nothing wrong. It was amber on the card, a low item on
the roadmap, and the anomalies panel rated BIMI-without-enforcement as high
severity, which put three separate nags in front of an operator for declining
an optional feature.

The line drawn here: nothing published is information. Something published
that cannot work, for example a record under p=none where no client will show
the logo, is amber, because there the owner did something and it does not do
what they intended.

The card's wording is unchanged from 08e6ac3, which taught it to say "No BIMI
record at the default selector" and to explain that a custom selector is not
discoverable from DNS. Only the grade moves here.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "bimi.test"
LOGO = "v=BIMI1; l=https://bimi.test/logo.svg;"


def _zone(bimi_record, policy):
    rec = {
        DOMAIN: {"MX": [(10, f"m.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.1"], "NS": [f"ns1.{DOMAIN}"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p={policy}; rua=mailto:r@{DOMAIN}"]},
        f"m.{DOMAIN}": {"A": ["203.0.113.2"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
    }
    if bimi_record:
        rec[f"default._bimi.{DOMAIN}"] = {"TXT": [bimi_record]}
    return FakeZone(rec)


def _run(audit, bimi_record, policy="reject"):
    return audit(_zone(bimi_record, policy), DOMAIN, scope="email_full")


def _card(result):
    return next(c for c in result["checks"] if c["name"] == "BIMI")


def test_absent_bimi_is_not_a_warning(audit):
    result = _run(audit, None)
    card = _card(result)

    assert card["status"] == "pass", (
        f"declining an optional branding feature is not a finding; got "
        f"{card['status']!r}"
    )
    assert card["pill_label"] == "Not configured"


def test_absent_bimi_gets_no_roadmap_item(audit):
    result = _run(audit, None)
    bimi_items = [i for i in result["security_roadmap"]["items"]
                  if i["protocol"] == "BIMI"]
    assert not bimi_items, (
        f"'you have not adopted an optional feature' competed for roadmap "
        f"space with findings the domain can act on: {bimi_items}"
    )


def test_absent_bimi_raises_no_anomaly(audit):
    result = _run(audit, None)
    bimi = [a for a in (result.get("anomalies") or []) if "BIMI" in a.get("title", "")]
    assert not bimi


def test_the_card_wording_from_08e6ac3_survives(audit):
    """The grade moved; the sentence that says what was actually queried did not."""
    card = _card(_run(audit, None))

    assert card["verdict"] == "No BIMI record at the default selector"
    body = " ".join(d["text"] for d in card["details"]).lower()
    assert "custom selector" in body and "cannot be discovered" in body


def test_a_published_record_that_cannot_work_is_still_amber(audit):
    """p=none means no client displays the logo. The owner acted, and it does
    not do what they intended, so this one is a finding."""
    result = _run(audit, LOGO, policy="none")
    card = _card(result)

    assert card["status"] == "warn"
    anomalies = [a for a in (result.get("anomalies") or [])
                 if "BIMI" in a.get("title", "")]
    assert anomalies, "a published record that cannot display is worth surfacing"
    assert anomalies[0]["severity"] == "medium", (
        f"the cost is a logo not displaying; no security property is weakened. "
        f"Got {anomalies[0]['severity']!r}"
    )


def test_a_working_record_passes(audit):
    card = _card(_run(audit, LOGO, policy="reject"))
    assert card["status"] == "pass"
