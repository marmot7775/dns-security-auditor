"""Regression tests for doc 18 item 5: small copy errors.

- "requests that mail receivers to send/reject" carried an extra "to".
- BIMI's "DMARC not at enforcement" issue guessed the policy was 'none'
  when the audit had actually read the record and knew the real value.
- The VMC fix text named specific CAs (DigiCert, Entrust); everywhere
  else in the report says "VMC or CMC" with no vendor endorsement.
- The DANE roadmap item's impact text described what DANE does, not the
  risk of not having it, so it read oddly in the "biggest risk" slot.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import checks_extra
import result_transformer

BIMI_RECORD = "v=BIMI1; l=https://example.com/logo.svg"


def test_quarantine_explanation_has_no_doubled_to():
    card = result_transformer.transform_dmarc({
        "domain": "example.com",
        "record": "v=DMARC1; p=quarantine; rua=mailto:a@example.com",
        "policy": "quarantine", "rua": "mailto:a@example.com", "issues": [],
    })
    assert "receivers to send" not in card["explanation"]
    assert "receivers send" in card["explanation"]


def test_reject_explanation_has_no_doubled_to():
    card = result_transformer.transform_dmarc({
        "domain": "example.com",
        "record": "v=DMARC1; p=reject; rua=mailto:a@example.com",
        "policy": "reject", "rua": "mailto:a@example.com", "issues": [],
    })
    assert "receivers to reject" not in card["explanation"]
    assert "receivers reject" in card["explanation"]


def test_bimi_states_the_actual_policy_read_not_a_guess():
    dmarc_record = "v=DMARC1; p=none; rua=mailto:r@example.com"

    def _fake_lookup(name, raise_on_failure=False):
        if name == "default._bimi.example.com":
            return [BIMI_RECORD]
        if name == "_dmarc.example.com":
            return [dmarc_record]
        return []

    with patch.object(checks_extra, "_lookup_txt", side_effect=_fake_lookup), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", False):
        raw = checks_extra.check_bimi("example.com")

    card = result_transformer.transform_bimi(raw, "example.com", has_mx=True)
    texts = " ".join(d.get("text", "") for d in card["details"])
    assert "likely" not in texts.lower()
    assert "'none'" in texts.lower()


def test_missing_vmc_fix_names_no_specific_vendor():
    tags, issues = checks_extra._validate_bimi_record(
        "v=BIMI1; l=https://example.com/logo.svg"
    )
    fix_texts = " ".join(i.get("fix") or "" for i in issues)
    assert "DigiCert" not in fix_texts
    assert "Entrust" not in fix_texts
    assert "VMC or CMC" in fix_texts


def test_dane_roadmap_impact_states_a_risk_not_a_feature():
    checks = [
        {"name": "DANE", "status": "warn", "pill_label": "Not configured"},
    ]
    roadmap = result_transformer.build_security_roadmap(checks)
    dane_items = [i for i in roadmap["items"] if i["protocol"] == "DANE"]
    assert len(dane_items) == 1
    impact = dane_items[0]["impact"].lower()
    assert "provides" not in impact
    assert "relies solely on the ca system" in impact
