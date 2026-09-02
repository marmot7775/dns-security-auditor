"""Regression test: a send-only subdomain with no DKIM must show DKIM as a
real finding, not "pass / No mail domain".

The defensive-DNS classifier in run_full_audit was already fixed to stop
inferring "non-mail" from absent MX, but result_transformer.transform_dkim
(and transform_mta_sts / transform_tls_rpt / transform_bimi) had their own
gate on has_mx=False that force-passed the card as "No mail domain". So a
send-only subdomain with p=reject, a real SPF include, no MX and no DKIM
still rendered DKIM as N/A.

The transformers now waive a check only on the same positive non-mail
signal the engine uses (RFC 7505 null MX, or an SPF record that is exactly
v=spf1 -all), passed in as non_mail=. Absent MX alone never waives anything.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer as rt

SEND_ONLY = "send.example.test"
PARKED = "parked.example.test"

SEND_ONLY_ZONE = {
    SEND_ONLY: {"TXT": ["v=spf1 include:sendgrid.net -all"]},
    "_dmarc." + SEND_ONLY: {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.test"]},
    "sendgrid.net": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]},
}

PARKED_ZONE = {
    PARKED: {"MX": [(0, "")], "TXT": ["v=spf1 -all"]},
    "_dmarc." + PARKED: {"TXT": ["v=DMARC1; p=reject;"]},
}

NO_DKIM = {"found_selectors": [], "tested_count": 12}


def _card(result, name):
    for check in result["checks"]:
        if check.get("name") == name:
            return check
    return None


def _is_waived(card):
    return card["status"] == "pass" and card.get("pill_label") == "N/A"


# --- unit: the transformers no longer waive on has_mx=False alone ---------

def test_transform_dkim_absent_mx_alone_is_a_real_finding():
    card = rt.transform_dkim(NO_DKIM, SEND_ONLY, has_mx=False)
    assert not _is_waived(card), card
    assert card["status"] != "pass"
    assert card["status"] in ("warn", "fail"), card["status"]
    assert "non-mail" not in card["verdict"].lower()


def test_transform_dkim_waives_only_on_positive_non_mail_signal():
    card = rt.transform_dkim(NO_DKIM, PARKED, has_mx=False, non_mail=True)
    assert _is_waived(card), card
    assert card["fix"] is None


def test_transform_mta_sts_absent_mx_alone_is_not_waived():
    raw = {"status": "warning", "txt_record": None, "policy_mode": None}
    assert not _is_waived(rt.transform_mta_sts(raw, SEND_ONLY, has_mx=False))
    assert _is_waived(rt.transform_mta_sts(raw, PARKED, has_mx=False, non_mail=True))


def test_transform_tls_rpt_absent_mx_alone_is_not_waived():
    raw = {"status": "warning", "record": None}
    assert not _is_waived(rt.transform_tls_rpt(raw, SEND_ONLY, has_mx=False))
    assert _is_waived(rt.transform_tls_rpt(raw, PARKED, has_mx=False, non_mail=True))


def test_transform_bimi_absent_mx_alone_is_not_waived():
    raw = {"status": "info", "record": None, "records_found": 0}
    assert not _is_waived(rt.transform_bimi(raw, SEND_ONLY, has_mx=False))
    assert _is_waived(rt.transform_bimi(raw, PARKED, has_mx=False, non_mail=True))


# --- unit: the shared signal ----------------------------------------------

def test_positive_non_mail_signal_never_fires_on_absent_mx_alone():
    f = audit_engine._positive_non_mail_signal
    assert f({}, {}) is False
    assert f(None, None) is False
    assert f({"records": [], "has_null_mx": False},
             {"record": "v=spf1 include:sendgrid.net -all"}) is False
    assert f({"records": [], "has_null_mx": False}, {"record": None}) is False


def test_positive_non_mail_signal_fires_on_null_mx_or_null_spf():
    f = audit_engine._positive_non_mail_signal
    assert f({"has_null_mx": True}, {}) is True
    assert f({}, {"record": "v=spf1 -all"}) is True
    assert f({}, {"record": "  V=SPF1 -ALL "}) is True
    # -all with any mechanism in front of it is a real sending policy.
    assert f({}, {"record": "v=spf1 ip4:198.51.100.1 -all"}) is False


# --- end to end: the cards a user actually sees -----------------------------

def test_send_only_subdomain_dkim_is_a_real_finding(audit):
    result = audit(SEND_ONLY_ZONE, SEND_ONLY, scope="email_full")
    assert result["defensive_dns"] is False

    dkim = _card(result, "DKIM")
    assert dkim is not None
    assert dkim["status"] != "pass", (
        f"send-only subdomain with no DKIM must not pass DKIM; got "
        f"{dkim['status']!r} / {dkim.get('verdict')!r}"
    )
    assert dkim.get("pill_label") != "N/A"
    assert "non-mail" not in (dkim.get("verdict") or "").lower()

    for name in ("MTA-STS", "TLS-RPT", "BIMI"):
        card = _card(result, name)
        if card is None:
            continue
        assert "non-mail" not in (card.get("verdict") or "").lower(), (name, card.get("verdict"))
        assert card.get("pill_label") != "N/A", (name, card)


def test_parked_domain_dkim_is_still_waived(audit):
    result = audit(PARKED_ZONE, PARKED, scope="email_full")
    assert result["defensive_dns"] is True
    dkim = _card(result, "DKIM")
    assert dkim is not None
    assert dkim["status"] == "pass"
    assert dkim.get("pill_label") == "N/A"
