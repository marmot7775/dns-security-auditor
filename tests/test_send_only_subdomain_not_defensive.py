"""Regression test: an ordinary send-only subdomain is not a "defensive DNS"
domain, and null MX is detected as a boolean rather than by string-matching.

Bug 1: run_full_audit counted "no MX records" as a non-mail signal, so any
send-only subdomain with p=reject (no MX, a real SPF include, DMARC reject)
collected two signals and was declared a parked/defensive domain. That
force-set DKIM, MTA-STS, BIMI and DANE to "pass -- Not applicable (non-mail
domain)" and skipped the DMARC alignment cross-check, so a domain enforcing
p=reject with no DKIM at all reported clean.

Bug 2: the null MX test was `any("0 ." in r for r in records)`, but
mx_check.check_mx builds each record as f"{priority} {host}" after
str(rdata.exchange).rstrip("."), so a null MX renders as "0 " and the test
could never fire. check_mx now exposes has_null_mx.

Asserts on the cards users see, not on the raw check dicts.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mx_check
from conftest import FakeZone

SEND_ONLY = "send.example.test"
PARKED = "parked.example.test"


def _card(result, name):
    for check in result["checks"]:
        if check.get("name") == name:
            return check
    return None


SEND_ONLY_ZONE = {
    # A perfectly ordinary send-only subdomain: no MX (it receives nothing),
    # a real SPF include, and p=reject. No DKIM key anywhere.
    SEND_ONLY: {"TXT": ["v=spf1 include:sendgrid.net -all"]},
    "_dmarc." + SEND_ONLY: {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.test"]},
    "sendgrid.net": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]},
}

PARKED_ZONE = {
    # A genuinely parked domain: RFC 7505 null MX plus a null SPF record.
    PARKED: {"MX": [(0, "")], "TXT": ["v=spf1 -all"]},
    "_dmarc." + PARKED: {"TXT": ["v=DMARC1; p=reject;"]},
}


def test_send_only_subdomain_is_not_treated_as_non_mail(audit):
    result = audit(SEND_ONLY_ZONE, SEND_ONLY, scope="email_full")

    assert result["defensive_dns"] is False, (
        "A send-only subdomain (no MX, a live SPF include, p=reject) sends "
        "real mail. Absent MX is not a declaration that it does not."
    )

    dkim = _card(result, "DKIM")
    assert dkim is not None
    assert "non-mail" not in (dkim.get("verdict") or "").lower(), (
        f"The defensive-DNS override must not fire here; got "
        f"{dkim.get('verdict')!r}"
    )

    # The alignment cross-check was skipped entirely for "defensive" domains,
    # so p=reject with SPF only and no DKIM went unmentioned.
    dmarc = _card(result, "DMARC")
    assert dmarc is not None
    detail_texts = " ".join(d.get("text", "") for d in dmarc.get("details", []))
    assert "relies solely on SPF" in detail_texts, (
        f"The DMARC alignment cross-check must run for a sending domain; "
        f"got details: {detail_texts!r}"
    )


def test_null_mx_plus_null_spf_is_still_treated_as_non_mail(audit):
    """The positive signal still has to work: a real parked domain must keep
    its email-specific cards waived."""
    result = audit(PARKED_ZONE, PARKED, scope="email_full")

    assert result["defensive_dns"] is True, (
        "RFC 7505 null MX plus v=spf1 -all plus p=reject is a domain "
        "declaring it does not send or receive mail."
    )
    dkim = _card(result, "DKIM")
    assert dkim is not None and dkim["status"] == "pass"
    assert "non-mail" in (dkim.get("verdict") or "").lower()


def test_check_mx_reports_null_mx_as_a_boolean():
    """The display list renders a null MX as "0 " (the trailing dot is
    stripped from the exchange), so the old `"0 ." in record` test could
    never be true."""
    from conftest import fake_dns

    with fake_dns(FakeZone(PARKED_ZONE)):
        result = mx_check.check_mx(PARKED)

    assert result["has_null_mx"] is True, (
        f"check_mx must report null MX as a boolean; got records="
        f"{result['records']!r}"
    )
    assert not any("0 ." in record for record in result["records"]), (
        "Guards against a regression back to string-matching: the rendered "
        "record is '0 ', not '0 .'."
    )
