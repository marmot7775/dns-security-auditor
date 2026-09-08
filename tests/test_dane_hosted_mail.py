"""DANE advice has to be advice the domain owner can act on.

RFC 7672 section 3 puts the TLSA record at the MX host. When the MX belongs
to a mail provider, that record is the provider's to publish, and "generate a
TLSA record containing the SHA-256 hash of your mail server's certificate" is
an instruction for a name the owner does not control.

Two providers, two different answers, both sourced:

  Google Workspace. Verified against live DNS on 2026-09-08: no TLSA at
  smtp.google.com, aspmx.l.google.com or alt1.aspmx.l.google.com, and no DS
  record at google.com. Google neither publishes TLSA for those hosts nor
  signs the zone. Nothing the owner can do changes it, so the card is
  informational and carries no fix.

  Microsoft 365. Inbound SMTP DANE exists, but not by publishing TLSA. Per
  Microsoft's "How SMTP DNS-based Authentication of Named Entities (DANE)
  works", section "Inbound SMTP DANE with DNSSEC", Enable-DnssecForVerifiedDomain
  returns a new MX target under mx.microsoft and Microsoft publishes the TLSA
  for that host. A domain still on the legacy mail.protection.outlook.com MX
  has somewhere to go, so it stays amber with that path as the fix.

Self-hosted MX keeps the existing guidance, which is correct for it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone


def _zone(domain, mx_host):
    return FakeZone({
        domain: {"MX": [(10, mx_host)], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.1"], "NS": [f"ns1.{domain}"]},
        f"_dmarc.{domain}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:r@{domain}"]},
        mx_host: {"A": ["203.0.113.2"]},
        f"ns1.{domain}": {"A": ["203.0.113.53"]},
    })


def _dane(audit, domain, mx_host):
    result = audit(_zone(domain, mx_host), domain, scope="complete")
    return next(c for c in result["checks"] if c["name"] == "DANE")


@pytest.mark.parametrize("mx_host", [
    "aspmx.l.google.com", "alt1.aspmx.l.google.com", "smtp.google.com",
])
def test_google_workspace_dane_is_informational_with_no_fix(audit, mx_host):
    card = _dane(audit, "g.test", mx_host)

    assert card["status"] == "pass"
    assert card["pill_label"] == "N/A"
    assert not card.get("fix"), (
        f"a Workspace-hosted domain cannot publish TLSA for Google's hosts, so "
        f"the card must not hand it a fix: {card.get('fix')!r}"
    )
    body = (card["verdict"] + " " + card["explanation"]).lower()
    assert "not available" in body
    assert "mta-sts" in body, "the protection that does apply has to be named"
    details = " ".join(d["text"] for d in card["details"]).lower()
    assert "google" in details, "the card has to name who controls the MX host"


def test_microsoft_legacy_mx_gets_the_exchange_online_path(audit):
    card = _dane(audit, "m.test", "m-test.mail.protection.outlook.com")

    assert card["status"] == "warn", (
        "Microsoft supports inbound DANE, so this domain has somewhere to go"
    )
    assert card["pill_label"] == "Available, not enabled"

    fix = card["fix"]
    # Only what Microsoft's page says.
    assert "Enable-DnssecForVerifiedDomain" in fix
    assert "Enable-SmtpDaneInbound" in fix
    assert "mx.microsoft" in fix
    assert "priority 20" in fix and "priority 0" in fix, (
        "the two-stage priority change is part of the documented procedure"
    )
    assert "learn.microsoft.com" in fix, "the page has to be linked"

    body = " ".join(d["text"] for d in card["details"]).lower()
    assert "mta-sts" in body and "testing" in body, (
        "the page warns that an MTA-STS domain must go to testing mode first"
    )
    # The one thing it must never say to a Microsoft-hosted domain.
    assert "generate a tlsa" not in fix.lower()


def test_a_migrated_microsoft_domain_is_not_special_cased(audit):
    """Once the MX is on mx.microsoft the legacy branch must not fire."""
    card = _dane(audit, "n.test", "n-test.o-v1.mx.microsoft")
    assert card["pill_label"] != "Available, not enabled"


def test_self_hosted_mx_keeps_the_existing_guidance(audit):
    card = _dane(audit, "s.test", "mail.s.test")

    assert card["status"] == "warn"
    assert card["pill_label"] == "Not configured"
    assert "TLSA" in card["fix"], (
        "a self-hosted domain controls its own MX host and can publish TLSA"
    )
