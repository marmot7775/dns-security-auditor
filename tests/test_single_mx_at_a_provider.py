"""A single MX at a hosted provider is not a single point of failure.

The card's own explanation already said so, in as many words: "Major
providers like X handle redundancy internally across their infrastructure,
so a single MX hostname does not indicate a single point of failure." The
status beside it was amber and the fix said to add a secondary MX. The card
argued with itself, and the advice broke the provider's own supported
configuration: Microsoft's setup documentation requires exactly one MX
record.

Three things were tangled together and are separated here:

  - mx_check raised the redundancy warning for any single MX, including
    hosted ones. It now consults _detect_provider, the same matcher the MX
    card's provider column uses.
  - transform_mx kept a second, shorter hardcoded provider list, so a domain
    on Zoho or Fastmail was warned while a domain on Google was not, for no
    reason either card explained.
  - The single-MX finding was stated twice, once by mx_check as an issue and
    once by transform_mx as a hardcoded detail line, in slightly different
    words. The hardcoded copy is gone.

The typo in the old text, "all email queues and may bounce", went with it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

TYPO = "all email queues and may bounce"


def _zone(domain, hosts):
    rec = {
        domain: {"MX": [(10 * (i + 1), h) for i, h in enumerate(hosts)],
                 "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.1"],
                 "NS": [f"ns1.{domain}"]},
        f"_dmarc.{domain}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:r@{domain}"]},
        f"ns1.{domain}": {"A": ["203.0.113.53"]},
    }
    for i, h in enumerate(hosts):
        rec[h] = {"A": [f"203.0.113.{10 + i}"]}
    return FakeZone(rec)


def _mx(audit, domain, hosts):
    result = audit(_zone(domain, hosts), domain, scope="email_full")
    return next(c for c in result["checks"] if c["name"] == "MX Records")


def _lines(card):
    return [d["text"] for d in card["details"]
            if "redundan" in d["text"] or "failover" in d["text"]
            or "queue" in d["text"]]


@pytest.mark.parametrize("host", [
    "d-com.mail.protection.outlook.com",   # Microsoft 365
    "mx.zoho.com",                         # Zoho
    "aspmx.l.google.com",                  # Google Workspace
])
def test_single_mx_at_a_recognised_provider_is_a_pass(audit, host):
    card = _mx(audit, "hosted.test", [host])

    assert card["status"] == "pass", (
        f"{host}: the provider fans out behind one hostname, and its own setup "
        f"docs may require exactly one MX. Got {card['status']!r}"
    )
    assert not card.get("fix"), (
        f"{host}: telling this domain to add a secondary MX contradicts its "
        f"provider's supported configuration: {card.get('fix')!r}"
    )
    assert len(_lines(card)) == 1, (
        f"{host}: the redundancy point must be made once, not twice: "
        f"{_lines(card)}"
    )


def test_single_self_hosted_mx_still_warns(audit):
    """The case the warning was written for is unchanged."""
    card = _mx(audit, "self.test", ["mail.self.test"])

    assert card["status"] == "warn"
    assert card.get("fix"), "a self-hosted domain can and should add a secondary"
    assert len(_lines(card)) == 1, f"stated twice: {_lines(card)}"


def test_multiple_mx_hosts_unchanged(audit):
    card = _mx(audit, "multi.test", ["mail1.multi.test", "mail2.multi.test"])

    assert card["status"] == "pass"
    assert len(_lines(card)) == 1


@pytest.mark.parametrize("domain,hosts", [
    ("hosted.test", ["d-com.mail.protection.outlook.com"]),
    ("self.test", ["mail.self.test"]),
    ("multi.test", ["mail1.multi.test", "mail2.multi.test"]),
])
def test_the_typo_is_gone(audit, domain, hosts):
    card = _mx(audit, domain, hosts)
    body = " ".join(d["text"] for d in card["details"]) + " " + (card.get("fix") or "")
    assert TYPO not in body, f"{domain}: {TYPO!r} still present"
