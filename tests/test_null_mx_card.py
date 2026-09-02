"""Regression test: a send-only or parked domain gets one coherent MX card.

transform_mx detected null MX by string-matching the rendered record against
("0 .", "0  ."), but mx_check builds each record as f"{priority} {host}"
with the hostname already stripped of its trailing dot, so a null MX renders
as "0 " and the branch was unreachable. The card a parked domain got was a
"Single MX host" warning about lost inbound mail sitting directly above an
info line saying the domain does not accept email, with the record shown as
the meaningless string "0 ".

The card now keys off has_null_mx, the boolean mx_check already computes,
and renders the record as valid zone-file syntax.

Asserts on the MX card from a real audit, so the producer and the consumer
have to agree.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DOMAIN = "sendonly.example.test"

ZONE = {
    # RFC 7505 null MX: a single record, priority 0, root as the exchange.
    DOMAIN: {"MX": [(0, "")], "TXT": ["v=spf1 include:sendgrid.net -all"]},
    "_dmarc." + DOMAIN: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
    "sendgrid.net": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]},
}


def _mx_card(result):
    for check in result["checks"]:
        if check.get("name") == "MX Records":
            return check
    return None


def _card_text(card):
    parts = [card.get("verdict") or "", card.get("explanation") or ""]
    parts += [d.get("text", "") for d in card.get("details", [])]
    return " ".join(parts)


def test_null_mx_domain_gets_the_null_mx_card(audit):
    card = _mx_card(audit(ZONE, DOMAIN, scope="email_full"))

    assert card is not None
    assert card["pill_label"] == "Null MX", (
        f"A null MX record has its own card; got pill "
        f"{card.get('pill_label')!r} verdict {card.get('verdict')!r}"
    )
    assert card["status"] == "pass"
    assert "does not accept email" in card["verdict"]


def test_null_mx_record_renders_as_valid_zone_file_syntax(audit):
    card = _mx_card(audit(ZONE, DOMAIN, scope="email_full"))

    assert card["record"] == "0 .", (
        f"The hostname is stripped of its trailing dot upstream, so the "
        f"record must be reassembled for display; got {card['record']!r}"
    )


def test_null_mx_card_carries_no_failover_warning(audit):
    """The two halves of the old card contradicted each other."""
    text = _card_text(_mx_card(audit(ZONE, DOMAIN, scope="email_full")))

    assert "failover" not in text.lower(), (
        f"A domain that declares it accepts no mail cannot also be warned "
        f"about losing inbound mail; got: {text!r}"
    )
    assert "Single MX host" not in text, (
        f"Null MX is not a single mail host; got: {text!r}"
    )


def test_a_real_single_mx_domain_still_gets_its_failover_warning(audit):
    """Control: reading the boolean must not suppress the genuine warning."""
    domain = "onemx.example.test"
    zone = {
        domain: {"MX": [(10, "mail." + domain)], "TXT": ["v=spf1 -all"]},
        "mail." + domain: {"A": ["198.51.100.4"]},
        "_dmarc." + domain: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{domain}"]},
    }
    card = _mx_card(audit(zone, domain, scope="email_full"))

    assert card["pill_label"] != "Null MX"
    assert "Single MX host" in _card_text(card)
