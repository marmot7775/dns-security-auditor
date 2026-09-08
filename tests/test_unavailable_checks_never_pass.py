"""A check that did not run must not report pass.

B2. Two of the thirteen checks structurally cannot complete from where this
audit runs:

  - Spamhaus refuses DNSBL queries from public and cloud resolvers. Querying
    dbl.spamhaus.org from the droplet returns 127.255.255.254, Spamhaus's
    documented "query refused" code, on every request. It is not rate
    limiting that will pass.
  - Certificate Transparency reads crt.sh, which is frequently down. It was
    502ing across two consecutive deploy checks.

Certificate Transparency answered `status: "pass"` with pill "Skipped" for
this, which is the worst available option: a green card for a check that
assessed nothing about the domain. Blocklist answered "warn", which reads as
a finding against the domain rather than a gap in the tool.

Both now answer "unavailable", a status that is neither a pass nor a finding,
and both say plainly that the check did not run. The counts in the PDF and
the executive summary tally pass/warn/fail, so an unavailable check drops out
of all three rather than inflating any of them.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "unavail.test"

BASE = {
    DOMAIN: {
        "MX": [(10, "mail.unavail.test")],
        "TXT": ["v=spf1 mx -all"],
        "A": ["203.0.113.70"],
        "NS": ["ns1.unavail.test"],
    },
    f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@unavail.test"]},
    "mail.unavail.test": {"A": ["203.0.113.71"]},
    "ns1.unavail.test": {"A": ["203.0.113.53"]},
}


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)




def test_ct_without_a_reachable_log_service_is_not_a_pass(audit):
    """No ct_certs supplied, so the crt.sh call fails the way it does in
    production when the service is down."""
    result = audit(FakeZone(dict(BASE)), DOMAIN)
    card = _card(result, "Certificate Transparency")

    assert card["status"] == "unavailable", (
        "a check that never reached its data source cannot be a pass"
    )
    assert card["pill_label"] == "Not checked"
    assert "not assessed" in card["explanation"].lower()




def test_an_unavailable_check_counts_as_neither_pass_warn_nor_fail(audit):
    """The PDF cover and the executive summary tally these three. An
    unavailable check must fall outside all of them rather than pad one."""
    result = audit(FakeZone(dict(BASE)), DOMAIN)
    checks = result["checks"]

    counted = sum(1 for c in checks if c["status"] in ("pass", "warn", "fail"))
    unavailable = [c["name"] for c in checks if c["status"] == "unavailable"]

    # DKIM joined Certificate Transparency under Doc 15, by a different route:
    # its lookups complete and still cannot settle the question, because
    # selectors are not enumerable from DNS. Blocklist left the set entirely
    # under Doc 17 item 7, along with the check itself.
    assert set(unavailable) == {"Certificate Transparency", "DKIM"}
    assert counted == len(checks) - len(unavailable)






