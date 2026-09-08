"""Regression tests for doc 18 item 6: vendor list accuracy.

Four fingerprinting signals never named an actual vendor: SPF mechanism
count, DMARC policy strength, MTA-STS presence, and BIMI presence each
attached a category label ("Enterprise Email Security", "Enterprise
Brand Protection", "Multiple Email Systems") as if it were a detected
vendor, complete with a confidence score. None of those signals carry
any vendor evidence, so they are dropped rather than mislabeled.

Separately, a vendor authorized in SPF (outbound: can send as this
domain) is not necessarily the vendor named in MX (inbound: receives
this domain's mail). _format_vendors now records which side produced
each detection.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
from advanced_fingerprinting import AdvancedVendorFingerprinter


def _fingerprint(spf_record, mx_hosts, dmarc_record=None, mta_sts_record=None, bimi_record=None):
    fp = AdvancedVendorFingerprinter("victim.example", prefetch={
        "spf_record": spf_record, "mx_hosts": mx_hosts, "dmarc_record": dmarc_record,
        "tls_rpt_record": None, "mta_sts_record": mta_sts_record, "bimi_record": bimi_record,
        "txt_ttl": None,
    })
    return fp.fingerprint_all()


def test_spf_complexity_alone_is_not_a_vendor():
    result = _fingerprint(
        "v=spf1 ip4:1.2.3.4 ip4:1.2.3.5 ip4:1.2.3.6 a mx include:example.net ~all",
        [],
    )
    names = {v["vendor"] for v in result["vendors"]}
    assert "Multiple Email Systems" not in names


def test_enforcing_dmarc_policy_alone_is_not_a_vendor():
    result = _fingerprint(None, [], dmarc_record="v=DMARC1; p=reject")
    names = {v["vendor"] for v in result["vendors"]}
    assert "Enterprise Email Security" not in names


def test_mta_sts_presence_alone_is_not_a_vendor():
    result = _fingerprint(None, [], mta_sts_record="v=STSv1; id=1")
    names = {v["vendor"] for v in result["vendors"]}
    assert "Enterprise Email Security" not in names


def test_bimi_presence_alone_is_not_a_vendor():
    result = _fingerprint(None, [], bimi_record="v=BIMI1; l=https://example.com/logo.svg")
    names = {v["vendor"] for v in result["vendors"]}
    assert "Enterprise Brand Protection" not in names


def test_outbound_only_vendor_is_labeled_outbound_not_inbound():
    """SPF names a vendor authorized to send; MX does not list it. The
    ietf.org case: Google Workspace is in SPF, MX is self-hosted."""
    result = _fingerprint(
        "v=spf1 include:_spf.google.com ~all",
        ["mail.victim.example"],
    )
    formatted = audit_engine._format_vendors(result["vendors"])
    google = next(v for v in formatted if v["name"] == "Google Workspace")
    assert google["detected_via"] == "outbound"


def test_inbound_and_outbound_vendor_is_labeled_both():
    result = _fingerprint(
        "v=spf1 include:_spf.google.com ~all",
        ["aspmx.l.google.com"],
    )
    formatted = audit_engine._format_vendors(result["vendors"])
    google = next(v for v in formatted if v["name"] == "Google Workspace")
    assert "outbound" in google["detected_via"]
    assert "inbound" in google["detected_via"]
