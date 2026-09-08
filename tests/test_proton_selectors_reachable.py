"""A selector in the master list is not the same as a selector we ever probe.

Doc 17 reported that the 193-selector probe "missed all three" Proton
selectors, implying they were absent from the list. protonmail was already
in COMPREHENSIVE_DKIM_SELECTORS, at index 46 of 1128. smart_dkim_check caps
the prioritised slice at max_selectors=40 and then unions GENERIC_SELECTORS
in on top of that cap, so index 46 was never reached and the entry did
nothing. Adding the other two to the same list would have been a no-op for
the same reason, and would have passed a membership test.

So these assert reachability, not membership, by both routes independently:

  - GENERIC_SELECTORS, which bypasses the cap, so a Proton domain is probed
    even when its SPF says nothing recognisable
  - the SPF_VENDOR_MAP entry for _spf.protonmail.ch, which pulls them to the
    front of the prioritised slice when the include is present

Sourcing: verified live on proton.me on 2026-09-08. All three names exist as
CNAMEs into domains.proton.ch. protonmail and protonmail3 resolve through to
live 2048-bit RSA keys; protonmail2's CNAME target currently returns NoAnswer,
which is Proton's own provisioning and not a probe failure. All three are
probed regardless, since which of them is live is the domain's business and
can change.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from comprehensive_selectors import COMPREHENSIVE_DKIM_SELECTORS, GENERIC_SELECTORS
from spf_intelligence import detect_vendors_from_spf, get_prioritized_selectors

PROTON_SPF = "v=spf1 include:_spf.protonmail.ch ~all"
PROTON_SELECTORS = ("protonmail", "protonmail2", "protonmail3")
CAP = 40  # smart_dkim_check's max_selectors default


def _reachable(spf):
    """Exactly what smart_dkim_check probes: the capped slice plus generics."""
    return set(get_prioritized_selectors(spf, COMPREHENSIVE_DKIM_SELECTORS)[:CAP]) \
        | set(GENERIC_SELECTORS)


def test_proton_selectors_are_probed_with_the_include_present():
    reachable = _reachable(PROTON_SPF)
    missing = [s for s in PROTON_SELECTORS if s not in reachable]
    assert not missing, f"not probed even with Proton's own SPF include: {missing}"


def test_proton_selectors_are_probed_with_no_recognised_spf():
    """A domain can use Proton without that include appearing in its SPF."""
    reachable = _reachable("v=spf1 -all")
    missing = [s for s in PROTON_SELECTORS if s not in reachable]
    assert not missing, f"not probed without a vendor hint: {missing}"


def test_the_include_maps_to_a_vendor():
    vendors = detect_vendors_from_spf(PROTON_SPF)
    assert vendors, "the include mapped to no vendor, so nothing prioritised"
    assert any("proton" in v["vendor"].lower() for v in vendors)
    selectors = {s for v in vendors for s in v["dkim_selectors"]}
    assert set(PROTON_SELECTORS) <= selectors


def test_membership_alone_would_not_have_caught_this():
    """The test that would have passed while the bug was live.

    Guards the reasoning, not the data: if someone later 'simplifies' the
    tests above to membership checks, this documents why that is not enough.
    """
    assert "protonmail" in COMPREHENSIVE_DKIM_SELECTORS
    assert COMPREHENSIVE_DKIM_SELECTORS.index("protonmail") > CAP, (
        "protonmail sits past the cap; membership in the master list is not "
        "evidence that it is ever probed"
    )
