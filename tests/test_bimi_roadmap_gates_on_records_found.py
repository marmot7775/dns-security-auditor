"""Regression test for "Consider adding BIMI" being shown to domains
that already have BIMI, a logo, and a VMC.

Bug: build_security_roadmap keyed the BIMI recommendation off
bimi.get("status") != "pass" with no check for whether a record
actually exists. Every warn produced by bugs 6, 15, 17 and 18 (DMARC
prerequisite issues, weak/invalid keys, etc.) hit this same branch, so
a domain that already published BIMI with a logo and a VMC got told to
"consider adding BIMI for brand visibility" while its real, actionable
issue (e.g. a too-small logo) never reached the roadmap.

Fix: gate on records_found == 0, and surface the actual issue
(the card's own fix text) when a record exists but isn't clean.

Depends on bugs 15, 21 and 22 being fixed first, since this test's
"logo too small" scenario must be the *only* issue on an otherwise
compliant record for the assertion on which fix text surfaces to be
unambiguous.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import checks_extra
import result_transformer

VMC_URL = "https://example.com/vmc.pem"
LOGO_URL = "https://example.com/logo.svg"
BIMI_RECORD = f"v=BIMI1; l={LOGO_URL}; a={VMC_URL}"

# baseProfile=tiny-ps and a viewBox are both present and correct, so the
# only issue this SVG should raise is the sub-96px dimension warning.
SMALL_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" '
    b'width="64" height="64" viewBox="0 0 64 64"></svg>'
)


class _FakeSvgResponse:
    def __init__(self, svg_bytes, content_type="image/svg+xml"):
        self.status_code = 200
        self.headers = {"Content-Type": content_type}
        self._svg_bytes = svg_bytes

    def iter_content(self, chunk_size=8192):
        yield self._svg_bytes

    def close(self):
        pass


def _build_bimi_card(svg_bytes):
    with patch.object(checks_extra, "_lookup_txt", return_value=[BIMI_RECORD]), \
         patch.object(checks_extra, "REQUESTS_AVAILABLE", True), \
         patch.object(checks_extra, "_safe_fetch", return_value=_FakeSvgResponse(svg_bytes)):
        raw = checks_extra.check_bimi(
            "example.com",
            dmarc_enforcing_override=True,
            dmarc_found_override=True,
            dmarc_pct_override=100,
        )
    return result_transformer.transform_bimi(raw, "example.com", has_mx=True)


def test_small_logo_roadmap_item_is_about_resizing_not_adding_bimi():
    card = _build_bimi_card(SMALL_SVG)

    assert card["records_found"] == 1
    assert card["status"] != "pass", "A sub-96px logo must not pass the card clean"

    roadmap = result_transformer.build_security_roadmap([card])
    bimi_items = [i for i in roadmap["items"] if i["protocol"] == "BIMI"]

    assert len(bimi_items) == 1, f"Expected exactly one BIMI roadmap item, got: {bimi_items!r}"
    action = bimi_items[0]["action"].lower()
    assert "adding bimi" not in action, (
        f"A domain with an existing BIMI record, logo and VMC must not be told "
        f"to add BIMI; got action: {bimi_items[0]['action']!r}"
    )
    assert "resize" in action and "96" in action, (
        f"The roadmap item must surface the actual issue (resize to >=96px); "
        f"got action: {bimi_items[0]['action']!r}"
    )


def test_no_bimi_record_still_recommends_adding_it():
    """Control: the normal 'consider adding BIMI' path must still fire
    when no record is published at all."""
    with patch.object(checks_extra, "_lookup_txt", return_value=[]):
        raw = checks_extra.check_bimi("example.com", dmarc_enforcing_override=True,
                                       dmarc_found_override=True)
    card = result_transformer.transform_bimi(raw, "example.com", has_mx=True)
    assert card["records_found"] == 0

    roadmap = result_transformer.build_security_roadmap([card])
    bimi_items = [i for i in roadmap["items"] if i["protocol"] == "BIMI"]
    assert len(bimi_items) == 1
    assert "adding bimi" in bimi_items[0]["action"].lower()


def test_clean_bimi_record_produces_no_roadmap_item():
    """Control: a fully compliant record must not appear on the roadmap."""
    compliant_svg = (
        b'<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" '
        b'width="128" height="128" viewBox="0 0 128 128"></svg>'
    )
    card = _build_bimi_card(compliant_svg)
    assert card["records_found"] == 1
    assert card["status"] == "pass"

    roadmap = result_transformer.build_security_roadmap([card])
    bimi_items = [i for i in roadmap["items"] if i["protocol"] == "BIMI"]
    assert bimi_items == []
