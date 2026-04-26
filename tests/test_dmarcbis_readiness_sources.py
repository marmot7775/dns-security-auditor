"""Tests for the dmarcbis readiness recommendation source classification.

The audit must distinguish:
  - spec_required: explicitly mandated in dmarcbis-41 (e.g. pct removal,
    §C.5.2 / §A.6).
  - editorial: our own guidance not mandated by spec (e.g. np value
    relative to p, since dmarcbis-41 §4.7 is silent on this).

This file pins those classifications so silent regressions to "spec
says you must" framing can't slip back in.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine


def _run(record, **overrides):
    """Build a minimal dmarc_result dict and run the readiness assessor."""
    parsed = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            parsed[k.strip().lower()] = v.strip()

    result = {
        "record": record,
        "policy": parsed.get("p", ""),
        "np": parsed.get("np"),
        "t": parsed.get("t"),
        "psd": parsed.get("psd"),
    }
    result.update(overrides)
    return audit_engine._assess_dmarcbis_readiness(result)


def test_pct_tag_recommendation_is_spec_required_with_citation():
    """dmarcbis-41 §C.5.2 (Tags Removed) and §A.6 explicitly remove pct.
    The audit must mark this as spec_required and provide the section
    reference so the user can verify."""
    out = _run("v=DMARC1; p=reject; pct=50")

    pct_recs = [d for d in out["deprecated_tags"] if d["tag"] == "pct"]
    assert pct_recs, f"pct should be flagged: {out['deprecated_tags']}"
    pct = pct_recs[0]
    assert pct["source"] == "spec_required", (
        f"pct removal IS in dmarcbis-41 §C.5.2 -> spec_required, got {pct['source']}"
    )
    assert pct["spec_reference"] is not None
    assert "C.5.2" in pct["spec_reference"] or "A.6" in pct["spec_reference"]


def test_np_recommendation_for_p_reject_is_editorial():
    """dmarcbis-41 §4.7 defines np but does NOT prescribe a value
    relative to p. Recommending np=reject for a p=reject record is
    best-practice advice, not a spec requirement -> editorial."""
    out = _run("v=DMARC1; p=reject")

    np = out["new_tags"]["np"]
    assert np["present"] is False
    assert np["source"] == "editorial", (
        f"dmarcbis-41 §4.7 is silent on np vs p -> editorial, got {np['source']}"
    )
    assert np["spec_reference"] is None
    assert np["recommendation"] is not None
    # The recommendation copy should make the "not spec-required" framing
    # explicit so a reader skimming the field sees the disclaimer.
    assert "not spec-required" in np["recommendation"].lower() or \
           "editorial" in np["recommendation"].lower()


def test_np_recommendation_for_p_none_is_editorial():
    """Same rule applies for p=none. The current convention to suggest
    np=quarantine is editorial, not spec text."""
    out = _run("v=DMARC1; p=none; rua=mailto:a@b.com")

    np = out["new_tags"]["np"]
    assert np["source"] == "editorial"
    assert np["spec_reference"] is None


def test_rf_and_ri_recommendations_are_editorial():
    """dmarcbis-41 §C.5.2 only lists pct as removed. rf and ri are
    absent from the §4.7 tag registry but not explicitly removed,
    so any "remove this" recommendation is editorial."""
    out = _run("v=DMARC1; p=reject; rf=afrf; ri=86400")

    by_tag = {d["tag"]: d for d in out["deprecated_tags"]}
    assert by_tag["rf"]["source"] == "editorial", (
        f"dmarcbis-41 §C.5.2 does not remove rf -> editorial, got {by_tag['rf']['source']}"
    )
    assert by_tag["ri"]["source"] == "editorial"
    assert by_tag["rf"]["spec_reference"] is None
    assert by_tag["ri"]["spec_reference"] is None


def test_recommendations_list_flattens_with_source_field():
    """The flat recommendations list should include each finding tagged
    with source/spec_reference so the frontend doesn't have to walk the
    nested structures."""
    out = _run("v=DMARC1; p=reject; pct=100")

    recs = out["recommendations"]
    assert recs, "expected non-empty recommendations list"
    # Every recommendation must carry a source classification.
    for r in recs:
        assert r["source"] in ("spec_required", "spec_recommended", "editorial"), r
        assert "tag" in r and "recommendation" in r

    pct_rec = next((r for r in recs if r["tag"] == "pct"), None)
    np_rec = next((r for r in recs if r["tag"] == "np"), None)
    assert pct_rec and pct_rec["source"] == "spec_required"
    assert np_rec and np_rec["source"] == "editorial"


def test_summary_separates_spec_required_from_editorial():
    """The human-readable summary must label each block, so a reader
    sees at a glance which advice is mandated vs suggested."""
    out = _run("v=DMARC1; p=reject; pct=100")

    summary = out["summary"].lower()
    # pct triggers a spec-required block
    assert "spec-required" in summary
    # missing np triggers an editorial block
    assert "editorial" in summary


def test_signed_record_with_explicit_np_has_no_editorial_np_finding():
    """If np is already present, no recommendation is generated for it."""
    out = _run("v=DMARC1; p=reject; np=reject")

    np = out["new_tags"]["np"]
    assert np["present"] is True
    assert np["recommendation"] is None
    # np should not appear in the flat recommendations list
    np_recs = [r for r in out["recommendations"] if r["tag"] == "np"]
    assert np_recs == [], f"np already set -> no recommendation, got {np_recs}"
