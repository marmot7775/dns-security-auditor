"""
Version tag parsing, one table per record type, each read against its own spec.

Five TXT record types are located by a leading version tag, and their five
specs define that tag differently on purpose. Two properties vary.

  Case.  RFC 7405 section 2 defines the %s prefix as case sensitive and states
         that a literal with no prefix "is case insensitive and is equivalent
         to having the %i prefix". A version value is case sensitive if and
         only if its own spec writes %s.

  Whitespace.  Some specs put *WSP on both sides of the equals sign. Some
         write the whole tag as a single literal, leaving no room for it.

  DMARC    RFC 9989 S5.4    equals         = *WSP "=" *WSP
                            dmarc-version  = "v" equals %s"DMARC1"
                            case sensitive, whitespace allowed
  BIMI     BIMI draft S4.2  bimi-version   = "v" *WSP "=" *WSP "BIMI1"
                            no %s, so case insensitive; whitespace allowed
  SPF      RFC 7208 S12     version        = "v=spf1"
                            no %s, so case insensitive; no whitespace
  MTA-STS  RFC 8461 S3.1    sts-version    = %s"v=STSv1"
                            case sensitive, no whitespace
  TLS-RPT  RFC 8460 S3      tlsrpt-version = %s"v=TLSRPTv1"
                            case sensitive, no whitespace

The asymmetry between those rows is the specification, not an oversight, and
the tables below encode it one record type at a time. Nothing here should be
"made consistent": collapsing them to one rule reintroduces either the false
negative these tests pin for DMARC and BIMI, where a published record is
reported as absent, or the false pass they pin for MTA-STS and TLS-RPT, where
a record every conforming receiver discards earns a green card.

Assertions land on the user-visible verdict wherever there is one. The DMARC
bug reproduced as policy=None in the raw dict and as "No DMARC policy
published" on the card, and it is the card that reaches a person.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns

import audit_engine
from checks_extra import check_bimi, check_mta_sts, check_tls_rpt

DOMAIN = "version.example.test"

# The four shapes every table covers.
#
# "leading" is accepted everywhere: DNS does not trim TXT strings for you and
# every parser here already stripped.
#
# "case_flipped" swaps the case of the version VALUE and leaves the tag name
# alone. Uppercasing outright would test nothing for DMARC and BIMI, whose
# canonical values are already uppercase. The tag name stays lowercase because
# it is a separate question: all five ABNFs write it as a bare "v" with no %s
# prefix, so its case is not what any of these rows is about.
SHAPES = ("canonical", "spaced", "case_flipped", "leading")


def tag(version, shape):
    return {
        "canonical": f"v={version}",
        "spaced": f"v = {version}",
        "case_flipped": f"v={version.swapcase()}",
        "leading": f"  v={version}",
    }[shape]


def card(result, name):
    for check in result["checks"]:
        if check.get("name") == name:
            return check
    raise AssertionError(f"no {name} card in {[c.get('name') for c in result['checks']]}")


def issue_text(result):
    return " ".join(
        i.get("issue", "") + " " + i.get("plain_english", "")
        for i in result.get("issues", [])
    )


# ------------------------------------------------------------------
# DMARC. RFC 9989 S5.4: %s"DMARC1", and equals = *WSP "=" *WSP.
# ------------------------------------------------------------------

# The whitespace half is the bug this file exists for. "v = DMARC1" is a valid
# DMARC record and was discarded, so a domain at p=reject was told it publishes
# no DMARC record at all: a critical finding, about the one protocol this tool
# is named for, that was false.
DMARC_EXPECTED = {
    "canonical": True,
    "spaced": True,       # equals = *WSP "=" *WSP, in RFC 9989 and in RFC 7489
    "case_flipped": False,  # %s"DMARC1" is case sensitive
    "leading": True,
}


def _dmarc_zone(record):
    return {
        DOMAIN: {"TXT": ["v=spf1 -all"]},
        "_dmarc." + DOMAIN: {"TXT": [record]},
    }


@pytest.mark.parametrize("shape", SHAPES)
def test_dmarc_version_tag_table(audit, shape):
    record = f"{tag('DMARC1', shape)}; p=reject; rua=mailto:d@{DOMAIN}"
    dmarc = card(audit(_dmarc_zone(record), DOMAIN, scope="dmarc"), "DMARC")

    if DMARC_EXPECTED[shape]:
        assert "p=reject" in dmarc["verdict"], (
            f"{record!r} is a valid DMARC record per RFC 9989 S5.4; "
            f"card says {dmarc['verdict']!r}"
        )
        assert dmarc["verdict"] != "No DMARC policy published"
    else:
        assert "p=reject" not in dmarc["verdict"], (
            f"{record!r} is not a DMARC record: RFC 9989 S5.4 writes the "
            f"version value as %s\"DMARC1\", which RFC 7405 S2 makes case "
            f"sensitive. Card says {dmarc['verdict']!r}"
        )


def test_dmarc_spaced_equals_is_not_reported_as_a_missing_policy(audit):
    """The false negative in full, asserted on the string a person reads."""
    record = f"v = DMARC1; p = reject; rua=mailto:d@{DOMAIN}"
    dmarc = card(audit(_dmarc_zone(record), DOMAIN, scope="dmarc"), "DMARC")

    assert dmarc["verdict"] != "No DMARC policy published"
    assert dmarc["status"] != "fail"
    assert dmarc.get("pill_label") != "Missing"


def test_dmarc_lowercase_version_is_named_not_filed_as_an_unrelated_record(audit):
    """A case variant is a near miss worth explaining, not a silent discard."""
    zone = _dmarc_zone("v=dmarc1; p=reject")
    with fake_dns(FakeZone(zone)):
        raw = audit_engine._raw_check_dmarc(DOMAIN)

    reported = " ".join(
        e.get("issue", "") + " " + e.get("plain_english", "")
        for e in raw.get("syntax_errors", [])
    ).lower()
    assert "dmarc1" in reported, (
        "a lowercase v=dmarc1 record should be explained, not dropped in "
        f"silence; syntax_errors were {raw.get('syntax_errors')}"
    )
    # And it must not be counted as some unrelated TXT record parked at
    # _dmarc, which would hand the operator an entirely different fix.
    assert "non_dmarc_txt_count" not in raw


# ------------------------------------------------------------------
# DMARC, apex and subdomain must agree.
# ------------------------------------------------------------------
#
# audit_engine held two different opinions about what a DMARC record is. The
# per-subdomain probe lowercased, so it counted a v=dmarc1 record that the
# apex path reports as a syntax error, and it had no whitespace tolerance, so
# it missed the v = DMARC1 the apex accepts. The subdomain answer feeds the
# spoofable-subdomain finding, one of the strongest claims the report makes.

def _apex_finds_dmarc(record):
    with fake_dns(FakeZone(_dmarc_zone(record))):
        return bool(audit_engine._raw_check_dmarc(DOMAIN).get("record"))


def _subdomain_finds_dmarc(record):
    zone = {
        "mail." + DOMAIN: {"A": ["198.51.100.10"]},
        "_dmarc.mail." + DOMAIN: {"TXT": [record]},
    }
    with fake_dns(FakeZone(zone)):
        return audit_engine._probe_subdomain("mail." + DOMAIN)["has_dmarc"]


@pytest.mark.parametrize("shape", SHAPES)
def test_apex_and_subdomain_agree_on_what_a_dmarc_record_is(shape):
    record = f"{tag('DMARC1', shape)}; p=reject"
    assert _apex_finds_dmarc(record) == _subdomain_finds_dmarc(record), (
        f"the apex path and the subdomain probe disagree about {record!r}; "
        "both must use the same matcher or the spoofable-subdomain finding "
        "contradicts the DMARC card"
    )


@pytest.mark.parametrize(
    "record, expected, why",
    [
        # The apex calls this a syntax error, so the subdomain must not
        # record it as DMARC protection the subdomain does not have.
        ("v=dmarc1; p=reject", False, 'RFC 9989 S5.4 writes %s"DMARC1"'),
        # Valid per RFC 9989 S5.4, so the subdomain must see it.
        ("v = DMARC1; p=reject", True, "equals = *WSP \"=\" *WSP"),
    ],
)
def test_subdomain_probe_on_the_records_that_used_to_split_the_two_paths(
    record, expected, why
):
    assert _subdomain_finds_dmarc(record) is expected, f"{record!r}: {why}"


# ------------------------------------------------------------------
# SPF. RFC 7208 S12: version = "v=spf1", a plain literal with no %s prefix.
# ------------------------------------------------------------------
#
# Case insensitive per RFC 7405 S2, and section 4.6.1 confirms mechanism and
# modifier names are case insensitive too. There is no *WSP, so the spacing
# DMARC and BIMI permit is not permitted here. This looks like the MTA-STS and
# TLS-RPT leniency and is not it. The SPF parser was left untouched on purpose.

SPF_EXPECTED = {
    "canonical": True,
    "spaced": False,     # no *WSP anywhere in the ABNF
    "case_flipped": True,  # no %s prefix, so case insensitive
    "leading": True,
}


@pytest.mark.parametrize("shape", SHAPES)
def test_spf_version_tag_table(audit, shape):
    record = f"{tag('spf1', shape)} ip4:198.51.100.0/24 -all"
    zone = {
        DOMAIN: {"TXT": [record]},
        "_dmarc." + DOMAIN: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
    }
    spf = card(audit(zone, DOMAIN, scope="dmarc"), "SPF")
    found = spf.get("record") is not None

    assert found is SPF_EXPECTED[shape], (
        f"{record!r}: RFC 7208 S12 writes version = \"v=spf1\" with no %s "
        f"prefix and no *WSP; card record is {spf.get('record')!r}"
    )


# ------------------------------------------------------------------
# BIMI. Draft S4.2: bimi-version = "v" *WSP "=" *WSP "BIMI1".
# ------------------------------------------------------------------
#
# Whitespace allowed, and the RFC 6376 S3.2 tag-spec the draft adopts permits
# [FWS] around the equals sign too, so both readings agree. The literal has no
# %s prefix, so unlike DMARC, MTA-STS and TLS-RPT the value is case
# insensitive per RFC 7405 S2. BIMI is a draft, not a published RFC.

BIMI_EXPECTED = {
    "canonical": True,
    "spaced": True,      # *WSP "=" *WSP
    "case_flipped": True,  # plain literal, no %s prefix
    "leading": True,
}


def _bimi_result(record):
    zone = {"default._bimi." + DOMAIN: {"TXT": [record]}}
    with fake_dns(FakeZone(zone)):
        return check_bimi(
            DOMAIN, dmarc_found_override=True, dmarc_enforcing_override=True
        )


@pytest.mark.parametrize("shape", SHAPES)
def test_bimi_version_tag_table(shape):
    record = f"{tag('BIMI1', shape)}; l=https://example.com/logo.svg"
    result = _bimi_result(record)

    assert (result["records_found"] == 1) is BIMI_EXPECTED[shape], (
        f"{record!r}: the BIMI draft S4.2 writes "
        f"bimi-version = \"v\" *WSP \"=\" *WSP \"BIMI1\"; "
        f"records_found is {result['records_found']}"
    )


def test_bimi_spaced_equals_is_assessed_rather_than_ignored():
    """The false negative: a published BIMI record treated as no record at all."""
    result = _bimi_result("v = BIMI1; l=https://example.com/logo.svg")

    assert result["records_found"] == 1
    assert "No BIMI record at the default selector" not in issue_text(result)


# ------------------------------------------------------------------
# MTA-STS. RFC 8461 S3.1: sts-version = %s"v=STSv1".
# ------------------------------------------------------------------
#
# Case sensitive, no whitespace. The policy file fetch is stubbed to succeed
# throughout, so the status under test is the one the TXT parse produces and
# not the fetch's: without that, every variant came back warning and the
# false pass was invisible.

MTA_STS_EXPECTED = {
    "canonical": True,
    "spaced": False,      # no *WSP in the ABNF
    "case_flipped": False,  # %s"v=STSv1" is case sensitive
    "leading": True,
}

MTA_STS_POLICY = (
    "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 604800\n"
)


def _mta_sts_result(record):
    zone = {"_mta-sts." + DOMAIN: {"TXT": [record]}}
    with fake_dns(FakeZone(zone), mta_sts_policy=MTA_STS_POLICY):
        return check_mta_sts(DOMAIN)


@pytest.mark.parametrize("shape", SHAPES)
def test_mta_sts_version_tag_table(shape):
    record = f"{tag('STSv1', shape)}; id=20240101"
    result = _mta_sts_result(record)

    assert (result["status"] == "ok") is MTA_STS_EXPECTED[shape], (
        f"{record!r}: RFC 8461 S3.1 writes sts-version = %s\"v=STSv1\", which "
        f"RFC 7405 S2 makes case sensitive, with no room for whitespace; "
        f"status is {result['status']} and issues were {issue_text(result)!r}"
    )


def test_mta_sts_case_variant_is_named_rather_than_called_absent():
    """V=STSV1 is discarded by senders. Say why, do not report an absence."""
    result = _mta_sts_result("V=STSV1; id=20240101")

    assert result["status"] != "ok"
    text = issue_text(result)
    assert "STSV1" in text and "STSv1" in text, (
        f"the operator who published V=STSV1 meant to enable MTA-STS and "
        f"needs the exact reason it is inert; got {text!r}"
    )
    assert "No MTA-STS TXT record found" not in text


# ------------------------------------------------------------------
# TLS-RPT. RFC 8460 S3: tlsrpt-version = %s"v=TLSRPTv1".
# ------------------------------------------------------------------
#
# Case sensitive, no whitespace. The false pass here is quiet: a domain
# publishing V=TLSRPTV1 got a green card saying TLS reporting is configured,
# conforming receivers discarded the record, no aggregate report was ever
# sent, and the silence is indistinguishable from having nothing to report.

TLS_RPT_EXPECTED = {
    "canonical": True,
    "spaced": False,      # no *WSP in the ABNF
    "case_flipped": False,  # %s"v=TLSRPTv1" is case sensitive
    "leading": True,
}


def _tls_rpt_result(record):
    zone = {"_smtp._tls." + DOMAIN: {"TXT": [record]}}
    with fake_dns(FakeZone(zone)):
        return check_tls_rpt(DOMAIN)


@pytest.mark.parametrize("shape", SHAPES)
def test_tls_rpt_version_tag_table(shape):
    record = f"{tag('TLSRPTv1', shape)}; rua=mailto:tls@{DOMAIN}"
    result = _tls_rpt_result(record)

    assert (result["records_found"] == 1) is TLS_RPT_EXPECTED[shape], (
        f"{record!r}: RFC 8460 S3 writes tlsrpt-version = %s\"v=TLSRPTv1\", "
        f"which RFC 7405 S2 makes case sensitive, with no room for "
        f"whitespace; records_found is {result['records_found']}"
    )


def test_tls_rpt_case_variant_does_not_earn_a_green_card():
    result = _tls_rpt_result(f"V=TLSRPTV1; rua=mailto:tls@{DOMAIN}")

    assert result["status"] != "ok"
    assert result["records_found"] == 0


def test_tls_rpt_case_variant_is_named_rather_than_called_absent():
    result = _tls_rpt_result(f"V=TLSRPTV1; rua=mailto:tls@{DOMAIN}")

    text = issue_text(result)
    assert "TLSRPTV1" in text and "TLSRPTv1" in text, (
        f"the operator who published V=TLSRPTV1 meant to enable TLS-RPT and "
        f"needs the exact reason no reports arrive; got {text!r}"
    )
    assert "No TLS-RPT record found" not in text


# ------------------------------------------------------------------
# The near-miss card, end to end.
# ------------------------------------------------------------------
#
# A malformed version tag is neither an absence nor a working record, and the
# card must not claim it is either. Reporting the record in the field the
# transformers read as "a record exists" put the MTA-STS verdict at "Record
# found" and had the TLS-RPT explanation open with "TLS-RPT is configured",
# directly above the detail saying receivers discard it.

NEAR_MISS_ZONE = {
    DOMAIN: {"TXT": ["v=spf1 -all"], "MX": [(10, "mail." + DOMAIN)]},
    "mail." + DOMAIN: {"A": ["198.51.100.5"]},
    "_dmarc." + DOMAIN: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
    "_mta-sts." + DOMAIN: {"TXT": ["V=STSV1; id=20240101"]},
    "_smtp._tls." + DOMAIN: {"TXT": [f"V=TLSRPTV1; rua=mailto:tls@{DOMAIN}"]},
}


@pytest.fixture
def near_miss(audit):
    return audit(
        NEAR_MISS_ZONE, DOMAIN, scope="transport", mta_sts_policy=MTA_STS_POLICY
    )


@pytest.mark.parametrize(
    "name, published, correct",
    [("MTA-STS", "V=STSV1", "v=STSv1"), ("TLS-RPT", "V=TLSRPTV1", "v=TLSRPTv1")],
)
def test_near_miss_card_says_published_and_ignored(near_miss, name, published, correct):
    check = card(near_miss, name)
    text = " ".join(
        [check.get("verdict") or "", check.get("explanation") or "",
         check.get("fix") or ""]
        + [d.get("text", "") for d in check.get("details", [])]
    )

    assert check["status"] == "fail", f"{name} near miss must not pass"
    assert published in text, f"{name} card must quote the record as published"
    assert correct in text, f"{name} card must give the exact spelling required"
    # The two claims the card must never make about a near miss.
    assert "No {} record found".format(name) not in text
    assert "is configured" not in text
    assert "Record found" not in check["verdict"]


# ------------------------------------------------------------------
# BIMI's own DMARC fallback is a third DMARC reader.
# ------------------------------------------------------------------
#
# check_bimi looks up _dmarc itself when the orchestrator passes no overrides,
# and that lookup carried both of the subdomain probe's bugs. It is reachable
# only for a standalone check_bimi call, but a third opinion about what a
# DMARC record is is exactly what the shared matcher exists to prevent.

@pytest.mark.parametrize("shape", SHAPES)
def test_bimi_dmarc_fallback_agrees_with_the_dmarc_card(shape):
    dmarc_record = f"{tag('DMARC1', shape)}; p=reject"
    zone = {
        "default._bimi." + DOMAIN: {"TXT": ["v=BIMI1; l=https://example.com/l.svg"]},
        "_dmarc." + DOMAIN: {"TXT": [dmarc_record]},
    }
    with fake_dns(FakeZone(zone)):
        result = check_bimi(DOMAIN)

    saw_dmarc = "BIMI requires DMARC, but no DMARC record found" not in issue_text(result)
    assert saw_dmarc is DMARC_EXPECTED[shape], (
        f"check_bimi's own _dmarc lookup disagrees with the DMARC card about "
        f"{dmarc_record!r}"
    )
