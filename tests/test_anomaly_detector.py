"""
Tests for anomaly_detector.py -- cross-check anomaly detection module.
"""

import pytest
from anomaly_detector import detect_anomalies


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def severities(anomalies):
    return [a["severity"] for a in anomalies]


def titles(anomalies):
    return [a["title"] for a in anomalies]


def find(anomalies, title_fragment):
    for a in anomalies:
        if title_fragment.lower() in a["title"].lower():
            return a
    return None


# ---------------------------------------------------------------------------
# Empty / safe defaults
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_raw_results(self):
        result = detect_anomalies({}, {}, has_mx=False)
        assert result == []

    def test_none_values_in_raw_results(self):
        raw = {"dmarc": None, "spf": None, "dkim": None}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert result == []

    def test_all_empty_dicts(self):
        raw = {k: {} for k in ("dmarc", "spf", "dkim", "mta_sts",
                               "tls_rpt", "bimi", "dns_infra", "dnssec")}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert result == []


# ---------------------------------------------------------------------------
# Rule 1 -- DMARC enforcement without SPF
# ---------------------------------------------------------------------------

class TestDmarcWithoutSpf:
    def _base(self, policy, spf_record=None):
        raw = {
            "dmarc": {"policy": policy, "record": "v=DMARC1; p={}".format(policy)},
            "spf": {"record": spf_record},
        }
        return detect_anomalies(raw, {}, has_mx=False)

    def test_quarantine_no_spf(self):
        result = self._base("quarantine", spf_record=None)
        a = find(result, "without SPF")
        assert a is not None
        assert a["severity"] == "critical"

    def test_reject_no_spf(self):
        result = self._base("reject", spf_record=None)
        assert find(result, "without SPF") is not None

    def test_reject_with_spf(self):
        result = self._base("reject", spf_record="v=spf1 include:sendgrid.net -all")
        assert find(result, "without SPF") is None

    def test_none_policy_no_fire(self):
        raw = {"dmarc": {"policy": "none", "record": "v=DMARC1; p=none"}, "spf": {}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "without SPF") is None

    def test_missing_dmarc_no_fire(self):
        raw = {"spf": {}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "without SPF") is None

    def test_spf_key_exists_but_none_value(self):
        # Key present, value None -- should still fire
        raw = {
            "dmarc": {"policy": "reject", "record": "v=DMARC1; p=reject"},
            "spf": {"record": None, "raw_record": None},
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "without SPF") is not None


# ---------------------------------------------------------------------------
# Rule 2 -- DMARC enforcement without DKIM (mail-sending domains only)
# ---------------------------------------------------------------------------

class TestDmarcWithoutDkim:
    def _base(self, policy, keys, has_mx):
        raw = {
            "dmarc": {"policy": policy, "record": "v=DMARC1; p={}".format(policy)},
            "spf": {"record": "v=spf1 -all"},
            "dkim": {"keys": keys},
        }
        return detect_anomalies(raw, {}, has_mx=has_mx)

    def test_reject_no_dkim_has_mx(self):
        result = self._base("reject", keys=[], has_mx=True)
        a = find(result, "without DKIM")
        assert a is not None
        assert a["severity"] == "high"

    def test_reject_no_dkim_no_mx(self):
        # No MX -- should not fire
        result = self._base("reject", keys=[], has_mx=False)
        assert find(result, "without DKIM") is None

    def test_reject_with_dkim(self):
        keys = [{"public_key": "MIIBIjANBg==", "selector": "default"}]
        result = self._base("reject", keys=keys, has_mx=True)
        assert find(result, "without DKIM") is None

    def test_none_policy_no_fire(self):
        result = self._base("none", keys=[], has_mx=True)
        assert find(result, "without DKIM") is None

    def test_dkim_keys_with_no_public_key_field(self):
        # Keys list present but no public_key values -- treated as no DKIM
        keys = [{"selector": "s1", "public_key": None}]
        result = self._base("reject", keys=keys, has_mx=True)
        assert find(result, "without DKIM") is not None


# ---------------------------------------------------------------------------
# Rule 3 -- SPF near lookup limit
# ---------------------------------------------------------------------------

class TestSpfNearLimit:
    def _base(self, lookup_count):
        raw = {"spf": {"record": "v=spf1 include:x -all", "lookup_count": lookup_count}}
        return detect_anomalies(raw, {}, has_mx=False)

    def test_exactly_9_fires(self):
        result = self._base(9)
        a = find(result, "lookup limit")
        assert a is not None
        assert a["severity"] == "medium"

    def test_8_does_not_fire(self):
        assert find(self._base(8), "lookup limit") is None

    def test_10_does_not_fire(self):
        # 10 is already flagged by the SPF check itself
        assert find(self._base(10), "lookup limit") is None

    def test_none_lookup_count_no_fire(self):
        assert find(self._base(None), "lookup limit") is None

    def test_string_9_fires(self):
        # lookup_count stored as string
        assert find(self._base("9"), "lookup limit") is not None

    def test_invalid_string_no_fire(self):
        assert find(self._base("many"), "lookup limit") is None


# ---------------------------------------------------------------------------
# Rule 4 -- MTA-STS without TLS-RPT
# ---------------------------------------------------------------------------

class TestMtaStsWithoutTlsRpt:
    def test_mta_sts_present_tls_rpt_missing(self):
        raw = {
            "mta_sts": {"txt_record": "v=STSv1; id=20240101"},
            "tls_rpt": {"record": None},
        }
        result = detect_anomalies(raw, {}, has_mx=True)
        a = find(result, "MTA-STS")
        assert a is not None
        assert a["severity"] == "medium"

    def test_mta_sts_present_tls_rpt_present(self):
        raw = {
            "mta_sts": {"txt_record": "v=STSv1; id=20240101"},
            "tls_rpt": {"record": "v=TLSRPTv1; rua=mailto:r@example.com"},
        }
        result = detect_anomalies(raw, {}, has_mx=True)
        assert find(result, "MTA-STS") is None

    def test_no_mta_sts_no_fire(self):
        raw = {"mta_sts": {}, "tls_rpt": {}}
        result = detect_anomalies(raw, {}, has_mx=True)
        assert find(result, "MTA-STS") is None

    def test_alt_field_name_record(self):
        raw = {
            "mta_sts": {"record": "v=STSv1; id=20240101"},
            "tls_rpt": {},
        }
        result = detect_anomalies(raw, {}, has_mx=True)
        assert find(result, "MTA-STS") is not None


# ---------------------------------------------------------------------------
# Rule 5 -- BIMI without strong DMARC
# ---------------------------------------------------------------------------

class TestBimiWithoutDmarc:
    def test_bimi_with_none_dmarc(self):
        raw = {
            "bimi": {"record": "v=BIMI1; l=https://example.com/logo.svg"},
            "dmarc": {"policy": "none", "record": "v=DMARC1; p=none"},
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        a = find(result, "BIMI")
        assert a is not None
        assert a["severity"] == "high"

    def test_bimi_with_no_dmarc_record(self):
        raw = {
            "bimi": {"record": "v=BIMI1; l=https://example.com/logo.svg"},
            "dmarc": {},
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "BIMI") is not None

    def test_bimi_with_quarantine_dmarc(self):
        raw = {
            "bimi": {"record": "v=BIMI1; l=https://example.com/logo.svg"},
            "dmarc": {"policy": "quarantine", "record": "v=DMARC1; p=quarantine"},
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "BIMI") is None

    def test_bimi_with_reject_dmarc(self):
        raw = {
            "bimi": {"record": "v=BIMI1; l=https://example.com/logo.svg"},
            "dmarc": {"policy": "reject", "record": "v=DMARC1; p=reject"},
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "BIMI") is None

    def test_no_bimi_no_fire(self):
        raw = {"bimi": {}, "dmarc": {"policy": "none", "record": "v=DMARC1; p=none"}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "BIMI") is None


# ---------------------------------------------------------------------------
# Rule 6 -- Mixed DKIM key strengths
# ---------------------------------------------------------------------------

class TestMixedDkimKeyStrengths:
    def test_mixed_strengths_fires(self):
        raw = {
            "dkim": {
                "keys": [
                    {"selector": "s1", "key_bits": 2048, "public_key": "abc"},
                    {"selector": "s2", "key_bits": 1024, "public_key": "def"},
                ]
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        a = find(result, "Mixed DKIM")
        assert a is not None
        assert a["severity"] == "medium"

    def test_all_strong_no_fire(self):
        raw = {
            "dkim": {
                "keys": [
                    {"selector": "s1", "key_bits": 2048, "public_key": "abc"},
                    {"selector": "s2", "key_bits": 4096, "public_key": "def"},
                ]
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "Mixed DKIM") is None

    def test_all_weak_no_fire(self):
        # All weak -- consistent, so no mixed-strength anomaly
        raw = {
            "dkim": {
                "keys": [
                    {"selector": "s1", "key_bits": 1024, "public_key": "abc"},
                    {"selector": "s2", "key_bits": 1024, "public_key": "def"},
                ]
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "Mixed DKIM") is None

    def test_single_key_no_fire(self):
        raw = {"dkim": {"keys": [{"selector": "s1", "key_bits": 2048, "public_key": "x"}]}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "Mixed DKIM") is None

    def test_alt_field_name_bits(self):
        raw = {
            "dkim": {
                "keys": [
                    {"selector": "s1", "bits": 2048, "public_key": "abc"},
                    {"selector": "s2", "bits": 1024, "public_key": "def"},
                ]
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "Mixed DKIM") is not None

    def test_no_bit_info_no_fire(self):
        raw = {
            "dkim": {
                "keys": [
                    {"selector": "s1", "public_key": "abc"},
                    {"selector": "s2", "public_key": "def"},
                ]
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "Mixed DKIM") is None


# ---------------------------------------------------------------------------
# Rule 7 -- Single nameserver
# ---------------------------------------------------------------------------

class TestSingleNameserver:
    def test_single_ns_fires(self):
        raw = {"dns_infra": {"nameservers": ["ns1.example.com"]}}
        result = detect_anomalies(raw, {}, has_mx=False)
        a = find(result, "Single nameserver")
        assert a is not None
        assert a["severity"] == "high"

    def test_two_ns_no_fire(self):
        raw = {"dns_infra": {"nameservers": ["ns1.example.com", "ns2.example.com"]}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "Single nameserver") is None

    def test_empty_ns_list_no_fire(self):
        raw = {"dns_infra": {"nameservers": []}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "Single nameserver") is None

    def test_no_dns_infra_no_fire(self):
        result = detect_anomalies({}, {}, has_mx=False)
        assert find(result, "Single nameserver") is None


# ---------------------------------------------------------------------------
# Rule 8 -- Parked domain with MX
# ---------------------------------------------------------------------------

class TestParkedDomainWithMx:
    def _parked_raw(self):
        return {
            "dmarc": {"policy": "reject", "record": "v=DMARC1; p=reject"},
            "spf": {"record": "v=spf1 -all", "raw_record": None},
            "dkim": {"keys": []},
        }

    def test_parked_domain_with_mx_fires(self):
        result = detect_anomalies(self._parked_raw(), {}, has_mx=True)
        a = find(result, "Parked domain")
        assert a is not None
        assert a["severity"] == "medium"

    def test_parked_domain_without_mx_no_fire(self):
        result = detect_anomalies(self._parked_raw(), {}, has_mx=False)
        assert find(result, "Parked domain") is None

    def test_not_parked_if_dkim_exists(self):
        raw = self._parked_raw()
        raw["dkim"] = {"keys": [{"public_key": "abc", "selector": "s1"}]}
        result = detect_anomalies(raw, {}, has_mx=True)
        assert find(result, "Parked domain") is None

    def test_not_parked_if_spf_not_null(self):
        raw = self._parked_raw()
        raw["spf"] = {"record": "v=spf1 include:sendgrid.net -all"}
        result = detect_anomalies(raw, {}, has_mx=True)
        assert find(result, "Parked domain") is None


# ---------------------------------------------------------------------------
# Rule 9 -- DMARC reporting to unauthorized destinations
# ---------------------------------------------------------------------------

class TestUnauthorizedReportDestinations:
    def test_unauthorized_destination_fires(self):
        raw = {
            "dmarc": {
                "policy": "reject",
                "record": "v=DMARC1; p=reject",
                "report_destinations": [
                    {"address": "reports@third-party.com", "authorized": False},
                ],
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        a = find(result, "unauthorized")
        assert a is not None
        assert a["severity"] == "critical"

    def test_all_authorized_no_fire(self):
        raw = {
            "dmarc": {
                "policy": "reject",
                "record": "v=DMARC1; p=reject",
                "report_destinations": [
                    {"address": "reports@example.com", "authorized": True},
                ],
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "unauthorized") is None

    def test_mixed_authorized_fires(self):
        raw = {
            "dmarc": {
                "policy": "none",
                "record": "v=DMARC1; p=none",
                "report_destinations": [
                    {"address": "ok@example.com", "authorized": True},
                    {"email": "bad@other.com", "authorized": False},
                ],
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        a = find(result, "unauthorized")
        assert a is not None
        assert "bad@other.com" in a["description"]

    def test_empty_destinations_no_fire(self):
        raw = {
            "dmarc": {
                "policy": "reject",
                "record": "v=DMARC1; p=reject",
                "report_destinations": [],
            }
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "unauthorized") is None

    def test_no_report_destinations_key_no_fire(self):
        raw = {"dmarc": {"policy": "reject", "record": "v=DMARC1; p=reject"}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "unauthorized") is None


# ---------------------------------------------------------------------------
# Rule 10 -- DNSSEC broken chain
# ---------------------------------------------------------------------------

class TestDnssecBrokenChain:
    def test_has_dnskey_chain_invalid_fires(self):
        raw = {"dnssec": {"dnskey": "abc123", "chain_valid": False}}
        result = detect_anomalies(raw, {}, has_mx=False)
        a = find(result, "DNSSEC chain broken")
        assert a is not None
        assert a["severity"] == "critical"

    def test_has_dnskey_chain_valid_no_fire(self):
        raw = {"dnssec": {"dnskey": "abc123", "chain_valid": True}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "DNSSEC") is None

    def test_no_dnskey_chain_invalid_no_fire(self):
        raw = {"dnssec": {"dnskey": None, "chain_valid": False}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "DNSSEC") is None

    def test_alt_field_has_dnskey(self):
        raw = {"dnssec": {"has_dnskey": True, "chain_valid": False}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "DNSSEC") is not None

    def test_chain_valid_none_no_fire(self):
        # chain_valid not yet determined -- should not fire
        raw = {"dnssec": {"dnskey": "abc123", "chain_valid": None}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert find(result, "DNSSEC") is None


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

class TestSeverityOrdering:
    def test_critical_before_high_before_medium(self):
        raw = {
            # critical: DNSSEC broken
            "dnssec": {"dnskey": "x", "chain_valid": False},
            # high: single nameserver
            "dns_infra": {"nameservers": ["ns1.example.com"]},
            # medium: SPF near limit
            "spf": {"record": "v=spf1 -all", "lookup_count": 9},
        }
        result = detect_anomalies(raw, {}, has_mx=False)
        assert len(result) >= 3
        sev_values = [_SEVERITY_ORDER[a["severity"]] for a in result]
        assert sev_values == sorted(sev_values)

    def test_return_type_is_list(self):
        assert isinstance(detect_anomalies({}, {}, has_mx=False), list)

    def test_each_anomaly_has_required_keys(self):
        raw = {"dns_infra": {"nameservers": ["ns1.only.com"]}}
        result = detect_anomalies(raw, {}, has_mx=False)
        assert len(result) == 1
        a = result[0]
        assert set(a.keys()) >= {"title", "description", "severity", "recommendation"}


# ---------------------------------------------------------------------------
# No em-dashes in output
# ---------------------------------------------------------------------------

class TestNoEmDashes:
    def _all_anomalies(self):
        raw = {
            "dmarc": {
                "policy": "reject",
                "record": "v=DMARC1; p=reject",
                "report_destinations": [{"address": "x@bad.com", "authorized": False}],
            },
            "spf": {"record": None, "raw_record": None, "lookup_count": 9},
            "dkim": {"keys": []},
            "mta_sts": {"txt_record": "v=STSv1; id=1"},
            "tls_rpt": {"record": None},
            "bimi": {"record": "v=BIMI1; l=https://x.com/l.svg"},
            "dns_infra": {"nameservers": ["ns1.x.com"]},
            "dnssec": {"dnskey": "abc", "chain_valid": False},
        }
        return detect_anomalies(raw, {}, has_mx=True)

    def test_no_em_dash_in_titles(self):
        for a in self._all_anomalies():
            assert "\u2014" not in a["title"]

    def test_no_em_dash_in_descriptions(self):
        for a in self._all_anomalies():
            assert "\u2014" not in a["description"]

    def test_no_em_dash_in_recommendations(self):
        for a in self._all_anomalies():
            assert "\u2014" not in a["recommendation"]


# ---------------------------------------------------------------------------
# Import path
# ---------------------------------------------------------------------------

def _SEVERITY_ORDER_map():
    return {"critical": 0, "high": 1, "medium": 2}


_SEVERITY_ORDER = _SEVERITY_ORDER_map()
