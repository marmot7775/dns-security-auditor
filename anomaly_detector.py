"""
anomaly_detector.py -- cross-check anomaly detection for DNS security audits.

Examines raw audit results across multiple checks to surface patterns that no
single check can catch on its own. Results appear in the "What's Unusual?"
section of the audit report.
"""

from typing import Dict, List


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


def detect_anomalies(raw_results: dict, score_result: dict, has_mx: bool) -> list:
    """
    Detect cross-check anomalies from raw audit results.

    Args:
        raw_results: Raw output dict from the audit engine, keyed by check name.
        score_result: Output from EmailSecurityScorer (grade, score, etc.).
        has_mx: Whether the domain has MX records.

    Returns:
        List of anomaly dicts sorted by severity (critical, high, medium).
        Each dict has keys: title, description, severity, recommendation.
    """
    anomalies: List[dict] = []

    dmarc = raw_results.get("dmarc") or {}
    spf = raw_results.get("spf") or {}
    dkim = raw_results.get("dkim") or {}
    mta_sts = raw_results.get("mta_sts") or {}
    tls_rpt = raw_results.get("tls_rpt") or {}
    bimi = raw_results.get("bimi") or {}
    nameservers_raw = raw_results.get("nameservers") or {}
    dnssec = raw_results.get("dnssec") or {}

    dmarc_policy = (dmarc.get("policy") or "").lower()
    dmarc_enforced = dmarc_policy in ("quarantine", "reject")
    dmarc_present = bool(dmarc.get("record") or dmarc.get("policy"))

    # 1. DMARC enforcement without SPF
    if dmarc_present and dmarc_enforced:
        spf_record = spf.get("record") or spf.get("raw_record")
        if not spf_record:
            anomalies.append({
                "title": "DMARC enforcement without SPF",
                "description": (
                    "DMARC is set to {} but no SPF record was found. "
                    "SPF alignment can never pass, so every message must rely "
                    "solely on DKIM to satisfy DMARC."
                ).format(dmarc_policy),
                "severity": "critical",
                "recommendation": (
                    "Publish an SPF record (e.g. \"v=spf1 include:your-esp.com -all\") "
                    "so that SPF alignment is available as a DMARC pass mechanism."
                ),
            })

    # 2. DMARC enforcement without DKIM (only for mail-sending domains)
    if dmarc_present and dmarc_enforced and has_mx:
        found_selectors = dkim.get("found_selectors") or []
        if not found_selectors:
            anomalies.append({
                "title": "DMARC enforcement without DKIM",
                "description": (
                    "DMARC is set to {} and this domain has MX records, but no "
                    "DKIM keys were found. Mail delivery depends entirely on SPF "
                    "alignment, which breaks for forwarded messages."
                ).format(dmarc_policy),
                "severity": "high",
                "recommendation": (
                    "Configure DKIM signing on your mail platform and publish "
                    "the corresponding DKIM TXT records so that forwarded mail "
                    "can still pass DMARC via DKIM alignment."
                ),
            })

    # 3. SPF near lookup limit (9/10 -- not already over)
    if spf:
        lookup_count = spf.get("lookup_count")
        if lookup_count is not None:
            try:
                lookup_count = int(lookup_count)
            except (TypeError, ValueError):
                lookup_count = None
        if lookup_count is not None and lookup_count == 9:
            anomalies.append({
                "title": "SPF at lookup limit",
                "description": (
                    "SPF is using 9 of the allowed 10 DNS lookups. "
                    "Adding one more include, a, or mx mechanism will push it "
                    "over the limit and cause a permerror for all recipients."
                ),
                "severity": "medium",
                "recommendation": (
                    "Flatten SPF by replacing include chains with their resolved "
                    "IP ranges, or use an SPF flattening service to stay under "
                    "the 10-lookup limit."
                ),
            })

    # 4. MTA-STS without TLS-RPT
    if mta_sts:
        mta_sts_txt = mta_sts.get("txt_record") or mta_sts.get("record")
        tls_rpt_record = tls_rpt.get("record") or tls_rpt.get("txt_record")
        if mta_sts_txt and not tls_rpt_record:
            anomalies.append({
                "title": "MTA-STS configured without TLS-RPT",
                "description": (
                    "MTA-STS is enforcing TLS for inbound mail but no TLS-RPT "
                    "record exists. TLS delivery failures are silently discarded "
                    "with no way to detect them."
                ),
                "severity": "medium",
                "recommendation": (
                    "Add a TLS-RPT record (_smtp._tls.<domain> TXT "
                    "\"v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com\") "
                    "so that sending servers can report TLS negotiation failures."
                ),
            })

    # 5. BIMI without strong DMARC
    if bimi:
        bimi_record = bimi.get("record") or bimi.get("txt_record")
        if bimi_record and not dmarc_enforced:
            anomalies.append({
                "title": "BIMI record without DMARC enforcement",
                "description": (
                    "A BIMI record is published but DMARC policy is \"{}\" -- "
                    "not quarantine or reject. Mail clients will not display the "
                    "BIMI logo because DMARC enforcement is required."
                ).format(dmarc_policy or "none"),
                "severity": "high",
                "recommendation": (
                    "Set DMARC policy to at least quarantine (p=quarantine) "
                    "before expecting mail clients to honour the BIMI logo."
                ),
            })

    # 6. Mixed DKIM key strengths
    if dkim:
        found_selectors = dkim.get("found_selectors") or []
        key_bits = []
        for k in found_selectors:
            bits = k.get("key_size") or k.get("key_bits") or k.get("bits")
            if bits is not None:
                try:
                    key_bits.append(int(bits))
                except (TypeError, ValueError):
                    pass
        if key_bits:
            strong = [b for b in key_bits if b >= 2048]
            weak = [b for b in key_bits if 0 < b < 2048]
            if strong and weak:
                anomalies.append({
                    "title": "Mixed DKIM key strengths",
                    "description": (
                        "Some DKIM selectors use 2048-bit (or larger) keys while "
                        "others use {}-bit keys. Weak selectors undermine the "
                        "security of your DKIM setup."
                    ).format(min(weak)),
                    "severity": "medium",
                    "recommendation": (
                        "Rotate all DKIM keys to 2048-bit RSA (or Ed25519) and "
                        "retire any selectors with keys smaller than 2048 bits."
                    ),
                })

    # 7. Single nameserver
    if nameservers_raw:
        ns_count = nameservers_raw.get("ns_count", 0)
        nameservers = nameservers_raw.get("nameservers") or []
        if ns_count == 1 or (isinstance(nameservers, list) and len(nameservers) == 1):
            anomalies.append({
                "title": "Single nameserver",
                "description": (
                    "Only one nameserver was found. If it becomes unreachable, "
                    "the entire domain goes offline -- including mail delivery, "
                    "web, and all DNS-dependent services."
                ),
                "severity": "high",
                "recommendation": (
                    "Add at least one secondary nameserver on a different "
                    "network and provider to eliminate this single point of "
                    "failure."
                ),
            })

    # 8. Parked domain with MX
    if has_mx and dmarc_present:
        spf_record = spf.get("record") or spf.get("raw_record") or ""
        spf_is_null = "v=spf1 -all" in spf_record or spf_record.strip() == "v=spf1 -all"

        found_selectors = dkim.get("found_selectors") or []
        no_dkim = not found_selectors

        if dmarc_policy == "reject" and no_dkim and spf_is_null:
            anomalies.append({
                "title": "Parked domain with live MX records",
                "description": (
                    "The domain is configured to reject all mail (null SPF, "
                    "no DKIM, DMARC reject) but still has MX records pointing "
                    "somewhere. This is a potential misconfiguration or "
                    "subdomain takeover risk."
                ),
                "severity": "medium",
                "recommendation": (
                    "Remove the MX records if this domain does not receive "
                    "mail, or verify that the MX targets are under your control "
                    "and that the security policy is intentional."
                ),
            })

    # 9. DMARC reporting to unauthorized destinations
    if dmarc_present:
        report_destinations = dmarc.get("report_destinations") or []
        unauthorized = [
            d for d in report_destinations
            if isinstance(d, dict) and d.get("authorized") is False
        ]
        if unauthorized:
            dest_list = ", ".join(
                d.get("address") or d.get("email") or "unknown"
                for d in unauthorized
            )
            anomalies.append({
                "title": "DMARC reports sent to unauthorized destinations",
                "description": (
                    "DMARC aggregate or forensic reports are addressed to "
                    "destination(s) that have not published the required "
                    "authorization record: {}. Those reports will be silently "
                    "dropped by compliant receivers."
                ).format(dest_list),
                "severity": "critical",
                "recommendation": (
                    "For each third-party report address, the destination domain "
                    "must publish a TXT record at "
                    "<yourdomain.com>._report._dmarc.<destination-domain> "
                    "containing \"v=DMARC1\" to authorize receipt."
                ),
            })

    # 10. DNSSEC broken chain
    if dnssec:
        has_dnskey = bool(dnssec.get("has_dnssec") or dnssec.get("has_dnskey"))
        chain_valid = dnssec.get("chain_valid")
        if has_dnskey and chain_valid is False:
            anomalies.append({
                "title": "DNSSEC chain broken",
                "description": (
                    "DNSKEY records are published but the DS record at the "
                    "parent zone does not match, breaking the DNSSEC chain of "
                    "trust. DNSSEC-validating resolvers will return SERVFAIL "
                    "for all queries to this domain."
                ),
                "severity": "critical",
                "recommendation": (
                    "Update the DS record at your domain registrar to match "
                    "the current DNSKEY, or disable DNSSEC at the registrar "
                    "until the mismatch is resolved."
                ),
            })

    anomalies.sort(key=lambda a: _SEVERITY_ORDER.get(a.get("severity") or "medium", 2))
    return anomalies
