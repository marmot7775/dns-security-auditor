"""
Remediation Planner
===================
Builds a prioritized, dependency-aware remediation plan from DNS audit results.

Each step is categorized into one of three timeframes:
  - immediate  -- critical security gaps, do now
  - short_term -- policy upgrades and missing best practices, 1-2 weeks
  - long_term  -- hardening measures, 1-3 months

Dependency ordering is baked into each category so that foundational steps
always appear before the steps that depend on them.
"""

from typing import Dict, List


# ============================================================
# Types
# ============================================================

Step = Dict[str, str]
Plan = Dict[str, List[Step]]


# ============================================================
# Public API
# ============================================================

def build_remediation_plan(
    checks: list,
    raw_results: dict,
    has_mx: bool,
    is_defensive: bool = False,
    tree_walk: dict = None,
) -> Plan:
    """Build a prioritized, dependency-aware remediation plan.

    Parameters
    ----------
    checks:
        The list of transformed check cards, each a dict with at minimum
        ``name``, ``status``, ``fix``, and optionally ``fix_records``.
    raw_results:
        The raw output dict from the audit engine, keyed by check name
        (e.g. ``"spf"``, ``"dmarc"``, ``"dkim"``).
    has_mx:
        True when the domain publishes at least one MX record.  Email-only
        recommendations are suppressed when this is False.
    tree_walk:
        Tree walk result for inherited DMARC policy detection.

    Returns
    -------
    dict
        ``{"immediate": [...], "short_term": [...], "long_term": [...]}``
        Each list is ordered highest-impact first.  Lists may be empty.
    """
    immediate: List[Step] = []
    short_term: List[Step] = []
    long_term: List[Step] = []

    # Defensive DNS domains intentionally do not send or receive email.
    # Only DNS infrastructure recommendations apply.
    if is_defensive:
        dnssec = raw_results.get("dnssec") or {}
        caa = raw_results.get("caa") or {}
        if not bool(dnssec.get("has_dnssec")):
            long_term.append({
                "title": "Enable DNSSEC",
                "description": (
                    "DNSSEC cryptographically signs your DNS records, protecting against "
                    "cache poisoning and DNS spoofing attacks."
                ),
                "effort": "medium",
                "impact": "medium",
                "check": "DNSSEC",
            })
        if (caa.get("record_count") or 0) == 0:
            long_term.append({
                "title": "Add CAA Records",
                "description": (
                    "CAA records restrict which certificate authorities can issue TLS "
                    "certificates for your domain."
                ),
                "effort": "low",
                "impact": "medium",
                "check": "CAA",
            })
        return {"immediate": immediate, "short_term": short_term, "long_term": long_term}

    spf = raw_results.get("spf") or {}
    dmarc = raw_results.get("dmarc") or {}
    dkim = raw_results.get("dkim") or {}
    mta_sts = raw_results.get("mta_sts") or {}
    tls_rpt = raw_results.get("tls_rpt") or {}
    dnssec = raw_results.get("dnssec") or {}
    caa = raw_results.get("caa") or {}
    dane = raw_results.get("dane") or {}
    mx = raw_results.get("mx") or {}
    blacklist = raw_results.get("blacklist") or {}

    # A check whose DNS query never completed reports status "unavailable"
    # with an empty record field. Every "you have no X record" item below
    # reads that emptiness as absence, so a plan built from a failed lookup
    # would tell the operator to publish records they may already have.
    spf_unavailable = spf.get("status") == "unavailable"
    dmarc_unavailable = (
        dmarc.get("status") == "unavailable" or bool(dmarc.get("inheritance_lookup_failed"))
    )

    spf_record = spf.get("record") or ""
    spf_all = (spf.get("all_mechanism") or "").lower()
    spf_lookups = spf.get("lookup_count") or 0

    dmarc_record = dmarc.get("record") or ""
    # Determine effective DMARC policy, including inherited from org domain
    _dmarc_inherited = not dmarc_record and dmarc.get("is_subdomain") and dmarc.get("inherited_policy")
    if _dmarc_inherited:
        dmarc_policy = dmarc["inherited_policy"].lower()
    else:
        dmarc_policy = (dmarc.get("policy") or "").lower()
    dmarc_enforced = dmarc_policy in ("quarantine", "reject")

    dnssec_enabled = bool(dnssec.get("has_dnssec"))
    dnssec_chain_valid = dnssec.get("chain_valid")
    dnssec_has_ds = bool(dnssec.get("has_ds"))

    caa_count = caa.get("record_count") or 0
    dane_has_tlsa = bool(dane.get("has_tlsa"))

    mx_records = mx.get("records") or []
    mx_count = mx.get("record_count") or len(mx_records)

    blacklist_listed = (blacklist.get("total_listings") or 0) > 0

    mta_sts_txt = mta_sts.get("txt_record") or ""
    mta_sts_mode = (mta_sts.get("policy_mode") or "").lower()

    tls_rpt_record = tls_rpt.get("record") or ""

    # DKIM: look at all found selectors for weak keys
    found_selectors = dkim.get("found_selectors") or []
    has_weak_dkim = _has_weak_dkim_keys(found_selectors)
    has_any_dkim = bool(found_selectors)

    # --------------------------------------------------------
    # IMMEDIATE -- critical security gaps
    # --------------------------------------------------------

    # Blacklist listing -- highest urgency, reputation at risk
    if blacklist_listed:
        immediate.append({
            "title": "Remove Blacklist Listing",
            "description": (
                "Your domain or sending IP appears on one or more DNS blacklists. "
                "Email from this domain is likely being rejected or marked as spam."
            ),
            "effort": "medium",
            "impact": "high",
            "check": "Blacklist",
        })

    # Missing SPF (only meaningful for mail-sending domains)
    if has_mx and not spf_record and not spf_unavailable:
        immediate.append({
            "title": "Publish SPF Record",
            "description": (
                "Your domain has no SPF record. Without SPF, receivers cannot use IP-based "
                "authentication as part of DMARC alignment evaluation."
            ),
            "effort": "low",
            "impact": "high",
            "check": "SPF",
        })

    # SPF +all -- authorizes the entire internet
    if spf_record and spf_all == "+all":
        immediate.append({
            "title": "Remove +all From SPF",
            "description": (
                "Your SPF record ends with +all, which authorizes every server on the "
                "internet to send mail as your domain. SPF provides no value in this state."
            ),
            "effort": "low",
            "impact": "high",
            "check": "SPF",
        })

    # SPF lookup limit exceeded
    if spf_record and isinstance(spf_lookups, (int, float)) and spf_lookups > 10:
        immediate.append({
            "title": "Fix SPF Lookup Limit",
            "description": (
                f"Your SPF record requires {spf_lookups} DNS lookups, exceeding the "
                "RFC 7208 limit of 10. Receivers may treat this as a PermError and "
                "reject or skip SPF evaluation entirely."
            ),
            "effort": "medium",
            "impact": "high",
            "check": "SPF",
        })

    # Missing DMARC (no direct record AND no inherited policy)
    if not dmarc_record and not _dmarc_inherited and not dmarc_unavailable:
        immediate.append({
            "title": "Publish DMARC Record",
            "description": (
                "Your domain has no DMARC record, so there is no policy instructing "
                "receivers what to do with unauthenticated mail and no reporting channel."
            ),
            "effort": "low",
            "impact": "high",
            "check": "DMARC",
        })
    elif not dmarc_record and _dmarc_inherited:
        _inh_source = dmarc.get("inherited_from", "organizational domain")
        short_term.append({
            "title": "Publish Dedicated DMARC Record",
            "description": (
                f"This subdomain inherits DMARC p={dmarc_policy} from {_inh_source}. "
                "While this provides policy coverage, publishing a dedicated record "
                "is best practice for any subdomain that sends email."
            ),
            "effort": "low",
            "impact": "medium",
            "check": "DMARC",
        })

    # DNSSEC broken chain (enabled but invalid -- worse than not enabled)
    if dnssec_enabled and dnssec_chain_valid is False:
        immediate.append({
            "title": "Repair DNSSEC Chain",
            "description": (
                "DNSSEC is configured but the validation chain is broken. "
                "Resolvers that enforce DNSSEC will refuse to resolve your domain entirely."
            ),
            "effort": "high",
            "impact": "high",
            "check": "DNSSEC",
        })

    # --------------------------------------------------------
    # SHORT-TERM -- policy upgrades and missing best practices
    # --------------------------------------------------------

    # DMARC p=none -- need to step up to quarantine
    # Applies to both direct record and inherited policy
    if (dmarc_record or _dmarc_inherited) and dmarc_policy == "none":
        short_term.append({
            "title": "Upgrade DMARC to p=quarantine",
            "description": (
                "DMARC p=none is monitoring-only; unauthenticated mail is still delivered. "
                "Once your SPF and DKIM pass rates look healthy in reports, advance to p=quarantine."
            ),
            "effort": "low",
            "impact": "high",
            "check": "DMARC",
        })

    # SPF ?all -- neutral, should be tightened
    if spf_record and spf_all == "?all":
        short_term.append({
            "title": "Tighten SPF all Mechanism",
            "description": (
                "Your SPF record ends with ?all (neutral), which provides no enforcement. "
                "Replace it with ~all (soft fail)."
            ),
            "effort": "low",
            "impact": "high",
            "check": "SPF",
        })

    # Weak DKIM keys (1024-bit)
    if has_any_dkim and has_weak_dkim:
        short_term.append({
            "title": "Replace Weak DKIM Keys",
            "description": (
                "One or more of your DKIM selectors use 1024-bit RSA keys, which no "
                "longer meet current security recommendations. Rotate to 2048-bit keys."
            ),
            "effort": "medium",
            "impact": "high",
            "check": "DKIM",
        })

    # Missing MTA-STS (mail domain)
    if has_mx and not mta_sts_txt:
        short_term.append({
            "title": "Implement MTA-STS",
            "description": (
                "MTA-STS allows you to publish a policy requiring TLS for inbound mail. "
                "Without it, mail to your domain may be delivered over an unencrypted connection."
            ),
            "effort": "medium",
            "impact": "medium",
            "check": "MTA-STS",
        })

    # Missing TLS-RPT (mail domain)
    if has_mx and not tls_rpt_record:
        short_term.append({
            "title": "Add TLS-RPT Record",
            "description": (
                "TLS-RPT (RFC 8460) enables receiving reports about TLS failures from "
                "mail servers connecting to your domain, useful for diagnosing delivery problems."
            ),
            "effort": "low",
            "impact": "medium",
            "check": "TLS-RPT",
        })

    # Missing CAA records
    if caa_count == 0:
        short_term.append({
            "title": "Add CAA Records",
            "description": (
                "CAA records restrict which certificate authorities can issue TLS certificates "
                "for your domain, reducing the risk of mis-issuance."
            ),
            "effort": "low",
            "impact": "medium",
            "check": "CAA",
        })

    # Single MX host -- no redundancy (skip for major providers who handle it internally)
    _major_mx = {"google", "microsoft", "outlook", "proofpoint", "mimecast", "barracuda", "cloudflare"}
    mx_providers = mx.get("providers") or []
    _mx_is_major = any(any(m in p.lower() for m in _major_mx) for p in mx_providers)
    if has_mx and mx_count == 1 and not _mx_is_major:
        short_term.append({
            "title": "Add a Secondary MX Host",
            "description": (
                "Your domain has only one MX record. If that server is unreachable, "
                "senders will be unable to deliver email to your domain."
            ),
            "effort": "medium",
            "impact": "medium",
            "check": "MX",
        })

    # --------------------------------------------------------
    # LONG-TERM -- hardening
    # --------------------------------------------------------

    # DMARC p=quarantine -- step up to reject
    # Applies to both direct record and inherited policy
    if (dmarc_record or _dmarc_inherited) and dmarc_policy == "quarantine":
        long_term.append({
            "title": "Advance DMARC to p=reject",
            "description": (
                "Once you have confirmed that legitimate mail is passing SPF and DKIM, "
                "move DMARC to p=reject to request that receivers reject unauthenticated mail "
                "rather than routing it to spam."
            ),
            "effort": "low",
            "impact": "high",
            "check": "DMARC",
        })

    # ~all is standard with DMARC; -all can cause issues with legacy receivers
    # that reject on SPF hardfail before checking DMARC. No recommendation to change.

    # DKIM key rotation (only for mail-sending domains with DKIM)
    if has_any_dkim and not has_weak_dkim and has_mx:
        long_term.append({
            "title": "Schedule Regular DKIM Key Rotation",
            "description": (
                "Rotating DKIM keys periodically (every 6-12 months) limits the exposure "
                "window if a private key is ever compromised."
            ),
            "effort": "medium",
            "impact": "medium",
            "check": "DKIM",
        })

    # Enable DNSSEC (not currently enabled, or no DS record)
    if not dnssec_enabled or not dnssec_has_ds:
        # Only suggest if chain is not already broken (broken chain is immediate)
        if not (dnssec_enabled and dnssec_chain_valid is False):
            long_term.append({
                "title": "Enable DNSSEC",
                "description": (
                    "DNSSEC cryptographically signs your DNS records, protecting against "
                    "cache poisoning and DNS spoofing attacks. It is also a prerequisite for DANE."
                ),
                "effort": "medium",
                "impact": "medium",
                "check": "DNSSEC",
            })

    # DANE -- requires DNSSEC to be working first
    if dnssec_enabled and dnssec_chain_valid and not dane_has_tlsa and has_mx:
        long_term.append({
            "title": "Implement DANE (TLSA Records)",
            "description": (
                "DANE publishes your mail server's TLS certificate fingerprint in DNS (via TLSA "
                "records), allowing senders to verify the certificate without relying on the CA system."
            ),
            "effort": "high",
            "impact": "medium",
            "check": "DANE",
        })

    # BIMI -- requires DMARC enforcement (quarantine or reject) and DKIM
    bimi_raw = raw_results.get("bimi") or {}
    bimi_has_record = bool(bimi_raw.get("record") or bimi_raw.get("records_found"))
    bimi_eligible = dmarc_enforced and has_any_dkim and not bimi_has_record
    if bimi_eligible and has_mx:
        long_term.append({
            "title": "Add BIMI Record",
            "description": (
                "BIMI displays your brand logo in supporting email clients for authenticated "
                "messages. It requires DMARC enforcement and a validated SVG logo."
            ),
            "effort": "medium",
            "impact": "low",
            "check": "BIMI",
        })

    # MTA-STS: upgrade from testing to enforce
    if has_mx and mta_sts_txt and mta_sts_mode == "testing":
        long_term.append({
            "title": "Advance MTA-STS to enforce Mode",
            "description": (
                "Your MTA-STS policy is in testing mode. After confirming that all sending "
                "servers support TLS, switch to enforce mode to require encrypted delivery."
            ),
            "effort": "low",
            "impact": "medium",
            "check": "MTA-STS",
        })

    return {
        "immediate": immediate,
        "short_term": short_term,
        "long_term": long_term,
    }


# ============================================================
# Internal helpers
# ============================================================

def _has_weak_dkim_keys(found_selectors) -> bool:
    """Return True if any selector serves an RSA key of 1024 bits or fewer.

    found_selectors is a list of dicts carrying key_type and key_bits, or the
    older key_size / key_analysis.key_bits shapes.
    """
    if not found_selectors or not isinstance(found_selectors, list):
        return False
    for sel in found_selectors:
        if not isinstance(sel, dict):
            continue
        key_analysis = sel.get("key_analysis")
        if not isinstance(key_analysis, dict):
            key_analysis = {}

        # 1024 is an RSA modulus threshold. Ed25519 keys are 256 bits and
        # strong, so comparing them against it reads every one as weak and
        # tells the user to rotate a key the card rates green.
        if _is_ed25519(sel, key_analysis):
            continue

        bits = sel.get("key_size") or sel.get("key_bits")
        if bits is None:
            bits = key_analysis.get("key_bits")
        if isinstance(bits, bool) or not isinstance(bits, (int, float)):
            continue
        # 0 means revoked (empty p=) or a key that could not be decoded, not a
        # short key. The card already reports those as errors, and the step
        # below claims the selectors "use 1024-bit RSA keys", which would be
        # untrue for them.
        if 0 < bits <= 1024:
            return True
    return False


def _is_ed25519(sel: dict, key_analysis: dict) -> bool:
    """Key type from the normalized field, falling back to the k= tag."""
    key_type = sel.get("key_type") or key_analysis.get("key_type") or ""
    if "ed25519" in str(key_type).lower():
        return True
    # Selector dicts assembled elsewhere may carry only the raw record.
    return "k=ed25519" in str(sel.get("record") or "").lower().replace(" ", "")
