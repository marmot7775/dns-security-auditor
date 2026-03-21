"""
Audit Engine
=============
Orchestrates all security checks for a domain.
Each check runs independently -- if one fails, the others still complete.
Assembles results for the security scorer and transforms everything
into the frontend's expected format.
"""

import logging
import re
import traceback
from html import escape as _e
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Per-check timeout in seconds (prevents hung DNS queries from blocking the audit)
CHECK_TIMEOUT = 15

import dns.resolver
import dns.flags
import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.dnssec
import dns.name

from checks_extra import check_mta_sts, check_tls_rpt, check_bimi
from mx_check import check_mx
from spf_recursive import count_spf_lookups
from advanced_fingerprinting import AdvancedVendorFingerprinter
from security_scoring import EmailSecurityScorer
from dkim_formatter import analyze_dkim_key_strength
from anomaly_detector import detect_anomalies
from remediation_planner import build_remediation_plan
from dkim_key_age import DKIMKeyAgeAnalyzer

from dmarc_tree_walk import dmarc_tree_walk
try:
    import tldextract
except ImportError:
    tldextract = None
from spf_intelligence import smart_dkim_check

from result_transformer import (
    transform_dmarc,
    transform_spf,
    transform_dkim,
    transform_mx,
    transform_mta_sts,
    transform_tls_rpt,
    transform_bimi,
    transform_dnssec,
    transform_dane,
    transform_caa,
    transform_nameservers,
    transform_ct,
    transform_blacklist,
)


# ============================================================
# Vendor SPF Include Mapping (for remediation suggestions)
# ============================================================

VENDOR_SPF_INCLUDES = {
    "Google Workspace": "include:_spf.google.com",
    "Microsoft 365": "include:spf.protection.outlook.com",
    "Zoho Mail": "include:zoho.com",
    "Fastmail": "include:spf.fastmail.com",
    "ProtonMail": "include:_spf.protonmail.ch",
    "Rackspace Email": "include:emailsrvr.com",
    "SendGrid": "include:sendgrid.net",
    "Mailchimp": "include:servers.mcsv.net",
    "Mailgun": "include:mailgun.org",
    "Amazon SES": "include:amazonses.com",
    "Postmark": "include:spf.mtasv.net",
    "SparkPost": "include:sparkpostmail.com",
    "Brevo (Sendinblue)": "include:sendinblue.com",
    "HubSpot": "include:hubspotemail.net",
    "Salesforce": "include:_spf.salesforce.com",
    "Zendesk": "include:mail.zendesk.com",
    "Freshdesk": "include:email.freshdesk.com",
    "Intercom": "include:intercom-mail.com",
    "Mimecast": "include:_netblocks.mimecast.com",
    "Barracuda": "include:spf.barracudanetworks.com",
}


# ============================================================
# Scope Configuration
# ============================================================

SCOPE_CHECKS = {
    "complete":      None,  # None = run all
    "email_full":    {"dmarc", "mx", "spf", "dkim", "mta_sts", "tls_rpt", "bimi", "blacklist"},
    "dmarc":         {"dmarc", "spf", "dkim"},
    "transport":     {"mx", "mta_sts", "tls_rpt", "dane"},
    "dns_infra":     {"dnssec", "caa", "dane", "nameservers", "ct"},
    "security_scan": {"dmarc", "spf", "dkim", "dnssec", "dane", "ct", "blacklist", "caa", "mta_sts"},
}

# Checks that depend on MX raw results
_MX_DEPENDENTS = {"spf", "dkim", "mta_sts", "tls_rpt", "bimi", "dane", "blacklist"}
# Checks that depend on SPF raw results
_SPF_DEPENDENTS = {"dkim"}


def _should_include(check_key, scope_set):
    """Return True if this check's card should appear in results."""
    return scope_set is None or check_key in scope_set


# ============================================================
# DNS Helpers
# ============================================================

def _get_resolver(timeout: float = 5.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def _get_dnssec_resolver(timeout: float = 8.0):
    """
    Return a resolver configured for DNSSEC queries.

    Key differences from _get_resolver():
      - Sets the DO (DNSSEC OK) EDNS flag so the recursive resolver
        returns DNSKEY/RRSIG/DS records and sets the AD bit when
        validation succeeds.
      - Uses DNSSEC-validating public resolvers (Cloudflare primary,
        Google fallback) instead of the system default, which may be
        a stub resolver that strips DNSSEC data.
      - Larger EDNS buffer (4096) to handle DNSKEY responses which
        are often >512 bytes.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    # Use DNSSEC-validating public resolvers
    resolver.nameservers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"]
    # Set DO flag — without this, resolvers may not return DNSKEY/RRSIG
    resolver.use_edns(0, dns.flags.DO, 4096)
    return resolver


def _lookup_txt(name: str) -> List[str]:
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            parts = []
            for s in rdata.strings:
                parts.append(s.decode("utf-8") if isinstance(s, bytes) else str(s))
            txt = "".join(parts)
            # Some resolvers escape semicolons in TXT records (\;).
            # Normalize so downstream parsers split correctly.
            txt = txt.replace("\\;", ";")
            records.append(txt)
        return records
    except dns.exception.DNSException:
        return []


# ============================================================
# DMARC Report Service Map
# ============================================================

DMARC_REPORT_SERVICES = {
    "dmarcian.com": "dmarcian",
    "ag.dmarcian.com": "dmarcian",
    "valimail.com": "Valimail",
    "agari.com": "Agari",
    "easydmarc.com": "EasyDMARC",
    "postmarkapp.com": "Postmark",
    "dmarc.postmarkapp.com": "Postmark",
    "report-uri.com": "Report URI",
    "uriports.com": "URIports",
    "ondmarc.com": "Red Sift OnDMARC",
    "dmarc.service.gov.uk": "UK NCSC Mail Check",
}


# ============================================================
# DMARC Report Authorization Check (RFC 7489 S7.1)
# ============================================================

def _check_report_authorization(domain: str, raw_dmarc: Dict, tree_walk_result: Optional[Dict] = None) -> Optional[Dict]:
    """Check whether external DMARC report destinations are authorized.

    RFC 7489 S7.1: When rua/ruf points to an external domain, that domain
    must publish a TXT record at {audited}._report._dmarc.{dest} containing
    'v=DMARC1' to authorize report delivery. Without this, reports are
    silently dropped.
    """
    resolver = _get_resolver()
    destinations = []
    issues = []
    ruf_present = False

    # Determine org domain for external check
    org_domain = None
    if tree_walk_result and tree_walk_result.get("org_domain"):
        org_domain = tree_walk_result["org_domain"].lower().rstrip(".")
    else:
        # Simple 2-label suffix
        parts = domain.lower().rstrip(".").split(".")
        org_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()

    for tag_type in ("rua", "ruf"):
        raw_val = raw_dmarc.get(tag_type)
        if not raw_val:
            continue
        if tag_type == "ruf":
            ruf_present = True

        addrs = [a.strip() for a in raw_val.split(",") if a.strip()]
        for addr in addrs:
            email = addr.removeprefix("mailto:").removeprefix("MAILTO:")
            if "@" not in email:
                continue
            dest_domain = email.split("@", 1)[1].lower().rstrip(".")

            # External?
            is_external = dest_domain != org_domain and not dest_domain.endswith("." + org_domain)

            dest_info = {
                "type": tag_type,
                "address": email,
                "domain": dest_domain,
                "is_external": is_external,
                "authorization_record": None,
                "authorized": None,
                "has_mx": None,
                "service": None,
            }

            # Match against known services
            for svc_domain, svc_name in DMARC_REPORT_SERVICES.items():
                if dest_domain == svc_domain or dest_domain.endswith("." + svc_domain):
                    dest_info["service"] = svc_name
                    break

            if is_external:
                # Check authorization record
                auth_fqdn = f"{domain}._report._dmarc.{dest_domain}"
                dest_info["authorization_record"] = auth_fqdn
                try:
                    txt_records = _lookup_txt(auth_fqdn)
                    authorized = any(
                        r.strip().lower().startswith("v=dmarc")
                        for r in txt_records
                    )
                    dest_info["authorized"] = authorized
                except dns.exception.DNSException:
                    dest_info["authorized"] = False

                if not dest_info["authorized"]:
                    issues.append({
                        "severity": "error",
                        "issue": f"External report destination not authorized: {email}",
                        "plain_english": (
                            f"Reports sent to {email} will be silently dropped. "
                            f"RFC 7489 S7.1 requires {dest_domain} to publish a TXT record at "
                            f"{auth_fqdn} containing 'v=DMARC1' to authorize report delivery."
                        ),
                        "fix": (
                            f"Ask the administrator of {dest_domain} to add a TXT record at "
                            f"{auth_fqdn} with value: v=DMARC1"
                        ),
                    })
            else:
                dest_info["authorized"] = None  # same domain, no auth needed

            # Check MX for destination domain
            try:
                resolver.resolve(dest_domain, "MX")
                dest_info["has_mx"] = True
            except dns.exception.DNSException:
                dest_info["has_mx"] = False
                if is_external:
                    issues.append({
                        "severity": "warning",
                        "issue": f"Report destination has no MX: {dest_domain}",
                        "plain_english": (
                            f"The domain {dest_domain} has no MX records, meaning it may not be "
                            f"able to receive DMARC aggregate reports sent to {email}."
                        ),
                        "fix": f"Verify that {dest_domain} can receive email, or use a different report address.",
                    })

            destinations.append(dest_info)

    if ruf_present:
        issues.append({
            "severity": "info",
            "issue": "Forensic reporting (ruf) configured",
            "plain_english": (
                "Forensic reporting (ruf) is configured. Most mailbox providers no longer send "
                "failure reports because of PII concerns."
            ),
            "fix": "No action needed. ruf is optional and most providers do not honor it.",
        })

    if not destinations:
        return None

    return {
        "report_destinations": destinations,
        "report_auth_issues": issues,
        "ruf_provider_note": ruf_present,
    }


# ============================================================
# Classic DMARC Inheritance (RFC 7489 Section 6.6.3)
# ============================================================

def _get_org_domain(domain: str) -> Optional[str]:
    """Determine the Organizational Domain using the Public Suffix List.

    Per RFC 7489 Section 3.2, the Organizational Domain is the domain
    at one level below the Public Suffix. For example:
      mail.yahoo.com -> yahoo.com
      sub.example.co.uk -> example.co.uk
      yahoo.com -> yahoo.com (already the org domain)

    Uses tldextract if available; falls back to a lightweight heuristic
    that handles common two-part TLDs (co.uk, com.au, etc.).

    Returns None if the domain cannot be parsed.
    """
    if tldextract is not None:
        ext = tldextract.extract(domain)
        if not ext.domain or not ext.suffix:
            return None
        return f"{ext.domain}.{ext.suffix}"

    # Lightweight fallback: handle common two-part public suffixes
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return None

    _TWO_PART_TLDS = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz",
        "co.za", "org.za", "web.za",
        "com.br", "net.br", "org.br",
        "co.in", "net.in", "org.in", "gen.in",
        "com.mx", "org.mx", "gob.mx",
        "co.kr", "or.kr", "ne.kr",
        "com.cn", "net.cn", "org.cn",
        "com.tw", "org.tw", "net.tw",
        "co.il", "org.il", "net.il",
        "com.sg", "org.sg", "net.sg",
        "com.hk", "org.hk", "net.hk",
        "co.id", "or.id", "web.id",
        "com.ar", "org.ar", "net.ar",
        "com.tr", "org.tr", "net.tr",
        "co.th", "or.th", "in.th",
        "com.ph", "org.ph", "net.ph",
        "co.ke", "or.ke",
    }

    # Check if the last two labels form a known two-part TLD
    last_two = ".".join(labels[-2:])
    if last_two in _TWO_PART_TLDS:
        # Org domain is the label above the two-part TLD
        if len(labels) < 3:
            return None  # Already the org domain
        return ".".join(labels[-3:])
    else:
        # Standard TLD: org domain is the last two labels
        return ".".join(labels[-2:])


def _enrich_dmarc_inheritance(
    raw_dmarc: Dict,
    domain: str,
    tree_walk_result: Optional[Dict] = None,
) -> None:
    """Enrich raw DMARC result with inherited policy for subdomains.

    Implements RFC 7489 Section 6.6.3: if no DMARC record exists at the
    Author Domain, check the Organizational Domain (determined via PSL).

    Uses tree walk result first (if available), falls back to PSL-based
    org domain lookup. Modifies raw_dmarc in place, adding:
      - inherited_from: the domain that provided the policy
      - inherited_policy: the effective policy (sp= or p=)
      - inherited_record: the full DMARC record from the org domain
      - is_subdomain: True
      - inheritance_method: "tree_walk" or "psl" (for transparency)
    """
    if raw_dmarc.get("record"):
        return  # Has its own record, no inheritance needed

    # -- Try tree walk first (DMARCbis) --
    if (tree_walk_result
        and tree_walk_result.get("policy_source")
        and tree_walk_result.get("is_subdomain")):
        eff_policy = (tree_walk_result.get("effective_policy") or "").lower()
        if eff_policy:
            raw_dmarc["inherited_from"] = tree_walk_result["policy_source"]
            raw_dmarc["inherited_policy"] = eff_policy
            raw_dmarc["inherited_record"] = tree_walk_result.get("effective_record")
            raw_dmarc["is_subdomain"] = True
            raw_dmarc["applied_tag"] = tree_walk_result.get("applied_tag", "p")
            raw_dmarc["inheritance_method"] = "tree_walk"
            return

    # -- Fallback: classic RFC 7489 PSL-based org domain lookup --
    org_domain = _get_org_domain(domain)
    if not org_domain or org_domain.lower() == domain.lower():
        return  # Already the org domain, no inheritance possible

    org_recs = _lookup_txt(f"_dmarc.{org_domain}")
    org_dmarc = [r for r in org_recs if r.strip().lower().startswith("v=dmarc")]
    if len(org_dmarc) != 1:
        return  # No valid record (zero or multiple)

    org_record = org_dmarc[0].strip()
    # Parse tags from org domain record
    org_tags = {}
    for part in org_record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, val = part.partition("=")
            org_tags[key.strip().lower()] = val.strip()

    # Determine effective policy: sp= overrides p= for subdomains
    sp = org_tags.get("sp", "").lower()
    p = org_tags.get("p", "").lower()
    effective_policy = sp if sp else p

    if effective_policy:
        raw_dmarc["inherited_from"] = org_domain
        raw_dmarc["inherited_policy"] = effective_policy
        raw_dmarc["inherited_record"] = org_record
        raw_dmarc["is_subdomain"] = True
        raw_dmarc["applied_tag"] = "sp" if sp else "p"
        raw_dmarc["inheritance_method"] = "psl"


# ============================================================
# Individual Raw Checks (DMARC and SPF written fresh here)
# ============================================================

def _raw_check_dmarc(domain: str) -> Dict[str, Any]:
    """Check DMARC record with comprehensive syntax validation.

    Syntax checks based on:
      - dmarc.org "Common Problems With DMARC Records" (2016)
      - dmarcchecker.app top-1M domain study
      - RFC 7489 Section 6.3 (formal grammar)
      - dmarcian "Top 5 DMARC Deployment Mistakes"
    """
    import re

    VALID_POLICIES = {"none", "quarantine", "reject"}
    VALID_ADKIM_ASPF = {"r", "s"}
    VALID_FO = {"0", "1", "d", "s"}
    VALID_RF = {"afrf"}
    # Tags defined in DMARCbis (draft-ietf-dmarc-dmarcbis, Section 4.7)
    # np, psd, t are new; pct, rf, ri are removed from DMARCbis
    KNOWN_TAGS = {"v", "p", "sp", "np", "rua", "ruf", "adkim", "aspf", "fo", "psd", "t"}
    # Tags from RFC 7489 that DMARCbis removes — recognize but flag
    DEPRECATED_TAGS = {"pct", "rf", "ri"}

    result = {
        "check": "DMARC",
        "domain": domain,
        "record": None,
        "policy": None,
        "pct": None,
        "rua": None,
        "ruf": None,
        "sp": None,
        "np": None,
        "adkim": None,
        "aspf": None,
        "fo": None,
        "t": None,
        "psd": None,
        "status": "ok",
        "issues": [],
        "syntax_errors": [],
        "recommendations": [],
    }

    def _add_issue(severity, issue, plain_english, fix):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    def _add_syntax(issue, plain_english, fix):
        """Syntax errors are always severity=error."""
        result["syntax_errors"].append({
            "severity": "error",
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    # ── Step 1: Lookup ──────────────────────────────────────────
    dmarc_recs = _lookup_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in dmarc_recs if r.strip().lower().startswith("v=dmarc")]

    if not dmarc_records:
        result["status"] = "error"
        _add_issue(
            "error",
            "No DMARC record found",
            f"No DMARC record exists at '_dmarc.{domain}'. "
            "Since February 2024, Google and Yahoo require at least a DMARC record "
            "(even p=none) from bulk senders, and may throttle or deprioritize mail without one. "
            "You also have no aggregate reporting visibility into who is sending as your domain.",
            f"Publish a DMARC record at _dmarc.{domain} starting with p=none and an rua address for aggregate reporting.",
        )
        return result

    # ── Step 2: Multiple records = none valid (RFC 7489) ────────
    if len(dmarc_records) > 1:
        result["status"] = "error"
        _add_issue(
            "error",
            f"Multiple DMARC records found ({len(dmarc_records)})",
            "RFC 7489 requires exactly one DMARC record per domain. "
            "When multiple records exist, DMARC processing aborts entirely. "
            "None of them are valid. This is the same as having no DMARC at all.",
            "Remove duplicate DMARC records so only one remains.",
        )
        return result

    record = dmarc_records[0]
    result["record"] = record

    # ── Step 3: Structural / formatting syntax checks ───────────
    # These run BEFORE tag parsing because they can make parsing unreliable.

    # 3a. "DMARC" must be uppercase (dmarc.org: non-negotiable)
    # The version tag value is case-sensitive per RFC 7489 §6.3
    stripped = record.strip()
    if stripped.startswith("v=dmarc1") and not stripped.startswith("v=DMARC1"):
        _add_syntax(
            "Version tag 'DMARC' is not uppercase",
            "The DMARC specification requires 'DMARC1' in uppercase. "
            "Lowercase 'dmarc1' may be ignored by some receivers.",
            "Change to v=DMARC1 (uppercase).",
        )

    # 3b. Missing version number: v=DMARC instead of v=DMARC1
    if re.match(r"v=DMARC\s*[;]", stripped, re.IGNORECASE) or \
       stripped.upper().startswith("V=DMARC;") or \
       stripped.upper().rstrip() == "V=DMARC":
        _add_syntax(
            "Version tag missing '1': v=DMARC instead of v=DMARC1",
            "The record says 'v=DMARC' but is missing the required '1'. "
            "Receivers will not recognize this as a valid DMARC record.",
            "Change to v=DMARC1.",
        )

    # 3c. Separator errors (dmarc.org: colons, slashes, missing semicolons)
    # Check for colons used as separators (v=DMARC1: p=none: ...)
    if re.search(r"DMARC1\s*:", stripped, re.IGNORECASE):
        _add_syntax(
            "Colons used as tag separators instead of semicolons",
            "DMARC tags must be separated by semicolons (;), not colons (:). "
            "This record will not be parsed correctly by any receiver.",
            "Replace all colons between tags with semicolons.",
        )

    # Check for forward-slash separators (v=DMARC1/; p=none/;)
    if "/;" in record:
        _add_syntax(
            "Forward-slash characters before semicolons",
            "The record contains '/;' sequences, likely confusing forward-slash "
            "with backslash escaping. Receivers will not parse this correctly.",
            "Remove all forward-slash characters from the record.",
        )

    # Note: backslash-escaped semicolons (\;) are normalized in _lookup_txt
    # since they are a resolver artifact, not a real record issue.

    # Check for no separators at all (v=DMARC1 p=none pct=100)
    if ";" not in record and " p=" in record.lower():
        _add_syntax(
            "No semicolon separators between tags",
            "DMARC tags must be separated by semicolons. This record uses spaces "
            "only, which means receivers cannot parse the tags.",
            "Add semicolons between each tag: v=DMARC1; p=none; ...",
        )

    # 3e. Commas used as tag separators (dmarcchecker.app: bonkerscorner.com example)
    # Pattern: value, tag= (e.g., "adkim=r, aspf=r, pct=100")
    if re.search(r'=[^\s;,]+\s*,\s*[a-z]+=', record, re.IGNORECASE):
        _add_syntax(
            "Commas used as tag separators instead of semicolons",
            "DMARC tags must be separated by semicolons (;). Commas (,) are only "
            "valid inside rua/ruf tags to list multiple report addresses. "
            "Using commas between tags causes everything after the first comma "
            "to be misinterpreted or ignored.",
            "Replace commas between tags with semicolons.",
        )

    # 3f. Stray quotes wrapping the record
    if stripped.startswith('"') or stripped.startswith('\\"') or \
       stripped.startswith("'") or stripped.endswith('"') or stripped.endswith("'"):
        _add_syntax(
            "Record contains stray quotation marks",
            "The DMARC record has quote characters that are part of the DNS value. "
            "Quotes are used by some DNS interfaces for entry, but should not appear "
            "in the actual record data.",
            "Remove leading/trailing quotation marks from the DNS TXT value.",
        )

    # ── Step 4: Parse tags ──────────────────────────────────────
    tags = {}
    tag_positions = []  # Track order for v= and p= position checks
    seen_tags = {}      # Track duplicates

    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            key_clean = key.strip().lower()
            value_clean = value.strip()

            # Track tag order
            tag_positions.append(key_clean)

            # Check for duplicate tags
            if key_clean in seen_tags:
                _add_syntax(
                    f"Duplicate tag: '{key_clean}' appears multiple times",
                    f"The tag '{key_clean}' is defined more than once. "
                    "RFC 7489 does not define behavior for duplicate tags, so "
                    "different receivers may use different values, leading to unpredictable results.",
                    f"Remove the duplicate '{key_clean}' tag. Keep only one.",
                )
            seen_tags[key_clean] = value_clean

            # Check for unknown/misspelled tags
            if key_clean not in KNOWN_TAGS and key_clean not in DEPRECATED_TAGS:
                _add_syntax(
                    f"Unknown tag: '{key_clean}'",
                    f"The tag '{key_clean}' is not defined in the DMARC specification. "
                    "It will be ignored by receivers. This may be a typo "
                    "(e.g., 'plicy' instead of 'p', 'rau' instead of 'rua').",
                    f"Check spelling. Valid DMARC tags are: {', '.join(sorted(KNOWN_TAGS))}.",
                )
            elif key_clean in DEPRECATED_TAGS:
                # Tag-specific deprecation guidance per DMARCbis
                if key_clean == "pct":
                    _add_issue(
                        "warning",
                        "Deprecated tag: 'pct' (removed in DMARCbis)",
                        "The pct tag is removed in DMARCbis with no replacement. "
                        "The intended approach is to use p=none for monitoring, then move "
                        "directly to p=quarantine or p=reject. Current receivers still honor "
                        "pct, but DMARCbis-compliant receivers will ignore it.",
                        "Remove the pct tag. Use p=none for monitoring before moving to enforcement.",
                    )
                elif key_clean == "ri":
                    _add_issue(
                        "info",
                        "Deprecated tag: 'ri' (removed in DMARCbis)",
                        "The ri (report interval) tag is removed in DMARCbis. "
                        "It was rarely honored by receivers. Most send aggregate "
                        "reports on their own schedule regardless of ri.",
                        "Remove the ri tag. Report frequency is determined by receivers.",
                    )
                elif key_clean == "rf":
                    _add_issue(
                        "info",
                        "Deprecated tag: 'rf' (removed in DMARCbis)",
                        "The rf (report format) tag is removed in DMARCbis. "
                        "The only value ever defined was 'afrf', making the tag "
                        "redundant.",
                        "Remove the rf tag.",
                    )

            tags[key_clean] = value_clean
        else:
            # Fragment without '=' — could be bare mailto: or junk
            if "mailto:" in part.lower():
                _add_syntax(
                    f"Bare mailto: address without tag prefix",
                    "A 'mailto:' address appears without a rua= or ruf= tag prefix. "
                    "Receivers will ignore it and no reports will be sent.",
                    "Change to: rua=mailto:address@example.com",
                )

    # ── Step 5: Tag ordering checks ─────────────────────────────
    # 5a. v= must be first tag (RFC 7489 §6.3, dmarc.org)
    if tag_positions and tag_positions[0] != "v":
        _add_syntax(
            "Version tag (v=DMARC1) is not the first tag",
            "RFC 7489 requires v=DMARC1 to be the very first tag in the record. "
            "If it appears anywhere else, receivers may ignore the entire record.",
            "Move v=DMARC1 to the beginning of the record.",
        )

    # 5b. p= must immediately follow v= (dmarc.org, Valimail)
    if len(tag_positions) >= 2 and tag_positions[0] == "v" and tag_positions[1] != "p":
        _add_syntax(
            f"Policy tag (p=) is not the second tag (found '{tag_positions[1]}=' instead)",
            "RFC 7489 requires the policy tag (p=) to appear immediately after "
            "v=DMARC1. Some receivers may skip DMARC processing if this order "
            "is wrong.",
            "Move p= to be the second tag, right after v=DMARC1.",
        )

    # ── Step 6: Extract and validate individual tag values ──────

    # 6a. Policy (p=) — required tag
    raw_policy = tags.get("p", "")
    policy = raw_policy.lower()
    result["policy"] = policy

    if not raw_policy:
        # DMARCbis §4.10.1: If p= missing but rua= present, treat as p=none
        if tags.get("rua"):
            _add_issue(
                "warning",
                "Missing policy tag (p=). Treated as p=none per DMARCbis",
                "This record has no explicit policy tag. Because a rua= tag is present, "
                "DMARCbis-compliant receivers will treat this as p=none (monitoring only). "
                "However, some older receivers following RFC 7489 may ignore the record entirely.",
                "Add an explicit p=none (or p=quarantine / p=reject) to the record.",
            )
            policy = "none"
            result["policy"] = policy
        else:
            _add_syntax(
                "Missing required policy tag (p=) and no rua= tag",
                "Every DMARC record must include a policy tag. Without p= or rua=, "
                "receivers will ignore this record entirely. "
                "This is the same as having no DMARC record at all.",
                "Add a policy tag. Start with p=none for monitoring, and add "
                "rua=mailto:dmarc-reports@yourdomain.com to receive aggregate reports.",
            )
    elif policy not in VALID_POLICIES:
        # Check for common misspellings (dmarc.org dataset)
        suggestions = {
            "monitor": "p=monitor was used in early DMARC drafts but was replaced by p=none before publication.",
            "quarintine": "Misspelling of 'quarantine'.",
            "quarantaine": "Misspelling of 'quarantine'.",
            "quaranteen": "Misspelling of 'quarantine'.",
            "qurantine": "Misspelling of 'quarantine'.",
            "blocked": "'blocked' is not a valid DMARC policy.",
            "block": "'block' is not a valid DMARC policy.",
            "deny": "'deny' is not a valid DMARC policy.",
            "discard": "'discard' is not a valid DMARC policy.",
            "accept": "'accept' is not a valid DMARC policy.",
        }
        hint = suggestions.get(policy, "")
        extra = f" {hint}" if hint else ""
        _add_syntax(
            f"Invalid policy value: p={raw_policy}",
            f"'{raw_policy}' is not a valid DMARC policy.{extra} "
            "Only three values are allowed: none, quarantine, or reject.",
            "Change to p=none, p=quarantine, or p=reject.",
        )

    # 6b. Subdomain policy (sp=)
    raw_sp = tags.get("sp", "")
    sp = raw_sp.lower() if raw_sp else None
    result["sp"] = sp
    if raw_sp and sp not in VALID_POLICIES:
        _add_syntax(
            f"Invalid subdomain policy: sp={raw_sp}",
            f"'{raw_sp}' is not a valid subdomain policy. Same rules as p= apply.",
            "Change to sp=none, sp=quarantine, or sp=reject.",
        )

    # 6b2. Non-existent subdomain policy (np=) — DMARCbis §4.7
    raw_np = tags.get("np", "")
    np_val = raw_np.lower() if raw_np else None
    result["np"] = np_val
    if raw_np and np_val not in VALID_POLICIES:
        _add_syntax(
            f"Invalid non-existent subdomain policy: np={raw_np}",
            f"'{raw_np}' is not a valid np policy. Same rules as p= apply. "
            "The np tag controls policy for subdomains that don't exist in DNS.",
            "Change to np=none, np=quarantine, or np=reject.",
        )

    # 6b3. Test mode (t=) — DMARCbis §4.5
    raw_t = tags.get("t", "")
    if raw_t and raw_t.lower() not in ("y", "n"):
        _add_syntax(
            f"Invalid test mode value: t={raw_t}",
            "The t tag only accepts 'y' (testing) or 'n' (enforce). "
            f"'{raw_t}' is not valid.",
            "Use t=y to test (policy drops one level) or t=n / omit the tag to enforce.",
        )

    # 6b4. PSD flag (psd=) — DMARCbis §4.7
    raw_psd = tags.get("psd", "")
    if raw_psd and raw_psd.lower() not in ("y", "n", "u"):
        _add_syntax(
            f"Invalid PSD flag value: psd={raw_psd}",
            "The psd tag only accepts 'y' (is a PSD), 'n' (not a PSD, is an "
            "Organizational Domain), or 'u' (unknown/default). "
            f"'{raw_psd}' is not valid.",
            "Use psd=y, psd=n, or psd=u (or omit the tag; 'u' is the default).",
        )
    result["psd"] = raw_psd.lower() if raw_psd else None

    # 6c. rua (aggregate reports)
    raw_rua = tags.get("rua", "")
    result["rua"] = raw_rua if raw_rua else None
    if raw_rua:
        # Check each address has mailto: prefix
        rua_addrs = [a.strip() for a in raw_rua.split(",")]
        for addr in rua_addrs:
            if addr and not addr.lower().startswith("mailto:"):
                _add_issue(
                    "warning",
                    f"rua address missing 'mailto:' prefix: {addr}",
                    "DMARC requires report addresses to be written as URIs with "
                    "a mailto: prefix. Without it, receivers won't send aggregate "
                    "reports to this address, so you lose visibility.",
                    f"Change to: rua=mailto:{addr}",
                )

    # 6d. ruf (forensic reports)
    raw_ruf = tags.get("ruf", "")
    result["ruf"] = raw_ruf if raw_ruf else None
    if raw_ruf:
        ruf_addrs = [a.strip() for a in raw_ruf.split(",")]
        for addr in ruf_addrs:
            if addr and not addr.lower().startswith("mailto:"):
                _add_issue(
                    "warning",
                    f"ruf address missing 'mailto:' prefix: {addr}",
                    "DMARC requires report addresses to be written as URIs with "
                    "a mailto: prefix. Note: most mailbox providers no longer send "
                    "failure reports because of PII concerns, so this is low priority.",
                    f"Change to: ruf=mailto:{addr}",
                )

    # 6e. adkim (DKIM alignment)
    raw_adkim = tags.get("adkim", "")
    result["adkim"] = raw_adkim.lower() if raw_adkim else None
    if raw_adkim and raw_adkim.lower() not in VALID_ADKIM_ASPF:
        _add_syntax(
            f"Invalid adkim value: adkim={raw_adkim}",
            "DKIM alignment mode must be 'r' (relaxed) or 's' (strict). "
            f"'{raw_adkim}' is not valid.",
            "Change to adkim=r (relaxed, recommended) or adkim=s (strict).",
        )

    # 6f. aspf (SPF alignment)
    raw_aspf = tags.get("aspf", "")
    result["aspf"] = raw_aspf.lower() if raw_aspf else None
    if raw_aspf and raw_aspf.lower() not in VALID_ADKIM_ASPF:
        _add_syntax(
            f"Invalid aspf value: aspf={raw_aspf}",
            "SPF alignment mode must be 'r' (relaxed) or 's' (strict). "
            f"'{raw_aspf}' is not valid.",
            "Change to aspf=r (relaxed, recommended) or aspf=s (strict).",
        )

    # 6g. pct (percentage) — removed in DMARCbis
    # Still validate if present since current receivers still honor it
    raw_pct = tags.get("pct", "")
    if raw_pct:
        try:
            pct_val = int(raw_pct)
            if pct_val < 0 or pct_val > 100:
                _add_syntax(
                    f"pct value out of range: pct={raw_pct}",
                    "The pct tag must be an integer between 0 and 100.",
                    "Change to a value between 0 and 100.",
                )
                result["pct"] = pct_val  # Store it anyway for reporting
            else:
                result["pct"] = pct_val
        except (ValueError, TypeError):
            _add_syntax(
                f"pct is not a valid integer: pct={raw_pct}",
                f"The pct tag value '{raw_pct}' is not a number. "
                "Receivers will likely ignore this and default to 100.",
                "Change to a whole number between 0 and 100 (e.g., pct=100).",
            )
            result["pct"] = 100  # Default per RFC
    else:
        result["pct"] = 100  # Default per RFC 7489

    # 6h. fo (failure reporting options)
    raw_fo = tags.get("fo", "")
    result["fo"] = raw_fo if raw_fo else None
    if raw_fo:
        fo_values = [v.strip() for v in raw_fo.split(":")]
        for fv in fo_values:
            if fv and fv not in VALID_FO:
                _add_syntax(
                    f"Invalid fo value: '{fv}' in fo={raw_fo}",
                    "The fo tag only accepts: 0 (all fail), 1 (any fail), "
                    "d (DKIM fail), s (SPF fail). Values are colon-separated.",
                    "Use fo=1 (recommended; reports on any authentication failure).",
                )

    # 6i. rf (report format)
    raw_rf = tags.get("rf", "")
    if raw_rf and raw_rf.lower() not in VALID_RF:
        _add_syntax(
            f"Invalid report format: rf={raw_rf}",
            "The only valid report format is 'afrf' (Authentication Failure "
            "Reporting Format). This is also the default if rf is omitted.",
            "Remove the rf tag (afrf is the default) or set rf=afrf.",
        )

    # 6j. ri (reporting interval)
    raw_ri = tags.get("ri", "")
    if raw_ri:
        try:
            ri_val = int(raw_ri)
            if ri_val < 0:
                _add_syntax(
                    f"Negative reporting interval: ri={raw_ri}",
                    "The ri tag must be a positive integer (seconds).",
                    "Use ri=86400 (daily, the default) or remove the tag.",
                )
        except (ValueError, TypeError):
            _add_syntax(
                f"ri is not a valid integer: ri={raw_ri}",
                f"The ri tag value '{raw_ri}' is not a number.",
                "Use ri=86400 (daily) or remove the tag to use the default.",
            )

    # ── Step 7: Policy-level issues (warnings, not syntax errors) ──

    if policy == "none":
        _add_issue(
            "warning",
            "DMARC policy is none (monitoring only)",
            "Policy p=none instructs receivers to deliver all email normally, "
            "even when authentication fails. This is the correct first step because "
            "it lets you collect data via aggregate reports, but it provides "
            "no protection against spoofing. Failed emails still reach inboxes.",
            "Review aggregate reports to identify all legitimate senders, then "
            "upgrade to p=quarantine, and ultimately p=reject.",
        )
    elif policy == "quarantine":
        pct = result["pct"]
        if pct is not None and pct < 100:
            _add_issue(
                "warning",
                f"DMARC pct={pct}% (partial enforcement)",
                f"Only {pct}% of messages that fail authentication are quarantined. "
                f"The remaining {100 - pct}% are still delivered normally, as if "
                "the policy were p=none.",
                "Increase pct to 100 once you've confirmed legitimate mail is passing.",
            )
    elif policy == "reject":
        pct = result["pct"]
        if pct is not None and pct < 100:
            _add_issue(
                "warning",
                f"DMARC pct={pct}% on reject policy (partial enforcement)",
                f"Only {pct}% of messages that fail authentication are rejected. "
                f"The remaining {100 - pct}% fall back to quarantine behavior.",
                "Increase pct to 100 for full reject enforcement.",
            )

    # DMARCbis t=y test mode (drops policy one level for cautious deployment)
    raw_t_val = tags.get("t", "")
    result["t"] = raw_t_val.lower() if raw_t_val else None
    if raw_t_val and raw_t_val.lower() == "y" and policy in ("quarantine", "reject"):
        effective = "none" if policy == "quarantine" else "quarantine"
        _add_issue(
            "warning",
            f"DMARC test mode active (t=y). Policy effectively {effective}",
            f"The t=y tag (DMARCbis Section 4.5) signals receivers to apply the policy "
            f"one level below {policy}. Receivers treat this as p={effective}. "
            f"This is useful for cautious deployment of a new enforcement policy.",
            f"Remove t=y (or set t=n) once you're confident in your authentication "
            f"to apply the full p={policy} policy.",
        )

    # Missing rua — critical visibility gap
    if not result["rua"]:
        severity = "error" if policy in ("quarantine", "reject") else "warning"
        if policy in ("quarantine", "reject"):
            plain = (
                f"You are enforcing DMARC at p={policy} with no aggregate reporting. "
                "This means you're blocking or quarantining failed email but have no "
                "visibility into what's being affected. If a legitimate service fails "
                "authentication, you won't know until users report missing email."
            )
        else:
            plain = (
                "Without a rua tag, you receive no aggregate reports. You have no "
                "visibility into who is sending email as your domain or whether "
                "authentication is passing or failing."
            )
        _add_issue(
            severity,
            "No aggregate reporting (rua) configured",
            plain,
            f"Add rua=mailto:dmarc-reports@{domain}, or use a DMARC reporting "
            "service like dmarcian, EasyDMARC, or Valimail for readable dashboards.",
        )

    # ── Step 8: Merge syntax errors into issues and set final status ──
    # Syntax errors are always severity=error and go into the main issues list
    for se in result["syntax_errors"]:
        result["issues"].append(se)

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    return result


def _raw_check_spf(domain: str) -> Dict[str, Any]:
    """Check SPF record with lookup counting, mechanism analysis, and syntax validation.

    Syntax checks based on:
      - RFC 7208 (SPF specification)
      - openspf.org common errors
      - dmarc.org / dmarcian deployment guidance
    """
    import re
    import ipaddress

    # Known mechanisms that consume a DNS lookup (RFC 7208 §4.6.4)
    LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
    # Known mechanisms/modifiers (anything else is likely a typo)
    KNOWN_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
    KNOWN_MODIFIERS = {"redirect", "exp"}

    result = {
        "check": "SPF",
        "domain": domain,
        "record": None,
        "all_mechanism": None,
        "lookup_count": 0,
        "include_count": 0,
        "ip4_count": 0,
        "ip6_count": 0,
        "mechanisms": [],
        "status": "ok",
        "issues": [],
        "syntax_errors": [],
        "recommendations": [],
    }

    def _add_issue(severity, issue, plain_english, fix):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    def _add_syntax(issue, plain_english, fix):
        """Syntax errors are always severity=error."""
        result["syntax_errors"].append({
            "severity": "error",
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    # ── Step 1: Lookup ──────────────────────────────────────────
    all_txt = _lookup_txt(domain)
    spf_records = [r for r in all_txt if r.strip().lower().startswith("v=spf1")]

    if not spf_records:
        result["status"] = "error"
        _add_issue(
            "error",
            "No SPF record found",
            "No SPF record tells receivers which servers can send your email.",
            f"Publish an SPF record at {domain} listing your authorized sending servers.",
        )
        return result

    # ── Step 2: Multiple records = permerror (RFC 7208) ─────────
    if len(spf_records) > 1:
        result["status"] = "error"
        _add_issue(
            "error",
            f"Multiple SPF records ({len(spf_records)})",
            "RFC 7208 requires exactly one SPF record per domain. "
            "When multiple records exist, receiving servers return a PermError and "
            "ignore both records. Your legitimate mail will fail SPF authentication. "
            "Merge all authorized IP addresses and includes into a single v=spf1 record.",
            "Merge all SPF records into one. Combine all authorized IPs and includes into a single v=spf1 string.",
        )
        return result

    record = spf_records[0]
    result["record"] = record

    # ── Step 3: Parse mechanisms and run syntax checks ──────────
    parts = record.split()
    all_mech = None
    include_count = 0
    ip4_count = 0
    ip6_count = 0
    has_redirect = False
    has_all = False
    seen_mechanisms = []

    for part in parts:
        # Skip the version tag
        if part.lower() == "v=spf1":
            continue

        # Strip qualifier prefix (+, -, ~, ?)
        qualifier = ""
        raw = part
        if raw and raw[0] in "+-~?":
            qualifier = raw[0]
            raw = raw[1:]

        raw_lower = raw.lower()

        # ── Check for spaces in mechanism syntax ────────────
        # Spaces between mechanism, colon, and value break parsing.
        # This is detected at the record level since split() already
        # separates on spaces. A token like "ip4:" with no value means
        # the value ended up as a separate token.
        if raw_lower.rstrip(":") in ("ip4", "ip6", "include", "exists", "a", "mx") and raw.endswith(":"):
            _add_syntax(
                f"Space after '{raw}' separates it from its value",
                f"'{part}' has a colon but no value. There may be a space between "
                "the mechanism and its argument. SPF mechanisms cannot have spaces "
                "between the name, colon, and value.",
                f"Remove the space: write as one token, e.g., ip4:1.2.3.4",
            )

        # ── Identify mechanism type ─────────────────────────
        if "=" in raw_lower:
            # Modifier (redirect=, exp=)
            mod_name, _, mod_value = raw.partition("=")
            mod_name_lower = mod_name.lower()

            if mod_name_lower == "redirect":
                has_redirect = True
                if not mod_value:
                    _add_syntax(
                        "Empty redirect= modifier (no domain specified)",
                        "The redirect= modifier has no domain value. "
                        "SPF will not know where to redirect lookups.",
                        "Specify a domain: redirect=_spf.example.com",
                    )
            elif mod_name_lower == "exp":
                pass  # exp= is informational, no validation needed
            elif mod_name_lower not in KNOWN_MODIFIERS:
                _add_syntax(
                    f"Unknown modifier: '{mod_name}'",
                    f"'{mod_name}' is not a recognized SPF modifier. "
                    "It may be a typo or misplaced DMARC/DKIM tag.",
                    f"Valid SPF modifiers are: redirect, exp.",
                )

        elif ":" in raw_lower:
            # Mechanism with value (include:, ip4:, ip6:, a:, mx:, etc.)
            mech_name, _, mech_value = raw.partition(":")
            mech_name_lower = mech_name.lower()

            if mech_name_lower == "include":
                include_count += 1
                if not mech_value:
                    _add_syntax(
                        "Empty include: mechanism (no domain specified)",
                        "An include: mechanism has no domain. SPF cannot look up "
                        "an empty domain. This wastes a DNS lookup and always fails.",
                        "Add a domain or remove the empty include.",
                    )
                seen_mechanisms.append(part)

            elif mech_name_lower == "ip4":
                ip4_count += 1
                # Validate IP address
                try:
                    if "/" in mech_value:
                        net = ipaddress.IPv4Network(mech_value, strict=False)
                        prefix = net.prefixlen
                        if prefix <= 16:
                            _add_issue(
                                "warning",
                                f"Overly broad SPF range: ip4:{mech_value} (/{prefix} = {net.num_addresses:,} addresses)",
                                f"This authorizes {net.num_addresses:,} IP addresses to send as your domain. "
                                "Broad ranges weaken SPF by authorizing far more servers than intended.",
                                "Narrow the range to only the IPs your mail servers actually use.",
                            )
                    else:
                        ipaddress.IPv4Address(mech_value)
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                    _add_syntax(
                        f"Invalid IPv4 address: ip4:{mech_value}",
                        f"'{mech_value}' is not a valid IPv4 address or CIDR range.",
                        "Use a valid IP like ip4:192.0.2.1 or range like ip4:192.0.2.0/24.",
                    )
                seen_mechanisms.append(part)

            elif mech_name_lower == "ip6":
                ip6_count += 1
                try:
                    if "/" in mech_value:
                        net = ipaddress.IPv6Network(mech_value, strict=False)
                        prefix = net.prefixlen
                        if prefix <= 48:
                            _add_issue(
                                "warning",
                                f"Overly broad SPF range: ip6:{mech_value} (/{prefix})",
                                f"This IPv6 range is very broad and authorizes a large number of addresses.",
                                "Narrow the range to only the IPs your mail servers actually use.",
                            )
                    else:
                        ipaddress.IPv6Address(mech_value)
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                    _add_syntax(
                        f"Invalid IPv6 address: ip6:{mech_value}",
                        f"'{mech_value}' is not a valid IPv6 address or CIDR range.",
                        "Use a valid IPv6 address like ip6:2001:db8::1 or range like ip6:2001:db8::/32.",
                    )
                seen_mechanisms.append(part)

            elif mech_name_lower == "ptr":
                _add_issue(
                    "warning",
                    f"Deprecated 'ptr' mechanism: {part}",
                    "The ptr mechanism is discouraged by RFC 7208 because it is slow and places "
                    "a burden on reverse DNS infrastructure. Receivers must still process it, but "
                    "its use is unreliable in practice.",
                    "Remove the ptr mechanism. Use ip4:/ip6: or include: instead.",
                )
                seen_mechanisms.append(part)

            elif mech_name_lower in KNOWN_MECHANISMS:
                seen_mechanisms.append(part)

            else:
                _add_syntax(
                    f"Unknown mechanism: '{mech_name}'",
                    f"'{mech_name}' is not a recognized SPF mechanism. "
                    "This may be a typo (e.g., 'inclde' instead of 'include').",
                    f"Valid mechanisms: {', '.join(sorted(KNOWN_MECHANISMS))}.",
                )

        else:
            # Bare mechanism (all, a, mx, ptr)
            mech_lower = raw_lower

            if mech_lower == "all":
                has_all = True
                effective_qualifier = qualifier if qualifier else "+"
                all_mech = effective_qualifier + "all"

            elif mech_lower == "ptr":
                _add_issue(
                    "warning",
                    "Deprecated 'ptr' mechanism",
                    "The ptr mechanism is discouraged by RFC 7208 because it is slow and places "
                    "a burden on reverse DNS infrastructure. Receivers must still process it, but "
                    "its use is unreliable in practice.",
                    "Remove the ptr mechanism. Use ip4:/ip6: or include: instead.",
                )
                seen_mechanisms.append(part)

            elif mech_lower in KNOWN_MECHANISMS:
                seen_mechanisms.append(part)

            elif mech_lower not in KNOWN_MECHANISMS:
                # Unknown bare token
                _add_syntax(
                    f"Unknown mechanism: '{raw}'",
                    f"'{raw}' is not a recognized SPF mechanism or modifier.",
                    f"Valid mechanisms: {', '.join(sorted(KNOWN_MECHANISMS))}.",
                )

    # ── Step 4: Cross-mechanism checks ──────────────────────────

    # redirect= is ignored when 'all' is present (common misconfiguration)
    if has_redirect and has_all:
        _add_issue(
            "warning",
            "Both 'redirect=' and 'all' present. Redirect is ignored",
            "When an SPF record contains both a redirect= modifier and an 'all' "
            "mechanism, the redirect is ignored entirely. The 'all' mechanism "
            "takes precedence. If you intended to redirect SPF evaluation to "
            "another domain, the 'all' mechanism is preventing that.",
            "Remove either redirect= or the 'all' mechanism, depending on your intent.",
        )

    # ── Step 5: Recursive SPF lookup count ──────────────────────
    spf_recursive_result = count_spf_lookups(domain)
    lookup_count = spf_recursive_result["total_lookups"]

    result["lookup_count"] = lookup_count
    result["include_count"] = include_count
    result["ip4_count"] = ip4_count
    result["ip6_count"] = ip6_count
    result["all_mechanism"] = all_mech
    result["has_redirect"] = has_redirect
    result["spf_chain"] = spf_recursive_result.get("chain", [])
    result["spf_recursive"] = spf_recursive_result

    # ── Step 6: Lookup limit checks ─────────────────────────────
    if lookup_count > 10:
        _add_issue(
            "error",
            f"SPF exceeds 10-lookup limit ({lookup_count} lookups)",
            "RFC 7208 limits SPF to 10 DNS lookups. Exceeding this causes "
            "SPF to return a permanent error (permerror). It fails entirely, "
            "as if no SPF record existed.",
            "Audit your includes and remove services you no longer use. Consolidate senders where possible.",
        )
    elif lookup_count == 10:
        _add_issue(
            "warning",
            "SPF is at the 10-lookup limit",
            "Adding any more includes or mechanisms that require DNS lookups "
            "will push SPF over the limit, causing it to fail entirely.",
            "Audit your includes and remove any services you no longer use to free up lookup slots.",
        )

    # ── Step 7: 'all' mechanism checks ──────────────────────────
    if all_mech == "+all":
        _add_issue(
            "error",
            "SPF uses +all (authorizes everyone)",
            "The +all mechanism authorizes the entire internet to send email "
            "as your domain. This completely defeats the purpose of SPF.",
            "Change +all to -all (hard fail) or ~all (soft fail).",
        )
    elif all_mech == "?all":
        _add_issue(
            "warning",
            "SPF uses ?all (neutral)",
            "The ?all mechanism provides no opinion about unauthorized senders. "
            "It does not protect your domain from spoofing.",
            "Change ?all to -all or ~all.",
        )
    elif not all_mech and not has_redirect:
        _add_issue(
            "warning",
            "No 'all' mechanism found",
            "SPF records should end with an 'all' mechanism to define what happens "
            "to mail from servers not listed in the record. Without it, the default "
            "is neutral (?all), which provides no protection.",
            "Add -all to the end of the SPF record.",
        )

    # ── Step 8: Merge syntax errors into issues and set final status ──
    for se in result["syntax_errors"]:
        result["issues"].append(se)

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    return result


def _raw_check_dnssec(domain: str) -> Dict[str, Any]:
    """Check DNSSEC configuration including algorithms and chain validation hints.

    Checks based on:
      - RFC 4035 (DNSSEC Protocol Modifications)
      - RFC 8624 (Algorithm Implementation Requirements)
      - NIST SP 800-81-2 (Secure DNS Deployment Guide)
    """
    # Algorithm names per IANA registry
    DNSSEC_ALGORITHMS = {
        1: "RSA/MD5 (deprecated, insecure)",
        3: "DSA/SHA-1 (deprecated)",
        5: "RSA/SHA-1 (legacy, avoid for new deployments)",
        6: "DSA-NSEC3-SHA1 (deprecated)",
        7: "RSASHA1-NSEC3-SHA1 (legacy)",
        8: "RSA/SHA-256 (recommended)",
        10: "RSA/SHA-512 (strong)",
        13: "ECDSA P-256/SHA-256 (recommended, modern)",
        14: "ECDSA P-384/SHA-384 (strong)",
        15: "Ed25519 (recommended, modern)",
        16: "Ed448 (strong)",
    }
    DEPRECATED_ALGORITHMS = {1, 3, 6}
    LEGACY_ALGORITHMS = {5, 7}

    result = {
        "has_dnssec": False,
        "algorithms": [],
        "key_count": 0,
        "has_ds": False,
        "ds_algorithms": [],
        "issues": [],
        "status": "ok",
    }

    def _add_issue(severity, issue, plain_english, fix):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    resolver = _get_dnssec_resolver()

    # Check DNSKEY records
    try:
        dnskey_answers = resolver.resolve(domain, "DNSKEY")
        result["has_dnssec"] = True
        result["key_count"] = len(dnskey_answers)

        # Check if the recursive resolver validated the chain (AD flag)
        ad_flag = bool(dnskey_answers.response.flags & dns.flags.AD)
        result["validated"] = ad_flag

        seen_algos = set()
        for rdata in dnskey_answers:
            algo_num = rdata.algorithm
            seen_algos.add(algo_num)

        for algo in sorted(seen_algos):
            algo_name = DNSSEC_ALGORITHMS.get(algo, f"Unknown ({algo})")
            result["algorithms"].append({
                "number": algo,
                "name": algo_name,
                "deprecated": algo in DEPRECATED_ALGORITHMS,
                "legacy": algo in LEGACY_ALGORITHMS,
            })

            if algo in DEPRECATED_ALGORITHMS:
                _add_issue(
                    "error",
                    f"Deprecated DNSSEC algorithm: {algo_name}",
                    f"Algorithm {algo} ({algo_name}) is deprecated and considered insecure. "
                    "Attackers may be able to forge DNSSEC signatures using this algorithm.",
                    "Migrate to algorithm 13 (ECDSA P-256) or 8 (RSA/SHA-256).",
                )
            elif algo in LEGACY_ALGORITHMS:
                _add_issue(
                    "warning",
                    f"Legacy DNSSEC algorithm: {algo_name}",
                    f"Algorithm {algo} is functional but not recommended for new deployments. "
                    "Modern algorithms offer better security and smaller signatures.",
                    "Consider migrating to algorithm 13 (ECDSA P-256) for better performance and security.",
                )
    except dns.resolver.NoAnswer:
        result["has_dnssec"] = False
    except dns.resolver.NXDOMAIN:
        result["has_dnssec"] = False
        _add_issue(
            "error",
            "Domain does not exist (NXDOMAIN)",
            "The domain returned NXDOMAIN when querying for DNSKEY records.",
            "Verify the domain name is correct and DNS is properly configured.",
        )
    except dns.resolver.LifetimeTimeout:
        # Timeout is NOT evidence of no DNSSEC — could be large DNSKEY response
        result["has_dnssec"] = False
        _add_issue(
            "warning",
            "DNSSEC check timed out",
            "The DNSKEY query timed out. This does not necessarily mean DNSSEC is "
            "unconfigured. Large DNSKEY responses can exceed typical timeouts.",
            "Try checking with 'delv' or 'dig +dnssec' for a definitive answer.",
        )
    except dns.exception.DNSException as e:
        result["has_dnssec"] = False
        _add_issue(
            "warning",
            f"DNSSEC check error: {type(e).__name__}",
            f"Could not determine DNSSEC status due to a resolver error. "
            "This may be a transient issue, not proof that DNSSEC is absent.",
            "Retry or verify manually with 'delv' or 'dig +dnssec DNSKEY <domain>'.",
        )

    # Check DS records at the parent (proves the chain is anchored)
    # DS records ONLY exist at the parent zone — child nameservers never serve them.
    # Strategy:
    #   Method 1: Direct DS query via recursive resolver (works when resolver is smart)
    #   Method 2: Query parent NS directly via dns.query.udp (no delegation following)
    #   Method 3: AD flag on DNSKEY response = chain already validated by resolver
    ds_found = False
    ds_algos = set()

    # Method 1: Direct DS query via recursive resolver
    for attempt_resolver in [resolver, _get_dnssec_resolver(timeout=12.0)]:
        if ds_found:
            break
        try:
            ds_answers = attempt_resolver.resolve(domain, "DS")
            ds_found = True
            for rdata in ds_answers:
                ds_algos.add(rdata.algorithm)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException:
            continue

    # Method 2: Query parent zone NS directly with dns.query.udp
    # This bypasses any delegation — we talk directly to the parent NS
    # which is the ONLY zone that holds the DS record.
    if not ds_found:
        try:
            parts = domain.split(".")
            if len(parts) >= 2:
                # Parent zone: for "example.com" -> "com", for "sub.example.com" -> "example.com"
                parent = ".".join(parts[1:])

                parent_resolver = _get_dnssec_resolver(timeout=10.0)
                parent_ns_answers = parent_resolver.resolve(parent, "NS")
                parent_ns_ips = []
                for ns_rdata in parent_ns_answers:
                    ns_name = str(ns_rdata.target)
                    try:
                        a_answers = parent_resolver.resolve(ns_name, "A")
                        for a_rdata in a_answers:
                            parent_ns_ips.append(str(a_rdata.address))
                    except dns.exception.DNSException:
                        pass

                # Build a raw DS query with DO flag and send directly to parent NS
                if parent_ns_ips:

                    ds_query = dns.message.make_query(
                        domain, dns.rdatatype.DS, want_dnssec=True
                    )
                    ds_query.flags |= dns.flags.RD  # ask for recursion just in case

                    for ns_ip in parent_ns_ips[:4]:
                        if ds_found:
                            break
                        try:
                            response = dns.query.udp(ds_query, ns_ip, timeout=8.0)
                            # Check for DS records in the answer section
                            for rrset in response.answer:
                                if rrset.rdtype == dns.rdatatype.DS:
                                    ds_found = True
                                    for rdata in rrset:
                                        ds_algos.add(rdata.algorithm)
                                    break
                        except (dns.exception.DNSException, OSError):
                            continue

                    # If UDP failed (possible truncation), try TCP
                    if not ds_found:
                        for ns_ip in parent_ns_ips[:2]:
                            if ds_found:
                                break
                            try:
                                response = dns.query.tcp(ds_query, ns_ip, timeout=10.0)
                                for rrset in response.answer:
                                    if rrset.rdtype == dns.rdatatype.DS:
                                        ds_found = True
                                        for rdata in rrset:
                                            ds_algos.add(rdata.algorithm)
                                        break
                            except (dns.exception.DNSException, OSError):
                                continue
        except (dns.exception.DNSException, OSError):
            pass

    # Method 3: If DNSKEY query had AD flag set, the chain is validated
    # (meaning DS must exist even if we couldn't fetch it directly)
    if not ds_found and result.get("validated"):
        ds_found = True  # AD flag proves the chain is complete

    if ds_found:
        result["has_ds"] = True
        result["ds_algorithms"] = sorted(ds_algos)
    else:
        if result["has_dnssec"]:
            _add_issue(
                "warning",
                "DNSKEY exists but no DS record found at parent",
                "DNSSEC keys are published but may not be anchored in the parent zone. "
                "Without a DS record at the parent, resolvers cannot validate the chain of trust.",
                "Add a DS record at your domain registrar pointing to your DNSKEY.",
            )

    # DS-to-DNSKEY chain of trust verification
    # Verify that the DS digest actually matches a published DNSKEY
    result["chain_valid"] = None
    result["chain_details"] = []

    if ds_found and result["has_dnssec"]:
        try:
            # Re-fetch DS records for digest comparison
            ds_records = []
            for attempt_resolver in [resolver, _get_dnssec_resolver(timeout=12.0)]:
                try:
                    ds_answers = attempt_resolver.resolve(domain, "DS")
                    ds_records = list(ds_answers)
                    break
                except dns.exception.DNSException:
                    continue

            # Re-fetch DNSKEYs
            dnskey_records = []
            try:
                dnskey_answers = resolver.resolve(domain, "DNSKEY")
                dnskey_records = list(dnskey_answers)
            except dns.exception.DNSException:
                pass

            if ds_records and dnskey_records:
                chain_matched = False
                for ds_rdata in ds_records:
                    ds_key_tag = ds_rdata.key_tag
                    for dnskey_rdata in dnskey_records:
                        try:
                            computed_key_id = dns.dnssec.key_id(dnskey_rdata)
                            if computed_key_id != ds_key_tag:
                                continue
                            # Key tag matches -- now verify digest
                            domain_name = dns.name.from_text(domain)
                            computed_ds = dns.dnssec.make_ds(
                                domain_name, dnskey_rdata, ds_rdata.digest_type
                            )
                            if computed_ds.digest == ds_rdata.digest:
                                chain_matched = True
                                algo_name = DNSSEC_ALGORITHMS.get(
                                    dnskey_rdata.algorithm,
                                    f"Algorithm {dnskey_rdata.algorithm}",
                                )
                                result["chain_details"].append(
                                    f"DS key_tag={ds_key_tag} matches DNSKEY ({algo_name})"
                                )
                                break
                        except (dns.dnssec.UnsupportedAlgorithm, dns.dnssec.ValidationFailure, ValueError, TypeError):
                            # UnsupportedAlgorithm or other -- skip this pair
                            continue
                    if chain_matched:
                        break

                result["chain_valid"] = chain_matched
                if not chain_matched:
                    _add_issue(
                        "error",
                        "DS digest does NOT match any DNSKEY (broken chain of trust)",
                        "The DS record at the parent zone does not match any of the published "
                        "DNSKEY records. This means DNSSEC validation will fail for all resolvers, "
                        "potentially making the domain unresolvable for DNSSEC-validating clients.",
                        "Re-generate the DS record from your current DNSKEY and update it at your registrar.",
                    )
        except Exception as e:
            log.debug("DNSSEC chain verification error: %s", e)
            result["chain_valid"] = None

    # Set final status
    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    return result


def _raw_check_caa(domain: str) -> Dict[str, Any]:
    """Check CAA (Certification Authority Authorization) records.

    Checks based on:
      - RFC 8659 (DNS Certification Authority Authorization)
      - CA/Browser Forum Ballot SC-54
      - Let's Encrypt CAA documentation
    """
    result = {
        "check": "CAA",
        "domain": domain,
        "records": [],
        "record_count": 0,
        "has_issue": False,
        "has_issuewild": False,
        "has_iodef": False,
        "authorized_cas": [],
        "wildcard_cas": [],
        "iodef_destinations": [],
        "issues": [],
        "status": "ok",
    }

    def _add_issue(severity, issue, plain_english, fix):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    resolver = _get_resolver()

    try:
        answers = resolver.resolve(domain, "CAA")
        raw_records = []
        for rdata in answers:
            flags = rdata.flags
            tag = rdata.tag.decode("utf-8") if isinstance(rdata.tag, bytes) else str(rdata.tag)
            value = rdata.value.decode("utf-8") if isinstance(rdata.value, bytes) else str(rdata.value)
            raw_records.append({
                "flags": flags,
                "tag": tag,
                "value": value,
                "raw": f'{flags} {tag} "{value}"',
            })

            if tag == "issue":
                result["has_issue"] = True
                if value and value != ";":
                    # Extract CA name (strip any parameters after ;)
                    ca_name = value.split(";")[0].strip()
                    if ca_name:
                        result["authorized_cas"].append(ca_name)
            elif tag == "issuewild":
                result["has_issuewild"] = True
                if value and value != ";":
                    ca_name = value.split(";")[0].strip()
                    if ca_name:
                        result["wildcard_cas"].append(ca_name)
            elif tag == "iodef":
                result["has_iodef"] = True
                result["iodef_destinations"].append(value)

            # Check for unknown critical flags
            if flags & 0x80:  # Issuer Critical flag
                if tag not in ("issue", "issuewild", "iodef"):
                    _add_issue(
                        "warning",
                        f"Unknown critical CAA tag: {tag}",
                        f"The tag '{tag}' has the critical flag set but is not a standard CAA tag. "
                        "CAs that do not understand this tag must refuse to issue certificates.",
                        "Verify this tag is intentional. Standard tags are: issue, issuewild, iodef.",
                    )

        result["records"] = raw_records
        result["record_count"] = len(raw_records)

        # Validation checks
        if result["has_issue"] and not result["authorized_cas"]:
            # issue ";" means no CA is authorized -- intentional lockdown
            _add_issue(
                "info",
                "CAA restricts all certificate issuance (issue \";\")",
                "No Certificate Authority is authorized to issue certificates for this domain. "
                "This is a deliberate security lockdown. New certificate requests will be refused.",
                "If you need certificates issued, add a CAA issue record for your CA (e.g., letsencrypt.org).",
            )

        if result["has_issue"] and not result["has_issuewild"]:
            _add_issue(
                "info",
                "No issuewild restriction",
                "CAA controls regular certificate issuance but does not separately restrict "
                "wildcard certificates. Wildcard issuance falls back to the issue tag. "
                "Adding issuewild gives you explicit control over wildcard certificates.",
                f'Add a CAA record: 0 issuewild "yourca.com" or 0 issuewild ";" to block wildcard issuance.',
            )

        if result["has_issue"] and not result["has_iodef"]:
            _add_issue(
                "info",
                "No CAA violation reporting (iodef)",
                "Without an iodef record, you will not be notified if a Certificate Authority "
                "receives a certificate request that violates your CAA policy.",
                f'Add a CAA record: 0 iodef "mailto:security@{domain}" to receive violation reports.',
            )

    except dns.resolver.NoAnswer:
        # No CAA records -- check parent domain
        pass
    except dns.resolver.NXDOMAIN:
        _add_issue(
            "error",
            "Domain does not exist (NXDOMAIN)",
            "The domain returned NXDOMAIN when querying for CAA records.",
            "Verify the domain name is correct.",
        )
    except dns.exception.DNSException:
        pass

    # No CAA records found at all
    if result["record_count"] == 0:
        _add_issue(
            "warning",
            "No CAA records published",
            "Without CAA records, any Certificate Authority in the world can issue "
            "SSL/TLS certificates for your domain. CAA lets you restrict issuance to "
            "only the CAs you actually use, reducing the risk of unauthorized certificates.",
            f'Add a CAA record: 0 issue "letsencrypt.org" (replace with your CA). '
            f'Add 0 iodef "mailto:security@{domain}" for violation alerts.',
        )

    # Set final status
    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"
    elif result["record_count"] > 0 and result["has_issue"]:
        result["status"] = "ok"

    return result


def _raw_check_nameservers(domain: str) -> Dict[str, Any]:
    """Check nameserver configuration for redundancy and network diversity.

    Checks based on:
      - RFC 1034/1035 (DNS specification)
      - RFC 2182 (Selection and Operation of Secondary DNS Servers)
      - NIST SP 800-81-2 (Secure DNS Deployment Guide)
    """
    import ipaddress

    result = {
        "check": "Nameservers",
        "domain": domain,
        "nameservers": [],
        "ns_count": 0,
        "providers": [],
        "networks": [],
        "issues": [],
        "status": "ok",
    }

    def _add_issue(severity, issue, plain_english, fix):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    resolver = _get_resolver()

    # Look up NS records
    try:
        ns_answers = resolver.resolve(domain, "NS")
    except dns.resolver.NoAnswer:
        _add_issue(
            "error",
            "No NS records found",
            "No nameserver records were returned for this domain. "
            "This is a fundamental DNS configuration issue.",
            "Configure NS records with your domain registrar.",
        )
        result["status"] = "error"
        return result
    except dns.resolver.NXDOMAIN:
        _add_issue(
            "error",
            "Domain does not exist (NXDOMAIN)",
            "The domain returned NXDOMAIN when querying for nameservers.",
            "Verify the domain name is correct.",
        )
        result["status"] = "error"
        return result
    except dns.exception.DNSException as e:
        _add_issue(
            "error",
            f"NS lookup failed: {str(e)[:100]}",
            "Could not retrieve nameserver records. This may be a temporary DNS issue.",
            "Try again later. If persistent, check your DNS configuration.",
        )
        result["status"] = "error"
        return result

    ns_hostnames = []
    for rdata in ns_answers:
        ns_hostnames.append(str(rdata.target).rstrip("."))

    result["ns_count"] = len(ns_hostnames)

    # Resolve each NS to get IP addresses and check reachability
    all_ips = []
    networks_v4 = set()
    ns_details = []

    for ns_host in sorted(ns_hostnames):
        ns_info = {
            "hostname": ns_host,
            "ipv4": [],
            "ipv6": [],
            "resolves": False,
        }

        # Resolve A records
        try:
            a_answers = resolver.resolve(ns_host, "A")
            for rdata in a_answers:
                ip_str = str(rdata)
                ns_info["ipv4"].append(ip_str)
                all_ips.append(ip_str)
                ns_info["resolves"] = True
                try:
                    net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                    networks_v4.add(str(net))
                except (ValueError, TypeError):
                    pass
        except dns.exception.DNSException:
            pass

        # Resolve AAAA records
        try:
            aaaa_answers = resolver.resolve(ns_host, "AAAA")
            for rdata in aaaa_answers:
                ns_info["ipv6"].append(str(rdata))
                ns_info["resolves"] = True
        except dns.exception.DNSException:
            pass

        ns_details.append(ns_info)

    result["nameservers"] = ns_details
    result["networks"] = list(networks_v4)

    # Authoritative response testing -- query each NS directly for SOA
    import time as _time
    auth_results = []
    soa_serials = {}

    for ns_info in ns_details:
        if not ns_info["resolves"]:
            continue
        # Use first IPv4 address for the query
        ns_ip = ns_info["ipv4"][0] if ns_info["ipv4"] else (ns_info["ipv6"][0] if ns_info["ipv6"] else None)
        if not ns_ip:
            continue
        try:
            soa_query = dns.message.make_query(domain, dns.rdatatype.SOA)
            soa_query.flags &= ~dns.flags.RD  # RD=0 for authoritative test
            t0 = _time.monotonic()
            response = dns.query.udp(soa_query, ns_ip, timeout=3)
            elapsed_ms = round((_time.monotonic() - t0) * 1000, 1)
            is_authoritative = bool(response.flags & dns.flags.AA)

            # Extract SOA serial from answer section
            soa_serial = None
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    for rdata in rrset:
                        soa_serial = rdata.serial
                        break
                    break

            auth_entry = {
                "hostname": ns_info["hostname"],
                "ip": ns_ip,
                "authoritative": is_authoritative,
                "soa_serial": soa_serial,
                "response_time_ms": elapsed_ms,
            }
            auth_results.append(auth_entry)
            ns_info["authoritative"] = is_authoritative
            ns_info["soa_serial"] = soa_serial
            ns_info["response_time_ms"] = elapsed_ms

            if soa_serial is not None:
                soa_serials[ns_info["hostname"]] = soa_serial

            if not is_authoritative:
                _add_issue(
                    "error",
                    f"Lame delegation: {ns_info['hostname']} ({ns_ip}) is not authoritative",
                    f"Nameserver {ns_info['hostname']} does not return the AA (Authoritative Answer) "
                    "flag for this domain. It is listed as a nameserver but cannot authoritatively "
                    "answer queries, which can cause intermittent resolution failures.",
                    "Remove this nameserver from your NS records or configure it to serve this zone.",
                )
        except (dns.exception.DNSException, OSError):
            # Query failed -- don't penalize, just skip
            ns_info["authoritative"] = None
            ns_info["soa_serial"] = None
            ns_info["response_time_ms"] = None

    result["auth_results"] = auth_results

    # Check SOA serial consistency across nameservers
    unique_serials = set(soa_serials.values())
    if len(unique_serials) > 1:
        serial_detail = ", ".join(f"{h}: {s}" for h, s in sorted(soa_serials.items()))
        _add_issue(
            "warning",
            f"SOA serial mismatch across nameservers ({len(unique_serials)} different serials)",
            f"Nameservers are returning different SOA serial numbers ({serial_detail}). "
            "This usually means zone transfers are delayed or failing, so some nameservers "
            "are serving stale data.",
            "Check zone transfer (AXFR/IXFR) configuration and ensure all secondaries are in sync.",
        )
    result["soa_serials_consistent"] = len(unique_serials) <= 1
    result["soa_serial"] = next(iter(unique_serials)) if len(unique_serials) == 1 else None

    # Detect providers from NS hostnames
    PROVIDER_PATTERNS = {
        "awsdns": "Amazon Route 53",
        "cloudflare": "Cloudflare",
        "google": "Google Cloud DNS",
        "azure-dns": "Azure DNS",
        "digitalocean": "DigitalOcean",
        "linode": "Linode/Akamai",
        "ns.dnsimple": "DNSimple",
        "nsone": "NS1 (IBM)",
        "dynect": "Dyn/Oracle",
        "ultradns": "UltraDNS/Neustar",
        "domaincontrol": "GoDaddy",
        "registrar-servers": "Namecheap",
        "hetzner": "Hetzner",
        "ovh": "OVH",
        "vultr": "Vultr",
    }

    detected_providers = set()
    for ns_info in ns_details:
        host_lower = ns_info["hostname"].lower()
        for pattern, provider in PROVIDER_PATTERNS.items():
            if pattern in host_lower:
                detected_providers.add(provider)
                break

    result["providers"] = sorted(detected_providers)

    # Validation checks

    # 1. Minimum nameserver count (RFC 1034 recommends at least 2)
    if result["ns_count"] < 2:
        _add_issue(
            "error",
            "Only one nameserver configured",
            "A single nameserver is a single point of failure. If it goes down, "
            "your entire domain becomes unreachable -- no website, no email, nothing. "
            "RFC 1034 requires at least two nameservers.",
            "Add at least one secondary nameserver, preferably on a different network.",
        )
    # Two nameservers is standard and fine. No need to flag it.

    # 2. Unresolvable nameservers (lame delegation)
    lame_ns = [ns for ns in ns_details if not ns["resolves"]]
    if lame_ns:
        lame_names = ", ".join(ns["hostname"] for ns in lame_ns)
        _add_issue(
            "error",
            f"Lame delegation: {len(lame_ns)} nameserver{'s' if len(lame_ns) != 1 else ''} do{'es' if len(lame_ns) == 1 else ''} not resolve",
            f"The following nameserver{'s' if len(lame_ns) != 1 else ''} cannot be reached: {lame_names}. "
            "A nameserver that doesn't resolve is useless for redundancy and can cause "
            "intermittent DNS failures as clients randomly select it.",
            "Remove the lame nameserver records or fix their DNS entries.",
        )

    # 3. Network diversity check
    resolving_ns = [ns for ns in ns_details if ns["resolves"]]
    if len(networks_v4) == 1 and len(resolving_ns) >= 2:
        _add_issue(
            "warning",
            "All nameservers on the same /24 network",
            "All nameservers resolve to IP addresses within the same network block. "
            "A network outage, routing issue, or datacenter failure could take down "
            "all nameservers simultaneously.",
            "Use nameservers on different networks, ideally from different providers.",
        )
    elif len(networks_v4) >= 2:
        pass  # Good diversity

    # 4. Provider diversity
    if len(detected_providers) == 1 and result["ns_count"] >= 2:
        provider = list(detected_providers)[0]
        _add_issue(
            "info",
            f"All nameservers with a single provider ({provider})",
            f"All nameservers are hosted by {provider}. While this provider likely has "
            "internal redundancy, using a secondary DNS provider eliminates the risk "
            "of a provider-wide outage affecting your domain.",
            "Consider adding a secondary DNS provider for maximum resilience.",
        )

    # 5. IPv6 support
    has_ipv6 = any(ns["ipv6"] for ns in ns_details)
    if not has_ipv6:
        _add_issue(
            "info",
            "No IPv6-enabled nameservers (no AAAA records)",
            "None of your nameservers have IPv6 addresses. While not critical today, "
            "IPv6 adoption is growing and some networks may prefer IPv6 connectivity.",
            "Ask your DNS provider about IPv6 support for nameservers.",
        )

    # Set final status
    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    return result


def _raw_check_dane(domain: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """Check DANE TLSA records for each MX host.

    DANE (RFC 7672) lets sending MTAs verify a mail server's TLS certificate
    via DNS by publishing TLSA records at _25._tcp.<mx-host>.  DANE requires
    DNSSEC to be meaningful — without it the TLSA records can be spoofed.

    This is a DNS-only check (no STARTTLS connections).
    """
    USAGE_NAMES = {
        0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE",
    }
    SELECTOR_NAMES = {0: "Full cert", 1: "SPKI"}
    MATCHING_NAMES = {0: "Exact", 1: "SHA-256", 2: "SHA-512"}

    result = {
        "check": "DANE",
        "domain": domain,
        "has_tlsa": False,
        "dnssec_validated": False,
        "mx_hosts_checked": 0,
        "mx_hosts_with_tlsa": 0,
        "tlsa_records": [],
        "issues": [],
        "status": "ok",
    }

    def _add_issue(severity, issue, plain_english, fix):
        result["issues"].append({
            "severity": severity, "issue": issue,
            "plain_english": plain_english, "fix": fix,
        })

    # Get MX hosts from earlier check
    raw_mx = raw_results.get("mx", {})
    mx_details = raw_mx.get("mx_details", [])
    mx_hosts = [d["hostname"] for d in mx_details if d.get("hostname") and d.get("resolved")]
    if not mx_hosts:
        # Fall back to raw records list
        for rec in raw_mx.get("records", []):
            parts = rec.strip().split()
            if len(parts) >= 2:
                host = parts[-1].rstrip(".")
                if host:
                    mx_hosts.append(host)

    if not mx_hosts:
        result["status"] = "ok"
        return result

    # DNSSEC status from earlier check
    raw_dnssec = raw_results.get("dnssec", {})
    dnssec_ok = (
        raw_dnssec.get("has_dnssec", False)
        and raw_dnssec.get("has_ds", False)
        and raw_dnssec.get("chain_valid") is not False
    )
    result["dnssec_validated"] = dnssec_ok

    resolver = _get_dnssec_resolver()
    result["mx_hosts_checked"] = len(mx_hosts)

    for mx_host in mx_hosts:
        query_name = f"_25._tcp.{mx_host}"
        host_result = {
            "mx_host": mx_host,
            "query_name": query_name,
            "found": False,
            "records": [],
            "error": None,
        }

        try:
            answers = resolver.resolve(query_name, "TLSA")
            for rdata in answers:
                usage = rdata.usage
                selector = rdata.selector
                mtype = rdata.mtype
                cert_data = rdata.cert.hex()

                rec_info = {
                    "usage": usage,
                    "usage_name": USAGE_NAMES.get(usage, f"Unknown ({usage})"),
                    "selector": selector,
                    "selector_name": SELECTOR_NAMES.get(selector, f"Unknown ({selector})"),
                    "matching_type": mtype,
                    "matching_type_name": MATCHING_NAMES.get(mtype, f"Unknown ({mtype})"),
                    "cert_data_short": cert_data[:16] + "..." if len(cert_data) > 16 else cert_data,
                    "raw": f"{usage} {selector} {mtype} {cert_data[:64]}...",
                }
                host_result["records"].append(rec_info)

                # Per-record warnings
                if usage in (0, 1):
                    _add_issue(
                        "warning",
                        f"PKIX usage ({USAGE_NAMES[usage]}) on {mx_host}",
                        f"TLSA usage {usage} ({USAGE_NAMES[usage]}) relies on the CA PKI system. "
                        "RFC 7672 recommends usage 2 (DANE-TA) or 3 (DANE-EE) for SMTP.",
                        f"Change the TLSA record for {mx_host} to usage 3 (DANE-EE) with selector 1 (SPKI).",
                    )
                if mtype == 0:
                    _add_issue(
                        "warning",
                        f"Full certificate matching (matching type 0) on {mx_host}",
                        "Matching type 0 stores the full certificate data. "
                        "SHA-256 (type 1) or SHA-512 (type 2) are preferred for smaller records and easier rotation.",
                        f"Use matching type 1 (SHA-256) for the TLSA record on {mx_host}.",
                    )

            if host_result["records"]:
                host_result["found"] = True
                result["has_tlsa"] = True
                result["mx_hosts_with_tlsa"] += 1

        except dns.resolver.NoAnswer:
            pass  # No TLSA — not an error per se
        except dns.resolver.NXDOMAIN:
            pass  # No TLSA
        except dns.resolver.LifetimeTimeout:
            host_result["error"] = "Query timed out"
        except dns.exception.DNSException as e:
            host_result["error"] = str(e)[:120]

        result["tlsa_records"].append(host_result)

    # Cross-check: TLSA without DNSSEC
    if result["has_tlsa"] and not dnssec_ok:
        _add_issue(
            "error",
            "TLSA records found but DNSSEC is not enabled",
            "DANE requires DNSSEC to be secure. Without DNSSEC, an attacker can spoof "
            "or strip the TLSA records, completely defeating DANE. Sending MTAs that "
            "follow RFC 7672 will ignore TLSA records when DNSSEC validation fails.",
            "Enable DNSSEC for your domain before relying on DANE.",
        )

    # Mixed coverage warning
    if result["has_tlsa"] and result["mx_hosts_with_tlsa"] < result["mx_hosts_checked"]:
        missing = [h["mx_host"] for h in result["tlsa_records"] if not h["found"]]
        _add_issue(
            "warning",
            f"DANE not configured on all MX hosts ({result['mx_hosts_with_tlsa']}/{result['mx_hosts_checked']})",
            f"Some MX hosts have TLSA records but others do not: {', '.join(missing)}. "
            "Sending MTAs may fall back to opportunistic TLS for those hosts.",
            f"Add TLSA records for: {', '.join(missing)}",
        )

    # Set final status
    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    return result


# ============================================================
# Certificate Transparency (crt.sh)
# ============================================================

def _raw_check_ct(domain: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """Query crt.sh for Certificate Transparency logs and analyze findings.

    Surfaces:
      - CAA enforcement mismatches (certs from unauthorized CAs)
      - Wildcard certificate inventory
      - Expiring/expired certificates
      - Subdomain discovery via SAN fields
      - Certificate sprawl (too many CAs)
    """
    import requests

    result = {
        "check": "Certificate Transparency",
        "domain": domain,
        "total_certs": 0,
        "active_certs": 0,
        "issuers": [],
        "wildcards": [],
        "expiring_soon": [],
        "expired_recent": [],
        "subdomains_found": [],
        "caa_mismatches": [],
        "issues": [],
        "status": "info",
    }

    def _add_issue(severity, issue, plain_english, fix=None):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    # Query crt.sh
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=10,
            headers={"User-Agent": "dns-audit.com/1.0"},
        )
        resp.raise_for_status()
        if len(resp.content) > 10 * 1024 * 1024:  # 10 MB hard limit
            result["status"] = "unavailable"
            result["unavailable_reason"] = "response_too_large"
            _add_issue(
                "warning",
                "crt.sh response too large to process",
                "The Certificate Transparency log query returned too much data to process. "
                "This domain likely has a very large number of certificates.",
            )
            return result
        elif not resp.text or not resp.text.strip():
            certs = []
        else:
            certs = resp.json()
    except requests.exceptions.Timeout:
        _add_issue("warning", "crt.sh timed out", "Certificate Transparency log query timed out.")
        result["status"] = "warning"
        return result
    except (requests.exceptions.RequestException, ValueError) as e:
        _add_issue("warning", f"crt.sh query failed: {type(e).__name__}", "Could not query Certificate Transparency logs.")
        result["status"] = "warning"
        return result

    if not certs:
        result["status"] = "info"
        return result

    # Deduplicate by serial number (crt.sh returns pre-cert + leaf dupes)
    seen_serials = set()
    unique_certs = []
    for cert in certs:
        serial = cert.get("serial_number")
        if serial and serial in seen_serials:
            continue
        if serial:
            seen_serials.add(serial)
        unique_certs.append(cert)

    # Limit to most recent 200 certs for analysis
    unique_certs.sort(key=lambda c: c.get("not_before", ""), reverse=True)
    unique_certs = unique_certs[:200]

    now = datetime.now(timezone.utc)
    result["total_certs"] = len(unique_certs)

    # Analyze certs
    issuer_counts = {}
    active_count = 0
    wildcards = []
    expiring_soon = []
    expired_recent = []
    subdomains = set()

    for cert in unique_certs:
        issuer_name = cert.get("issuer_name", "Unknown")
        # Extract the CN or O from the issuer DN
        issuer_short = issuer_name
        for part in issuer_name.split(","):
            part = part.strip()
            if part.startswith("CN="):
                issuer_short = part[3:]
                break
            elif part.startswith("O="):
                issuer_short = part[2:]

        issuer_counts[issuer_short] = issuer_counts.get(issuer_short, 0) + 1

        # Parse dates
        not_after_str = cert.get("not_after")
        not_before_str = cert.get("not_before")
        not_after = None
        if not_after_str:
            try:
                not_after = datetime.fromisoformat(not_after_str.replace("T", " ").split(".")[0]).replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                pass

        is_active = not_after and not_after > now
        if is_active:
            active_count += 1

        # Wildcard detection
        common_name = cert.get("common_name", "")
        if common_name.startswith("*."):
            wildcards.append({
                "common_name": common_name,
                "issuer": issuer_short,
                "not_after": not_after_str or "",
            })

        # Expiring soon (within 30 days) — only active certs
        if is_active and not_after:
            days_left = (not_after - now).days
            if days_left <= 30:
                expiring_soon.append({
                    "common_name": common_name,
                    "not_after": not_after_str or "",
                    "days_left": days_left,
                })

        # Recently expired (within 90 days)
        if not_after and not is_active:
            days_expired = (now - not_after).days
            if days_expired <= 90:
                expired_recent.append({
                    "common_name": common_name,
                    "not_after": not_after_str or "",
                })

        # Subdomain discovery from SAN (name_value field)
        name_value = cert.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and name != domain and name.endswith("." + domain):
                # Strip wildcard prefix
                if name.startswith("*."):
                    name = name[2:]
                if name != domain:
                    subdomains.add(name)

    result["active_certs"] = active_count

    # Sort issuers by count
    result["issuers"] = sorted(
        [{"name": k, "count": v} for k, v in issuer_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )

    # Deduplicate wildcards by common_name
    seen_wc = set()
    unique_wc = []
    for wc in wildcards:
        if wc["common_name"] not in seen_wc:
            seen_wc.add(wc["common_name"])
            unique_wc.append(wc)
    result["wildcards"] = unique_wc[:10]

    result["expiring_soon"] = expiring_soon[:10]
    result["expired_recent"] = expired_recent[:10]
    result["subdomains_found"] = sorted(subdomains)[:50]

    # CAA mismatch analysis
    raw_caa = raw_results.get("caa", {})
    authorized_cas = raw_caa.get("authorized_cas", [])
    if authorized_cas:
        # Normalize CA names for comparison
        caa_normalized = set()
        for ca in authorized_cas:
            caa_normalized.add(ca.lower().strip().strip('"'))

        # Check if any cert issuers don't match CAA
        for issuer_info in result["issuers"]:
            issuer_lower = issuer_info["name"].lower()
            # Check if any CAA entry is a substring of the issuer (or vice versa)
            matched = False
            for caa_ca in caa_normalized:
                if caa_ca in issuer_lower or issuer_lower in caa_ca:
                    matched = True
                    break
                # Common mappings
                if caa_ca == "letsencrypt.org" and "let's encrypt" in issuer_lower:
                    matched = True
                    break
                if caa_ca == "digicert.com" and "digicert" in issuer_lower:
                    matched = True
                    break
                if caa_ca == "sectigo.com" and ("sectigo" in issuer_lower or "comodo" in issuer_lower):
                    matched = True
                    break
                if caa_ca == "pki.goog" and "google" in issuer_lower:
                    matched = True
                    break
                if caa_ca == "amazon.com" and "amazon" in issuer_lower:
                    matched = True
                    break
                if caa_ca == "comodoca.com" and ("comodo" in issuer_lower or "sectigo" in issuer_lower):
                    matched = True
                    break
            if not matched:
                result["caa_mismatches"].append({
                    "cert_issuer": issuer_info["name"],
                    "caa_allows": authorized_cas,
                })

    # Set status based on findings
    if result["caa_mismatches"]:
        result["status"] = "warning"
        for mm in result["caa_mismatches"]:
            _add_issue(
                "warning",
                f"Certificate from {mm['cert_issuer']} not in CAA",
                f"CT logs show certificates issued by {mm['cert_issuer']}, but CAA only allows: {', '.join(mm['caa_allows'])}. "
                "These may be older certs issued before CAA was configured.",
                f"Verify these certificates are expected. Update CAA to include this issuer or revoke unauthorized certs.",
            )
    if expiring_soon:
        result["status"] = "warning"
        _add_issue(
            "warning",
            f"{len(expiring_soon)} certificate(s) expiring within 30 days",
            f"{len(expiring_soon)} active certificate(s) will expire soon. Ensure auto-renewal is working.",
        )

    if result["status"] == "info" and active_count > 0:
        result["status"] = "ok"

    return result


# ============================================================
# Blacklist (DNSBL) Check
# ============================================================

def _raw_check_blacklist(domain: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """Check if domain and MX IPs appear on major DNS-based blocklists.

    Uses the standard DNSBL lookup protocol:
      - Reverse IP octets, query against blocklist domain
      - A record returned = listed, NXDOMAIN = clean

    Checks both IP-based lists (against MX IPs) and domain-based lists.
    """
    import ipaddress
    import socket

    # Domain-based blocklists only. IP-based checks were removed because
    # MX host IPs are shared infrastructure (e.g. Microsoft 365, Google)
    # that the audited domain does not control. A listing on a shared IP
    # says nothing about the domain's reputation.
    DOMAIN_LISTS = [
        ("Spamhaus DBL", "dbl.spamhaus.org", 1, "https://check.spamhaus.org/"),
    ]
    SPAMHAUS_DBL_CODES = {
        "127.0.1.2": "Spam domain",
        "127.0.1.4": "Phishing domain",
        "127.0.1.5": "Malware domain",
        "127.0.1.6": "Botnet C&C domain",
    }

    result = {
        "check": "Blocklist",
        "domain": domain,
        "ips_checked": [],
        "domain_checked": domain,
        "total_listings": 0,
        "ip_results": [],
        "domain_results": [],
        "issues": [],
        "status": "ok",
    }

    def _add_issue(severity, issue, plain_english, fix=None):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    def _dnsbl_lookup(query_name: str, timeout: float = 3.0) -> Optional[str]:
        """Query a DNSBL. Returns the A record response or None if clean."""
        try:
            resolver = _get_resolver(timeout=timeout)
            answers = resolver.resolve(query_name, "A")
            for rdata in answers:
                return str(rdata)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except dns.exception.DNSException:
            return None

    # Check domain against domain-based lists
    for list_name, list_host, tier, delist_url in DOMAIN_LISTS:
        query = f"{domain}.{list_host}"
        return_code = _dnsbl_lookup(query)
        listed = return_code is not None

        meaning = None
        if listed:
            # Spamhaus error/test responses -- not a real listing
            if return_code and return_code.startswith("127.255.255."):
                result["domain_results"].append({
                    "list": list_name, "listed": False,
                    "return_code": return_code, "meaning": None,
                    "error": "Spamhaus query blocked (public resolver)",
                })
                continue
            if "spamhaus" in list_host:
                meaning = SPAMHAUS_DBL_CODES.get(return_code)
            if not meaning:
                meaning = f"Listed (response: {return_code})"

        result["domain_results"].append({
            "list": list_name, "listed": listed,
            "return_code": return_code, "meaning": meaning,
        })

    # Count total listings
    total_listings = 0
    tier1_listings = []
    tier2_listings = []

    for dr in result["domain_results"]:
        if dr.get("listed"):
            total_listings += 1
            for list_name, _, tier, delist_url in DOMAIN_LISTS:
                if list_name == dr["list"]:
                    if tier == 1:
                        tier1_listings.append(f"{domain} on {dr['list']}")
                    else:
                        tier2_listings.append(f"{domain} on {dr['list']}")
                    break

    result["total_listings"] = total_listings

    # Set status and issues
    if tier1_listings:
        result["status"] = "error"
        for listing in tier1_listings:
            _add_issue(
                "error",
                f"Listed: {listing}",
                f"{listing}. This is a major blocklist that can cause significant email deliverability issues.",
            )
    if tier2_listings:
        if result["status"] == "ok":
            result["status"] = "warning"
        for listing in tier2_listings:
            _add_issue(
                "warning",
                f"Listed: {listing}",
                f"{listing}. This is a secondary blocklist with less impact on deliverability.",
            )

    return result


# ============================================================
# Main Audit Orchestrator
# ============================================================

_shared_executor = ThreadPoolExecutor(max_workers=8)


def _run_with_timeout(func, *args, timeout=CHECK_TIMEOUT):
    """Run a check function with a timeout. Raises TimeoutError on expiry."""
    future = _shared_executor.submit(func, *args)
    return future.result(timeout=timeout)


def _count_checks_for_scope(scope_set) -> int:
    """Count how many check steps will run for a given scope."""
    count = 0
    needs_dmarc = scope_set is None or "dmarc" in scope_set
    needs_mx = scope_set is None or bool(scope_set & (_MX_DEPENDENTS | {"mx"}))
    needs_spf = scope_set is None or bool(scope_set & (_SPF_DEPENDENTS | {"spf"}))

    # Tree walk runs only when DMARC is needed
    if needs_dmarc:
        count += 1  # tree walk
        count += 1  # dmarc check
    if needs_mx:
        count += 1
    if needs_spf:
        count += 1

    other_checks = ["mta_sts", "tls_rpt", "bimi", "dnssec", "caa",
                     "nameservers", "dane", "dkim", "ct", "blacklist"]
    for ck in other_checks:
        if _should_include(ck, scope_set):
            count += 1

    # Vendor fingerprinting runs when email checks are in scope
    _email_checks = {"dmarc", "spf", "dkim", "mx"}
    if scope_set is None or bool(scope_set & _email_checks):
        count += 1
    # Scoring always runs
    count += 1
    return count


def run_full_audit(domain: str, dkim_selector: Optional[str] = None,
                   scope: Optional[str] = None,
                   progress_callback=None) -> Dict[str, Any]:
    """
    Run all security checks and return the complete audit result
    in the format expected by the frontend.

    Each check runs in a try/except so one failure doesn't kill the audit.
    Per-check timeouts prevent hung DNS queries from blocking the entire audit.

    If progress_callback is provided, it is called after each check with:
        progress_callback(step_name: str, completed: int, total: int)
    """
    start_time = datetime.now(timezone.utc)
    checks = []
    raw_results = {}
    errors = []

    # Resolve scope to a set of check keys (None = run everything)
    if scope and scope not in SCOPE_CHECKS:
        raise ValueError(f"Invalid scope '{scope}'. Valid scopes: {', '.join(sorted(SCOPE_CHECKS))}")
    scope_set = SCOPE_CHECKS.get(scope) if scope else None
    total_checks = _count_checks_for_scope(scope_set)
    completed = 0

    def _notify(step_name):
        nonlocal completed
        completed += 1
        if progress_callback:
            progress_callback(step_name, completed, total_checks)

    # Determine which dependency checks must run even if not in scope
    needs_dmarc = scope_set is None or "dmarc" in scope_set
    needs_mx = scope_set is None or bool(scope_set & (_MX_DEPENDENTS | {"mx"}))
    needs_spf = scope_set is None or bool(scope_set & (_SPF_DEPENDENTS | {"spf"}))

    # --- DMARC Tree Walk (DMARCbis Section 4.10) ---
    # Run before DMARC card so inherited policy can inform the card
    tree_walk_result = None
    if needs_dmarc:
        try:
            tree_walk_result = _run_with_timeout(dmarc_tree_walk, domain)
        except Exception as e:
            log.warning("Tree Walk failed: %s", e, exc_info=True)
            errors.append(f"Tree Walk: {str(e)}")
        _notify("Tree Walk")

    # --- 1. DMARC ---
    if needs_dmarc:
        try:
            raw_dmarc = _run_with_timeout(_raw_check_dmarc, domain)
            # Enrich with inherited policy (tree walk first, PSL fallback)
            _enrich_dmarc_inheritance(raw_dmarc, domain, tree_walk_result)
            raw_results["dmarc"] = raw_dmarc
            if _should_include("dmarc", scope_set):
                checks.append(transform_dmarc(raw_dmarc, tree_walk=tree_walk_result))
        except FuturesTimeoutError:
            errors.append("DMARC: timed out")
            if _should_include("dmarc", scope_set):
                checks.append(_timeout_card("DMARC"))
        except Exception as e:
            log.warning("DMARC check failed: %s", e, exc_info=True)
            errors.append(f"DMARC: {str(e)}")
            if _should_include("dmarc", scope_set):
                checks.append(_error_card("DMARC", e))
        _notify("DMARC")

    # --- DMARC Report Authorization (RFC 7489 S7.1) ---
    report_auth = None
    raw_dmarc = raw_results.get("dmarc")
    if raw_dmarc and raw_dmarc.get("record") and (raw_dmarc.get("rua") or raw_dmarc.get("ruf")):
        try:
            report_auth = _run_with_timeout(
                _check_report_authorization, domain, raw_dmarc,
                tree_walk_result, timeout=10,
            )
            if report_auth:
                raw_dmarc["report_destinations"] = report_auth["report_destinations"]
                raw_dmarc["report_auth_issues"] = report_auth.get("report_auth_issues", [])
                raw_dmarc["ruf_provider_note"] = report_auth.get("ruf_provider_note", False)
                raw_dmarc["issues"].extend(report_auth.get("report_auth_issues", []))
        except Exception:
            log.debug("Report auth enrichment failed", exc_info=True)

    # --- 2. MX Records (run before SPF so we know if domain sends mail) ---
    if needs_mx:
        try:
            raw_mx = _run_with_timeout(check_mx, domain)
            raw_results["mx"] = raw_mx
            if _should_include("mx", scope_set):
                checks.append(transform_mx(raw_mx))
        except FuturesTimeoutError:
            errors.append("MX: timed out")
            if _should_include("mx", scope_set):
                checks.append(_timeout_card("MX Records"))
        except Exception as e:
            log.warning("MX check failed: %s", e, exc_info=True)
            errors.append(f"MX: {str(e)}")
            if _should_include("mx", scope_set):
                checks.append(_error_card("MX Records", e))
        _notify("MX")

    has_mx = bool(raw_results.get("mx", {}).get("records")) or bool(raw_results.get("mx", {}).get("mx_details"))

    # --- 3. SPF ---
    spf_record = None
    if needs_spf:
        try:
            raw_spf = _run_with_timeout(_raw_check_spf, domain)
            raw_results["spf"] = raw_spf
            spf_record = raw_spf.get("record")
            if _should_include("spf", scope_set):
                checks.append(transform_spf(raw_spf, has_mx=has_mx))
        except FuturesTimeoutError:
            errors.append("SPF: timed out")
            if _should_include("spf", scope_set):
                checks.append(_timeout_card("SPF"))
        except Exception as e:
            log.warning("SPF check failed: %s", e, exc_info=True)
            errors.append(f"SPF: {str(e)}")
            if _should_include("spf", scope_set):
                checks.append(_error_card("SPF", e))
        _notify("SPF")

    # --- SPF Execution Trace (post-processor, zero DNS queries) ---
    spf_execution = None
    raw_spf = raw_results.get("spf")
    if raw_spf and raw_spf.get("spf_recursive"):
        try:
            from spf_execution_engine import build_spf_execution_trace
            spf_execution = build_spf_execution_trace(
                raw_spf["spf_recursive"], raw_spf.get("record")
            )
        except Exception:
            log.debug("SPF execution trace failed", exc_info=True)

    # --- SPF Include Tree (post-processor, zero DNS queries) ---
    spf_tree_viz = None
    raw_spf = raw_results.get("spf")
    if raw_spf and raw_spf.get("spf_recursive"):
        try:
            from spf_execution_engine import build_spf_tree_viz
            spf_tree_viz = build_spf_tree_viz(raw_spf["spf_recursive"])
        except Exception:
            log.debug("SPF tree viz failed", exc_info=True)

    # --- 4. MTA-STS ---
    if _should_include("mta_sts", scope_set):
        try:
            raw_mta_sts = _run_with_timeout(check_mta_sts, domain)
            raw_results["mta_sts"] = raw_mta_sts
            checks.append(transform_mta_sts(raw_mta_sts, domain, has_mx=has_mx))
        except FuturesTimeoutError:
            errors.append("MTA-STS: timed out")
            checks.append(_timeout_card("MTA-STS"))
        except Exception as e:
            log.warning("MTA-STS check failed: %s", e, exc_info=True)
            errors.append(f"MTA-STS: {str(e)}")
            checks.append(_error_card("MTA-STS", e))
        _notify("MTA-STS")

    # --- 5. TLS-RPT ---
    if _should_include("tls_rpt", scope_set):
        try:
            raw_tls_rpt = _run_with_timeout(check_tls_rpt, domain)
            raw_results["tls_rpt"] = raw_tls_rpt
            checks.append(transform_tls_rpt(raw_tls_rpt, domain, has_mx=has_mx))
        except FuturesTimeoutError:
            errors.append("TLS-RPT: timed out")
            checks.append(_timeout_card("TLS-RPT"))
        except Exception as e:
            log.warning("TLS-RPT check failed: %s", e, exc_info=True)
            errors.append(f"TLS-RPT: {str(e)}")
            checks.append(_error_card("TLS-RPT", e))
        _notify("TLS-RPT")

    # --- 6. BIMI ---
    if _should_include("bimi", scope_set):
        try:
            # Pass resolved DMARC enforcement (including inherited) to BIMI check
            _bimi_dmarc = raw_results.get("dmarc") or {}
            _bimi_dmarc_enforcing = (
                (_bimi_dmarc.get("policy") or "").lower() in ("quarantine", "reject")
                or (_bimi_dmarc.get("inherited_policy") or "").lower() in ("quarantine", "reject")
            )
            raw_bimi = _run_with_timeout(check_bimi, domain, dmarc_enforcing_override=_bimi_dmarc_enforcing)
            raw_results["bimi"] = raw_bimi
            checks.append(transform_bimi(raw_bimi, domain, has_mx=has_mx))
        except FuturesTimeoutError:
            errors.append("BIMI: timed out")
            checks.append(_timeout_card("BIMI"))
        except Exception as e:
            log.warning("BIMI check failed: %s", e, exc_info=True)
            errors.append(f"BIMI: {str(e)}")
            checks.append(_error_card("BIMI", e))
        _notify("BIMI")

    # --- 7. DNSSEC ---
    if _should_include("dnssec", scope_set):
        try:
            raw_dnssec = _run_with_timeout(_raw_check_dnssec, domain)
            raw_results["dnssec"] = raw_dnssec
            checks.append(transform_dnssec(raw_dnssec))
        except FuturesTimeoutError:
            errors.append("DNSSEC: timed out")
            checks.append(_timeout_card("DNSSEC"))
        except Exception as e:
            log.warning("DNSSEC check failed: %s", e, exc_info=True)
            errors.append(f"DNSSEC: {str(e)}")
            checks.append(_error_card("DNSSEC", e))
        _notify("DNSSEC")

    # --- 8. CAA ---
    if _should_include("caa", scope_set):
        try:
            raw_caa = _run_with_timeout(_raw_check_caa, domain)
            raw_results["caa"] = raw_caa
            checks.append(transform_caa(raw_caa, domain))
        except FuturesTimeoutError:
            errors.append("CAA: timed out")
            checks.append(_timeout_card("CAA"))
        except Exception as e:
            log.warning("CAA check failed: %s", e, exc_info=True)
            errors.append(f"CAA: {str(e)}")
            checks.append(_error_card("CAA", e))
        _notify("CAA")

    # --- 9. Nameservers ---
    if _should_include("nameservers", scope_set):
        try:
            raw_ns = _run_with_timeout(_raw_check_nameservers, domain)
            raw_results["nameservers"] = raw_ns
            checks.append(transform_nameservers(raw_ns, domain))
        except FuturesTimeoutError:
            errors.append("Nameservers: timed out")
            checks.append(_timeout_card("Nameservers"))
        except Exception as e:
            log.warning("Nameservers check failed: %s", e, exc_info=True)
            errors.append(f"Nameservers: {str(e)}")
            checks.append(_error_card("Nameservers", e))
        _notify("Nameservers")

    # --- 10. DANE ---
    if _should_include("dane", scope_set):
        try:
            raw_dane = _run_with_timeout(_raw_check_dane, domain, raw_results)
            raw_results["dane"] = raw_dane
            checks.append(transform_dane(raw_dane, domain))
        except FuturesTimeoutError:
            errors.append("DANE: timed out")
            checks.append(_timeout_card("DANE"))
        except Exception as e:
            log.warning("DANE check failed: %s", e, exc_info=True)
            errors.append(f"DANE: {str(e)}")
            checks.append(_error_card("DANE", e))
        _notify("DANE")

    # --- 11. DKIM (direct lookup of user-provided selector) ---
    if _should_include("dkim", scope_set):
        try:
            if dkim_selector and dkim_selector.strip():
                sel = dkim_selector.strip()
                fqdn = f"{sel}._domainkey.{domain}"
                raw_dkim = {
                    "domain": domain,
                    "found_selectors": [],
                    "selector_queried": sel,
                }
                try:
                    import dns.resolver as _dkim_resolver
                    answers = _run_with_timeout(_dkim_resolver.resolve, fqdn, "TXT")
                    txt = "".join(
                        s.decode() if isinstance(s, bytes) else s
                        for rdata in answers for s in rdata.strings
                    )
                    if "p=" in txt:
                        key_analysis = analyze_dkim_key_strength(txt)
                        raw_dkim["found_selectors"].append({
                            "selector": sel,
                            "record": txt,
                            "key_size": key_analysis.get("key_bits"),
                        })
                except FuturesTimeoutError:
                    raise  # Let outer handler catch it
                except dns.exception.DNSException:
                    # User-provided selector not found
                    raw_dkim["selector_not_found"] = sel
                    raw_dkim["tested_count"] = 1
            else:
                # No selector provided -- fall back to auto-discovery
                raw_dkim = _run_with_timeout(smart_dkim_check, domain, spf_record)
            raw_results["dkim"] = raw_dkim
            dkim_pos = min(2, len(checks))
            checks.insert(dkim_pos, transform_dkim(raw_dkim, domain, has_mx=has_mx))
        except FuturesTimeoutError:
            errors.append("DKIM: timed out")
            raw_results["dkim"] = {"found_selectors": [], "tested_count": 0, "timed_out": True}
            dkim_pos = min(2, len(checks))
            checks.insert(dkim_pos, _timeout_card("DKIM"))
        except Exception as e:
            log.warning("DKIM check failed: %s", e, exc_info=True)
            errors.append(f"DKIM: {str(e)}")
            dkim_pos = min(2, len(checks))
            checks.insert(dkim_pos, _error_card("DKIM", e))
        _notify("DKIM")

    # --- Detect Defensive DNS pattern (moved early -- roadmap needs it) ---
    defensive_signals = []
    is_defensive = False
    if "dmarc" in raw_results and "mx" in raw_results and "spf" in raw_results:
        _raw_mx = raw_results["mx"]
        _raw_spf = raw_results["spf"]
        _raw_dmarc = raw_results["dmarc"]

        _mx_records = _raw_mx.get("records", []) or []
        _has_null_mx = any("0 ." in r for r in _mx_records) if _mx_records else False
        _has_no_mx = not _mx_records

        _spf_record = (_raw_spf.get("record") or "").strip().lower()
        _has_null_spf = _spf_record == "v=spf1 -all"

        # Only count DMARC reject from the domain's OWN record, not inherited.
        # A domain that inherits reject from a parent is a normal subdomain,
        # not a deliberately parked/defensive domain.
        _dmarc_policy = (_raw_dmarc.get("policy") or "").lower()
        _has_dmarc_reject = _dmarc_policy == "reject"

        if _has_null_mx or _has_no_mx:
            defensive_signals.append("null_mx")
        if _has_null_spf:
            defensive_signals.append("null_spf")
        if _has_dmarc_reject:
            defensive_signals.append("dmarc_reject")

        is_defensive = len(defensive_signals) >= 2

    # --- Override email-specific cards for defensive DNS domains ---
    # Defensive domains intentionally do not send/receive email. Email-specific
    # checks should not show as failures or warnings.
    if is_defensive:
        _defensive_override = {"MTA-STS", "TLS-RPT", "BIMI", "DKIM", "DANE"}
        for check in checks:
            if check.get("name") in _defensive_override and check.get("status") != "pass":
                check["status"] = "pass"
                check["pill_label"] = "N/A"
                check["verdict"] = "Not applicable (non-mail domain)"
                check["fix"] = None
                check["fix_records"] = None

    # --- DMARC Evaluation Summary (post-processor, zero DNS queries) ---
    dmarc_eval = None
    if raw_results.get("dmarc"):
        try:
            from spf_execution_engine import build_dmarc_evaluation
            dmarc_eval = build_dmarc_evaluation(
                raw_results.get("dmarc", {}),
                raw_results.get("spf", {}),
                raw_results.get("dkim", {}),
                tree_walk_result,
            )
        except Exception:
            log.debug("DMARC evaluation failed", exc_info=True)

    # --- DMARC Alignment Cross-Check ---
    # Flag misconfigurations where DMARC alignment settings conflict with
    # actual SPF/DKIM deployment. Requires all three checks to have run.
    _xc_dmarc = raw_results.get("dmarc")
    _xc_inherited = (
        _xc_dmarc
        and not _xc_dmarc.get("record")
        and tree_walk_result
        and tree_walk_result.get("policy_source")
        and tree_walk_result.get("is_subdomain")
    )
    _xc_can_crosscheck = (
        _xc_dmarc
        and (_xc_dmarc.get("record") or _xc_inherited)
        and "spf" in raw_results
        and "dkim" in raw_results
        and _should_include("dmarc", scope_set)
    )

    if _xc_can_crosscheck:
        _xc_spf = raw_results["spf"]
        _xc_dkim = raw_results["dkim"]

        if _xc_inherited:
            _xc_policy = (tree_walk_result.get("effective_policy") or "").lower()
            # Alignment tags are NOT inherited per spec; defaults apply (relaxed)
            _xc_adkim = "r"
            _xc_aspf = "r"
        else:
            _xc_policy = (_xc_dmarc.get("policy") or "").lower()
            _xc_adkim = (_xc_dmarc.get("adkim") or "r").lower()
            _xc_aspf = (_xc_dmarc.get("aspf") or "r").lower()

        _xc_has_spf = bool(_xc_spf.get("record"))
        _xc_has_dkim = bool(_xc_dkim.get("found_selectors"))
        _xc_enforcing = _xc_policy in ("quarantine", "reject")

        # Skip for non-mail / defensive DNS (null SPF + no DKIM = intentional)
        _xc_spf_rec = (_xc_spf.get("record") or "").strip().lower()
        _xc_is_defensive = (
            (not has_mx)
            or (_xc_spf_rec == "v=spf1 -all" and not _xc_has_dkim)
        )

        if not _xc_is_defensive:
            _XC_RANK = {"pass": 0, "warn": 1, "fail": 2}
            _xc_details = []
            _xc_downgrade = None

            # 1. Enforcement with neither auth method -- all mail will fail DMARC
            if _xc_enforcing and not _xc_has_spf and not _xc_has_dkim:
                _xc_details.append({
                    "type": "error",
                    "text": (
                        f"DMARC policy is {_xc_policy} but neither SPF nor DKIM is configured. "
                        f"All legitimate email will fail DMARC and be "
                        f"{'rejected' if _xc_policy == 'reject' else 'sent to spam'}"
                    ),
                })
                _xc_downgrade = "fail"
            else:
                # 2. Strict DKIM alignment but no DKIM keys detected
                if _xc_adkim == "s" and not _xc_has_dkim:
                    _xc_details.append({
                        "type": "warning",
                        "text": (
                            "Strict DKIM alignment (adkim=s) is set but no DKIM keys were detected. "
                            "DMARC can only pass via SPF alignment. "
                            "If mail forwarding breaks SPF, messages will fail DMARC"
                        ),
                    })
                    if not _xc_downgrade:
                        _xc_downgrade = "warn"

                # 3. Strict SPF alignment but no SPF record
                if _xc_aspf == "s" and not _xc_has_spf:
                    _xc_details.append({
                        "type": "warning",
                        "text": (
                            "Strict SPF alignment (aspf=s) is set but no SPF record found. "
                            "DMARC can only pass via DKIM alignment"
                        ),
                    })
                    if not _xc_downgrade:
                        _xc_downgrade = "warn"

                # 4. Enforcement with single auth method
                #    (skip if strict alignment already flagged the missing method above)
                if _xc_enforcing and _xc_has_spf and not _xc_has_dkim and _xc_adkim != "s":
                    _xc_details.append({
                        "type": "info",
                        "text": (
                            "DMARC enforcement relies solely on SPF (no DKIM detected). "
                            "Adding DKIM provides a second authentication path that survives mail forwarding"
                        ),
                    })
                elif _xc_enforcing and _xc_has_dkim and not _xc_has_spf and _xc_aspf != "s":
                    _xc_details.append({
                        "type": "warning",
                        "text": (
                            "DMARC enforcement relies solely on DKIM (no SPF record). "
                            "Adding SPF provides defense-in-depth and is expected by receivers"
                        ),
                    })
                    if not _xc_downgrade:
                        _xc_downgrade = "warn"

            # Inject cross-check results into the DMARC card
            if _xc_details:
                for card in checks:
                    if card.get("name") == "DMARC":
                        card["details"].extend(_xc_details)
                        if _xc_downgrade:
                            cur = _XC_RANK.get(card.get("status", "pass"), 0)
                            new = _XC_RANK.get(_xc_downgrade, 0)
                            if new > cur:
                                card["status"] = _xc_downgrade
                        break

    # --- 12. Certificate Transparency ---
    if _should_include("ct", scope_set):
        try:
            raw_ct = _run_with_timeout(_raw_check_ct, domain, raw_results, timeout=15)
            raw_results["ct"] = raw_ct
            checks.append(transform_ct(raw_ct, domain))
        except FuturesTimeoutError:
            errors.append("Certificate Transparency: timed out")
            checks.append(_timeout_card("Certificate Transparency"))
        except Exception as e:
            log.warning("CT check failed: %s", e, exc_info=True)
            errors.append(f"Certificate Transparency: {str(e)}")
            checks.append(_error_card("Certificate Transparency", e))
        _notify("Certificate Transparency")

    # --- 13. Blacklist ---
    if _should_include("blacklist", scope_set):
        try:
            raw_blacklist = _run_with_timeout(_raw_check_blacklist, domain, raw_results, timeout=15)
            raw_results["blacklist"] = raw_blacklist
            checks.append(transform_blacklist(raw_blacklist, domain))
        except FuturesTimeoutError:
            errors.append("Blacklist: timed out")
            checks.append(_timeout_card("Blacklist"))
        except Exception as e:
            log.warning("Blacklist check failed: %s", e, exc_info=True)
            errors.append(f"Blacklist: {str(e)}")
            checks.append(_error_card("Blacklist", e))
        _notify("Blacklist")

    # --- Vendor Fingerprinting (only useful for email scopes) ---
    fp_vendors = []
    _email_checks = {"dmarc", "spf", "dkim", "mx"}
    if scope_set is None or bool(scope_set & _email_checks):
        try:
            fp = AdvancedVendorFingerprinter(domain)
            fp_result = fp.fingerprint_all()
            fp_vendors = fp_result.get("vendors", [])
        except Exception:
            log.debug("Vendor fingerprinting failed", exc_info=True)
        _notify("Vendor Fingerprinting")

    # --- Security Score ---
    score_result = _calculate_score(raw_results, domain, tree_walk=tree_walk_result, fp_vendors=fp_vendors)

    # --- Vendor list for frontend ---
    vendors = _format_vendors(fp_vendors)

    # --- Enrich SPF fix text with vendor-specific includes ---
    if vendors:
        current_spf = raw_results.get("spf", {}).get("record", "") or ""
        missing_includes = []
        matched_vendors = []
        for v in vendors:
            spf_inc = VENDOR_SPF_INCLUDES.get(v["name"])
            if spf_inc and spf_inc not in current_spf:
                missing_includes.append(spf_inc)
                matched_vendors.append(v["name"])
        if missing_includes:
            for check in checks:
                if check.get("name") != "SPF":
                    continue
                # Build suggested record
                existing_includes = re.findall(r'include:\S+', current_spf)
                all_includes = list(dict.fromkeys(existing_includes + missing_includes))
                all_mech = raw_results.get("spf", {}).get("all_mechanism") or "-all"
                suggested = f"v=spf1 {' '.join(all_includes)} {all_mech}"
                vendor_list = ", ".join(matched_vendors)
                vendor_hint = (
                    f"<strong>Detected services:</strong> {_e(vendor_list)}<br><br>"
                    f"<strong>Suggested SPF record:</strong><br>"
                    f"<code>{_e(suggested)}</code>"
                )
                if check.get("fix"):
                    check["fix"] = vendor_hint + "<br><br>" + check["fix"]
                else:
                    check["fix"] = vendor_hint
                break

    # --- Priority Fixes ---
    raw_mx = raw_results.get("mx", {})
    has_mx = bool(raw_mx.get("records")) or bool(raw_mx.get("mx_details"))
    priority_fixes = _build_priority_fixes(checks, score_result, has_mx=has_mx)
    _notify("Scoring")

    # --- Anomaly Detection ("What's Unusual") ---
    try:
        anomalies = detect_anomalies(raw_results, score_result, has_mx, is_defensive, tree_walk=tree_walk_result)
    except Exception:
        log.debug("Anomaly detection failed", exc_info=True)
        anomalies = []

    # --- Remediation Plan ---
    try:
        remediation_plan = build_remediation_plan(checks, raw_results, has_mx, is_defensive, tree_walk=tree_walk_result)
    except Exception:
        log.debug("Remediation plan failed", exc_info=True)
        remediation_plan = {"immediate": [], "short_term": [], "long_term": []}

    # --- Authentication Resilience Analysis ---
    try:
        resilience_result = _build_resilience_analysis(raw_results, checks, has_mx, is_defensive, tree_walk=tree_walk_result)
    except Exception:
        log.debug("Resilience analysis failed", exc_info=True)
        resilience_result = None

    # --- Ensure every check has pill_label ---
    _DEFAULT_PILLS = {"pass": "Pass", "warn": "Warning", "fail": "Fail"}
    for check in checks:
        if not check.get("pill_label"):
            check["pill_label"] = _DEFAULT_PILLS.get(check.get("status"), check.get("status", ""))

    # --- Assemble final response ---
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

    return {
        "domain": domain,
        "timestamp": start_time.isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "score": {
            "total": score_result.get("total_score", 0),
            "grade": score_result.get("grade", "?"),
            "category_scores": score_result.get("category_scores", {}),
            "weaknesses": score_result.get("weaknesses", []),
            "strengths": score_result.get("strengths", []),
            "recommendations": score_result.get("recommendations", []),
        },
        "checks": checks,
        "priority_fixes": priority_fixes,
        "anomalies": anomalies,
        "remediation_plan": remediation_plan,
        "vendors": vendors,
        "tree_walk": tree_walk_result,
        "spf_execution": spf_execution,
        "dmarc_eval": dmarc_eval,
        "report_chain": report_auth,
        "spf_tree": spf_tree_viz,
        "scope": scope or "complete",
        "defensive_dns": is_defensive,
        "defensive_signals": defensive_signals,
        "resilience": resilience_result,
        "errors": errors if errors else None,
    }


# ============================================================
# Score Calculation
# ============================================================

def _calculate_score(raw_results: Dict, domain: str, tree_walk: Optional[Dict] = None, fp_vendors: Optional[List] = None) -> Dict:
    """Build the audit_results dict that EmailSecurityScorer expects."""
    try:
        # DMARC results — include inherited policy info
        raw_dmarc = raw_results.get("dmarc", {})
        # Use inherited policy from raw_dmarc (set by _enrich_dmarc_inheritance)
        inherited_policy = raw_dmarc.get("inherited_policy")

        dmarc_for_scorer = {
            "record": raw_dmarc.get("record"),
            "policy": raw_dmarc.get("policy", ""),
            "pct": raw_dmarc.get("pct") or 100,
            "rua": raw_dmarc.get("rua"),
            "ruf": raw_dmarc.get("ruf"),
            "sp": raw_dmarc.get("sp"),
            "adkim": raw_dmarc.get("adkim"),
            "aspf": raw_dmarc.get("aspf"),
            "domain": domain,
            "inherited_policy": inherited_policy,
        }

        # Detect non-mail-sending subdomains: no MX + inherited DMARC
        raw_mx = raw_results.get("mx", {})
        has_mx = bool(raw_mx.get("records")) or bool(raw_mx.get("mx_details"))

        # SPF results
        raw_spf = raw_results.get("spf", {})
        spf_for_scorer = {
            "record": raw_spf.get("record"),
            "all": raw_spf.get("all_mechanism", ""),
            "has_redirect": raw_spf.get("has_redirect", False),
            "lookup_count": raw_spf.get("lookup_count", 0),
            "include_count": raw_spf.get("include_count", 0),
        }

        # DKIM results
        raw_dkim = raw_results.get("dkim", {})
        dkim_for_scorer = {
            "found_selectors": raw_dkim.get("found_selectors", []),
        }

        # Key age analysis
        key_age = {"overdue": 0, "due_soon": 0, "current": 0}
        try:
            analyzer = DKIMKeyAgeAnalyzer(domain)
            for sel in raw_dkim.get("found_selectors", []):
                record = sel.get("record", "")
                key_analysis = analyze_dkim_key_strength(record)
                key_size = key_analysis.get("key_bits", 2048)
                result = analyzer.analyze_key(sel.get("selector", ""), record, key_size)
                status = result.get("rotation_status", "UNKNOWN")
                if status == "OVERDUE":
                    key_age["overdue"] += 1
                elif status == "DUE_SOON":
                    key_age["due_soon"] += 1
                elif status == "CURRENT":
                    key_age["current"] += 1
        except Exception:
            log.debug("DKIM key age analysis failed", exc_info=True)

        # Vendor fingerprint (pre-computed, passed in)
        vendor_for_scorer = {"vendors": [
            {"vendor": v["vendor"], "confidence": v["confidence"]}
            for v in (fp_vendors or [])
        ]}

        # MTA-STS / TLS-RPT / BIMI configured flags
        mta_sts_configured = bool(raw_results.get("mta_sts", {}).get("txt_record"))
        tls_rpt_configured = bool(raw_results.get("tls_rpt", {}).get("record"))
        bimi_configured = bool(raw_results.get("bimi", {}).get("record"))
        dane_configured = bool(raw_results.get("dane", {}).get("has_tlsa"))

        # Assemble for scorer
        audit_input = {
            "dmarc_results": dmarc_for_scorer,
            "spf_results": spf_for_scorer,
            "dkim_results": dkim_for_scorer,
            "key_age_analysis": key_age,
            "vendor_fingerprint": vendor_for_scorer,
            "mta_sts": {"configured": mta_sts_configured},
            "tls_rpt": {"configured": tls_rpt_configured},
            "bimi": {"configured": bimi_configured},
            "dane": {"configured": dane_configured},
            "has_mx": has_mx,
        }

        scorer = EmailSecurityScorer()
        return scorer.calculate_score(audit_input)

    except Exception as e:
        import traceback, logging
        logging.error("Scoring failed: %s\n%s", e, traceback.format_exc())
        return {"total_score": 0, "grade": "?", "error": str(e)}


# ============================================================
# Vendor Detection
# ============================================================

def _format_vendors(fp_vendors: List) -> List[Dict]:
    """Format pre-computed vendor fingerprint results for frontend."""
    vendors = []
    for v in fp_vendors:
        confidence = v.get("confidence", 0)
        if confidence >= 0.5:  # Only show meaningful detections
            vendors.append({
                "name": v["vendor"],
                "confidence": int(confidence * 100),
            })

    # Deduplicate by name, keep highest confidence
    seen = {}
    for v in vendors:
        name = v["name"]
        if name not in seen or v["confidence"] > seen[name]["confidence"]:
            seen[name] = v
    return sorted(seen.values(), key=lambda x: x["confidence"], reverse=True)


# ============================================================
# Authentication Resilience Analysis
# ============================================================

def _build_resilience_analysis(
    raw_results: Dict,
    checks: List[Dict],
    has_mx: bool,
    is_defensive: bool,
    tree_walk: Optional[Dict] = None,
) -> Dict:
    """Analyze authentication resilience posture.

    Evaluates how well the domain can survive the failure of any single
    authentication mechanism (SPF, DKIM, DMARC) and returns a structured
    summary suitable for frontend display.

    Args:
        raw_results: Raw check outputs keyed by check name.
        checks: Transformed frontend-ready check cards.
        has_mx: True if the domain has MX records.
        is_defensive: True if the domain is a non-mail defensive DNS domain.
        tree_walk: Tree walk result for inherited DMARC policy detection.

    Returns:
        Dict with keys: level, summary, mechanisms, risk.
    """
    raw_spf = raw_results.get("spf") or {}
    raw_dkim = raw_results.get("dkim") or {}
    raw_dmarc = raw_results.get("dmarc") or {}

    # -- SPF mechanism status --
    spf_record = raw_spf.get("record")
    spf_lookup_count = raw_spf.get("lookup_count") or 0
    if spf_record and spf_lookup_count > 10:
        spf_status = "broken"
        spf_note = (
            f"SPF record exceeds the 10-lookup limit ({spf_lookup_count} lookups). "
            "Receivers will return PermError, which means SPF is effectively non-functional. "
            "This leaves DKIM as the only viable authentication path."
        )
    elif spf_record:
        spf_status = "pass"
        spf_note = (
            f"SPF record is valid ({spf_lookup_count}/10 lookups used). "
            "SPF verifies that the sending server's IP address is authorized by the domain owner. "
            "However, SPF breaks when mail is forwarded because the forwarding server's IP "
            "is not in the original domain's SPF record."
        )
    else:
        spf_status = "missing"
        spf_note = (
            "No SPF record found. Without SPF, receivers cannot verify "
            "whether a sending server is authorized to send mail for this domain."
        )

    # -- DKIM mechanism status --
    found_selectors = raw_dkim.get("found_selectors") or []
    dkim_tested = "dkim" in raw_results
    dkim_timed_out = raw_dkim.get("timed_out", False) or any(
        c.get("name") == "DKIM" and "timed out" in (c.get("verdict") or "").lower()
        for c in checks
    )
    if not dkim_tested:
        dkim_status = "inconclusive"
        dkim_note = "DKIM check was not included in this audit scope."
    elif dkim_timed_out:
        dkim_status = "inconclusive"
        dkim_note = (
            "DKIM check timed out before completing. "
            "DKIM may be configured with custom selectors. Cannot determine status."
        )
    elif found_selectors:
        dkim_status = "detected"
        sel_names = [s.get("selector", "") for s in found_selectors if s.get("selector")]
        sel_count = len(sel_names)
        sel_list = f"Selectors found: {', '.join(sel_names)}." if sel_names else ""
        if sel_count >= 5:
            coverage = (
                f"{sel_count} DKIM selectors detected, indicating broad coverage across multiple email services. "
            )
        elif sel_count >= 2:
            coverage = (
                f"{sel_count} DKIM selectors detected across multiple services. "
            )
        else:
            coverage = "DKIM key detected. "
        dkim_note = (
            f"{coverage}"
            "DKIM signs each message with a cryptographic signature that travels with the email. "
            "Unlike SPF, DKIM survives forwarding because the signature is attached to the message itself, "
            f"not tied to the sending server's IP. {sel_list}"
        )
    else:
        dkim_status = "not_detected"
        dkim_note = (
            "No DKIM keys were found among common selectors tested. "
            "DKIM selector names are chosen by each mail service and are not publicly enumerable, "
            "so DKIM may well be configured with selectors this audit did not test."
        )

    # -- DMARC mechanism status --
    # Check for inherited policy (set by _enrich_dmarc_inheritance)
    _inherited = not raw_dmarc.get("record") and raw_dmarc.get("is_subdomain") and raw_dmarc.get("inherited_policy")
    if _inherited:
        _inh_policy = raw_dmarc["inherited_policy"].lower()
        _inh_source = raw_dmarc.get("inherited_from", "organizational domain")
        _inh_tag = raw_dmarc.get("applied_tag", "p")
        _tag_label = {"sp": "sp=", "np": "np=", "p": "p="}.get(_inh_tag, f"{_inh_tag}=")
        _inh_method = raw_dmarc.get("inheritance_method", "psl")
        _method_label = "DMARCbis tree walk" if _inh_method == "tree_walk" else "RFC 7489 organizational domain fallback (Public Suffix List)"
        dmarc_policy = _inh_policy
    else:
        dmarc_policy = (raw_dmarc.get("policy") or "").lower().strip()

    if _inherited and _inh_policy in ("reject", "quarantine"):
        dmarc_status = _inh_policy
        dmarc_note = (
            f"No DMARC record at this subdomain, but it inherits {_tag_label}{_inh_policy} "
            f"from the organizational domain {_inh_source}. "
        )
        if _inh_policy == "reject":
            dmarc_note += (
                "Messages that fail both SPF and DKIM alignment will be rejected."
            )
        else:
            dmarc_note += (
                "Failing messages will be routed "
                "to the spam or junk folder."
            )
        dmarc_note += (
            f" Discovery method: {_method_label}. "
            ""
        )
    elif _inherited and _inh_policy == "none":
        dmarc_status = "none"
        dmarc_note = (
            f"No DMARC record at this subdomain. It inherits {_tag_label}none "
            f"from {_inh_source} (monitoring only, no enforcement). "
            f"Discovery method: {_method_label}. "
            "Publishing a dedicated record with p=quarantine or p=reject would provide "
            "direct protection for this subdomain."
        )
    elif not raw_dmarc.get("record"):
        dmarc_status = "missing"
        dmarc_note = (
            "No DMARC record found. Without DMARC, there is no policy telling receivers "
            "what to do with messages that fail SPF and DKIM. Anyone can send email that "
            "appears to come from this domain."
        )
    elif dmarc_policy == "reject":
        dmarc_status = "reject"
        dmarc_note = (
            "DMARC policy is p=reject, the strongest enforcement level. "
            "Messages that fail both SPF and DKIM alignment will be rejected. "
            "Spoofed mail from this domain should not reach inboxes."
        )
    elif dmarc_policy == "quarantine":
        dmarc_status = "quarantine"
        dmarc_note = (
            "DMARC policy is p=quarantine. Messages that fail authentication are routed "
            "to the spam or junk folder instead of the inbox. This is one step below p=reject, "
            "which blocks failing messages entirely."
        )
    elif dmarc_policy == "none":
        dmarc_status = "none"
        dmarc_note = (
            "DMARC policy is p=none (monitoring only). Messages are delivered "
            "even if they fail authentication. This is useful for collecting aggregate reports "
            "before enforcing, but provides no protection against spoofing."
        )
    else:
        dmarc_status = "none"
        dmarc_note = "DMARC record exists but policy could not be determined."

    mechanisms = {
        "spf": {"status": spf_status, "note": spf_note},
        "dkim": {"status": dkim_status, "note": dkim_note},
        "dmarc": {"status": dmarc_status, "note": dmarc_note},
    }

    # -- Non-mail domain: short-circuit --
    if is_defensive:
        return {
            "level": "high",
            "summary": (
                "This domain is configured to not send email. "
                "SPF rejects all senders and DMARC policy instructs receivers to reject "
                "any message claiming to be from this domain."
            ),
            "mechanisms": mechanisms,
            "risk": "Low risk. All email from this domain will be rejected by compliant receivers.",
        }

    # -- Derive resilience level and risk text --
    spf_functional = spf_status == "pass"
    dkim_functional = dkim_status == "detected"
    # "not_detected" means our heuristic didn't find keys, but DKIM may still be
    # configured with custom selectors. Treat it the same as "inconclusive" so we
    # never penalize based on a heuristic miss.
    dkim_inconclusive = dkim_status in ("inconclusive", "not_detected")
    dmarc_enforcing = dmarc_status in ("quarantine", "reject")

    # Alignment explainer fragments (used in several branches)
    _alignment_how = (
        "DMARC requires identifier alignment: the domain authenticated by SPF or DKIM "
        "must match the domain in the visible From address. For SPF, the Return-Path domain "
        "must align with the From domain. For DKIM, the d= domain in the signature must align "
        "with the From domain. In relaxed mode (the default), subdomains of the same "
        "organizational domain satisfy alignment (e.g. mail.example.com aligns with example.com)."
    )

    # Check if this is a non-sending subdomain with inherited DMARC
    _is_inherited_dmarc = _inherited and dmarc_enforcing
    _is_non_sending_sub = _is_inherited_dmarc and not has_mx and not spf_functional

    if _is_non_sending_sub:
        _inh_source = raw_dmarc.get("inherited_from", "organizational domain")
        level = "high" if dmarc_status == "reject" else "moderate"
        summary = (
            f"This subdomain does not send email (no MX records, no SPF). "
            f"It inherits DMARC {dmarc_status} from {_inh_source}, which instructs receivers to "
            + ("reject" if dmarc_status == "reject" else "quarantine")
            + " any message claiming to be from this subdomain. "
            "This is the expected configuration for a non-sending subdomain."
        )
        risk = (
            "No action needed. The inherited DMARC policy protects this subdomain against spoofing. "
            "SPF and DKIM are not required because this subdomain does not send email."
        )
    elif dmarc_status == "missing":
        level = "none"
        summary = (
            "No DMARC record found. Without a DMARC policy, receivers have no instructions "
            "for handling messages that fail authentication. SPF and DKIM results alone "
            "do not protect against spoofing without DMARC tying them together."
        )
        risk = (
            "Publishing a DMARC record is the single most impactful step this domain can take. "
            "Start with p=none and a rua= address to collect aggregate reports showing who is "
            "sending mail as this domain. Once legitimate sources are identified and authenticated, "
            "move to p=quarantine and then p=reject."
        )
    elif spf_status == "broken" and not dkim_functional:
        level = "low"
        summary = (
            "SPF is broken (PermError) and no DKIM was detected. This domain has no reliable "
            "path to DMARC pass. Messages may be rejected or junked depending on the DMARC policy."
        )
        risk = (
            "Fix SPF first by reducing the record to 10 or fewer DNS lookups "
            "(remove includes for services you no longer use)."
        )
    elif not spf_functional and not dkim_functional:
        level = "low"
        summary = (
            "Neither SPF nor DKIM is providing a working authentication path. Even with a DMARC record, "
            "there is no mechanism that can pass and satisfy alignment."
        )
        risk = (
            "Publish an SPF record listing authorized sending IPs and enable DKIM signing "
            "for all mail services. Both should be configured so the domain has redundant "
            "alignment paths. DKIM is especially important because it survives mail forwarding."
        )
    elif spf_functional and dkim_functional and dmarc_enforcing:
        level = "high"
        summary = (
            "SPF and DKIM both provide independent paths to DMARC alignment, and DMARC is enforcing. "
            "This is the strongest configuration. If one mechanism fails for a given message, "
            "the other can still satisfy DMARC on its own."
        )
        if dmarc_status == "quarantine":
            policy_note = (
                "The current policy is p=quarantine, which sends failing messages to the spam or junk folder. "
                "This is effective but not the strongest option. With p=reject, receivers block "
                "failing messages entirely rather than delivering them to spam. If all legitimate mail sources "
                "are properly authenticated with SPF and DKIM, upgrading to p=reject "
                "provides the strongest protection against spoofing."
            )
        else:
            policy_note = (
                "The current policy is p=reject, the strongest enforcement level. "
                "Messages that fail both SPF and DKIM alignment are rejected outright."
            )
        risk = (
            f"{policy_note} "
            "Having both mechanisms active matters because SPF and DKIM fail in different scenarios. "
            "SPF checks the sending server's IP against the domain's authorized list, which means it breaks "
            "when mail is forwarded through mailing lists, forwarding rules, or relay services. "
            "DKIM attaches a cryptographic signature to the message itself, so it survives forwarding. "
            "Of the two, DKIM is the more reliable alignment mechanism for this reason. "
            f"{_alignment_how}"
        )
    elif spf_status == "broken" and dkim_functional:
        level = "moderate"
        summary = (
            "SPF is broken (PermError), leaving DKIM as the only authentication path. "
            "This is a single point of failure: if DKIM fails for any message, there is no fallback."
        )
        risk = (
            "Fix the SPF record by reducing it to 10 or fewer DNS lookups to restore the second "
            "alignment path. With only DKIM available, the domain depends entirely on every sending "
            "service signing messages correctly. SPF provides a useful safety net even though DKIM is "
            "the more resilient mechanism."
        )
    elif dkim_functional and not spf_functional and dmarc_enforcing:
        level = "moderate"
        summary = (
            "DKIM is configured and provides a path to DMARC alignment, but no SPF record was found. "
            "DKIM is the more resilient mechanism (survives forwarding), so this is stronger than SPF alone."
        )
        risk = (
            "Publishing an SPF record would add a second alignment path. While DKIM alone can satisfy "
            "DMARC, having both provides redundancy if one mechanism fails for a given message."
        )
    elif dkim_inconclusive and spf_functional and dmarc_enforcing:
        level = "moderate"
        summary = (
            "SPF is functional and DMARC is enforcing. DKIM status could not be confirmed "
            "because DKIM selectors are not publicly enumerable. "
            "If DKIM is configured (likely), resilience is high."
        )
        risk = (
            "DKIM selector names are chosen by each mail service and cannot be discovered from "
            "the outside. This audit tested common selectors but may have missed custom ones. "
            "SPF provides one alignment path. If DKIM is also configured, the domain has "
            "redundant alignment paths and strong resilience."
        )
    elif dkim_inconclusive and spf_functional:
        level = "moderate"
        summary = (
            "SPF is functional but DKIM status could not be confirmed, "
            "and DMARC is not enforcing."
        )
        risk = (
            "Move the DMARC policy from p=none to p=quarantine or p=reject. "
            "Without enforcement, DMARC reports authentication failures but takes no action to prevent spoofing."
        )
    elif not dkim_functional and spf_functional:
        level = "moderate"
        summary = (
            "SPF is functional and provides one DMARC alignment path. "
            "DKIM status could not be confirmed."
        )
        risk = (
            "SPF provides IP-based authentication. DKIM selector names are chosen by each "
            "mail service and are not publicly enumerable, so DKIM may be configured with "
            "selectors this audit did not test."
        )
    elif not dmarc_enforcing:
        level = "moderate"
        summary = (
            f"DMARC is p={dmarc_status} (monitoring only). SPF and DKIM may be present, but "
            "receivers will not act on authentication failures. Spoofed messages will still be delivered."
        )
        risk = (
            "p=none is the right starting point for collecting data, but it provides no protection. "
            "Review DMARC aggregate reports (rua=) to identify all legitimate mail sources, ensure each "
            "one passes SPF or DKIM with alignment, and then move to p=quarantine. After confirming no "
            "legitimate mail is being caught, upgrade to p=reject."
        )
    else:
        level = "moderate"
        summary = "Authentication is partially configured. At least one mechanism is missing or inactive."
        risk = (
            "A complete email authentication setup requires three layers: SPF to authorize sending IPs, "
            "DKIM to cryptographically sign messages, and DMARC to enforce a policy when both fail. "
            "DKIM is especially important because it is the only mechanism that survives mail forwarding."
        )

    return {
        "level": level,
        "summary": summary,
        "mechanisms": mechanisms,
        "risk": risk,
    }


# ============================================================
# Priority Fixes
# ============================================================

def _build_priority_fixes(checks: List[Dict], score_result: Dict, has_mx: bool = True) -> List[str]:
    """
    Build prioritized fix list from check results and scorer recommendations.
    Maximum 5 items, ordered by severity. Deduplicates by check name.

    For non-mail domains (has_mx=False), skip email-infrastructure fixes
    since they're not applicable.
    """
    # Checks that only matter for mail-sending domains
    MAIL_ONLY_CHECKS = {"SPF", "MX Records", "MX", "MTA-STS", "TLS-RPT", "DKIM", "BIMI", "DANE"}

    fixes = []
    covered_checks = set()

    # Scorer recommendations (already prioritized and more actionable)
    scorer_recs = score_result.get("recommendations", [])
    for rec in scorer_recs:
        # Strip emoji prefixes for clean display
        clean = re.sub(r'^[^\w]*\s*(?:CRITICAL|HIGH|MEDIUM|LOW):\s*', '', rec)
        if clean and clean not in fixes:
            fixes.append(clean)
            # Track which checks are covered to avoid duplicates
            for keyword in ['DMARC', 'SPF', 'DKIM', 'MTA-STS', 'TLS-RPT', 'MX', 'CAA', 'Nameservers', 'DNSSEC', 'DANE']:
                if keyword.lower() in clean.lower():
                    covered_checks.add(keyword)

    # Check-level fixes (only for checks the scorer didn't already cover)
    for check in checks:
        if check.get("status") == "fail" and check.get("fix"):
            check_name = check.get("name", "")
            if check_name in covered_checks:
                continue
            # Skip email-infrastructure fixes for non-mail domains
            if not has_mx and check_name in MAIL_ONLY_CHECKS:
                continue
            # Skip error cards (generic retry messages aren't actionable)
            if check.get("pill_label") == "Error":
                continue
            # Strip HTML for the priority list
            fix_text = re.sub(r'<[^>]+>', '', check["fix"])
            # Collapse whitespace from removed HTML tags
            fix_text = re.sub(r'\s+', ' ', fix_text).strip()
            if fix_text and fix_text not in fixes:
                fixes.append(fix_text)

    return fixes[:5]


# ============================================================
# Error Card Helper
# ============================================================

def _timeout_card(name: str) -> Dict:
    """Generate a card for a check that timed out."""
    return {
        "name": name,
        "status": "warn",
        "pill_label": "Timeout",
        "verdict": f"{name} check timed out",
        "record": None,
        "explanation": f"The {name} check did not complete within {CHECK_TIMEOUT} seconds. This usually means the domain's DNS server is slow to respond.",
        "details": [
            {"type": "warning", "text": f"Check timed out after {CHECK_TIMEOUT}s"},
        ],
        "fix": "Try running the audit again. If the issue persists, the domain's DNS infrastructure may have connectivity issues.",
    }


def _error_card(name: str, error: Exception) -> Dict:
    """Generate a card for a check that threw an exception."""
    return {
        "name": name,
        "status": "fail",
        "pill_label": "Error",
        "verdict": "Check failed due to an error",
        "record": None,
        "explanation": f"An unexpected error occurred while running the {name} check. This may be a temporary DNS issue.",
        "details": [
            {"type": "error", "text": f"Error: {str(error)[:200]}"},
        ],
        "fix": "Try running the audit again. If the issue persists, the DNS server may be unresponsive.",
    }
