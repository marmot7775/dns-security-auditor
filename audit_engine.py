"""
Audit Engine
=============
Orchestrates all security checks for a domain.
Each check runs independently -- if one fails, the others still complete.
Assembles results for the security scorer and transforms everything
into the frontend's expected format.
"""

import ipaddress
import logging
import os
import re
import threading as _ct_threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from datetime import datetime, timezone
from html import escape as _e
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Per-check timeout in seconds (prevents hung DNS queries from blocking the audit)
CHECK_TIMEOUT = 15

# CT (crt.sh) result cache -- 24-hour TTL because CT data rarely changes
# and crt.sh is frequently slow or unavailable.
_ct_cache = {}
_ct_cache_lock = _ct_threading.Lock()
CT_CACHE_TTL = 86400  # 24 hours


def _get_cached_ct(domain):
    with _ct_cache_lock:
        entry = _ct_cache.get(domain)
        if entry and (time.time() - entry['timestamp']) < CT_CACHE_TTL:
            return entry['data']
    return None


def _get_stale_ct(domain):
    """Return stale cache entry if available (for fallback on timeout)."""
    with _ct_cache_lock:
        entry = _ct_cache.get(domain)
        if entry:
            return entry['data']
    return None


def _set_cached_ct(domain, data):
    with _ct_cache_lock:
        _ct_cache[domain] = {'data': data, 'timestamp': time.time()}


import dns.resolver
import dns.flags
import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.dnssec
import dns.name
import dns.rcode


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/loopback/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return True  # Reject unparseable IPs

from checks_extra import check_mta_sts, check_tls_rpt, check_bimi
from mx_check import check_mx
from spf_recursive import count_spf_lookups, repair_spf_missing_spaces
from advanced_fingerprinting import AdvancedVendorFingerprinter
from dkim_formatter import analyze_dkim_key_strength
from anomaly_detector import detect_anomalies
from remediation_planner import build_remediation_plan
from dkim_key_age import DKIMKeyAgeAnalyzer

from dmarc_tree_walk import dmarc_tree_walk
try:
    import tldextract
    # ProtectHome=read-only on the prod systemd unit makes tldextract's
    # default ~/.cache path unwritable, which crashes the DMARC check.
    # Pin the cache under the working directory (in ReadWritePaths).
    _tldextract_cache_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".tldextract_cache"
    )
    _tld_extract = tldextract.TLDExtract(cache_dir=_tldextract_cache_dir)
except ImportError:
    tldextract = None
    _tld_extract = None
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
    build_security_roadmap,
    build_executive_summary,
    build_subdomain_audit,
    build_change_detection,
    build_consistency_findings,
    _build_provider_intelligence,
)
from dns_snapshots import store_audit_snapshots, get_all_history, purge_old_snapshots, get_first_seen


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
    "Omnivery/Mailkit": "include:spf.mailkit.eu",
}


# ============================================================
# Business Risk Vocabulary
# ============================================================
# Plain-English business-impact callouts for selected SPF/DKIM/DMARC findings.
# Audience: non-technical readers (executives, compliance, marketing).
# Style rules: max 25 words per sentence, no em-dashes, no scare tactics,
# second person ("your domain", "your customers"). Lead with consequence.

BUSINESS_RISK = {
    # ── SPF ──────────────────────────────────────────────────
    "SPF_NO_RECORD": (
        "Without SPF, attackers can send email claiming to be from your domain, "
        "exposing customers to phishing and damaging brand trust."
    ),
    "SPF_MULTIPLE_RECORDS": (
        "Multiple SPF records cause receivers to ignore all of them, so your "
        "legitimate mail fails authentication and may be marked as spam."
    ),
    "SPF_PERMERROR": (
        "SPF errors mean receivers cannot verify your legitimate mail; "
        "spoofed mail may pass while real mail gets rejected, causing "
        "customer service and deliverability problems."
    ),
    "SPF_PLUS_ALL": (
        "Authorizing every server on the internet defeats SPF entirely and "
        "lets anyone send email impersonating your domain."
    ),
    "SPF_NEUTRAL_ALL": (
        "A neutral all mechanism tells receivers nothing about unauthorized "
        "senders, so impersonation attempts against your customers are not blocked."
    ),
    "SPF_NO_ALL": (
        "Without an all mechanism, receivers default to neutral and have no "
        "guidance to reject spoofed mail from your domain."
    ),
    # ── DMARC ────────────────────────────────────────────────
    "DMARC_NO_RECORD": (
        "No DMARC record means receivers have no guidance on what to do with "
        "unauthenticated mail. Google and Yahoo deprioritize or reject mail "
        "from bulk senders without DMARC, harming legitimate deliverability."
    ),
    "DMARC_MULTIPLE_RECORDS": (
        "When multiple DMARC records exist, receivers ignore the policy entirely, "
        "so spoofing protections you intended to publish are not actually applied."
    ),
    "DMARC_P_NONE": (
        "DMARC monitoring-only mode collects data but does not block spoofing. "
        "Attackers can still impersonate your domain in phishing attacks against "
        "customers and staff."
    ),
    "DMARC_NO_RUA": (
        "Without aggregate reporting, you have no visibility into who is sending "
        "mail as your domain. Spoofing attacks may already be happening undetected."
    ),
    "DMARC_PCT_LOW": (
        "Partial enforcement leaves some failed messages delivered, so attackers "
        "still succeed at impersonating your domain a fraction of the time."
    ),
    "DMARC_TEST_MODE": (
        "Test mode signals receivers to apply a softer policy than published, so "
        "attackers see the relaxed policy rather than your intended enforcement."
    ),
    "DMARC_PARSE_FAILURE": (
        "An unparseable DMARC record gives receivers no policy to apply, leaving "
        "your domain effectively unprotected against spoofing."
    ),
    # ── DKIM ─────────────────────────────────────────────────
    "DKIM_NO_KEYS_FOUND": (
        "Without DKIM, mail can be modified in transit and your domain reputation "
        "cannot accumulate. Receivers have less reason to trust your mail, "
        "increasing spam folder placement."
    ),
    "DKIM_SELECTOR_NOT_FOUND": (
        "If your DKIM selector is missing or misconfigured, receivers cannot "
        "verify your signatures and your mail is more likely to land in spam."
    ),
    "DKIM_WEAK_KEY": (
        "A 1024-bit DKIM key can be cracked with current resources, allowing "
        "attackers to forge signed mail that appears genuinely from your domain."
    ),
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
    # Use DNSSEC-validating public resolvers. Quad9 first because its
    # AD-bit signal is the strictest (drops bogus answers rather than
    # returning AD=0), so when we fall back to AD-only annotation the
    # signal is most trustworthy.
    resolver.nameservers = ["9.9.9.9", "1.1.1.1", "1.0.0.1", "8.8.8.8"]
    # Set DO flag — without this, resolvers may not return DNSKEY/RRSIG
    resolver.use_edns(0, dns.flags.DO, 4096)
    return resolver


def _lookup_txt(name: str) -> List[str]:
    """Look up TXT records, correctly concatenating multi-string records.

    Per RFC 7208 Section 3.3, multi-string TXT records MUST be
    concatenated with no separator (raw byte join).  This preserves
    values that span string boundaries (e.g. a 255-byte split landing
    mid-IP-address).  SPF-specific code downstream uses
    repair_spf_missing_spaces() to handle domains (like GitHub) that
    store each mechanism as a separate string without embedded spaces.
    """
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            parts = []
            for s in rdata.strings:
                parts.append(s.decode("utf-8") if isinstance(s, bytes) else str(s))
            # Concatenate WITHOUT spaces -- RFC-correct for all record types.
            txt = "".join(parts)
            # Some resolvers escape semicolons in TXT records (\;).
            # Normalize so downstream parsers split correctly.
            txt = txt.replace("\\;", ";")
            records.append(txt)
        return records
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NoNameservers:
        log.debug("SERVFAIL/REFUSED for TXT lookup: %s", name)
        return []
    except dns.exception.Timeout:
        log.debug("Timeout for TXT lookup: %s", name)
        return []
    except dns.exception.DNSException as e:
        log.debug("DNS error for TXT lookup %s: %s", name, e)
        return []


def _lookup_ttl(name: str, rdtype: str = "TXT") -> Optional[int]:
    """Look up the TTL for a DNS record. Returns None on any failure."""
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, rdtype)
        return answers.rrset.ttl if answers.rrset else None
    except dns.exception.DNSException:
        return None


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

    # Determine org domain for external check. Tree walk takes priority;
    # fall back to the PSL-aware _get_org_domain so two-part TLDs like
    # co.uk and com.au resolve correctly (an inline last-two-labels
    # heuristic would yield "co.uk" for example.co.uk and falsely flag
    # rua=mailto:dmarc@example.co.uk as external).
    org_domain = None
    if tree_walk_result and tree_walk_result.get("org_domain"):
        org_domain = tree_walk_result["org_domain"].lower().rstrip(".")
    else:
        psl_org = _get_org_domain(domain)
        if psl_org:
            org_domain = psl_org.lower().rstrip(".")
        else:
            org_domain = domain.lower().rstrip(".")

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
                        r.strip().startswith("v=DMARC1")
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
        ext = _tld_extract(domain)
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
    org_dmarc = [r for r in org_recs if r.strip().startswith("v=DMARC1")]
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

_RUA_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _is_rua_syntactically_valid(rua_value: str) -> bool:
    """Return True if rua_value contains at least one syntactically
    valid reporting URI, per dmarcbis-41 §4.10.1.

    A URI counts as syntactically valid if it starts with mailto:
    (case-insensitive) and the email part matches local@domain.tld.
    Per RFC 6068, an optional !size modifier after the email address
    is stripped before validation.
    """
    if not rua_value:
        return False
    for raw in rua_value.split(","):
        candidate = raw.strip()
        if len(candidate) < 7 or not candidate[:7].lower() == "mailto:":
            continue
        email_part = candidate[7:].split("!", 1)[0]
        if _RUA_EMAIL_RE.match(email_part):
            return True
    return False


def _emit_size_modifier_info(result: Dict[str, Any], tag_name: str, addr: str) -> None:
    """Append a spec-required info issue for a rua/ruf URI carrying an
    obsolete !size modifier (dmarcbis-41 §C.4 / §4.8).

    Caller has already verified addr starts with 'mailto:' and contains
    '!' in the payload after 'mailto:'. Modifier is everything after the
    first '!' in the payload; format isn't validated (it's obsolete —
    deeper validation is wasted work).
    """
    modifier = addr[7:].split("!", 1)[1]
    result["issues"].append({
        "severity": "info",
        "issue": "rua/ruf size modifier (!N) is obsolete in dmarcbis",
        "plain_english": (
            f"Your DMARC record uses the legacy size modifier "
            f"(e.g., {addr} has !{modifier}). dmarcbis-41 §C.4 removed "
            "this syntax. Receivers implementing dmarcbis will ignore "
            "the size limit; receivers following RFC 7489 still honor it. "
            "Remove the modifier to be forward-compatible."
        ),
        "fix": (
            f"Edit the {tag_name}= URI to remove the !N suffix "
            "(everything after the @domain.tld!). Example: change "
            f"{tag_name}=mailto:reports@example.com!10m to "
            f"{tag_name}=mailto:reports@example.com."
        ),
        "source": "spec_required",
        "spec_reference": "dmarcbis-41 §C.4 / §4.8",
    })


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
        "policy_recovery_applied": False,
    }

    def _add_issue(severity, issue, plain_english, fix, business_risk_key=None):
        entry = {
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        }
        if business_risk_key:
            risk = BUSINESS_RISK.get(business_risk_key)
            if risk:
                entry["business_risk"] = risk
        result["issues"].append(entry)

    def _add_syntax(issue, plain_english, fix):
        """Syntax errors are always severity=error."""
        result["syntax_errors"].append({
            "severity": "error",
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    # ── Step 0: CNAME detection ────────────────────────────────
    dmarc_fqdn = f"_dmarc.{domain}"
    try:
        resolver = _get_resolver()
        cname_answers = resolver.resolve(dmarc_fqdn, "CNAME")
        cname_target = str(cname_answers[0].target).rstrip(".")
        result["cname_target"] = cname_target
        _add_issue(
            "info",
            f"DMARC record is aliased via CNAME to {cname_target}",
            f"The DMARC record at {dmarc_fqdn} is a CNAME pointing to "
            f"{cname_target}. This is a supported configuration commonly used "
            "with managed DMARC services. The actual record is fetched from the "
            "CNAME target.",
            "No action needed. CNAME-based DMARC delegation is valid.",
        )
    except dns.exception.DNSException:
        pass  # No CNAME -- normal case

    # ── Step 1: Lookup ──────────────────────────────────────────
    dmarc_recs = _lookup_txt(dmarc_fqdn)

    # Pre-check: lowercase v=dmarc1 is invalid per RFC 7489 S6.3 (case-sensitive).
    # Detect BEFORE the strict v=DMARC1 filter so the syntax error is captured
    # even though the record is excluded from the count.
    for _r in dmarc_recs:
        _stripped = _r.strip()
        if _stripped.lower().startswith("v=dmarc1") and not _stripped.startswith("v=DMARC1"):
            _add_syntax(
                "Lowercase v=dmarc1 detected",
                "Lowercase v=dmarc1 detected. RFC 7489 requires uppercase. "
                "This record is invalid and will not be honored.",
                "Change to v=DMARC1 (uppercase).",
            )

    dmarc_records = [r for r in dmarc_recs if r.strip().startswith("v=DMARC1")]

    # Note any non-DMARC TXT records at the _dmarc subdomain.
    # Lowercase v=dmarc1 records are excluded here because the pre-check above
    # already reports them via a dedicated syntax error.
    non_dmarc_txt = [
        r for r in dmarc_recs
        if not r.strip().startswith("v=DMARC1")
        and not r.strip().lower().startswith("v=dmarc1")
    ]
    if non_dmarc_txt:
        result["non_dmarc_txt_count"] = len(non_dmarc_txt)
        _add_issue(
            "info",
            f"{len(non_dmarc_txt)} non-DMARC TXT record(s) at {dmarc_fqdn}",
            f"Found {len(non_dmarc_txt)} TXT record(s) at {dmarc_fqdn} that "
            "do not start with 'v=DMARC1'. These are not DMARC records and "
            "are ignored by DMARC processors. They may be misconfigured SPF "
            "or other records accidentally placed at the wrong subdomain.",
            f"Review the non-DMARC TXT records at {dmarc_fqdn} and remove "
            "any that were placed there by mistake.",
        )

    # Detect wildcard DMARC records (not valid for DMARC)
    if "*" in domain:
        _add_issue(
            "warning",
            "Wildcard DMARC records are not supported",
            "DMARC does not support wildcard records. A record at "
            "_dmarc.*.example.com will not be discovered during DMARC "
            "policy lookup. Each subdomain must have its own DMARC record "
            "or inherit from the organizational domain.",
            "Remove the wildcard and publish DMARC records on specific "
            "subdomains, or rely on policy inheritance from the org domain.",
        )

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
            business_risk_key="DMARC_NO_RECORD",
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
            business_risk_key="DMARC_MULTIPLE_RECORDS",
        )
        result["record"] = dmarc_records[0]
        result["strict_validation"] = _validate_dmarc_strict(
            dmarc_records[0], dmarc_records_count=len(dmarc_records)
        )
        result["legacy_validation"] = _validate_dmarc_legacy(
            dmarc_records[0], dmarc_records_count=len(dmarc_records)
        )
        return result

    record = dmarc_records[0]
    result["record"] = record

    # Capture TTL for freshness indicators
    result["ttl"] = _lookup_ttl(dmarc_fqdn, "TXT")

    # ── Step 2b: Long record warning ────────────────────────────
    if len(record) > 1000:
        _add_issue(
            "warning",
            f"DMARC record is very long ({len(record)} characters)",
            "This DMARC record exceeds 1000 characters. DNS responses over "
            "512 bytes may be truncated when using UDP transport, which could "
            "cause some resolvers to fail to retrieve the full record. Most "
            "modern resolvers retry over TCP, but some older or misconfigured "
            "resolvers may not.",
            "Consider shortening the record by consolidating report addresses "
            "or removing unnecessary tags.",
        )

    # ── Step 3: Structural / formatting syntax checks ───────────
    # These run BEFORE tag parsing because they can make parsing unreliable.

    # 3a. Lowercase v=dmarc1 is handled by the pre-check above Step 1.
    # Records reaching here have already passed the strict v=DMARC1 filter.
    stripped = record.strip()

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
                        "Deprecated tag: 'pct' (removed in dmarcbis-41 §C.5.2)",
                        "dmarcbis-41 §C.5.2 (Tags Removed) and §A.6 explicitly "
                        "remove the pct tag. The dmarcbis testing mechanism is "
                        "the t tag (§4.7): t=y signals receivers to apply the "
                        "policy one level below the published p value. Current "
                        "RFC 7489 receivers still honor pct, but dmarcbis-"
                        "compliant receivers will ignore it.",
                        "Remove the pct tag. If you were using pct<100 to test enforcement, set t=y instead.",
                    )
                elif key_clean == "ri":
                    _add_issue(
                        "info",
                        "Deprecated tag: 'ri' (removed in dmarcbis-41 §C.5.2)",
                        "dmarcbis-41 §C.5.2 (Tags Removed) explicitly lists "
                        "ri among the tags removed from the protocol, so it "
                        "is also absent from the §4.7 tag registry. Current "
                        "RFC 7489 receivers may still honor ri, but dmarcbis-"
                        "compliant receivers will ignore it; in practice "
                        "receivers send aggregate reports on their own "
                        "schedule regardless of ri.",
                        "Remove the ri tag.",
                    )
                elif key_clean == "rf":
                    _add_issue(
                        "info",
                        "Deprecated tag: 'rf' (removed in dmarcbis-41 §C.5.2)",
                        "dmarcbis-41 §C.5.2 (Tags Removed) explicitly lists "
                        "rf among the tags removed from the protocol, so it "
                        "is also absent from the §4.7 tag registry. The only "
                        "value ever defined was 'afrf', so the tag never "
                        "carried useful information; dmarcbis-compliant "
                        "receivers will ignore it.",
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

    # 6a. Policy (p=) — required tag. Syntax errors are emitted here;
    #     receiver-side recovery (dmarcbis §4.10.1) is decided after
    #     sp= and np= have also been validated.
    raw_policy = tags.get("p", "")
    policy = raw_policy.lower()
    result["policy"] = policy

    p_missing = not raw_policy
    p_invalid_value = bool(raw_policy) and policy not in VALID_POLICIES

    if p_invalid_value:
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
    sp_invalid_value = bool(raw_sp) and sp not in VALID_POLICIES
    if sp_invalid_value:
        _add_syntax(
            f"Invalid subdomain policy: sp={raw_sp}",
            f"'{raw_sp}' is not a valid subdomain policy. Same rules as p= apply.",
            "Change to sp=none, sp=quarantine, or sp=reject.",
        )

    # 6b2. Non-existent subdomain policy (np=) — DMARCbis §4.7
    raw_np = tags.get("np", "")
    np_val = raw_np.lower() if raw_np else None
    result["np"] = np_val
    np_invalid_value = bool(raw_np) and np_val not in VALID_POLICIES
    if np_invalid_value:
        _add_syntax(
            f"Invalid non-existent subdomain policy: np={raw_np}",
            f"'{raw_np}' is not a valid np policy. Same rules as p= apply. "
            "The np tag controls policy for subdomains that don't exist in DNS.",
            "Change to np=none, np=quarantine, or np=reject.",
        )

    # 6b-recovery. dmarcbis-41 §4.10.1 receiver behavior.
    #
    # Verbatim from §4.10.1:
    #   "If a retrieved DMARC Policy Record does not contain a valid 'p'
    #    tag, or contains an 'sp' or 'np' tag that is not valid, then:
    #    *  If a 'rua' tag is present and contains at least one
    #       syntactically valid reporting URI, the Mail Receiver MUST
    #       act as if a record containing 'p=none' was retrieved and
    #       continue processing;
    #    *  Otherwise, the Mail Receiver applies no DMARC processing to
    #       this message."
    #
    # The trigger covers all four cases: missing p, invalid p, invalid
    # sp, invalid np. Recovery is dmarcbis-only; RFC 7489 has no such
    # fallback. We surface the interop split so users don't assume the
    # broken record is universally honored. Per-tag _add_syntax above
    # is preserved — recovery is a separate, receiver-side concern.
    recovery_trigger = None
    if p_missing:
        recovery_trigger = ("p", None, "missing")
    elif p_invalid_value:
        recovery_trigger = ("p", raw_policy, "invalid")
    elif sp_invalid_value:
        recovery_trigger = ("sp", raw_sp, "invalid")
    elif np_invalid_value:
        recovery_trigger = ("np", raw_np, "invalid")

    if recovery_trigger:
        rua_for_recovery = tags.get("rua", "")
        rua_valid_for_recovery = _is_rua_syntactically_valid(rua_for_recovery)
        rec_tag_name, rec_tag_value, rec_kind = recovery_trigger
        if rua_valid_for_recovery:
            policy = "none"
            result["policy"] = policy
            result["policy_recovery_applied"] = True
            if rec_kind == "missing":
                _add_issue(
                    "warning",
                    "Missing p= tag. Spec recovery: dmarcbis treats "
                    "record as p=none, RFC 7489 receivers ignore.",
                    "This record has no explicit policy tag. Per "
                    "dmarcbis-41 §4.10.1, because rua= contains at "
                    "least one syntactically valid reporting URI, "
                    "dmarcbis-compliant receivers MUST act as if a "
                    "record containing p=none was retrieved and "
                    "continue processing. RFC 7489 has no such "
                    "fallback; older receivers (still common) will "
                    "ignore the record entirely. Same record, two "
                    "different behaviors.",
                    "Add an explicit p=none (or p=quarantine / "
                    "p=reject). Explicit policy works under both "
                    "specs and removes the ambiguity.",
                )
            else:
                _add_issue(
                    "warning",
                    f"Invalid {rec_tag_name}= value: {rec_tag_name}="
                    f"{rec_tag_value}. Spec recovery: dmarcbis treats "
                    f"record as p=none, RFC 7489 receivers may ignore.",
                    f"Per dmarcbis-41 §4.10.1, because rua= contains "
                    f"at least one syntactically valid reporting URI, "
                    f"dmarcbis-compliant receivers MUST act as if a "
                    f"record containing p=none was retrieved and "
                    f"continue processing. RFC 7489 has no such "
                    f"recovery rule; older receivers may instead "
                    f"ignore the record entirely. Interop hazard — "
                    f"fix the value rather than relying on this "
                    f"fallback.",
                    f"Set {rec_tag_name}= to one of: none, quarantine, "
                    f"reject. Do not rely on the dmarcbis recovery "
                    f"fallback to mask the invalid value.",
                )
        else:
            if rec_kind == "missing":
                _add_syntax(
                    "Missing required policy tag (p=) and no valid rua= URI",
                    "Per dmarcbis-41 §4.10.1, a record without a valid "
                    "p= tag is recoverable only when rua= contains at "
                    "least one syntactically valid mailto: URI. This "
                    "record has neither, so receivers apply no DMARC "
                    "processing to messages — equivalent to having no "
                    "DMARC record at all.",
                    "Add a policy tag. Start with p=none for "
                    "monitoring, and add rua=mailto:dmarc-reports@"
                    "yourdomain.com to receive aggregate reports.",
                )
            else:
                _add_issue(
                    "error",
                    f"Invalid {rec_tag_name}= value AND no valid rua= URI. "
                    f"Per dmarcbis-41 §4.10.1, this record yields no "
                    f"DMARC processing.",
                    f"dmarcbis-41 §4.10.1 specifies that receivers "
                    f"apply no DMARC processing when an invalid "
                    f"{rec_tag_name}= is published without a "
                    f"syntactically valid rua= URI. Effectively, this "
                    f"record produces the same outcome as having no "
                    f"DMARC record at all.",
                    f"Set {rec_tag_name}= to a valid value (none, "
                    f"quarantine, or reject) AND add a valid rua= URI "
                    f"such as rua=mailto:reports@yourdomain.com.",
                    business_risk_key="DMARC_PARSE_FAILURE",
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
            elif addr and "!" in addr[7:]:
                _emit_size_modifier_info(result, "rua", addr)

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
            elif addr and "!" in addr[7:]:
                _emit_size_modifier_info(result, "ruf", addr)

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
            business_risk_key="DMARC_P_NONE",
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
                business_risk_key="DMARC_PCT_LOW",
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
                business_risk_key="DMARC_PCT_LOW",
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
            business_risk_key="DMARC_TEST_MODE",
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
            business_risk_key="DMARC_NO_RUA",
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

    # ── DMARCbis Readiness Assessment (informational only) ─────
    if result["record"]:
        result["dmarcbis_readiness"] = _assess_dmarcbis_readiness(result)
        result["strict_validation"] = _validate_dmarc_strict(
            result["record"], dmarc_records_count=1
        )
        result["legacy_validation"] = _validate_dmarc_legacy(
            result["record"], dmarc_records_count=1
        )

    return result


def _validate_dmarc_strict(record: str, dmarc_records_count: int = 1) -> Dict:
    """DMARCbis-strict layered validation.

    Returns structured results with pass/fail/warn per check, grouped by
    category: record_structure, uri_validation, external_auth, tag_values,
    dns_integrity.
    """
    import re

    SINGLETON_TAGS = {"v", "p", "sp", "np", "adkim", "aspf", "pct", "fo", "rf", "ri", "psd", "t"}
    KNOWN_TAGS = SINGLETON_TAGS | {"rua", "ruf"}
    VALID_POLICIES = {"none", "quarantine", "reject"}

    checks: list = []
    has_structural_errors = False

    def _add(category, code, status, message):
        nonlocal has_structural_errors
        checks.append({"category": category, "code": code, "status": status, "message": message})
        if status == "fail":
            has_structural_errors = True

    # ── Layer 1: Tokenization ──────────────────────────────
    tokens = re.split(r'\s*;\s*', record.strip().rstrip(";").strip())
    tokens = [t for t in tokens if t.strip()]

    parsed_tags: list = []  # list of (key, value, raw_token)
    tag_counts: dict = {}

    for token in tokens:
        m = re.match(r'^(?P<key>[a-zA-Z][a-zA-Z0-9_-]*)=(?P<value>.+)$', token.strip())
        if m:
            key = m.group("key").lower()
            value = m.group("value")
            parsed_tags.append((key, value, token.strip()))
            tag_counts[key] = tag_counts.get(key, 0) + 1
        elif token.strip():
            _add("record_structure", "MALFORMED_TAG", "fail",
                 f"Cannot parse '{token.strip()}'. Expected format: tag=value.")

    # Build dict of first-seen values for semantic checks
    tag_dict: dict = {}
    for k, v, _ in parsed_tags:
        if k not in tag_dict:
            tag_dict[k] = v

    # ── Layer 2: Grammar enforcement ───────────────────────

    # Check 1: Single record
    if dmarc_records_count > 1:
        _add("record_structure", "MULTIPLE_RECORDS", "fail",
             f"{dmarc_records_count} DMARC records found. DMARCbis requires exactly one. "
             "Receivers return PermError, meaning DMARC fails entirely.")
    elif dmarc_records_count == 1:
        _add("record_structure", "SINGLE_RECORD", "pass", "Exactly one DMARC record found.")

    # Check 2: Version first
    if not parsed_tags:
        _add("record_structure", "V_MISSING", "fail",
             "No v=DMARC1 found. This is not a valid DMARC record.")
    elif parsed_tags[0][0] != "v" or parsed_tags[0][1] != "DMARC1":
        if any(k == "v" for k, _, _ in parsed_tags):
            _add("record_structure", "V_NOT_FIRST", "fail",
                 "v=DMARC1 must be the first tag in the record.")
        else:
            _add("record_structure", "V_MISSING", "fail",
                 "No v=DMARC1 found. This is not a valid DMARC record.")
    else:
        _add("record_structure", "V_FIRST", "pass", "v=DMARC1 is the first tag.")

    # Check 3: Policy required
    p_count = tag_counts.get("p", 0)
    if p_count == 0:
        _add("record_structure", "P_MISSING", "fail",
             "No policy tag. Every DMARC record requires p=none, p=quarantine, or p=reject.")
    elif p_count > 1:
        p_vals = [v for k, v, _ in parsed_tags if k == "p"]
        _add("record_structure", "DUPLICATE_TAG", "fail",
             f"p= appears twice with values '{p_vals[0]}' and '{p_vals[1]}'. "
             "Receivers may interpret this unpredictably.")
    else:
        _add("record_structure", "P_PRESENT", "pass", "Policy tag present.")

    # Check 4: No duplicate singletons
    dup_found = False
    for tag_name in SINGLETON_TAGS:
        count = tag_counts.get(tag_name, 0)
        if count > 1:
            dup_found = True
            _add("record_structure", "DUPLICATE_TAG", "fail",
                 f"'{tag_name}' appears {count} times. DMARCbis requires each tag at most once.")
    if not dup_found and p_count <= 1:
        _add("record_structure", "NO_DUPLICATES", "pass", "No duplicate tags found.")

    # Check 5: No empty values
    empty_found = False
    for k, v, raw in parsed_tags:
        if not v.strip():
            empty_found = True
            _add("record_structure", "EMPTY_VALUE", "fail",
                 f"Empty value for '{k}'. Every tag must have a valid value.")
    if not empty_found:
        _add("record_structure", "NO_EMPTY_VALUES", "pass", "All tags have values.")

    # Check 7: Unknown tags
    for k, v, _ in parsed_tags:
        if k not in KNOWN_TAGS:
            _add("record_structure", "UNKNOWN_TAG", "warn",
                 f"'{k}={v}' is not defined in DMARC or DMARCbis and will be ignored by receivers. "
                 "Verify this is not a typo.")

    # Check 8: Trailing content
    if record.rstrip().endswith(";"):
        pass  # trailing semicolons are harmless, don't even warn

    # ── Layer 3: Value validation (semantics) ──────────────

    # Check 9: Policy values
    for tag_name in ("p", "sp", "np"):
        val = tag_dict.get(tag_name)
        if val is not None and val.lower() not in VALID_POLICIES:
            _add("tag_values", f"{tag_name.upper()}_INVALID", "fail",
                 f"Invalid policy '{val}' for {tag_name}=. Must be none, quarantine, or reject.")
        elif val is not None:
            _add("tag_values", f"{tag_name.upper()}_VALID", "pass",
                 f"{tag_name}={val} is a valid policy value.")

    # Check 10: Alignment values
    for tag_name in ("adkim", "aspf"):
        val = tag_dict.get(tag_name)
        if val is not None and val.lower() not in ("r", "s"):
            _add("tag_values", "ALIGNMENT_INVALID", "fail",
                 f"{tag_name}={val} is not valid. Must be r (relaxed) or s (strict).")
        elif val is not None:
            _add("tag_values", f"{tag_name.upper()}_VALID", "pass",
                 f"{tag_name}={val} is valid.")

    # Check 11: Percentage
    pct_val = tag_dict.get("pct")
    if pct_val is not None:
        if not re.match(r'^-?\d+$', pct_val):
            _add("tag_values", "PCT_INVALID", "fail",
                 f"pct={pct_val} is not a valid integer.")
        else:
            pct_int = int(pct_val)
            if pct_int < 0 or pct_int > 100:
                _add("tag_values", "PCT_INVALID", "fail",
                     f"pct={pct_val} is out of range. Must be 0-100.")
            elif pct_val != str(pct_int):  # leading zeros
                _add("tag_values", "PCT_LEADING_ZEROS", "warn",
                     f"pct={pct_val} has leading zeros. Use pct={pct_int}.")
            else:
                _add("tag_values", "PCT_VALID", "pass", f"pct={pct_val} is valid.")

    # Check 12: URI validation (STRICT)
    for tag_name in ("rua", "ruf"):
        val = tag_dict.get(tag_name)
        if val is None:
            continue

        uris = val.split(",")
        all_valid = True
        for uri in uris:
            uri_stripped = uri.strip()

            if not uri_stripped.startswith("mailto:"):
                _add("uri_validation", "URI_NO_MAILTO", "fail",
                     f"{tag_name}={uri_stripped} is not a valid URI. Must start with mailto:. "
                     f"Correct format: mailto:{uri_stripped}. This is the most common DMARC error "
                     "and older tools silently accept it. DMARCbis requires valid URI format.")
                all_valid = False
            else:
                # Split mailto:<addr>!<size>. The email part is validated even
                # when a size modifier is present; the modifier is reported as
                # a separate, non-fatal warn (it's obsolete, not forbidden —
                # dmarcbis-41 §4.8 keeps obs-dmarc-uri in the ABNF for parsing
                # legacy records).
                payload_parts = uri_stripped[7:].split("!", 1)
                email_part = payload_parts[0]
                size_modifier = payload_parts[1] if len(payload_parts) == 2 else ""

                if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email_part):
                    _add("uri_validation", "URI_BAD_EMAIL", "fail",
                         f"{tag_name} contains invalid email address in URI: {uri_stripped}")
                    all_valid = False

                if size_modifier:
                    _add("uri_validation", "URI_SIZE_MODIFIER_OBSOLETE", "warn",
                         f"{tag_name}={uri_stripped} contains a size modifier (!{size_modifier}). "
                         "dmarcbis-41 §C.4 removes the ability to specify a maximum report size; "
                         "§4.8 marks the syntax as obsolete. Reporters following dmarcbis will "
                         "ignore the size suffix. RFC 7489 receivers may still honor it. "
                         "Remove the modifier.")

        if all_valid:
            uri_count = len(uris)
            _add("uri_validation", f"{tag_name.upper()}_VALID", "pass",
                 f"{tag_name} has {uri_count} valid URI(s).")

    # Check 14: fo values
    fo_val = tag_dict.get("fo")
    if fo_val is not None:
        valid_fo_parts = {"0", "1", "d", "s"}
        fo_parts = re.split(r'[:]', fo_val)
        invalid_fo = [p for p in fo_parts if p not in valid_fo_parts]
        if invalid_fo or not fo_val:
            _add("tag_values", "FO_INVALID", "fail",
                 f"fo={fo_val} contains invalid values. Must be 0, 1, d, s or colon-separated combinations.")
        else:
            _add("tag_values", "FO_VALID", "pass", f"fo={fo_val} is valid.")

    # Check 15: DMARCbis-specific tag values
    psd_val = tag_dict.get("psd")
    if psd_val is not None and psd_val.lower() not in ("y", "n", "u"):
        _add("tag_values", "PSD_INVALID", "fail",
             f"psd={psd_val} is not valid. Must be y, n, or u.")
    elif psd_val is not None:
        _add("tag_values", "PSD_VALID", "pass", f"psd={psd_val} is valid.")

    t_val = tag_dict.get("t")
    if t_val is not None and t_val.lower() not in ("y", "n"):
        _add("tag_values", "T_INVALID", "fail",
             f"t={t_val} is not valid. Must be y or n.")
    elif t_val is not None:
        _add("tag_values", "T_VALID", "pass", f"t={t_val} is valid.")

    # Check 16: DNS integrity
    # Multi-string TXT records (joined by caller), check for truncation
    if record.rstrip(";").rstrip().endswith("=") and not record.rstrip(";").rstrip().endswith("v="):
        _add("dns_integrity", "POSSIBLE_TRUNCATION", "warn",
             "Record may be truncated. It ends with '=' which could indicate an incomplete tag value.")
    else:
        _add("dns_integrity", "RECORD_INTACT", "pass", "Record structure appears complete.")

    # Summary
    pass_count = sum(1 for c in checks if c["status"] == "pass")
    fail_count = sum(1 for c in checks if c["status"] == "fail")
    warn_count = sum(1 for c in checks if c["status"] == "warn")

    if fail_count > 0:
        summary = "This record has errors that DMARCbis-compliant receivers will reject."
    elif warn_count > 0:
        summary = "This record passes strict validation with warnings."
    else:
        summary = "This record passes DMARCbis strict validation."

    return {
        "checks": checks,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "total_count": len(checks),
        "summary": summary,
        "has_structural_errors": has_structural_errors,
    }


def _validate_dmarc_legacy(record: str, dmarc_records_count: int = 1) -> Dict:
    """RFC 7489 (legacy) lenient validation for spec comparison.

    Key differences from strict:
    - Bare email in rua/ruf accepted (no mailto: required)
    - Duplicate tags: warn not fail
    - Whitespace in URI lists: tolerated
    - Tag ordering: lenient (v= doesn't strictly need to be first)
    - np=, psd=, t= treated as unknown (no warnings about missing)
    - pct, rf, ri validated normally (no deprecation)
    """
    import re

    SINGLETON_TAGS = {"v", "p", "sp", "adkim", "aspf", "pct", "fo", "rf", "ri"}
    KNOWN_TAGS = SINGLETON_TAGS | {"rua", "ruf"}
    VALID_POLICIES = {"none", "quarantine", "reject"}

    checks: list = []
    has_structural_errors = False

    def _add(category, code, status, message):
        nonlocal has_structural_errors
        checks.append({"category": category, "code": code, "status": status, "message": message})
        if status == "fail":
            has_structural_errors = True

    # Tokenize
    tokens = re.split(r'\s*;\s*', record.strip().rstrip(";").strip())
    tokens = [t for t in tokens if t.strip()]

    parsed_tags: list = []
    tag_counts: dict = {}

    for token in tokens:
        m = re.match(r'^(?P<key>[a-zA-Z][a-zA-Z0-9_-]*)=(?P<value>.+)$', token.strip())
        if m:
            key = m.group("key").lower()
            value = m.group("value")
            parsed_tags.append((key, value, token.strip()))
            tag_counts[key] = tag_counts.get(key, 0) + 1
        elif token.strip():
            _add("record_structure", "MALFORMED_TAG", "fail",
                 f"Cannot parse '{token.strip()}'. Expected format: tag=value.")

    tag_dict: dict = {}
    for k, v, _ in parsed_tags:
        if k not in tag_dict:
            tag_dict[k] = v

    # Single record
    if dmarc_records_count > 1:
        _add("record_structure", "MULTIPLE_RECORDS", "fail",
             f"{dmarc_records_count} DMARC records found. RFC 7489 requires exactly one.")
    else:
        _add("record_structure", "SINGLE_RECORD", "pass", "Exactly one DMARC record found.")

    # Version present (lenient on position)
    if any(k == "v" and v == "DMARC1" for k, v, _ in parsed_tags):
        _add("record_structure", "V_PRESENT", "pass", "v=DMARC1 found.")
    else:
        _add("record_structure", "V_MISSING", "fail", "No v=DMARC1 found.")

    # Policy required
    p_count = tag_counts.get("p", 0)
    if p_count == 0:
        _add("record_structure", "P_MISSING", "fail", "No policy tag found.")
    elif p_count > 1:
        _add("record_structure", "DUPLICATE_TAG", "warn",
             "p= appears more than once. First value used.")
    else:
        _add("record_structure", "P_PRESENT", "pass", "Policy tag present.")

    # Duplicate singletons (warn, not fail)
    for tag_name in SINGLETON_TAGS:
        count = tag_counts.get(tag_name, 0)
        if count > 1:
            _add("record_structure", "DUPLICATE_TAG", "warn",
                 f"'{tag_name}' appears {count} times. First value used.")

    # Empty values
    for k, v, raw in parsed_tags:
        if not v.strip():
            _add("record_structure", "EMPTY_VALUE", "fail",
                 f"Empty value for '{k}'.")

    # Unknown tags (np, psd, t are unknown in legacy)
    for k, v, _ in parsed_tags:
        if k not in KNOWN_TAGS:
            _add("record_structure", "UNKNOWN_TAG", "warn",
                 f"'{k}={v}' is not defined in RFC 7489. Ignored by receivers.")

    # Policy values
    for tag_name in ("p", "sp"):
        val = tag_dict.get(tag_name)
        if val is not None and val.lower() not in VALID_POLICIES:
            _add("tag_values", f"{tag_name.upper()}_INVALID", "fail",
                 f"Invalid policy '{val}' for {tag_name}=.")
        elif val is not None:
            _add("tag_values", f"{tag_name.upper()}_VALID", "pass",
                 f"{tag_name}={val} is valid.")

    # Alignment
    for tag_name in ("adkim", "aspf"):
        val = tag_dict.get(tag_name)
        if val is not None and val.lower() not in ("r", "s"):
            _add("tag_values", "ALIGNMENT_INVALID", "fail",
                 f"{tag_name}={val} is not valid.")
        elif val is not None:
            _add("tag_values", f"{tag_name.upper()}_VALID", "pass", f"{tag_name}={val} is valid.")

    # pct (validated normally, no deprecation)
    pct_val = tag_dict.get("pct")
    if pct_val is not None:
        if not re.match(r'^\d+$', pct_val):
            _add("tag_values", "PCT_INVALID", "fail", f"pct={pct_val} is not a valid integer.")
        else:
            pct_int = int(pct_val)
            if pct_int < 0 or pct_int > 100:
                _add("tag_values", "PCT_INVALID", "fail", f"pct={pct_val} out of range (0-100).")
            else:
                _add("tag_values", "PCT_VALID", "pass", f"pct={pct_val} is valid.")

    # URI validation (LENIENT: bare email accepted, whitespace tolerated)
    for tag_name in ("rua", "ruf"):
        val = tag_dict.get(tag_name)
        if val is not None:
            _add("uri_validation", f"{tag_name.upper()}_PRESENT", "pass",
                 f"{tag_name} is configured.")

    # fo
    fo_val = tag_dict.get("fo")
    if fo_val is not None:
        valid_fo_parts = {"0", "1", "d", "s"}
        fo_parts = re.split(r'[:]', fo_val)
        invalid_fo = [p for p in fo_parts if p not in valid_fo_parts]
        if invalid_fo:
            _add("tag_values", "FO_INVALID", "fail", f"fo={fo_val} contains invalid values.")
        else:
            _add("tag_values", "FO_VALID", "pass", f"fo={fo_val} is valid.")

    # Summary
    pass_count = sum(1 for c in checks if c["status"] == "pass")
    fail_count = sum(1 for c in checks if c["status"] == "fail")
    warn_count = sum(1 for c in checks if c["status"] == "warn")

    if fail_count > 0:
        summary = "This record has errors under RFC 7489."
    elif warn_count > 0:
        summary = "This record passes RFC 7489 validation with warnings."
    else:
        summary = "This record passes RFC 7489 validation."

    return {
        "checks": checks,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "total_count": len(checks),
        "summary": summary,
        "has_structural_errors": has_structural_errors,
    }


def _assess_dmarcbis_readiness(dmarc_result: Dict) -> Dict:
    """Assess readiness for DMARCbis (draft-ietf-dmarc-dmarcbis-41).

    Purely informational. Does NOT affect scoring or status.

    Each recommendation carries a "source" field so the user can
    distinguish spec-mandated changes from our own editorial guidance:

      - spec_required:    explicitly mandated by dmarcbis-41 (with
                          spec_reference pointing to the section).
      - spec_recommended: SHOULD-level guidance from the draft. Reserved;
                          we do not use it when the spec is silent.
      - editorial:        our own recommendation, derived from
                          best-practice rather than spec text.

    Rationale: dmarcbis-41 §C.5.2 (Tags Removed) explicitly lists
    pct, rf, and ri as removed from the protocol, so all three are
    spec_required removals. The spec is still silent on
    np-value-relative-to-p and on progression from p=none to
    enforcement, so those remain editorial. Calling editorial
    advice "spec-required" misrepresents the draft, and calling
    spec-mandated removals "editorial" understates them; both are
    flagged so the reader can weigh them.
    """
    deprecated_tags = []
    record = dmarc_result.get("record", "")
    policy = (dmarc_result.get("policy") or "").lower()

    tags_in_record = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags_in_record[k.strip().lower()] = v.strip()

    if "pct" in tags_in_record:
        pct_val = tags_in_record["pct"]
        t_present = "t" in tags_in_record
        if t_present:
            action = (
                "Remove pct. dmarcbis removes the tag (§C.5.2 / §A.6) and "
                "you already have t= set, which is the dmarcbis replacement "
                "for the testing role pct used to play."
            )
        else:
            action = (
                "Remove pct. dmarcbis removes the tag (§C.5.2 / §A.6); "
                "if you were using pct<100 to test enforcement, set t=y "
                "instead, which is the dmarcbis-defined test mode."
            )
        deprecated_tags.append({
            "tag": "pct",
            "value": pct_val,
            "source": "spec_required",
            "spec_reference": "dmarcbis-41 §C.5.2 / §A.6",
            "recommendation": action,
        })

    if "rf" in tags_in_record:
        deprecated_tags.append({
            "tag": "rf",
            "value": tags_in_record["rf"],
            "source": "spec_required",
            "spec_reference": "dmarcbis-41 §C.5.2",
            "recommendation": (
                "Remove the rf tag. dmarcbis-41 §C.5.2 lists rf as "
                "removed from the protocol. Receivers implementing "
                "dmarcbis will ignore this tag."
            ),
        })

    if "ri" in tags_in_record:
        deprecated_tags.append({
            "tag": "ri",
            "value": tags_in_record["ri"],
            "source": "spec_required",
            "spec_reference": "dmarcbis-41 §C.5.2",
            "recommendation": (
                "Remove the ri tag. dmarcbis-41 §C.5.2 lists ri as "
                "removed from the protocol. Receivers implementing "
                "dmarcbis will ignore this tag."
            ),
        })

    # New DMARCbis tags
    np_val = dmarc_result.get("np")
    t_val = dmarc_result.get("t")
    psd_val = dmarc_result.get("psd")

    np_info = {
        "present": bool(np_val),
        "value": np_val,
        "source": None,
        "spec_reference": None,
        "recommendation": None,
    }
    if not np_val:
        # dmarcbis-41 §4.7 defines np but does NOT prescribe a value
        # relative to p. The recommendations below are editorial: they
        # reflect the email-security convention of treating mail from
        # non-existent subdomains at least as strictly as mail from
        # the apex, since no such mail can be legitimate.
        np_info["source"] = "editorial"
        np_info["spec_reference"] = None
        if policy == "reject":
            np_info["recommendation"] = (
                "Editorial recommendation (not spec-required): consider "
                "np=reject so mail from non-existent subdomains is rejected "
                "the same as mail at p=reject. dmarcbis-41 §4.7 does not "
                "prescribe an np value relative to p; if np is absent, the "
                "fallback is sp then p."
            )
        elif policy == "quarantine":
            np_info["recommendation"] = (
                "Editorial recommendation (not spec-required): consider "
                "np=reject so mail from non-existent subdomains is treated "
                "more strictly than the apex p=quarantine. dmarcbis-41 §4.7 "
                "does not prescribe an np value; if np is absent, the "
                "fallback is sp then p."
            )
        elif policy == "none":
            np_info["recommendation"] = (
                "Editorial recommendation (not spec-required): consider "
                "np=quarantine to flag mail from non-existent subdomains "
                "even while you keep p=none for monitoring. dmarcbis-41 "
                "§4.7 does not prescribe an np value; if np is absent, "
                "the fallback is sp then p."
            )
        else:
            np_info["recommendation"] = (
                "Editorial recommendation (not spec-required): set np "
                "explicitly once you have an enforcement policy in place. "
                "dmarcbis-41 §4.7 leaves the value to the domain owner."
            )

    t_info = {"present": bool(t_val), "value": t_val}
    psd_info = {"present": bool(psd_val), "value": psd_val}

    # Readiness tier (informational only).
    has_deprecated = len(deprecated_tags) > 0
    has_np = bool(np_val)

    if not has_deprecated and has_np:
        status = "ready"
    elif has_deprecated and not has_np:
        status = "needs_update"
    else:
        status = "compatible"

    # Build a flattened recommendation list so the frontend can render
    # spec-required and editorial findings with distinct treatments
    # without re-walking the nested structures.
    recommendations = []
    for d in deprecated_tags:
        recommendations.append({
            "tag": d["tag"],
            "value": d["value"],
            "source": d["source"],
            "spec_reference": d["spec_reference"],
            "recommendation": d["recommendation"],
        })
    if np_info["recommendation"]:
        recommendations.append({
            "tag": "np",
            "value": np_info["value"],
            "source": np_info["source"],
            "spec_reference": np_info["spec_reference"],
            "recommendation": np_info["recommendation"],
        })

    # Build summary, separating spec-required from editorial points so
    # readers can tell at a glance which changes the spec mandates.
    parts = ["Your DMARC record is valid and works under both RFC 7489 and DMARCbis."]
    spec_required_tags = [r["tag"] for r in recommendations if r["source"] == "spec_required"]
    editorial_tags = [r["tag"] for r in recommendations if r["source"] == "editorial"]
    if spec_required_tags:
        names = ", ".join(spec_required_tags)
        parts.append(f"Spec-required: remove {names} (dmarcbis-41).")
    if editorial_tags:
        names = ", ".join(editorial_tags)
        parts.append(f"Editorial suggestion: review {names} (not spec-required).")
    if not has_deprecated and has_np:
        parts.append("No changes needed for DMARCbis compliance.")

    return {
        "status": status,
        "deprecated_tags": deprecated_tags,
        "new_tags": {
            "np": np_info,
            "t": t_info,
            "psd": psd_info,
        },
        "recommendations": recommendations,
        "summary": " ".join(parts),
    }


def _raw_check_spf(domain: str) -> Dict[str, Any]:
    """Check SPF record with lookup counting, mechanism analysis, and syntax validation.

    Syntax checks based on:
      - RFC 7208 (SPF specification)
      - openspf.org common errors
      - dmarc.org / dmarcian deployment guidance
    """
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

    def _add_issue(severity, issue, plain_english, fix, business_risk_key=None):
        entry = {
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        }
        if business_risk_key:
            risk = BUSINESS_RISK.get(business_risk_key)
            if risk:
                entry["business_risk"] = risk
        result["issues"].append(entry)

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
            business_risk_key="SPF_NO_RECORD",
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
            business_risk_key="SPF_MULTIPLE_RECORDS",
        )
        return result

    raw_record = spf_records[0]
    record, spf_was_malformed = repair_spf_missing_spaces(raw_record)
    result["record"] = record
    result["ttl"] = _lookup_ttl(domain, "TXT")

    if spf_was_malformed:
        # Lenient parser recovered the mechanisms, so this is a warning, not a
        # fatal error.  Reserve "error" severity for cases where SPF genuinely
        # cannot be evaluated (no record, >10 lookups, multiple records, etc.).
        _add_issue(
            "warning",
            "SPF record has syntax issues: mechanisms are not space-delimited",
            "The SPF record has mechanisms jammed together without spaces, "
            "likely caused by multi-string TXT record configuration in DNS. "
            "While the tool extracted the mechanisms, this violates RFC 7208 "
            "and can cause unpredictable SPF evaluation at some receivers.",
            "Ensure each mechanism in the SPF record is separated by a space. "
            "Check your DNS provider's TXT record configuration for improper string splitting.",
        )

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
                    f"Remove or correct '{mech_name}' in your SPF record. "
                    f"Check for typos against the SPF specification (RFC 7208).",
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
                    f"Remove or correct '{raw}' in your SPF record. "
                    f"Check for typos against the SPF specification (RFC 7208).",
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
            business_risk_key="SPF_PERMERROR",
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
            business_risk_key="SPF_PLUS_ALL",
        )
    elif all_mech == "?all":
        _add_issue(
            "warning",
            "SPF uses ?all (neutral)",
            "The ?all mechanism provides no opinion about unauthorized senders. "
            "It does not protect your domain from spoofing.",
            "Change ?all to -all or ~all.",
            business_risk_key="SPF_NEUTRAL_ALL",
        )
    elif not all_mech and not has_redirect:
        _add_issue(
            "warning",
            "No 'all' mechanism found",
            "SPF records should end with an 'all' mechanism to define what happens "
            "to mail from servers not listed in the record. Without it, the default "
            "is neutral (?all), which provides no protection.",
            "Add ~all (softfail) to the end of the SPF record as a safe starting point. "
            "Once you are confident all legitimate senders are listed, tighten to -all (hardfail).",
            business_risk_key="SPF_NO_ALL",
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


def _probe_dnssec_bogus(domain: str) -> bool:
    """Probe whether a zone is in BOGUS DNSSEC state.

    A zone is bogus when its signatures fail validation. Validating
    resolvers return SERVFAIL while unvalidating paths see normal
    answers. Causes include expired RRSIGs, orphaned DS at the parent
    after a key rollover, and KSK/ZSK mismatch.

    Returns True only when both:
      - A query (with SOA fallback if A returns NXDOMAIN) sent to a
        strict validating resolver (Quad9 9.9.9.9, DO=1) yields SERVFAIL.
      - The same query sent with CD=1 (checking disabled) to 8.8.4.4
        yields NOERROR with at least one answer record.

    Any other outcome — including timeouts, exceptions, or one resolver
    disagreeing with the other — returns False. The probe fails closed
    so that ambiguous evidence cannot produce a false positive.
    """
    VALIDATING_NS = "9.9.9.9"
    UNVALIDATING_NS = "8.8.4.4"
    TIMEOUT = 6.0

    def _ask(ns_ip: str, qtype: str, *, want_dnssec: bool, checking_disabled: bool):
        try:
            q = dns.message.make_query(domain, qtype, want_dnssec=want_dnssec)
            if checking_disabled:
                # CD=1 disables validation at recursive resolvers that
                # otherwise validate by default (e.g. Google 8.8.x.x).
                # Without this we can't distinguish bogus from unsigned.
                q.flags |= dns.flags.CD
            resp = dns.query.udp(q, ns_ip, timeout=TIMEOUT)
            return resp.rcode(), len(resp.answer)
        except (dns.exception.DNSException, OSError):
            return None

    try:
        # Validating path: A first, fall back to SOA on NXDOMAIN.
        v = _ask(VALIDATING_NS, "A", want_dnssec=True, checking_disabled=False)
        if v is None:
            return False
        v_rcode, _ = v
        probe_qtype = "A"
        if v_rcode == dns.rcode.NXDOMAIN:
            v = _ask(VALIDATING_NS, "SOA", want_dnssec=True, checking_disabled=False)
            if v is None:
                return False
            v_rcode, _ = v
            probe_qtype = "SOA"

        if v_rcode != dns.rcode.SERVFAIL:
            return False

        # Unvalidating path: same qtype, CD=1.
        u = _ask(UNVALIDATING_NS, probe_qtype, want_dnssec=False, checking_disabled=True)
        if u is None:
            return False
        u_rcode, u_count = u
        return u_rcode == dns.rcode.NOERROR and u_count > 0
    except Exception:
        return False


def _raw_check_dnssec(domain: str) -> Dict[str, Any]:
    """Check DNSSEC configuration including algorithms and chain validation hints.

    Checks based on:
      - RFC 4035 (DNSSEC Protocol Modifications)
      - RFC 8624 (Algorithm Implementation Requirements)
      - NIST SP 800-81-2 (Secure DNS Deployment Guide)

    dnssec_state values (machine-readable four-state classification):
      secure            = signed AND anchored. Validators can verify via
                          the global trust chain (DNSKEY present + DS at
                          parent).
      signed_unanchored = DNSKEY present but no DS at parent. Validators
                          cannot anchor; effectively insecure for end
                          users behind validating resolvers, but signals
                          operator intent to deploy DNSSEC. Often a
                          transient state during initial deployment or
                          post-rollover.
      insecure          = unsigned. No DNSSEC deployed. Most domains.
      bogus             = signed but signatures fail validation.
                          SERVFAIL territory. Worse than insecure because
                          validating resolvers refuse to resolve the
                          domain.
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
        "dnssec_state": "insecure",
        "algorithms": [],
        "key_count": 0,
        "has_ds": False,
        "ds_algorithms": [],
        "validated_by_resolver": False,
        "issues": [],
        "status": "ok",
    }
    # Track whether the DNSKEY query failed so we can run the bogus probe
    # once after the DNSKEY block, instead of duplicating the call across
    # several exception handlers.
    should_probe_bogus = False
    # Bogus is tracked separately so the four-state classification can be
    # computed at the end of the function from the boolean flags rather
    # than assigned imperatively in different branches.
    is_bogus = False

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

        # Record whether the recursive resolver validated the chain (AD
        # flag). This is a corroborating signal only: an on-path attacker
        # can clear AD, and AD=0 does not prove DS is absent. Treat it
        # as soft evidence, never as the sole basis for has_ds.
        ad_flag = bool(dnskey_answers.response.flags & dns.flags.AD)
        result["validated_by_resolver"] = ad_flag

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
        should_probe_bogus = True
    except dns.resolver.NXDOMAIN:
        result["has_dnssec"] = False
        should_probe_bogus = True
        _add_issue(
            "error",
            "Domain does not exist (NXDOMAIN)",
            "The domain returned NXDOMAIN when querying for DNSKEY records.",
            "Verify the domain name is correct and DNS is properly configured.",
        )
    except dns.resolver.LifetimeTimeout:
        # Timeout is NOT evidence of no DNSSEC — large DNSKEY RRsets or
        # slow authoritative servers can exceed the default timeout.
        # Retry once with a generous 30s timeout before giving up.
        retry_resolver = _get_dnssec_resolver(timeout=30.0)
        try:
            dnskey_answers = retry_resolver.resolve(domain, "DNSKEY")
            result["has_dnssec"] = True
            result["key_count"] = len(dnskey_answers)

            ad_flag = bool(dnskey_answers.response.flags & dns.flags.AD)
            result["validated_by_resolver"] = ad_flag

            seen_algos = set()
            for rdata in dnskey_answers:
                seen_algos.add(rdata.algorithm)

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
        except dns.exception.DNSException:
            result["has_dnssec"] = False
            should_probe_bogus = True
            _add_issue(
                "warning",
                "DNSSEC check timed out",
                "The DNSKEY query timed out on two attempts (including a 30s retry). "
                "This does not necessarily mean DNSSEC is unconfigured. Large DNSKEY "
                "responses or slow authoritative servers can cause timeouts.",
                "Verify manually with 'delv' or 'dig +dnssec DNSKEY " + domain + "'.",
            )
    except dns.exception.DNSException as e:
        result["has_dnssec"] = False
        should_probe_bogus = True
        _add_issue(
            "warning",
            f"DNSSEC check error: {type(e).__name__}",
            f"Could not determine DNSSEC status due to a resolver error. "
            "This may be a transient issue, not proof that DNSSEC is absent.",
            "Retry or verify manually with 'delv' or 'dig +dnssec DNSKEY <domain>'.",
        )

    # Bogus-state probe: when DNSKEY didn't return data, distinguish a
    # zone that's unsigned (normal for most domains) from one whose
    # signatures fail validation. Bogus is worse than unsigned: validating
    # resolvers (Cloudflare 1.1.1.1, Quad9 9.9.9.9, Google 8.8.8.8 in
    # DNSSEC mode) return SERVFAIL, making the domain unresolvable for
    # users behind those resolvers.
    if should_probe_bogus and _probe_dnssec_bogus(domain):
        is_bogus = True
        _add_issue(
            "error",
            "DNSSEC validation failure (BOGUS state)",
            "DNSSEC is configured but signatures fail to validate. Validating "
            "resolvers (Cloudflare 1.1.1.1, Quad9 9.9.9.9, Google 8.8.8.8 in "
            "DNSSEC mode) will return SERVFAIL for this domain, making it "
            "unresolvable for users behind those resolvers. Common causes: "
            "expired RRSIGs, orphaned DS record at parent after a key "
            "rollover, or KSK/ZSK mismatch.",
            "Run 'delv " + domain + "' locally for a chain analysis, or open "
            "https://dnsviz.net/d/" + domain + "/dnssec/ in a browser. If a "
            "key rollover is in progress, coordinate with your registrar to "
            "update the DS record at the parent zone.",
        )

    # Check DS records at the parent (proves the chain is anchored)
    # DS records ONLY exist at the parent zone. Child nameservers never serve them.
    # Strategy:
    #   Method 1: Direct DS query via recursive resolver (works when resolver is smart)
    #   Method 2: Query parent NS directly via dns.query.udp (no delegation following)
    # The AD bit on the earlier DNSKEY response is consulted later as a
    # corroborating signal only (annotation, never as proof of has_ds).
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
                        if _is_private_ip(ns_ip):
                            continue
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
                            if _is_private_ip(ns_ip):
                                continue
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

    # Methods 1 and 2 are the only direct evidence that a DS record
    # exists at the parent. The AD bit on the DNSKEY response is a
    # corroborating signal (RFC 4035 §5, RFC 6840 §5.7-5.9): a
    # validating resolver setting AD=1 implies the chain validated, but
    # an on-path attacker can clear AD and AD=0 does not prove DS is
    # absent. So we never let AD alone set has_ds — we only annotate.
    if ds_found:
        result["has_ds"] = True
        result["ds_algorithms"] = sorted(ds_algos)
    elif result["has_dnssec"]:
        if result.get("validated_by_resolver"):
            _add_issue(
                "info",
                "DS not directly observable; resolver AD bit is set",
                "We could not fetch the DS record at the parent zone via direct "
                "query or parent-NS query, but a validating resolver reports the "
                "chain is intact (AD bit set). This is consistent with a working "
                "DNSSEC deployment but is not cryptographic proof. Verify with: "
                "dig +dnssec DS " + domain + " @1.1.1.1",
                "No action needed if the AD bit is set by a validating resolver "
                "you trust. If you want certainty, query the parent zone's "
                "authoritative nameservers directly.",
            )
        else:
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

    # Four-state finalization: compute dnssec_state from the boolean flags
    # in priority order. See the function docstring for definitions.
    #   1. bogus              — probe confirmed validation failure
    #   2. insecure           — no DNSKEY observed
    #   3. secure             — DNSKEY present AND DS at parent
    #   4. signed_unanchored  — DNSKEY present but no DS at parent
    # Bogus takes priority over has_ds presence: a bogus zone may have
    # an orphaned DS at the parent, but the bogus signal is strictly
    # more informative for downstream consumers.
    if is_bogus:
        result["dnssec_state"] = "bogus"
    elif not result["has_dnssec"]:
        result["dnssec_state"] = "insecure"
    elif result["has_ds"]:
        result["dnssec_state"] = "secure"
    else:
        result["dnssec_state"] = "signed_unanchored"

    # Set final status
    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    result["ttl"] = _lookup_ttl(domain, "DNSKEY")
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

    result["ttl"] = _lookup_ttl(domain, "CAA")
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
        if not ns_ip or _is_private_ip(ns_ip):
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
            "your entire domain becomes unreachable: no website, no email, nothing. "
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

    result["ttl"] = _lookup_ttl(domain, "NS")
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

    # DNSSEC status: query directly rather than relying on raw_results,
    # because DNSSEC and DANE run as parallel Phase 2 checks so the
    # DNSSEC result may not be available in the raw_results snapshot.
    raw_dnssec = raw_results.get("dnssec")
    if raw_dnssec is None:
        raw_dnssec = _raw_check_dnssec(domain)
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
    """CT check with 24-hour caching and stale-cache fallback on timeout."""
    cached = _get_cached_ct(domain)
    if cached is not None:
        return cached

    result = _raw_check_ct_uncached(domain, raw_results)

    # On failure, try returning stale cache
    if result.get("unavailable_reason") in ("timeout", "request_error"):
        stale = _get_stale_ct(domain)
        if stale is not None:
            return stale
        return result

    _set_cached_ct(domain, result)
    return result


def _raw_check_ct_uncached(domain: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
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
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
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
        _add_issue("warning", "CT data temporarily unavailable",
                   "Certificate Transparency data is sourced from crt.sh, which was temporarily unavailable. "
                   "This does not affect the audit results.")
        result["status"] = "warning"
        result["unavailable_reason"] = "timeout"
        return result
    except (requests.exceptions.RequestException, ValueError) as e:
        _add_issue("warning", "CT data temporarily unavailable",
                   "Certificate Transparency data is sourced from crt.sh, which was temporarily unavailable. "
                   "This does not affect the audit results.")
        result["status"] = "warning"
        result["unavailable_reason"] = "request_error"
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

_shared_executor = ThreadPoolExecutor(max_workers=20)


# ============================================================
# Subdomain Discovery & Audit
# ============================================================

_SUBDOMAIN_PREFIXES = [
    "mail", "email", "smtp", "mx", "newsletter", "marketing",
    "support", "helpdesk", "portal", "app", "dev", "staging",
    "test", "api", "shop", "store", "billing", "secure", "login",
    "accounts",
]

_SUBDOMAIN_TIMEOUT = 2.0  # seconds per DNS query


def _probe_subdomain(subdomain: str) -> Dict[str, Any]:
    """Probe a single subdomain for DNS existence, DMARC, SPF, and MX records.

    Returns a dict with probe results.  All DNS errors are caught and treated
    as "record not found" so a single slow or broken subdomain never blocks
    the audit.
    """
    result = {
        "subdomain": subdomain,
        "exists": False,
        "has_mx": False,
        "has_spf": False,
        "has_dmarc": False,
        "dmarc_record": None,
        "spf_record": None,
        "mx_hosts": [],
    }
    resolver = _get_resolver(timeout=_SUBDOMAIN_TIMEOUT)

    # Check existence (A / AAAA / CNAME)
    for rdtype in ("A", "AAAA", "CNAME"):
        try:
            resolver.resolve(subdomain, rdtype, raise_on_no_answer=False)
            result["exists"] = True
            break
        except dns.exception.DNSException:
            continue

    # MX records
    try:
        mx_ans = resolver.resolve(subdomain, "MX")
        mx_list = [str(r.exchange).rstrip(".") for r in mx_ans]
        if mx_list:
            result["has_mx"] = True
            result["mx_hosts"] = mx_list
            result["exists"] = True  # MX implies existence
    except dns.exception.DNSException:
        pass

    # SPF record
    try:
        txt_ans = resolver.resolve(subdomain, "TXT")
        for rdata in txt_ans:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=spf1"):
                result["has_spf"] = True
                result["spf_record"] = txt
                result["exists"] = True
                break
    except dns.exception.DNSException:
        pass

    # DMARC record
    dmarc_name = f"_dmarc.{subdomain}"
    try:
        txt_ans = resolver.resolve(dmarc_name, "TXT")
        for rdata in txt_ans:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=dmarc1"):
                result["has_dmarc"] = True
                result["dmarc_record"] = txt
                break
    except dns.exception.DNSException:
        pass

    return result


def _audit_subdomains(domain: str) -> Dict[str, Any]:
    """Probe common subdomains in parallel and return raw discovery results.

    All queries run concurrently with a 2-second per-query timeout.
    The entire batch is bounded by CHECK_TIMEOUT to stay within budget.
    """
    subdomains = [f"{prefix}.{domain}" for prefix in _SUBDOMAIN_PREFIXES]

    futures = {}
    for sub in subdomains:
        future = _shared_executor.submit(_probe_subdomain, sub)
        futures[future] = sub

    results = []
    for future in as_completed(futures, timeout=CHECK_TIMEOUT):
        try:
            results.append(future.result(timeout=_SUBDOMAIN_TIMEOUT + 1))
        except Exception:
            # Skip subdomains that time out or error
            pass

    return {
        "domain": domain,
        "probes": results,
    }


def _run_with_timeout(func, *args, timeout=CHECK_TIMEOUT, **kwargs):
    """Run a check function with a timeout. Raises TimeoutError on expiry."""
    future = _shared_executor.submit(func, *args, **kwargs)
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
            errors.append("DMARC: check failed")
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

    # ================================================================
    # Phase 2: Parallel checks (all inputs from Phase 1 are ready)
    # ================================================================
    _bimi_dmarc = raw_results.get("dmarc") or {}
    _bimi_dmarc_enforcing = (
        (_bimi_dmarc.get("policy") or "").lower() in ("quarantine", "reject")
        or (_bimi_dmarc.get("inherited_policy") or "").lower() in ("quarantine", "reject")
    )

    # Define each independent check as (key, run_func, transform_func, label, extra_kwargs)
    _parallel_checks = []

    if _should_include("mta_sts", scope_set):
        _parallel_checks.append(("mta_sts",
            lambda: check_mta_sts(domain),
            lambda raw: transform_mta_sts(raw, domain, has_mx=has_mx),
            "MTA-STS"))

    if _should_include("tls_rpt", scope_set):
        _parallel_checks.append(("tls_rpt",
            lambda: check_tls_rpt(domain),
            lambda raw: transform_tls_rpt(raw, domain, has_mx=has_mx),
            "TLS-RPT"))

    if _should_include("bimi", scope_set):
        _bimi_enforcing = _bimi_dmarc_enforcing  # capture for closure
        _parallel_checks.append(("bimi",
            lambda: check_bimi(domain, dmarc_enforcing_override=_bimi_enforcing),
            lambda raw: transform_bimi(raw, domain, has_mx=has_mx),
            "BIMI"))

    if _should_include("dnssec", scope_set):
        _parallel_checks.append(("dnssec",
            lambda: _raw_check_dnssec(domain),
            lambda raw: transform_dnssec(raw, domain),
            "DNSSEC"))

    if _should_include("caa", scope_set):
        _parallel_checks.append(("caa",
            lambda: _raw_check_caa(domain),
            lambda raw: transform_caa(raw, domain),
            "CAA"))

    if _should_include("nameservers", scope_set):
        _parallel_checks.append(("nameservers",
            lambda: _raw_check_nameservers(domain),
            lambda raw: transform_nameservers(raw, domain),
            "Nameservers"))

    if _should_include("dane", scope_set):
        # DANE needs raw_results for MX info -- capture current snapshot
        _dane_raw = dict(raw_results)
        _parallel_checks.append(("dane",
            lambda: _raw_check_dane(domain, _dane_raw),
            lambda raw: transform_dane(raw, domain),
            "DANE"))

    if _should_include("dkim", scope_set):
        # DKIM2 (draft-ietf-dkim-dkim2-spec) is a successor protocol in
        # active IETF development. No major mailbox provider validates
        # it yet and senders publish nothing new for it (it reuses DKIM
        # keys), so there is nothing to look up. We only surface a
        # static info-level note so the audit reflects awareness of the
        # space without producing false signals. This is appended to the
        # DKIM raw result after the check runs; transform_dkim renders
        # raw["issues"] at the end of details.
        def _append_dkim2_note(raw: Dict) -> None:
            raw.setdefault("issues", []).append({
                "severity": "info",
                "issue": "DKIM2 (successor protocol) is in IETF development",
                "plain_english": (
                    "DKIM2 is a successor to DKIM currently in active IETF "
                    "development. It addresses replay attacks, forwarding-"
                    "induced authentication failures, and adds secure delayed "
                    "bounces. No major mailbox provider has deployed it yet, "
                    "and senders do not need to publish anything new for it "
                    "(it reuses DKIM keys). We will check for DKIM2 signing "
                    "once major mailbox providers begin validating it."
                ),
                "fix": (
                    "No action required today. Track the IETF draft at "
                    "https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/ "
                    "if you want early visibility."
                ),
                "spec_reference": "draft-ietf-dkim-dkim2-spec",
            })

        if dkim_selector and dkim_selector.strip():
            _dkim_sel = dkim_selector.strip()
            def _run_dkim_direct():
                _fqdn = f"{_dkim_sel}._domainkey.{domain}"
                _raw = {"domain": domain, "found_selectors": [], "selector_queried": _dkim_sel}
                try:
                    import dns.resolver as _dkim_resolver
                    answers = _dkim_resolver.resolve(_fqdn, "TXT")
                    txt = "".join(
                        s.decode() if isinstance(s, bytes) else s
                        for rdata in answers for s in rdata.strings
                    )
                    if "p=" in txt:
                        key_analysis = analyze_dkim_key_strength(txt)
                        _raw["found_selectors"].append({
                            "selector": _dkim_sel, "record": txt,
                            "key_size": key_analysis.get("key_bits"),
                        })
                except dns.exception.DNSException:
                    _raw["selector_not_found"] = _dkim_sel
                    _raw["tested_count"] = 1
                _append_dkim2_note(_raw)
                return _raw
            _parallel_checks.append(("dkim", _run_dkim_direct,
                lambda raw: transform_dkim(raw, domain, has_mx=has_mx), "DKIM"))
        else:
            _spf_rec = spf_record  # capture
            def _dkim_progress(found_count):
                if progress_callback:
                    progress_callback(f"DKIM:{found_count}", completed, total_checks)
            def _run_dkim_smart():
                _raw = smart_dkim_check(domain, _spf_rec, progress_callback=_dkim_progress)
                _append_dkim2_note(_raw)
                return _raw
            _parallel_checks.append(("dkim", _run_dkim_smart,
                lambda raw: transform_dkim(raw, domain, has_mx=has_mx), "DKIM"))

    if _should_include("ct", scope_set):
        _ct_raw = dict(raw_results)
        _parallel_checks.append(("ct",
            lambda: _raw_check_ct(domain, _ct_raw),
            lambda raw: transform_ct(raw, domain),
            "Certificate Transparency"))

    if _should_include("blacklist", scope_set):
        _bl_raw = dict(raw_results)
        _parallel_checks.append(("blacklist",
            lambda: _raw_check_blacklist(domain, _bl_raw),
            lambda raw: transform_blacklist(raw, domain),
            "Blacklist"))

    # Submit all Phase 2 checks in parallel
    _p2_futures = {}
    for key, run_fn, transform_fn, label in _parallel_checks:
        future = _shared_executor.submit(run_fn)
        _p2_futures[future] = (key, transform_fn, label)

    # Desired card ordering (DKIM inserted at position 2 later)
    _CARD_ORDER = ["mta_sts", "tls_rpt", "bimi", "dnssec", "caa",
                    "nameservers", "dane", "ct", "blacklist"]
    _p2_cards = {}  # key -> card

    for future in as_completed(_p2_futures):
        key, transform_fn, label = _p2_futures[future]
        try:
            raw = future.result(timeout=CHECK_TIMEOUT + 5)
            raw_results[key] = raw
            _p2_cards[key] = transform_fn(raw)
        except FuturesTimeoutError:
            errors.append(f"{label}: timed out")
            if key == "dkim":
                raw_results["dkim"] = {"found_selectors": [], "tested_count": 0, "timed_out": True}
            _p2_cards[key] = _timeout_card(label)
        except Exception as e:
            log.warning("%s check failed: %s", label, e, exc_info=True)
            errors.append(f"{label}: {str(e)}")
            _p2_cards[key] = _error_card(label, e)
        _notify(label)

    # Insert DKIM card at position 2 (after DMARC+SPF), others in order
    if "dkim" in _p2_cards:
        dkim_pos = min(2, len(checks))
        checks.insert(dkim_pos, _p2_cards.pop("dkim"))
    for key in _CARD_ORDER:
        if key in _p2_cards:
            checks.append(_p2_cards[key])

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

    # --- Vendor list for frontend ---
    vendors = _format_vendors(fp_vendors)

    # --- Provider Intelligence (Prompt 19) ---
    provider_intelligence = _build_provider_intelligence(raw_results, checks)

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
    priority_fixes = _build_priority_fixes(checks, raw_results, has_mx=has_mx)
    _notify("Scoring")

    # --- Anomaly Detection ("What's Unusual") ---
    try:
        anomalies = detect_anomalies(raw_results, has_mx, is_defensive, tree_walk=tree_walk_result)
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

    # --- Advisories ---
    advisories = []

    # www subdomain advisory
    labels = domain.split(".")
    if labels[0] == "www" and len(labels) > 2:
        root_domain = ".".join(labels[1:])
        advisories.append({
            "type": "info",
            "title": "Auditing www subdomain",
            "message": (
                f"You are auditing the www subdomain. "
                f"To audit the root domain, use {root_domain}."
            ),
        })

    # Partial results warning (some checks timed out or errored)
    if errors:
        advisories.append({
            "type": "warning",
            "title": "Incomplete results",
            "message": (
                "Some DNS queries timed out or failed. Results may be incomplete. "
                "Try again in a few minutes."
            ),
        })

    # --- Subdomain Discovery & Audit ---
    subdomain_raw = None
    if needs_dmarc and not raw_results.get("dmarc", {}).get("is_subdomain"):
        try:
            subdomain_raw = _run_with_timeout(_audit_subdomains, domain, timeout=CHECK_TIMEOUT)
        except Exception as e:
            log.warning("Subdomain audit failed: %s", e, exc_info=True)

    # Build the subdomain audit section from raw probes + DMARC policy context
    subdomain_audit = None
    if subdomain_raw:
        dmarc_raw = raw_results.get("dmarc", {})
        subdomain_audit = build_subdomain_audit(
            subdomain_raw,
            policy=dmarc_raw.get("policy"),
            sp=dmarc_raw.get("sp"),
            np=dmarc_raw.get("np"),
            has_record=bool(dmarc_raw.get("record")),
        )

    # --- Snapshot storage & change detection ---
    # Store current records for future change tracking
    try:
        store_audit_snapshots(domain, raw_results)
        purge_old_snapshots()
    except Exception as e:
        log.debug("Snapshot storage failed: %s", e)

    # Retrieve history for change detection
    record_history = {}
    first_seen = None
    try:
        record_history = get_all_history(domain)
        first_seen = get_first_seen(domain)
    except Exception as e:
        log.debug("History retrieval failed: %s", e)

    # Build change detection from history + current raw results
    change_detection = build_change_detection(raw_results, record_history, first_seen)

    # Build TTL map from raw results
    ttl_map = {}
    for check_key in ("dmarc", "spf", "mta_sts", "tls_rpt", "bimi", "dnssec", "caa", "nameservers", "mx"):
        raw = raw_results.get(check_key, {})
        if raw.get("ttl") is not None:
            ttl_map[check_key] = raw["ttl"]

    # Build consistency findings (Part 4)
    consistency = build_consistency_findings(raw_results, checks)

    # --- Assemble final response ---
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    _roadmap = build_security_roadmap(checks)

    return {
        "domain": domain,
        "timestamp": start_time.isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "checks": checks,
        "priority_fixes": priority_fixes,
        "anomalies": anomalies,
        "remediation_plan": remediation_plan,
        "vendors": vendors,
        "provider_intelligence": provider_intelligence,
        "tree_walk": tree_walk_result,
        "spf_execution": spf_execution,
        "dmarc_eval": dmarc_eval,
        "report_chain": report_auth,
        "spf_tree": spf_tree_viz,
        "scope": scope or "complete",
        "defensive_dns": is_defensive,
        "defensive_signals": defensive_signals,
        "resilience": resilience_result,
        "security_roadmap": _roadmap,
        "executive_summary": build_executive_summary(checks, _roadmap),
        "subdomain_audit": subdomain_audit,
        "change_detection": change_detection,
        "ttl_map": ttl_map,
        "consistency_findings": consistency,
        "advisories": advisories if advisories else None,
        "errors": errors if errors else None,
    }


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
            "Receivers will return PermError, which means SPF cannot provide a DMARC alignment path. "
            "This leaves DKIM as the only viable authentication mechanism."
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

def _build_priority_fixes(checks: List[Dict], raw_results: Dict = None, has_mx: bool = True) -> List[str]:
    """
    Build prioritized fix list directly from check results.
    Maximum 5 items: BOGUS DNSSEC first, then fails, then warnings.
    Deduplicates by check name.

    For non-mail domains (has_mx=False), skip email-infrastructure fixes
    since they're not applicable.

    BOGUS DNSSEC sorts to the very top: validating resolvers return
    SERVFAIL, so the domain is effectively unresolvable for those users.
    """
    MAIL_ONLY_CHECKS = {"SPF", "MX Records", "MX", "MTA-STS", "TLS-RPT", "DKIM", "BIMI", "DANE"}

    fixes: List[str] = []
    covered_checks: set = set()

    def _clean(html_text: str) -> str:
        text = re.sub(r'<[^>]+>', '', html_text)
        return re.sub(r'\s+', ' ', text).strip()

    if raw_results and raw_results.get("dnssec", {}).get("dnssec_state") == "bogus":
        for check in checks:
            if check.get("name") == "DNSSEC" and check.get("fix"):
                text = _clean(check["fix"])
                if text:
                    fixes.append(text)
                    covered_checks.add("DNSSEC")
                break

    for status in ("fail", "warn"):
        for check in checks:
            if check.get("status") != status:
                continue
            name = check.get("name", "")
            if name in covered_checks:
                continue
            if not has_mx and name in MAIL_ONLY_CHECKS:
                continue
            if check.get("pill_label") == "Error":
                continue
            fix = check.get("fix")
            if not fix:
                continue
            text = _clean(fix)
            if text and text not in fixes:
                fixes.append(text)
                covered_checks.add(name)

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
    """Generate a card for a check that threw an exception.

    The raw exception is intentionally NOT echoed to the user. Callers
    already log it with exc_info=True; including str(error) here has
    leaked filesystem paths and other server-side detail in the past.
    """
    return {
        "name": name,
        "status": "fail",
        "pill_label": "Error",
        "verdict": "Check failed due to an error",
        "record": None,
        "explanation": f"An unexpected error occurred while running the {name} check. This may be a temporary DNS issue.",
        "details": [
            {"type": "error", "text": f"The {name} check could not be completed. Please try again."},
        ],
        "fix": "Try running the audit again. If the issue persists, the DNS server may be unresponsive.",
    }
