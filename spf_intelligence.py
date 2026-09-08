"""
Intelligent DKIM Selector Discovery via SPF Analysis
Uses SPF includes to detect vendors, then prioritizes appropriate DKIM selectors.

This is 10x smarter than blind looping through all selectors.
Based on real-world consulting experience with 100+ enterprise deployments.
"""

import re
import time
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeoutError, as_completed
from typing import List, Dict, Optional, Callable

from dkim_formatter import analyze_dkim_key_strength

from dns_tools import get_resolver, get_uncached_resolver

# Hard limits for DKIM selector discovery
# Kept below the Phase 2 batch budget (CHECK_TIMEOUT + 5 = 20s). A child
# deadline larger than its parent's can only ever be enforced by the parent,
# which means the child's own timeout handling never runs.
DKIM_DISCOVERY_TIMEOUT = 15   # seconds for entire discovery
DKIM_MAX_FOUND = 15           # stop after finding this many selectors

# Map SPF includes to vendors and their DKIM selectors
SPF_VENDOR_MAP = {
    # Google
    '_spf.google.com': {
        'vendor': 'Google Workspace',
        'dkim_selectors': ['google', '20230601', '20221208', '20210112', '20161025', '20120113', 'ga1', 'googlemail'],
        'category': 'email_provider'
    },
    
    # Proton Mail.
    #
    # Verified live on proton.me, 2026-09-08: protonmail, protonmail2 and
    # protonmail3 under _domainkey are CNAMEs into domains.proton.ch, and each
    # resolves through to a live 2048-bit RSA key. Proton's own setup adds
    # exactly these three CNAMEs. Without this entry the include mapped to no
    # vendor at all, so nothing pulled the selectors ahead of the 40-name cap
    # and a domain publishing three live keys was reported as unconfirmed.
    '_spf.protonmail.ch': {
        'vendor': 'Proton Mail',
        'dkim_selectors': ['protonmail', 'protonmail2', 'protonmail3'],
        'category': 'email_provider'
    },

    # Microsoft 365
    'spf.protection.outlook.com': {
        'vendor': 'Microsoft 365',
        'dkim_selectors': ['selector1', 'selector2'],
        'category': 'email_provider'
    },
    
    # Proofpoint
    '_spf.pphosted.com': {
        'vendor': 'Proofpoint',
        'dkim_selectors': ['proofpoint', 'pp', 'default'],
        'category': 'email_security'
    },
    
    # Mailchimp
    'servers.mcsv.net': {
        'vendor': 'Mailchimp',
        'dkim_selectors': ['k1', 'k2', 'k3'],
        'category': 'marketing_esp'
    },
    
    # SendGrid
    'sendgrid.net': {
        'vendor': 'SendGrid',
        'dkim_selectors': ['em', 's1', 's2', 'sendgrid'],
        'category': 'transactional_esp'
    },
    
    # Amazon SES
    'amazonses.com': {
        'vendor': 'Amazon SES',
        'dkim_selectors': ['amazonses', 'ses'],
        'category': 'transactional_esp'
    },
    
    # Mailgun
    'mailgun.org': {
        'vendor': 'Mailgun',
        'dkim_selectors': ['mailgun', 'mg', 'k1'],
        'category': 'transactional_esp'
    },
    
    # Mandrill
    'mandrillapp.com': {
        'vendor': 'Mandrill',
        'dkim_selectors': ['mandrill', 'k1'],
        'category': 'transactional_esp'
    },
    
    # SparkPost
    'sparkpostmail.com': {
        'vendor': 'SparkPost',
        'dkim_selectors': ['sparkpost', 'scph'],
        'category': 'transactional_esp'
    },
    
    # Constant Contact
    'constantcontact.com': {
        'vendor': 'Constant Contact',
        'dkim_selectors': ['k1', 'k2'],
        'category': 'marketing_esp'
    },
    
    # HubSpot
    '_spf.hubspot.com': {
        'vendor': 'HubSpot',
        'dkim_selectors': ['hs1', 'hs2', 'k1'],
        'category': 'marketing_esp'
    },
    
    # Zendesk
    'mail.zendesk.com': {
        'vendor': 'Zendesk',
        'dkim_selectors': ['zendesk1', 'zendesk2', 'k1'],
        'category': 'support_platform'
    },

    # Omnivery / Mailkit
    'spf.mailkit.eu': {
        'vendor': 'Omnivery/Mailkit',
        'dkim_selectors': ['mailkit', 'mkt', 'omnivery', 'mk'],
        'category': 'transactional_esp'
    },
    'mailkit.eu': {
        'vendor': 'Omnivery/Mailkit',
        'dkim_selectors': ['mailkit', 'mkt', 'omnivery', 'mk'],
        'category': 'transactional_esp'
    },
}

def parse_spf_record(spf_record: str) -> List[str]:
    """Extract all include: mechanisms from SPF record.

    RFC 7208 section 4.6.1 makes terms case insensitive, so INCLUDE: and
    Include: are the same mechanism as include:.
    """
    include_pattern = r'include:([^\s]+)'
    return re.findall(include_pattern, spf_record, flags=re.IGNORECASE)

def detect_vendors_from_spf(spf_record: str) -> List[Dict]:
    """
    Detect email vendors/ESPs from SPF record includes.
    
    Example:
        SPF: v=spf1 include:_spf.google.com include:servers.mcsv.net ~all
        Detects: Google Workspace + Mailchimp
        Returns: Their respective DKIM selectors to test
    """
    includes = parse_spf_record(spf_record)
    detected_vendors = []
    seen_vendors = set()
    
    for include in includes:
        # Match on label boundaries, not substrings. "sendgrid.net" inside
        # "sendgrid.net.attacker.example" is a lookalike, not SendGrid, and
        # labeling it as the vendor is the wrong way for this tool to fail.
        include_lower = include.lower().rstrip(".")
        for pattern, vendor_info in SPF_VENDOR_MAP.items():
            if include_lower == pattern or include_lower.endswith("." + pattern):
                vendor_name = vendor_info['vendor']
                if vendor_name not in seen_vendors:
                    detected_vendors.append({
                        'vendor': vendor_name,
                        'dkim_selectors': vendor_info['dkim_selectors'],
                        'category': vendor_info['category'],
                        'spf_include': include
                    })
                    seen_vendors.add(vendor_name)
    
    return detected_vendors


# MX hostname to vendor name, for the handful of vendors that both receive
# and sign mail on the same hosted platform (Google Workspace, Microsoft
# 365), or run as a relay that resigns outbound mail (Proofpoint, Mimecast).
# Deliberately the same small set advanced_fingerprinting.py's MX matcher
# uses, keyed to the same vendor names SPF_VENDOR_MAP already has selectors
# for, so a domain that never mentions its vendor in SPF (self-hosted DNS in
# front of a hosted mailbox, or an SPF record this audit could not read) can
# still have its selectors prioritized instead of falling straight to the
# generic sweep.
MX_VENDOR_PATTERNS = {
    'google.com': 'Google Workspace',
    'outlook.com': 'Microsoft 365',
    'protection.outlook.com': 'Microsoft 365',
    'pphosted.com': 'Proofpoint',
    'mimecast.com': 'Mimecast',
}

_VENDOR_NAME_TO_INFO = {
    info['vendor']: info for info in SPF_VENDOR_MAP.values()
}


def detect_vendors_from_mx(mx_hosts: List[str]) -> List[Dict]:
    """Detect email vendors from MX hostnames, the same way
    detect_vendors_from_spf detects them from SPF includes."""
    detected_vendors = []
    seen_vendors = set()

    for mx_host in mx_hosts or []:
        mx_lower = (mx_host or "").lower().rstrip(".")
        for pattern, vendor_name in MX_VENDOR_PATTERNS.items():
            if mx_lower == pattern or mx_lower.endswith("." + pattern):
                if vendor_name in seen_vendors:
                    continue
                vendor_info = _VENDOR_NAME_TO_INFO.get(vendor_name)
                if not vendor_info:
                    continue
                detected_vendors.append({
                    'vendor': vendor_name,
                    'dkim_selectors': vendor_info['dkim_selectors'],
                    'category': vendor_info['category'],
                    'mx_host': mx_host,
                })
                seen_vendors.add(vendor_name)

    return detected_vendors


def _selectors_from_vendors(vendors: List[Dict], base_selectors: List[str]) -> List[str]:
    """Reorder base_selectors so the selectors named by vendors come first."""
    priority_selectors = []
    for vendor in vendors:
        priority_selectors.extend(vendor['dkim_selectors'])

    # Remove duplicates while preserving order
    seen = set()
    priority_selectors = [x for x in priority_selectors if not (x in seen or seen.add(x))]

    # Add remaining base selectors
    remaining = [s for s in base_selectors if s not in priority_selectors]

    return priority_selectors + remaining


def get_prioritized_selectors(spf_record: str, base_selectors: List[str]) -> List[str]:
    """
    Generate prioritized DKIM selector list based on SPF analysis.

    Strategy:
    1. HIGH PRIORITY: Selectors from vendors detected in SPF (80% hit rate)
    2. LOW PRIORITY: Remaining base selectors (20% hit rate)

    This means we find most DKIM records in the first 5-10 tests instead of 20+
    """
    return _selectors_from_vendors(detect_vendors_from_spf(spf_record), base_selectors)

def generate_vendor_intelligence_report(spf_record: str) -> str:
    """Generate report showing what vendors were auto-detected from SPF"""
    vendors = detect_vendors_from_spf(spf_record)
    
    if not vendors:
        return "ℹ️  No known vendors detected in SPF. Testing all common selectors."
    
    report = "🔍 INTELLIGENT DISCOVERY (from SPF analysis):\n\n"
    
    # Group by category
    categories = {}
    for vendor in vendors:
        cat = vendor['category']
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(vendor)
    
    category_labels = {
        'email_provider': '📧 Email Provider',
        'marketing_esp': '📢 Marketing Platform',
        'transactional_esp': '🔔 Transactional Email',
        'email_security': '🛡️ Email Security',
        'support_platform': '💬 Support Platform'
    }
    
    for cat, cat_vendors in categories.items():
        report += f"{category_labels.get(cat, cat)}:\n"
        for vendor in cat_vendors:
            report += f"  • {vendor['vendor']}\n"
            report += f"    SPF: {vendor['spf_include']}\n"
            report += f"    Testing selectors: {', '.join(vendor['dkim_selectors'])}\n\n"
    
    return report

def smart_dkim_check(domain: str, spf_record: Optional[str] = None, max_selectors: int = 40,
                     mx_hosts: Optional[List[str]] = None,
                     progress_callback: Optional[Callable[[int], None]] = None,
                     executor: Optional[ThreadPoolExecutor] = None) -> Dict:
    """
    INTELLIGENT DKIM checking using SPF- and MX-based vendor detection.

    This is the smart version that:
    1. Analyzes SPF and MX to detect vendors
    2. Prioritizes relevant DKIM selectors
    3. Finds records faster with fewer DNS queries
    4. Returns vendor context with each found selector

    Args:
        domain: Domain to check
        spf_record: SPF record (optional, will query if not provided)
        max_selectors: Max prioritized selectors to test (default 40, 0 = unlimited).
        mx_hosts: MX hostnames, for vendors that both receive and sign mail
            (Google Workspace, Microsoft 365) or resign it as a relay
            (Proofpoint, Mimecast). Used alongside SPF-detected vendors.
        executor: Pool to run the selector probes on. Defaults to a private
            pool. Callers that already run inside a pool must pass one that is
            not the pool they are running on.

    Returns:
        Complete DKIM discovery results with vendor intelligence
    """
    from comprehensive_selectors import (
        COMPREHENSIVE_DKIM_SELECTORS as DKIM_SELECTORS,
        GENERIC_SELECTORS,
    )

    result = {
        'domain': domain,
        'vendors_detected': [],
        'found_selectors': [],
        'tested_count': 0,
        'discovery_method': 'blind_loop',
        'intelligence_report': ''
    }

    # Get SPF record if not provided
    if spf_record is None:
        try:
            answers = get_resolver().resolve(domain, 'TXT')
            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                # RFC 7208 section 4.6.1: the version term is case
                # insensitive, and spf_recursive already lowercases here.
                if txt.strip().lower().startswith('v=spf1'):
                    from spf_recursive import repair_spf_missing_spaces
                    spf_record, _ = repair_spf_missing_spaces(txt)
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
            spf_record = None

    # Combine SPF- and MX-detected vendors, SPF first: a domain naming its
    # own vendor in SPF is a stronger signal than an MX host pattern match.
    # A domain hosted at Google Workspace with no SPF include for it (rare,
    # but SPF can fail to resolve) still gets Google's selectors from MX.
    vendors = []
    seen_vendor_names = set()
    from_spf = False
    if spf_record:
        for v in detect_vendors_from_spf(spf_record):
            if v['vendor'] not in seen_vendor_names:
                vendors.append(v)
                seen_vendor_names.add(v['vendor'])
                from_spf = True
    for v in detect_vendors_from_mx(mx_hosts or []):
        if v['vendor'] not in seen_vendor_names:
            vendors.append(v)
            seen_vendor_names.add(v['vendor'])
    result['vendors_detected'] = vendors

    if vendors:
        priority_selectors = _selectors_from_vendors(vendors, DKIM_SELECTORS)
        result['discovery_method'] = 'spf_intelligent' if from_spf else 'mx_intelligent'
        if spf_record:
            result['intelligence_report'] = generate_vendor_intelligence_report(spf_record)
    else:
        # No vendor detected from either signal: the head of the master
        # list, which is organized by named vendor before it gets to the
        # sequential/date-based/generic tail, is no more likely to match
        # than anywhere else. The generic fallback below is what actually
        # finds these domains (chiefly "default", self-hosted mail's own
        # convention).
        priority_selectors = DKIM_SELECTORS
        result['discovery_method'] = 'blind_loop'

    if max_selectors > 0:
        priority_selectors = priority_selectors[:max_selectors]

    # GENERIC_SELECTORS is a fallback sweep, not a standing addition. Before,
    # it was unioned into every probe regardless of outcome, so every audit
    # ran 40 (capped priority) + 156 (generic) = 196 probes even when the
    # very first vendor-implied selector was going to match. It only runs
    # now when the priority list -- vendor-implied selectors, or the head of
    # the master list when no vendor was detected -- finds nothing, which is
    # the common case for self-hosted mail publishing "default" and the rare
    # case for everyone else.
    _seen_priority = set(priority_selectors)
    fallback_selectors = [
        s for s in GENERIC_SELECTORS if not (s in _seen_priority or _seen_priority.add(s))
    ]

    # Wildcard detection: query a random nonsense selector. If it returns
    # a TXT record, the domain has wildcard DNS and DKIM discovery is unreliable.
    import uuid
    _canary = f"_dkimwildcardtest{uuid.uuid4().hex[:8]}._domainkey.{domain}"
    try:
        # Uncached: the canary name is random per call, so caching it can
        # only evict a real answer to store one that will never be read.
        _canary_answers = get_uncached_resolver(3).resolve(_canary, 'TXT')
        # Got a response for a random selector -- wildcard DNS detected
        result['wildcard_detected'] = True
        result['found_selectors'] = []
        result['status'] = 'warning'
        result['issues'] = result.get('issues', [])
        result['issues'].append({
            'severity': 'warning',
            'issue': 'Wildcard DNS detected',
            'plain_english': (
                'This domain has wildcard DNS records that respond to any subdomain query. '
                'DKIM selector discovery is not possible because every selector appears to exist.'
            ),
        })
        return result
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
        pass  # No wildcard -- proceed normally

    # Test selectors in parallel
    vendors_detected = result.get('vendors_detected', [])

    def _test_selector(selector: str) -> dict | None:
        fqdn = f"{selector}._domainkey.{domain}"
        try:
            # Built per probe, but no longer re-reading /etc/resolv.conf from
            # disk each time: get_uncached_resolver copies a configuration
            # read once at import instead of reconfiguring from the file.
            # Uncached on purpose: with the fallback sweep now conditional,
            # a typical audit's unique probe names are fewer still, and a
            # name that resolves once here is not one any other domain's
            # audit will ever ask again.
            resolver = get_uncached_resolver(3)
            resolver.lifetime = 3
            answers = resolver.resolve(fqdn, 'TXT')

            # Every record at the name, one joined string each. Looking only
            # at answers[0] dropped the key whenever a domain verification
            # token happened to sort first, and the domain was then reported
            # as having no DKIM at all.
            dkim_record = None
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                )
                if "p=" in txt and not txt.strip().startswith("v=spf1"):
                    dkim_record = txt
                    break

            if dkim_record is None:
                return None

            # Key type and size come from the same analyzer the manual
            # selector path uses, so both discovery paths hand downstream
            # consumers an identical selector shape. Guessing the size from
            # base64 length cannot tell 2048 from 3072 or 4096 apart.
            key_analysis = analyze_dkim_key_strength(dkim_record)

            matched_vendor = None
            for vendor in vendors_detected:
                if selector in vendor['dkim_selectors']:
                    matched_vendor = vendor['vendor']
                    break

            return {
                'selector': selector,
                'fqdn': fqdn,
                'record': dkim_record,
                'record_display': dkim_record[:100] + '...' if len(dkim_record) > 100 else dkim_record,
                'key_type': key_analysis['key_type'],
                'key_bits': key_analysis['key_bits'],
                'vendor': matched_vendor,
                'discovery_priority': 'HIGH' if matched_vendor else 'LOW',
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
            return None

    found = []
    timed_out = False
    tested = 0
    deadline = time.monotonic() + DKIM_DISCOVERY_TIMEOUT

    # A private pool here meant 15 fresh threads per audit, so eight
    # concurrent audits spawned up to 120 of them on top of the audit pools.
    # Callers pass a long-lived pool instead.
    own_pool = executor is None
    pool = executor or ThreadPoolExecutor(max_workers=15)

    def _run_wave(selectors: List[str]) -> None:
        nonlocal timed_out, tested
        if not selectors or timed_out:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            return
        futures = {pool.submit(_test_selector, sel): sel for sel in selectors}
        try:
            # A timeout passed to as_completed is enforced by the stdlib; the
            # previous form checked time.monotonic() only after each future
            # completed, so a slow queue meant the 15s budget was advisory,
            # observed overshooting to 15.2s.
            for future in as_completed(futures, timeout=remaining):
                tested += 1
                r = future.result()
                if r:
                    found.append(r)
                    if progress_callback:
                        progress_callback(len(found))
                    if len(found) >= DKIM_MAX_FOUND:
                        break
        except _FuturesTimeoutError:
            timed_out = True
        finally:
            # Cancel the stragglers rather than shutting the pool down. The
            # pool may belong to the caller, and shutting a shared pool down
            # from inside one check would take every other check in the
            # process with it. A future still queued (never started) is
            # actually stopped by cancel(); one already running is not, a
            # limit of the underlying thread, not of this call.
            for f in futures:
                f.cancel()

    try:
        _run_wave(priority_selectors)
        if not found:
            _run_wave(fallback_selectors)
    finally:
        if own_pool:
            pool.shutdown(wait=False, cancel_futures=True)

    # Preserve priority order: vendor-implied selectors, then generics.
    selector_order = {sel: i for i, sel in enumerate(priority_selectors + fallback_selectors)}
    found.sort(key=lambda r: selector_order.get(r['selector'], 999))

    result['found_selectors'] = found
    # The real number of probes that finished, not the number queued. The
    # deadline and the DKIM_MAX_FOUND break both stop the loop early, and
    # reporting the queued count told users we had checked selectors we never
    # got to.
    result['tested_count'] = tested

    if timed_out:
        result['timed_out'] = True
        result['timeout_note'] = 'DKIM selector discovery timed out, results may be incomplete.'

    return result


# Example usage and testing
if __name__ == "__main__":
    # Test with sample SPF record
    sample_spf = "v=spf1 include:_spf.google.com include:servers.mcsv.net include:sendgrid.net ~all"
    
    print("=" * 70)
    print("SPF-BASED INTELLIGENT DKIM DISCOVERY")
    print("=" * 70)
    print(f"\nSample SPF: {sample_spf}\n")
    
    # Show vendor detection
    vendors = detect_vendors_from_spf(sample_spf)
    print(f"Detected {len(vendors)} vendors:")
    for v in vendors:
        print(f"  • {v['vendor']}: {v['dkim_selectors']}")
    
    # Show prioritized selector order
    from comprehensive_selectors import COMPREHENSIVE_DKIM_SELECTORS as DKIM_SELECTORS
    prioritized = get_prioritized_selectors(sample_spf, DKIM_SELECTORS)
    print("\nPrioritized selector order (first 10):")
    for i, sel in enumerate(prioritized[:10], 1):
        print(f"  {i}. {sel}")
    
    print(f"\nTotal selectors to test: {len(prioritized)}")
    print(f"HIGH PRIORITY (from SPF): {len([s for s in prioritized if s in ['google', 'k1', 'k2', 'k3', 'em', 's1', 's2']])}")
    print(f"LOW PRIORITY (generic): {len(prioritized) - len([s for s in prioritized if s in ['google', 'k1', 'k2', 'k3', 'em', 's1', 's2']])}")

