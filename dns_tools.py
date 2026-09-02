"""
DNS Security Auditor - Core DNS Tools
======================================
Domain normalization and audit entry point.
"""

from typing import Any, Dict, Optional

import dns.flags
import dns.resolver
import idna

# ============================================================
# Shared DNS resolvers
# ============================================================
#
# Nothing in this codebase cached DNS, so a single complete audit re-issued
# roughly 35 identical queries: _dmarc.<domain>/TXT five times, <domain>/TXT
# five times, _mta-sts.<domain>/TXT four times, and NS, CAA, DNSKEY and DS two
# or three times each.
#
# Two caches, not one. dnspython keys its cache on (name, rdtype, rdclass)
# alone. The DO flag and the nameserver list are not part of that key, so a
# plain answer sharing a cache with the DNSSEC resolver would satisfy a DNSSEC
# query with a response carrying no RRSIG, and the DNSSEC check would report a
# signed zone as unsigned. That is a worse bug than the duplication.
#
# LRUCache takes its own lock, so it is safe to share across threads, and it
# honors record TTLs, so entries expire on their own. Process-wide is right.
_PLAIN_CACHE = dns.resolver.LRUCache(max_size=2000)
_DNSSEC_CACHE = dns.resolver.LRUCache(max_size=1000)

# DNSSEC-validating public resolvers. Quad9 first because its AD-bit signal is
# the strictest: it drops bogus answers rather than returning AD=0.
_DNSSEC_NAMESERVERS = ["9.9.9.9", "1.1.1.1", "1.0.0.1", "8.8.8.8"]


def get_resolver(timeout: float = 5.0) -> "dns.resolver.Resolver":
    """A plain resolver backed by the shared answer cache."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    resolver.cache = _PLAIN_CACHE
    return resolver


def get_dnssec_resolver(timeout: float = 8.0) -> "dns.resolver.Resolver":
    """A resolver with the DO flag set, backed by its own separate cache.

    Sets DO so DNSKEY/RRSIG/DS come back and the AD bit is meaningful, points
    at validating public resolvers instead of a possibly stub system resolver,
    and uses a 4096 byte EDNS buffer because DNSKEY responses run over 512.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    resolver.nameservers = list(_DNSSEC_NAMESERVERS)
    resolver.use_edns(0, dns.flags.DO, 4096)
    resolver.cache = _DNSSEC_CACHE
    return resolver


def normalize_domain(value: str) -> str:
    """Normalize a user-supplied string into a bare domain name.

    Handles URLs, email addresses, trailing dots, ports, and IDN domains.
    """
    if not value:
        return ""
    domain = str(value).strip().lower()
    if "@" in domain:
        domain = domain.split("@")[-1]
    domain = (
        domain.removeprefix("http://")
        .removeprefix("https://")
    )
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    # Strip port (e.g. example.com:443)
    if ":" in domain:
        domain = domain.rsplit(":", 1)[0]
    domain = domain.rstrip(".")
    # IDNA2008 (multi-label aware). Leave invalid input for downstream rejection.
    try:
        domain = idna.encode(domain).decode("ascii")
    except idna.IDNAError:
        pass
    return domain


def audit_dns_security(
    domain: str,
    *,
    dkim_selector: Optional[str] = None,
    scope: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a full audit via audit_engine.

    Parameters
    ----------
    domain : str
        The domain to audit (will be normalized).
    dkim_selector : str | None
        A specific DKIM selector to test.
    scope : str | None
        Audit scope (e.g. "email_full", "dmarc"). None = complete.
    """
    domain = normalize_domain(domain)
    if not domain:
        return {
            "domain": "",
            "error": "Empty domain after normalization",
            "checks": [],
            "priority_fixes": [],
        }

    # Imported here rather than at module scope: audit_engine imports the
    # resolver factories above, so a module-level import in both directions
    # fails whichever module is loaded second.
    from audit_engine import run_full_audit

    return run_full_audit(domain, dkim_selector=dkim_selector, scope=scope)
