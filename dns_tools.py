"""
DNS Security Auditor - Core DNS Tools
======================================
Domain normalization and audit entry point.
"""

import re
import time
from typing import Any, Dict, List, Optional

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

# How long a "there is no such record" answer may be reused. Deliberately
# shorter than the 5 minute result cache in server.py, so a re-audit can never
# be answered from a negative entry the previous audit created.
NEGATIVE_TTL_CAP = 120.0


class BoundedNegativeCache(dns.resolver.LRUCache):
    """LRUCache that will not hold a negative answer for long.

    dnspython caches NODATA under (qname, rdtype, rdclass) and NXDOMAIN under
    (qname, ANY, rdclass), and Answer.expiration is time.time() plus
    chaining_result.minimum_ttl, which for a negative answer comes from the
    SOA minimum in the authority section. Measured on dnspython 2.8.0:

        NXDOMAIN with SOA (minimum 86400)   900 s
        NODATA with SOA                     900 s
        NXDOMAIN with no SOA                4,294,967,295 s (136 years)

    The last one pins an entry for the life of the process, bounded only by
    LRU eviction, and it is reachable through any stub forwarder that drops
    the authority section.

    The result cache in server.py is 5 minutes, and it is 5 minutes on
    purpose: a re-audit is supposed to show a change. A 15 minute negative
    entry underneath it breaks the one workflow this tool exists for. An
    operator audits, is told "No DMARC policy published", publishes the
    record, waits out the result cache, re-runs, and is told the same thing
    again, with nothing in the report explaining why. For a tool whose job is
    to verify a fix, that is the worst failure available.

    Positive answers keep their real TTL. They are where the saving of about
    35 duplicate queries per audit came from. The negatives contribute almost
    none of it and carry all of the staleness.
    """

    def put(self, key, value):
        # rrset is None for both negative shapes: the NODATA answer and the
        # ANY-keyed NXDOMAIN answer. A positive answer always has an rrset.
        if getattr(value, "rrset", None) is None:
            cap = time.time() + NEGATIVE_TTL_CAP
            if getattr(value, "expiration", 0) > cap:
                value.expiration = cap
        super().put(key, value)


_PLAIN_CACHE = BoundedNegativeCache(max_size=2000)
_DNSSEC_CACHE = BoundedNegativeCache(max_size=1000)

# Selector probes get their own resolver with no cache at all. Auto-discovery
# tries roughly 193 unique <selector>._domainkey.<domain> names per audit and
# essentially every one is NXDOMAIN. Cached, one audit evicts about a tenth of
# a 2000 entry cache and ten audits flush it, pushing out exactly the repeated
# record lookups the cache exists for, in favour of names that will never be
# queried again for any other domain. With 193 unique names a cache buys
# nothing here.
#
# dns.resolver.Resolver() re-reads /etc/resolv.conf from disk on every
# construction (configure=True by default), and one of these gets built per
# probe: /etc/resolv.conf opened 241 times in a single audit, counted by
# patching builtins.open. Read it once at import and hand every probe
# resolver a copy of the parsed configuration instead of the file.
_resolv_conf_template = dns.resolver.Resolver()


def get_uncached_resolver(timeout: float = 5.0) -> "dns.resolver.Resolver":
    """A resolver that neither reads nor writes the shared answer cache."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(_resolv_conf_template.nameservers)
    resolver.domain = _resolv_conf_template.domain
    resolver.search = list(_resolv_conf_template.search)
    resolver.rotate = _resolv_conf_template.rotate
    resolver.ndots = _resolv_conf_template.ndots
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    resolver.cache = None
    return resolver

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


# ============================================================
# Record version tags
# ============================================================
#
# Five TXT record types are found by a leading version tag, and their five
# specs define that tag differently on purpose. Two properties vary, and
# normalizing them to one rule is exactly the mistake this module exists to
# prevent, so both are arguments rather than a choice baked in here.
#
# Case. RFC 7405 section 2 defines the %s prefix as case sensitive and states
# that a literal with no prefix "is case insensitive and is equivalent to
# having the %i prefix". So a version string is case sensitive if and only if
# its own spec writes %s.
#
# Whitespace. Some specs put *WSP on both sides of the equals sign and some
# write the whole tag as one literal with no room for it.
#
#   DMARC    RFC 9989 section 5.4 (obsoletes RFC 7489 section 6.4)
#              equals        = *WSP "=" *WSP
#              dmarc-version = "v" equals %s"DMARC1"
#            case sensitive, whitespace allowed
#
#   BIMI     draft-brand-indicators-for-message-identification section 4.2
#              bimi-version = "v" *WSP "=" *WSP "BIMI1"
#            no %s prefix, so case insensitive; whitespace allowed. BIMI
#            assertion records follow the RFC 6376 section 3.2 tag-value
#            syntax, whose tag-spec also permits [FWS] around the equals.
#
#   SPF      RFC 7208 section 12
#              version = "v=spf1"
#            no %s prefix, so case insensitive; no whitespace. Section 4.6.1
#            confirms mechanism and modifier names are case insensitive too.
#
#   MTA-STS  RFC 8461 section 3.1
#              sts-version = %s"v=STSv1"
#            case sensitive, no whitespace
#
#   TLS-RPT  RFC 8460 section 3
#              tlsrpt-version = %s"v=TLSRPTv1"
#            case sensitive, no whitespace
#
# SPF deliberately has no wrapper below. Its two call sites in audit_engine
# are correct as written and routing them through here would change what they
# accept after the version value, which is a separate question this helper is
# not asking.

_TAG_GAP = r"[ \t]*"


def _version_tag_pattern(value: str, allow_whitespace: bool) -> str:
    """Anchored pattern for a leading version tag, capturing the value."""
    gap = _TAG_GAP if allow_whitespace else ""
    return rf"^v{gap}={gap}({re.escape(value)})\b"


def matches_version_tag(record: str, value: str, *,
                        allow_whitespace: bool, case_sensitive: bool) -> bool:
    """True when ``record`` opens with this version tag, as its spec defines it.

    ``allow_whitespace`` permits *WSP around the equals sign. ``case_sensitive``
    requires the version value to be spelled exactly. Pass both from the record
    type's own ABNF; there is no defensible default.
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = _version_tag_pattern(value, allow_whitespace)
    return re.match(pattern, record.strip(), flags) is not None


def version_tag_deviations(record: str, value: str, *,
                           allow_whitespace: bool,
                           case_sensitive: bool) -> Optional[List[str]]:
    """Why a near-miss record will be ignored, for a record plainly meant to be one.

    Returns None when ``record`` does not carry this version tag even under the
    loosest reading, so it is some other TXT record and none of our business.
    Otherwise returns the reasons it deviates from the spec, empty when it
    conforms. A domain that published a near miss meant to turn the protocol
    on, and telling it why the record is inert beats reporting nothing at all.
    """
    stripped = record.strip()
    loose = re.match(_version_tag_pattern(value, True), stripped, re.IGNORECASE)
    if not loose:
        return None

    reasons = []
    if case_sensitive and loose.group(1) != value:
        reasons.append(
            f"the version value is written '{loose.group(1)}' and must be "
            f"spelled exactly '{value}'"
        )
    # Probed case insensitively on purpose: a record that is wrong on both
    # axes should be told about both, not have the case error mask the
    # whitespace one.
    if not allow_whitespace and not re.match(
        _version_tag_pattern(value, False), stripped, re.IGNORECASE
    ):
        reasons.append("there is whitespace around the equals sign")
    return reasons


def is_dmarc_version_tag(record: str) -> bool:
    """RFC 9989 section 5.4: case sensitive DMARC1, *WSP around the equals."""
    return matches_version_tag(record, "DMARC1",
                               allow_whitespace=True, case_sensitive=True)


def is_bimi_version_tag(record: str) -> bool:
    """BIMI draft section 4.2: plain literal, so case insensitive, *WSP allowed."""
    return matches_version_tag(record, "BIMI1",
                               allow_whitespace=True, case_sensitive=False)


def is_mta_sts_version_tag(record: str) -> bool:
    """RFC 8461 section 3.1: case sensitive STSv1, no whitespace."""
    return matches_version_tag(record, "STSv1",
                               allow_whitespace=False, case_sensitive=True)


def mta_sts_version_deviations(record: str) -> Optional[List[str]]:
    """Reasons an intended MTA-STS record at _mta-sts is not one. See above."""
    return version_tag_deviations(record, "STSv1",
                                  allow_whitespace=False, case_sensitive=True)


def is_tls_rpt_version_tag(record: str) -> bool:
    """RFC 8460 section 3: case sensitive TLSRPTv1, no whitespace."""
    return matches_version_tag(record, "TLSRPTv1",
                               allow_whitespace=False, case_sensitive=True)


def tls_rpt_version_deviations(record: str) -> Optional[List[str]]:
    """Reasons an intended TLS-RPT record at _smtp._tls is not one. See above."""
    return version_tag_deviations(record, "TLSRPTv1",
                                  allow_whitespace=False, case_sensitive=True)


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
