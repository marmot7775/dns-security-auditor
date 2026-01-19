"""
DNS Security Auditor - Core Tools
Checks: DMARC, SPF, DKIM, MTA-STS, TLS-RPT, DNSSEC, CAA, NS, Zone Transfer, Subdomain Takeover
"""

import os
import re
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

# DNS imports
try:
    import dns.resolver
    import dns.exception
    import dns.rdatatype
    import dns.dnssec
    import dns.name
    import dns.query
    import dns.zone
    import dns.rcode
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ------------------------------------------------------------
# Domain Normalization
# ------------------------------------------------------------

def normalize_domain(value: str) -> str:
    """Normalize user input into a bare domain name."""
    if value is None:
        return ""
    domain = str(value).strip().lower()
    if domain.startswith("http://"):
        domain = domain[len("http://"):]
    elif domain.startswith("https://"):
        domain = domain[len("https://"):]
    domain = domain.split("/", 1)[0]
    domain = domain.split("?", 1)[0]
    domain = domain.split("#", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    if ":" in domain:
        host, _, _port = domain.partition(":")
        domain = host
    domain = domain.rstrip(".")
    return domain


# ------------------------------------------------------------
# DNS Lookup Helpers
# ------------------------------------------------------------

def _get_resolver():
    """Return a resolver with reasonable timeouts."""
    if not DNS_AVAILABLE:
        raise RuntimeError("dnspython library not available")
    try:
        resolver = dns.resolver.Resolver()
    except dns.resolver.NoResolverConfiguration:
        # No system DNS config - use Google DNS
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    resolver.timeout = 5
    resolver.lifetime = 10
    return resolver


def _lookup_txt_records(name: str) -> List[str]:
    """Return all TXT records for a name as plain strings."""
    if not DNS_AVAILABLE:
        return []

    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, "TXT")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        Exception,
    ):
        return []

    records: List[str] = []
    for rdata in answers:
        try:
            parts = [
                p.decode("utf-8") if isinstance(p, bytes) else str(p)
                for p in rdata.strings
            ]
            records.append("".join(parts))
        except AttributeError:
            text = str(rdata)
            if text.startswith('"') and text.endswith('"'):
                text = text[1:-1]
            records.append(text)

    return records


def _lookup_records(name: str, rdtype: str) -> List[str]:
    """Generic record lookup."""
    if not DNS_AVAILABLE:
        return []

    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, rdtype)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


# ------------------------------------------------------------
# DMARC Checks
# ------------------------------------------------------------

def _validate_dmarc_syntax(record: str) -> List[str]:
    """
    Validate DMARC record syntax and return list of syntax errors.
    """
    errors = []
    record_lower = record.strip()
    
    # Must start with v=DMARC1
    if not record_lower.lower().startswith("v=dmarc1"):
        errors.append("DMARC record must start with 'v=DMARC1'")
        return errors
    
    # Valid tags per RFC 7489
    valid_tags = {
        "v": "version",
        "p": "policy",
        "sp": "subdomain policy",
        "rua": "aggregate report URI",
        "ruf": "forensic report URI",
        "adkim": "DKIM alignment mode",
        "aspf": "SPF alignment mode",
        "pct": "percentage",
        "rf": "report format",
        "ri": "report interval",
        "fo": "failure reporting options",
    }
    
    valid_policies = ["none", "quarantine", "reject"]
    valid_alignment = ["r", "s"]  # relaxed, strict
    
    tags_found = {}
    
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        
        if "=" not in part:
            errors.append(f"Invalid tag format (missing '='): '{part}'")
            continue
        
        tag, value = part.split("=", 1)
        tag = tag.strip().lower()
        value = value.strip()
        
        if tag not in valid_tags:
            errors.append(f"Unknown tag '{tag}' — not defined in RFC 7489")
        
        if tag in tags_found:
            errors.append(f"Duplicate tag '{tag}' — each tag should appear only once")
        tags_found[tag] = value
        
        # Validate specific tag values
        if tag == "p" and value.lower() not in valid_policies:
            errors.append(f"Invalid policy '{value}' — must be 'none', 'quarantine', or 'reject'")
        
        if tag == "sp" and value.lower() not in valid_policies:
            errors.append(f"Invalid subdomain policy '{value}' — must be 'none', 'quarantine', or 'reject'")
        
        if tag == "adkim" and value.lower() not in valid_alignment:
            errors.append(f"Invalid DKIM alignment '{value}' — must be 'r' (relaxed) or 's' (strict)")
        
        if tag == "aspf" and value.lower() not in valid_alignment:
            errors.append(f"Invalid SPF alignment '{value}' — must be 'r' (relaxed) or 's' (strict)")
        
        if tag == "pct":
            try:
                pct_val = int(value)
                if pct_val < 0 or pct_val > 100:
                    errors.append(f"Invalid pct value '{value}' — must be between 0 and 100")
            except ValueError:
                errors.append(f"Invalid pct value '{value}' — must be an integer")
        
        if tag == "ri":
            try:
                ri_val = int(value)
                if ri_val < 0:
                    errors.append(f"Invalid ri (report interval) '{value}' — must be a positive integer")
            except ValueError:
                errors.append(f"Invalid ri (report interval) '{value}' — must be an integer (seconds)")
    
    # Required tags
    if "p" not in tags_found:
        errors.append("Missing required 'p' (policy) tag")
    
    return errors


def check_dmarc(domain: str) -> Dict[str, Any]:
    """
    Check DMARC record for a domain per RFC 7489.
    Validates syntax, policy, and reporting configuration.
    """
    name = f"_dmarc.{domain}"
    
    # Get all TXT records at _dmarc.domain
    all_txt = _lookup_txt_records(name)
    dmarc_records = [rec for rec in all_txt if rec.lower().startswith("v=dmarc1")]

    result = {
        "check": "DMARC",
        "domain": domain,
        "record_location": name,
        "record": None,
        "record_count": len(dmarc_records),
        "tags": {},
        "status": "error",
        "issues": [],
        "warnings": [],
        "recommendations": [],
        "syntax_errors": [],
    }

    # --- No DMARC record ---
    if not dmarc_records:
        result["issues"].append(
            f"NO DMARC RECORD at {name}. "
            f"Without DMARC, anyone can spoof emails from your domain. "
            f"Receivers have no policy guidance for handling unauthenticated mail."
        )
        result["recommendations"].append(
            f"Add a TXT record at {name} to start monitoring:\n"
            f"  v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; fo=1\n\n"
            f"This enables reporting without affecting mail delivery. "
            f"Review reports, then gradually move to p=quarantine and p=reject."
        )
        return result

    # --- Multiple DMARC records (RFC 7489 violation) ---
    if len(dmarc_records) > 1:
        result["status"] = "error"
        result["issues"].append(
            f"MULTIPLE DMARC RECORDS FOUND ({len(dmarc_records)} records) at {name}. "
            f"RFC 7489 Section 6.6.3 requires exactly one DMARC record. "
            f"Receivers MUST ignore all records when multiple exist."
        )
        result["recommendations"].append(
            "Delete duplicate records, keeping only one. Current records:\n" +
            "\n".join([f"  {i+1}. {rec}" for i, rec in enumerate(dmarc_records)])
        )
        result["record"] = dmarc_records[0]
        return result

    record = dmarc_records[0]
    result["record"] = record

    # --- Syntax validation ---
    syntax_errors = _validate_dmarc_syntax(record)
    if syntax_errors:
        result["syntax_errors"] = syntax_errors
        for err in syntax_errors:
            result["issues"].append(f"Syntax: {err}")
        result["status"] = "error"

    # --- Parse tags ---
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    result["tags"] = tags

    # --- Evaluate policy ---
    policy = tags.get("p", "").lower()
    
    if policy == "none":
        if result["status"] != "error":
            result["status"] = "warning"
        result["warnings"].append(
            "Policy p=none (MONITORING ONLY). "
            "Unauthenticated mail is delivered normally. "
            "This is appropriate for initial deployment to collect data."
        )
        result["recommendations"].append(
            "After reviewing DMARC aggregate reports and fixing authentication issues, "
            "progress to p=quarantine (spam folder) then p=reject (block)."
        )
    elif policy == "quarantine":
        if result["status"] != "error":
            result["status"] = "warning"
        result["warnings"].append(
            "Policy p=quarantine (PARTIAL ENFORCEMENT). "
            "Unauthenticated mail is sent to spam/junk folder."
        )
        result["recommendations"].append(
            "Consider moving to p=reject once you've confirmed all legitimate "
            "mail sources are properly authenticated (SPF aligned or DKIM aligned)."
        )
    elif policy == "reject":
        if result["status"] != "error":
            result["status"] = "ok"
        result["warnings"].append(
            "Policy p=reject (FULL ENFORCEMENT). "
            "Unauthenticated mail is blocked. This is the strongest protection."
        )
    elif policy:
        result["issues"].append(
            f"Invalid policy value '{policy}'. "
            f"Must be 'none', 'quarantine', or 'reject' per RFC 7489."
        )
    else:
        result["issues"].append(
            "Missing required 'p' (policy) tag. "
            "DMARC record is invalid without a policy."
        )

    # --- Check subdomain policy (sp) ---
    sp = tags.get("sp", "").lower()
    if sp:
        if sp != policy:
            result["warnings"].append(
                f"Subdomain policy sp={sp} differs from domain policy p={policy}. "
                f"Subdomains will use '{sp}' instead of '{policy}'."
            )

    # --- Check aggregate reporting (rua) ---
    if "rua" not in tags:
        result["issues"].append(
            "No 'rua' tag — you will NOT receive aggregate reports. "
            "Without reports, you cannot monitor authentication or detect spoofing."
        )
        result["recommendations"].append(
            f"Add aggregate reporting: rua=mailto:dmarc-reports@{domain}\n"
            f"(Use a dedicated mailbox or a DMARC report analysis service)"
        )
    else:
        rua = tags["rua"]
        if not rua.startswith("mailto:"):
            result["warnings"].append(
                f"rua value '{rua}' should start with 'mailto:' for email delivery."
            )

    # --- Check forensic reporting (ruf) ---
    if "ruf" in tags:
        result["warnings"].append(
            "Forensic reporting (ruf) is configured. Note: Many receivers do not send "
            "forensic reports due to privacy concerns. Don't rely solely on ruf."
        )

    # --- Check pct (percentage) ---
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
            if pct < 100:
                result["warnings"].append(
                    f"pct={pct} — Policy applies to only {pct}% of mail. "
                    f"The remaining {100-pct}% is treated as p=none."
                )
                result["recommendations"].append(
                    "DMARCbis (draft standard) recommends against pct-based rollouts. "
                    "Consider using p=none for testing, then p=quarantine or p=reject at pct=100."
                )
        except ValueError:
            pass  # Already caught in syntax validation

    # --- Check alignment modes ---
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()
    
    if adkim == "s":
        result["warnings"].append(
            "DKIM alignment is STRICT (adkim=s). "
            "The DKIM d= domain must exactly match the From domain."
        )
    
    if aspf == "s":
        result["warnings"].append(
            "SPF alignment is STRICT (aspf=s). "
            "The envelope sender (Return-Path) domain must exactly match the From domain."
        )

    # --- Check fo (failure reporting options) ---
    fo = tags.get("fo", "0")
    if "1" in fo:
        result["warnings"].append(
            "fo=1: Forensic reports generated if either SPF or DKIM fails "
            "(not just when both fail). This provides more detailed failure data."
        )

    return result


# ------------------------------------------------------------
# SPF Checks
# ------------------------------------------------------------

def _validate_spf_syntax(record: str) -> List[str]:
    """
    Validate SPF record syntax and return list of syntax errors.
    """
    errors = []
    record_lower = record.lower().strip()
    
    # Must start with v=spf1
    if not record_lower.startswith("v=spf1"):
        errors.append("SPF record must start with 'v=spf1'")
        return errors  # Can't validate further without proper version
    
    parts = record_lower.split()
    
    # Valid mechanisms and modifiers
    valid_mechanisms = ["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]
    valid_modifiers = ["redirect", "exp"]
    valid_qualifiers = ["+", "-", "~", "?"]
    
    has_all = False
    has_redirect = False
    
    for i, part in enumerate(parts[1:], 1):  # Skip v=spf1
        # Check for modifier (contains =)
        if "=" in part and not part.startswith(("ip4:", "ip6:")):
            modifier = part.split("=")[0].lstrip("+-~?")
            if modifier not in valid_modifiers:
                errors.append(f"Unknown modifier '{part}' at position {i}")
            if modifier == "redirect":
                has_redirect = True
            continue
        
        # Strip qualifier if present
        mechanism_part = part
        if part[0] in valid_qualifiers:
            mechanism_part = part[1:]
        
        # Extract mechanism name
        if ":" in mechanism_part:
            mechanism = mechanism_part.split(":")[0]
        elif "/" in mechanism_part:
            mechanism = mechanism_part.split("/")[0]
        else:
            mechanism = mechanism_part
        
        if mechanism == "all":
            has_all = True
            if i != len(parts) - 1:
                errors.append(f"'all' mechanism should be the last term, but found at position {i}")
        elif mechanism not in valid_mechanisms:
            errors.append(f"Unknown mechanism '{part}' at position {i}")
        
        # Validate IP addresses
        if mechanism == "ip4":
            ip_part = mechanism_part.split(":", 1)[1] if ":" in mechanism_part else ""
            if not ip_part:
                errors.append(f"ip4 mechanism requires an IP address: '{part}'")
        elif mechanism == "ip6":
            ip_part = mechanism_part.split(":", 1)[1] if ":" in mechanism_part else ""
            if not ip_part:
                errors.append(f"ip6 mechanism requires an IPv6 address: '{part}'")
        
        # include requires a domain
        if mechanism == "include":
            if ":" not in mechanism_part:
                errors.append(f"include mechanism requires a domain: '{part}'")
    
    # Warn if no all mechanism and no redirect
    if not has_all and not has_redirect:
        errors.append("SPF record has no 'all' mechanism or 'redirect' modifier — implicit '?all' will be assumed")
    
    return errors


def check_spf(domain: str) -> Dict[str, Any]:
    """
    Check SPF record for a domain per RFC 7208.
    Validates syntax, counts DNS lookups, and follows includes.
    """
    result = {
        "check": "SPF",
        "domain": domain,
        "record": None,
        "dns_lookups": 0,
        "lookup_limit": 10,
        "status": "error",
        "issues": [],
        "warnings": [],
        "recommendations": [],
        "includes_followed": [],
        "syntax_errors": [],
    }

    # Get all TXT records that look like SPF
    all_txt = _lookup_txt_records(domain)
    spf_records = [rec for rec in all_txt if rec.lower().startswith("v=spf1")]

    # --- No SPF record ---
    if not spf_records:
        result["issues"].append(f"No SPF record found at {domain}")
        result["recommendations"].append(
            f"Add a TXT record at {domain} with your SPF policy. Example:\n"
            f"  v=spf1 include:_spf.google.com ~all\n"
            f"  (Adjust 'include' for your actual email senders)"
        )
        return result

    # --- Multiple SPF records (RFC 7208 violation) ---
    if len(spf_records) > 1:
        result["status"] = "error"
        result["issues"].append(
            f"MULTIPLE SPF RECORDS FOUND ({len(spf_records)} records). "
            f"RFC 7208 Section 3.2 requires exactly one SPF record per domain. "
            f"Receivers may return PermError and reject all mail."
        )
        result["recommendations"].append(
            "Merge all SPF records into a single TXT record. Current records found:\n" +
            "\n".join([f"  {i+1}. {rec}" for i, rec in enumerate(spf_records)])
        )
        # Still analyze the first one
        result["record"] = spf_records[0]
        return result

    record = spf_records[0]
    result["record"] = record

    # --- Syntax validation ---
    syntax_errors = _validate_spf_syntax(record)
    if syntax_errors:
        result["syntax_errors"] = syntax_errors
        for err in syntax_errors:
            result["issues"].append(f"Syntax: {err}")

    # --- Count DNS lookups (RFC 7208 Section 4.6.4) ---
    visited = set()
    lookups, includes = _count_spf_lookups(domain, record, visited)
    result["dns_lookups"] = lookups
    result["includes_followed"] = includes

    # Evaluate lookup count against RFC 7208 limit
    if lookups > 10:
        result["status"] = "error"
        result["issues"].append(
            f"SPF FAILS: {lookups}/10 DNS lookups. Exceeds RFC 7208 limit. "
            f"Receivers will return PermError, causing authentication failures."
        )
        result["recommendations"].append(
            "Reduce DNS lookups by:\n"
            "  • Flattening includes (replace with ip4/ip6 ranges)\n"
            "  • Removing unused include statements\n"
            "  • Using an SPF flattening service\n"
            f"  Current includes: {', '.join(includes) if includes else 'none'}"
        )
    elif lookups > 7:
        result["status"] = "warning"
        result["warnings"].append(
            f"SPF PASSES but at risk: {lookups}/10 DNS lookups per RFC 7208. "
            f"Adding more senders may exceed the limit."
        )
        result["recommendations"].append(
            "Consider flattening SPF before adding more email senders."
        )
    else:
        if not syntax_errors:
            result["status"] = "ok"
        else:
            result["status"] = "warning"
        result["warnings"].append(f"SPF PASSES: {lookups}/10 DNS lookups per RFC 7208.")

    # --- Check 'all' mechanism ---
    record_lower = record.lower()
    if "+all" in record_lower:
        result["status"] = "error"
        result["issues"].append(
            "CRITICAL: '+all' allows ANY server worldwide to send email as your domain. "
            "This completely disables SPF protection."
        )
        result["recommendations"].append("Change '+all' to '~all' (softfail) or '-all' (hardfail)")
    elif "?all" in record_lower:
        result["status"] = "warning"
        result["issues"].append(
            "'?all' (neutral) provides no SPF protection. "
            "Receivers will not use SPF results for filtering decisions."
        )
        result["recommendations"].append("Change '?all' to '~all' (softfail) or '-all' (hardfail)")
    elif "-all" in record_lower:
        result["warnings"].append("Using '-all' (hardfail) — strictest setting, unauthorized senders will fail SPF.")
    elif "~all" in record_lower:
        result["warnings"].append("Using '~all' (softfail) — unauthorized senders will softfail SPF.")

    # --- Check for deprecated ptr mechanism ---
    if " ptr" in record_lower or ":ptr" in record_lower:
        result["warnings"].append(
            "'ptr' mechanism is deprecated per RFC 7208 Section 5.5. "
            "It is slow, unreliable, and may not be checked by all receivers."
        )
        result["recommendations"].append("Replace 'ptr' mechanism with explicit 'a' or 'ip4/ip6' entries.")

    return result


def _count_spf_lookups(domain: str, record: str, visited: Set[str]) -> Tuple[int, List[str]]:
    """Recursively count SPF DNS lookups."""
    if domain in visited or len(visited) > 20:
        return 0, []

    visited.add(domain)
    lookups = 0
    includes = []

    parts = record.lower().split()
    for part in parts:
        # include
        if part.startswith("include:"):
            lookups += 1
            target = part.split(":", 1)[1]
            includes.append(target)
            # Follow the include
            sub_record = None
            for rec in _lookup_txt_records(target):
                if rec.lower().startswith("v=spf1"):
                    sub_record = rec
                    break
            if sub_record:
                sub_lookups, sub_includes = _count_spf_lookups(target, sub_record, visited)
                lookups += sub_lookups
                includes.extend(sub_includes)

        # a mechanism (with or without domain)
        elif part.startswith("a:") or part == "a" or part.lstrip("+-~?") == "a":
            lookups += 1

        # mx mechanism
        elif part.startswith("mx:") or part == "mx" or part.lstrip("+-~?") == "mx":
            lookups += 1

        # ptr (deprecated but still counts)
        elif part.startswith("ptr:") or part == "ptr" or part.lstrip("+-~?") == "ptr":
            lookups += 1

        # exists
        elif part.startswith("exists:"):
            lookups += 1

        # redirect
        elif part.startswith("redirect="):
            lookups += 1
            target = part.split("=", 1)[1]
            includes.append(f"redirect:{target}")

    return lookups, includes


# ------------------------------------------------------------
# DKIM Checks
# ------------------------------------------------------------

COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "k1", "k2", "k3",
    "default", "dkim", "mail", "email", "smtp",
    "s1", "s2", "m1", "mx", "mandrill", "mailjet",
    "everlytickey1", "everlytickey2", "cm", "amazonses",
    "protonmail", "protonmail2", "protonmail3",
]


def check_dkim(domain: str, selectors: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Check DKIM records for common selectors.
    DKIM selectors are arbitrary strings chosen by the domain owner,
    so we can only check known/common ones without prior knowledge.
    """
    if selectors is None:
        selectors = COMMON_DKIM_SELECTORS

    result = {
        "check": "DKIM",
        "domain": domain,
        "selectors_checked": list(selectors),  # Return the list, not just count
        "selectors_found": [],
        "records": {},
        "record": None,  # Will be built at end
        "status": "warning",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    found_details = []

    for selector in selectors:
        dkim_name = f"{selector}._domainkey.{domain}"
        records = _lookup_txt_records(dkim_name)
        
        # Also try CNAME (common for delegated DKIM)
        if not records:
            cnames = _lookup_records(dkim_name, "CNAME")
            if cnames:
                result["selectors_found"].append(selector)
                cname_target = cnames[0].rstrip(".")
                result["records"][selector] = {"type": "CNAME", "target": cname_target}
                found_details.append(f"  {selector}._domainkey.{domain}")
                found_details.append(f"    → CNAME to {cname_target} (delegated signing)")
                continue

        for rec in records:
            if "v=dkim1" in rec.lower() or "p=" in rec.lower():
                result["selectors_found"].append(selector)
                
                # Parse key details
                key_type = "rsa"  # default
                if "k=ed25519" in rec.lower():
                    key_type = "ed25519"
                elif "k=rsa" in rec.lower():
                    key_type = "rsa"
                
                # Check for testing mode
                testing = "t=y" in rec.lower()
                
                # Check for empty key (revoked)
                if "p=" in rec and ("p=;" in rec or "p= ;" in rec or rec.strip().endswith("p=")):
                    result["records"][selector] = {"type": "TXT", "key_type": key_type, "revoked": True}
                    found_details.append(f"  {selector}._domainkey.{domain}")
                    found_details.append(f"    → REVOKED (empty public key)")
                else:
                    result["records"][selector] = {"type": "TXT", "key_type": key_type, "testing": testing}
                    mode_str = " [TESTING MODE]" if testing else ""
                    truncated = rec[:80] + "..." if len(rec) > 80 else rec
                    found_details.append(f"  {selector}._domainkey.{domain}")
                    found_details.append(f"    → {key_type.upper()} key{mode_str}")
                    found_details.append(f"    → {truncated}")
                break

    # Build status and messages
    if result["selectors_found"]:
        result["status"] = "ok"
        result["warnings"].append(
            f"DKIM FOUND: {len(result['selectors_found'])} selector(s) discovered: "
            f"{', '.join(result['selectors_found'])}"
        )
        
        # Check for testing mode selectors
        testing_selectors = [s for s, d in result["records"].items() 
                           if isinstance(d, dict) and d.get("testing")]
        if testing_selectors:
            result["warnings"].append(
                f"Selector(s) in TESTING mode (t=y): {', '.join(testing_selectors)}. "
                f"Receiving servers may not enforce DKIM failures."
            )
        
        # Check for revoked selectors
        revoked_selectors = [s for s, d in result["records"].items() 
                           if isinstance(d, dict) and d.get("revoked")]
        if revoked_selectors:
            result["warnings"].append(
                f"Selector(s) REVOKED (empty key): {', '.join(revoked_selectors)}. "
                f"These selectors will cause DKIM failures."
            )
    else:
        result["issues"].append(
            f"NO DKIM SELECTORS FOUND. Checked {len(selectors)} common selector names. "
            f"DKIM may still be configured with a custom selector name not in our list."
        )
        result["recommendations"].append(
            "To verify DKIM:\n"
            "  1. Check with your email provider for your selector name\n"
            "  2. Send a test email and examine the DKIM-Signature header\n"
            "  3. Common selectors by provider:\n"
            "     • Google Workspace: google, google2\n"
            "     • Microsoft 365: selector1, selector2\n"
            "     • SendGrid: s1, s2\n"
            "     • Mailchimp: k1, k2, k3"
        )

    # Build record display
    if found_details:
        result["record"] = "DKIM Selectors Found:\n" + "\n".join(found_details)
    else:
        checked_sample = ", ".join(selectors[:5]) + f"... ({len(selectors)} total)"
        result["record"] = f"No DKIM records found.\nSelectors checked: {checked_sample}"

    return result


# ------------------------------------------------------------
# MTA-STS Checks
# ------------------------------------------------------------

def check_mta_sts(domain: str) -> Dict[str, Any]:
    """
    Check MTA-STS TXT record and fetch policy file per RFC 8461.
    """
    result = {
        "check": "MTA-STS",
        "domain": domain,
        "record_location": f"_mta-sts.{domain}",
        "txt_record": None,
        "policy_url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
        "policy": None,
        "policy_mode": None,
        "policy_mx": [],
        "policy_max_age": None,
        "record": None,  # Combined display record
        "status": "error",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    # --- Check TXT record at _mta-sts.domain ---
    txt_name = f"_mta-sts.{domain}"
    txt_records = _lookup_txt_records(txt_name)

    sts_record = None
    for rec in txt_records:
        if rec.lower().startswith("v=stsv1"):
            sts_record = rec
            break

    if not sts_record:
        result["issues"].append(
            f"NO MTA-STS: No TXT record found at {txt_name}. "
            f"MTA-STS requires both a DNS TXT record and a policy file. "
            f"Without MTA-STS, SMTP connections can be downgraded to unencrypted."
        )
        result["recommendations"].append(
            f"To enable MTA-STS, add these two components:\n"
            f"  1. TXT record at {txt_name}:\n"
            f"     v=STSv1; id=20240101\n"
            f"  2. Policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt:\n"
            f"     version: STSv1\n"
            f"     mode: testing\n"
            f"     mx: mail.{domain}\n"
            f"     max_age: 86400"
        )
        return result

    result["txt_record"] = sts_record

    # --- Fetch and parse policy file ---
    policy_url = result["policy_url"]
    policy_fetched = False
    policy_content = None
    
    try:
        resp = requests.get(policy_url, timeout=10)
        if resp.status_code == 200:
            policy_fetched = True
            policy_content = resp.text
            result["policy"] = policy_content
            
            # Parse policy fields
            for line in policy_content.splitlines():
                line = line.strip()
                if line.startswith("mode:"):
                    result["policy_mode"] = line.split(":", 1)[1].strip()
                elif line.startswith("mx:"):
                    result["policy_mx"].append(line.split(":", 1)[1].strip())
                elif line.startswith("max_age:"):
                    try:
                        result["policy_max_age"] = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass

            # Evaluate policy mode
            mode = result["policy_mode"]
            if mode == "enforce":
                result["status"] = "ok"
                result["warnings"].append(
                    "MTA-STS ENFORCING: Sending servers MUST use TLS with valid certificates. "
                    "Connections that fail TLS verification will be rejected."
                )
            elif mode == "testing":
                result["status"] = "warning"
                result["warnings"].append(
                    "MTA-STS TESTING: TLS is requested but not enforced. "
                    "Failures are reported via TLS-RPT but mail is still delivered."
                )
                result["recommendations"].append(
                    "After verifying mail flow with TLS-RPT reports, change mode to 'enforce'."
                )
            elif mode == "none":
                result["status"] = "warning"
                result["issues"].append(
                    "MTA-STS DISABLED: mode=none means MTA-STS is explicitly disabled. "
                    "This provides no protection."
                )
                result["recommendations"].append("Set mode=testing, then mode=enforce after verification.")
            else:
                result["issues"].append(f"Unknown or missing MTA-STS mode: '{mode}'")
                result["recommendations"].append("Policy must contain 'mode: enforce', 'mode: testing', or 'mode: none'")

            # Check max_age
            max_age = result["policy_max_age"]
            if max_age:
                if max_age < 86400:
                    result["warnings"].append(
                        f"max_age={max_age} seconds ({max_age//3600} hours) is very short. "
                        f"Consider at least 86400 (1 day) for production."
                    )
                elif max_age >= 31536000:
                    days = max_age // 86400
                    result["warnings"].append(
                        f"max_age={max_age} seconds ({days} days). Policy cached for extended period."
                    )

            # Check mx entries match actual MX
            if result["policy_mx"]:
                result["warnings"].append(
                    f"Policy allows MX hosts: {', '.join(result['policy_mx'])}"
                )

        else:
            result["issues"].append(
                f"Policy file returned HTTP {resp.status_code}. "
                f"MTA-STS requires the policy file to be accessible."
            )
            result["recommendations"].append(
                f"Ensure policy file exists at:\n"
                f"  {policy_url}\n"
                f"The file must be served over HTTPS with a valid certificate."
            )
    except requests.exceptions.SSLError as e:
        result["issues"].append(
            f"TLS/SSL ERROR fetching policy: {str(e)}. "
            f"MTA-STS policy must be served over HTTPS with a valid certificate."
        )
        result["recommendations"].append(
            f"Fix the SSL certificate for mta-sts.{domain}. "
            f"The certificate must be valid and trusted."
        )
    except requests.exceptions.ConnectionError:
        result["issues"].append(
            f"CONNECTION ERROR: Cannot reach mta-sts.{domain}. "
            f"The MTA-STS policy host must be publicly accessible."
        )
        result["recommendations"].append(
            f"Ensure mta-sts.{domain} resolves and is reachable on port 443."
        )
    except Exception as e:
        result["issues"].append(f"Error fetching policy: {str(e)}")
        result["recommendations"].append(f"Ensure https://mta-sts.{domain} is reachable with valid TLS")

    # --- Build combined record display ---
    record_lines = []
    record_lines.append(f"DNS TXT Record ({txt_name}):")
    record_lines.append(f"  {sts_record}")
    record_lines.append("")
    record_lines.append(f"Policy File ({policy_url}):")
    if policy_fetched and policy_content:
        for line in policy_content.strip().splitlines():
            record_lines.append(f"  {line.strip()}")
    else:
        record_lines.append("  (not retrieved)")
    
    result["record"] = "\n".join(record_lines)

    return result


# ------------------------------------------------------------
# TLS-RPT Checks
# ------------------------------------------------------------

def check_tls_rpt(domain: str) -> Dict[str, Any]:
    """
    Check TLS-RPT (TLS Reporting) record per RFC 8460.
    TLS-RPT enables receiving reports about TLS connection failures.
    """
    result = {
        "check": "TLS-RPT",
        "domain": domain,
        "record_location": f"_smtp._tls.{domain}",
        "record": None,
        "rua": [],
        "status": "error",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    txt_name = f"_smtp._tls.{domain}"
    records = _lookup_txt_records(txt_name)

    tls_rpt_record = None
    for rec in records:
        if "v=tlsrptv1" in rec.lower():
            tls_rpt_record = rec
            break

    if not tls_rpt_record:
        result["issues"].append(
            f"NO TLS-RPT: No TXT record found at {txt_name}. "
            f"Without TLS-RPT, you won't receive reports when sending servers "
            f"fail to establish TLS connections to your mail servers."
        )
        result["recommendations"].append(
            f"Add TLS-RPT to receive TLS failure reports:\n"
            f"  TXT record at {txt_name}:\n"
            f"  v=TLSRPTv1; rua=mailto:tls-reports@{domain}\n\n"
            f"TLS-RPT works with MTA-STS to provide visibility into connection security."
        )
        return result

    result["record"] = f"TXT at {txt_name}:\n  {tls_rpt_record}"

    # Parse rua destinations
    rua_matches = re.findall(r'rua=([^;]+)', tls_rpt_record, re.IGNORECASE)
    if rua_matches:
        for rua in rua_matches:
            # Can be comma-separated
            for dest in rua.split(","):
                dest = dest.strip()
                if dest:
                    result["rua"].append(dest)

    # Validate record
    if not result["rua"]:
        result["status"] = "warning"
        result["issues"].append(
            "TLS-RPT record exists but has no 'rua=' destination. "
            "Reports cannot be delivered without a destination."
        )
        result["recommendations"].append(
            f"Add report destination: rua=mailto:tls-reports@{domain}"
        )
    else:
        result["status"] = "ok"
        rua_list = ", ".join(result["rua"])
        result["warnings"].append(
            f"TLS-RPT CONFIGURED: Reports will be sent to: {rua_list}"
        )
        
        # Check if using mailto vs https
        has_mailto = any("mailto:" in r for r in result["rua"])
        has_https = any("https:" in r for r in result["rua"])
        
        if has_mailto:
            result["warnings"].append(
                "Using mailto: for reports. Reports arrive as email attachments (JSON format)."
            )
        if has_https:
            result["warnings"].append(
                "Using https: endpoint for reports. Reports posted directly to your server."
            )

    # Check for common syntax issues
    if ";" not in tls_rpt_record:
        result["warnings"].append(
            "Record may have syntax issues — tags should be separated by semicolons."
        )

    return result


# ------------------------------------------------------------
# DNSSEC Checks
# ------------------------------------------------------------

def check_dnssec(domain: str) -> Dict[str, Any]:
    """
    Check if domain has valid DNSSEC per RFC 4033-4035.
    """
    result = {
        "check": "DNSSEC",
        "domain": domain,
        "signed": False,
        "valid": False,
        "ds_records": [],
        "status": "warning",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    if not DNS_AVAILABLE:
        result["issues"].append("DNS library not available for DNSSEC validation")
        return result

    try:
        resolver = _get_resolver()

        # Check for DNSKEY at the domain
        try:
            resolver.resolve(domain, "DNSKEY")
            result["signed"] = True
            result["warnings"].append(
                f"DNSKEY records found — domain is signed with DNSSEC."
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["status"] = "warning"
            result["issues"].append(
                f"NO DNSSEC: No DNSKEY record found at {domain}. "
                f"Domain is not signed. DNS responses can be spoofed."
            )
            result["recommendations"].append(
                "Enable DNSSEC signing through your DNS provider or registrar. "
                "This protects against DNS cache poisoning and man-in-the-middle attacks."
            )
            return result
        except Exception as e:
            result["issues"].append(f"Could not query DNSKEY: {str(e)}")
            return result

        # Check for DS record at parent (proves chain of trust)
        try:
            ds_answer = resolver.resolve(domain, "DS")
            result["ds_records"] = [str(r) for r in ds_answer]
            result["valid"] = True
            result["status"] = "ok"
            result["warnings"].append(
                f"DNSSEC VALID: DS record found at parent zone. "
                f"Chain of trust is complete. DNS responses are authenticated."
            )
        except dns.resolver.NoAnswer:
            result["status"] = "warning"
            result["issues"].append(
                "DNSSEC INCOMPLETE: DNSKEY exists but NO DS record at parent zone. "
                "The chain of trust is broken — DNSSEC validation will fail."
            )
            result["recommendations"].append(
                "Add the DS record to your domain's parent zone through your registrar. "
                "Without the DS record, DNSSEC provides no security benefit."
            )
        except dns.resolver.NXDOMAIN:
            result["status"] = "warning"
            result["issues"].append(
                "Could not find DS record — parent zone may not support DNSSEC."
            )
        except Exception as e:
            result["issues"].append(f"Could not verify DS record: {str(e)}")

    except Exception as e:
        result["issues"].append(f"DNSSEC check failed: {str(e)}")

    return result


# ------------------------------------------------------------
# CAA Checks
# ------------------------------------------------------------

def check_caa(domain: str) -> Dict[str, Any]:
    """
    Check CAA (Certificate Authority Authorization) records per RFC 8659.
    """
    result = {
        "check": "CAA",
        "domain": domain,
        "records": [],
        "allowed_cas": [],
        "allows_wildcard": False,
        "has_iodef": False,
        "status": "warning",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    records = _lookup_records(domain, "CAA")

    if not records:
        result["issues"].append(
            f"NO CAA RECORDS at {domain}. "
            f"Any Certificate Authority can issue SSL/TLS certificates for this domain. "
            f"This increases risk of unauthorized certificate issuance."
        )
        result["recommendations"].append(
            "Add CAA records to restrict which CAs can issue certificates:\n"
            "  Example: 0 issue \"letsencrypt.org\"\n"
            "  Example: 0 issue \"digicert.com\"\n"
            "  Example: 0 iodef \"mailto:security@yourdomain.com\""
        )
        return result

    result["records"] = records
    result["status"] = "ok"

    for rec in records:
        rec_lower = rec.lower()
        
        # Extract CA names from issue/issuewild
        if "issue" in rec_lower:
            parts = rec.split('"')
            if len(parts) >= 2:
                ca = parts[1]
                if ca:
                    result["allowed_cas"].append(ca)
        
        if "issuewild" in rec_lower:
            result["allows_wildcard"] = True
        
        if "iodef" in rec_lower:
            result["has_iodef"] = True

    # Build informative message
    if result["allowed_cas"]:
        ca_list = ", ".join(set(result["allowed_cas"]))
        result["warnings"].append(
            f"CAA CONFIGURED: Only these CAs can issue certificates: {ca_list}"
        )
    
    if not result["has_iodef"]:
        result["warnings"].append(
            "No iodef record — you won't be notified of certificate issuance policy violations."
        )
        result["recommendations"].append(
            "Consider adding: 0 iodef \"mailto:security@yourdomain.com\" "
            "to receive notifications of CAA violations."
        )

    return result


# ------------------------------------------------------------
# NS Checks
# ------------------------------------------------------------

def check_ns(domain: str) -> Dict[str, Any]:
    """
    Check nameserver configuration for diversity and issues.
    """
    result = {
        "check": "NS",
        "domain": domain,
        "nameservers": [],
        "ns_ips": {},
        "status": "ok",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    ns_records = _lookup_records(domain, "NS")

    if not ns_records:
        result["status"] = "error"
        result["issues"].append(
            f"NO NS RECORDS found for {domain}. "
            f"This is a critical DNS configuration issue."
        )
        return result

    result["nameservers"] = [ns.rstrip(".") for ns in ns_records]

    # Check for redundancy
    if len(ns_records) < 2:
        result["status"] = "warning"
        result["issues"].append(
            "Only ONE nameserver configured — no redundancy. "
            "If this server goes down, your domain becomes unreachable."
        )
        result["recommendations"].append(
            "Add at least one more nameserver from a different provider/network for redundancy."
        )
    else:
        result["warnings"].append(
            f"{len(ns_records)} nameservers configured: {', '.join(result['nameservers'])}"
        )

    # Check NS IPs for diversity
    networks = set()
    for ns in ns_records:
        ns = ns.rstrip(".")
        ips = _lookup_records(ns, "A")
        result["ns_ips"][ns] = ips
        
        for ip in ips:
            # Get /24 network
            parts = ip.split(".")
            if len(parts) == 4:
                network = ".".join(parts[:3])
                networks.add(network)

    if len(networks) == 1 and len(ns_records) > 1:
        result["status"] = "warning"
        result["issues"].append(
            "All nameservers are on the SAME /24 network — single point of failure. "
            "A network outage could make your domain unreachable."
        )
        result["recommendations"].append(
            "Use nameservers on different networks/providers for geographic and network resilience."
        )
    elif len(networks) > 1:
        result["warnings"].append(
            f"Nameservers distributed across {len(networks)} different networks — good diversity."
        )

    return result


# ------------------------------------------------------------
# Zone Transfer Check
# ------------------------------------------------------------

def check_zone_transfer(domain: str) -> Dict[str, Any]:
    """
    Check if zone transfer (AXFR) is allowed — this is usually a vulnerability.
    """
    result = {
        "check": "Zone Transfer",
        "domain": domain,
        "vulnerable": False,
        "vulnerable_ns": [],
        "status": "ok",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    if not DNS_AVAILABLE:
        result["issues"].append("DNS library not available")
        return result

    ns_records = _lookup_records(domain, "NS")

    for ns in ns_records:
        ns = ns.rstrip(".")
        try:
            # Get NS IP
            ns_ips = _lookup_records(ns, "A")
            for ns_ip in ns_ips:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                    if zone:
                        result["vulnerable"] = True
                        result["vulnerable_ns"].append(ns)
                        break
                except Exception:
                    # Transfer failed = good
                    pass
        except Exception:
            pass

    if result["vulnerable"]:
        result["status"] = "error"
        result["issues"].append(
            f"ZONE TRANSFER ALLOWED on: {', '.join(result['vulnerable_ns'])}. "
            f"This exposes your entire DNS zone to attackers, revealing all subdomains, "
            f"internal hostnames, and network structure."
        )
        result["recommendations"].append(
            "Restrict zone transfers (AXFR) to authorized secondary nameservers only. "
            "Configure your DNS server to deny AXFR requests from unauthorized IPs."
        )
    else:
        result["warnings"].append(
            f"Zone transfer (AXFR) properly restricted. "
            f"Tested {len(ns_records)} nameserver(s)."
        )

    return result


# ------------------------------------------------------------
# Subdomain Takeover Check
# ------------------------------------------------------------

TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "no such app",
    "amazonaws.com": "NoSuchBucket",
    "cloudfront.net": "Bad request",
    "azure": "404 Web Site not found",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "tumblr.com": "There's nothing here",
    "wordpress.com": "Do you want to register",
    "ghost.io": "The thing you were looking for is no longer here",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "pantheon.io": "404 error unknown site",
    "zendesk.com": "Help Center Closed",
    "fastly.net": "Fastly error: unknown domain",
}


def check_subdomain_takeover(domain: str, subdomains: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Check for potential subdomain takeover vulnerabilities.
    Scans common subdomains for dangling CNAME records pointing to unclaimed external services.
    """
    if subdomains is None:
        subdomains = ["www", "mail", "blog", "shop", "store", "app", "dev", "staging", "test", "cdn", "api"]

    result = {
        "check": "Subdomain Takeover",
        "domain": domain,
        "checked": [],
        "vulnerable": [],
        "status": "ok",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    for sub in subdomains:
        fqdn = f"{sub}.{domain}"
        result["checked"].append(fqdn)

        # Check for CNAME
        cnames = _lookup_records(fqdn, "CNAME")
        if not cnames:
            continue

        cname_target = cnames[0].rstrip(".")

        # Check if CNAME points to known vulnerable service
        for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
            if service in cname_target.lower():
                # Try to fetch and check for fingerprint
                try:
                    resp = requests.get(f"http://{fqdn}", timeout=5, allow_redirects=True)
                    if fingerprint.lower() in resp.text.lower():
                        result["vulnerable"].append({
                            "subdomain": fqdn,
                            "cname": cname_target,
                            "service": service,
                        })
                except Exception:
                    # Check if CNAME target resolves
                    target_ips = _lookup_records(cname_target, "A")
                    if not target_ips:
                        result["vulnerable"].append({
                            "subdomain": fqdn,
                            "cname": cname_target,
                            "service": service,
                            "note": "CNAME target does not resolve",
                        })

    if result["vulnerable"]:
        result["status"] = "error"
        for vuln in result["vulnerable"]:
            note = f" ({vuln['note']})" if vuln.get("note") else ""
            result["issues"].append(
                f"POTENTIAL TAKEOVER: {vuln['subdomain']} → {vuln['cname']}{note}. "
                f"An attacker could claim this resource and serve malicious content."
            )
        result["recommendations"].append(
            "Remove dangling CNAME records or reclaim the external resources. "
            "Until fixed, attackers may be able to serve content on your subdomain."
        )
    else:
        result["warnings"].append(
            f"Scanned {len(result['checked'])} common subdomains. "
            f"No takeover vulnerabilities detected."
        )

    return result


# ------------------------------------------------------------
# MX Check
# ------------------------------------------------------------

# Common mail providers for identification
MAIL_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "barracudanetworks.com": "Barracuda",
    "messagelabs.com": "Symantec/Broadcom",
    "iphmx.com": "Cisco Email Security",
    "fireeyecloud.com": "FireEye/Trellix",
    "ppe-hosted.com": "Proofpoint Essentials",
    "secureserver.net": "GoDaddy",
    "emailsrvr.com": "Rackspace",
    "zoho.com": "Zoho Mail",
    "mail.protection.outlook.com": "Microsoft 365 (EOP)",
    "sophos.com": "Sophos",
}


def check_mx(domain: str) -> Dict[str, Any]:
    """
    Check MX records for a domain.
    Validates mail exchange configuration and identifies mail providers.
    """
    result = {
        "check": "MX",
        "domain": domain,
        "records": [],
        "parsed_records": [],
        "providers_detected": [],
        "status": "ok",
        "issues": [],
        "warnings": [],
        "recommendations": [],
    }

    mx_records = _lookup_records(domain, "MX")

    # --- No MX records ---
    if not mx_records:
        result["status"] = "error"
        result["issues"].append(
            f"NO MX RECORDS at {domain}. "
            f"This domain cannot receive email. "
            f"Any mail sent to @{domain} addresses will bounce."
        )
        result["recommendations"].append(
            "Add MX records pointing to your mail servers. Example:\n"
            "  Priority 10: mail.yourdomain.com\n"
            "  Priority 20: mail-backup.yourdomain.com (backup)\n\n"
            "Or use a hosted provider like Google Workspace or Microsoft 365."
        )
        return result

    result["records"] = mx_records

    # --- Parse MX records ---
    parsed = []
    providers = set()
    has_null_mx = False
    
    for mx in mx_records:
        parts = mx.strip().split()
        if len(parts) >= 2:
            try:
                priority = int(parts[0])
                hostname = parts[1].rstrip(".")
                
                # Check for Null MX (RFC 7505)
                if hostname == "" or hostname == ".":
                    has_null_mx = True
                    parsed.append({
                        "priority": priority,
                        "hostname": "(null)",
                        "type": "Null MX - domain does not accept mail"
                    })
                    continue
                
                # Try to resolve the MX hostname
                mx_ips = _lookup_records(hostname, "A")
                
                # Identify provider
                provider = None
                for provider_domain, provider_name in MAIL_PROVIDERS.items():
                    if provider_domain in hostname.lower():
                        provider = provider_name
                        providers.add(provider_name)
                        break
                
                parsed.append({
                    "priority": priority,
                    "hostname": hostname,
                    "resolves": len(mx_ips) > 0,
                    "ips": mx_ips[:3] if mx_ips else [],  # First 3 IPs
                    "provider": provider,
                })
                
            except (ValueError, IndexError):
                result["issues"].append(f"Malformed MX record: '{mx}'")
    
    result["parsed_records"] = sorted(parsed, key=lambda x: x.get("priority", 999))
    result["providers_detected"] = list(providers)

    # --- Check for Null MX ---
    if has_null_mx:
        result["status"] = "warning"
        result["warnings"].append(
            "NULL MX (RFC 7505) detected. "
            "This domain explicitly declares it does not accept email."
        )
        return result

    # --- Validate MX hostnames resolve ---
    unresolved = [p for p in parsed if not p.get("resolves", True) and p.get("hostname") != "(null)"]
    if unresolved:
        result["status"] = "error"
        for mx in unresolved:
            result["issues"].append(
                f"MX hostname '{mx['hostname']}' does not resolve to any IP address. "
                f"Mail delivery to this MX will fail."
            )
        result["recommendations"].append(
            "Ensure all MX hostnames have valid A or AAAA records."
        )

    # --- Check for single MX (no redundancy) ---
    valid_mx = [p for p in parsed if p.get("resolves", True)]
    if len(valid_mx) == 1:
        result["warnings"].append(
            "Only ONE MX record found. No backup mail server. "
            "If your mail server goes down, incoming mail will queue at senders (up to 5 days) then bounce."
        )
        result["recommendations"].append(
            "Consider adding a backup MX with lower priority (higher number) for redundancy."
        )
    elif len(valid_mx) >= 2:
        result["warnings"].append(
            f"{len(valid_mx)} MX records found — backup mail servers configured."
        )

    # --- Identify mail providers ---
    if providers:
        result["warnings"].append(
            f"Mail provider(s) detected: {', '.join(sorted(providers))}"
        )

    # --- Build record display ---
    if parsed:
        record_lines = ["MX Records (by priority):"]
        for mx in sorted(parsed, key=lambda x: x.get("priority", 999)):
            prov = f" [{mx['provider']}]" if mx.get("provider") else ""
            resolves = "✓" if mx.get("resolves", True) else "✗ NOT RESOLVING"
            record_lines.append(
                f"  {mx.get('priority', '?'):3} → {mx.get('hostname', '?')} {resolves}{prov}"
            )
        result["record"] = "\n".join(record_lines)

    return result


# ------------------------------------------------------------
# Main Audit Functions
# ------------------------------------------------------------

def build_priority_fixes(checks: Dict[str, Any], limit: int = 10) -> List[str]:
    """Build prioritized list of fixes from check results."""
    priority: List[str] = []

    # Errors first
    for check_name, check in checks.items():
        if check.get("status") == "error":
            recs = check.get("recommendations", []) or []
            if recs:
                priority.append(f"[{check_name.upper()}] {recs[0]}")

    # Warnings second
    for check_name, check in checks.items():
        if check.get("status") == "warning":
            recs = check.get("recommendations", []) or []
            if recs:
                priority.append(f"[{check_name.upper()}] {recs[0]}")

    return priority[:limit]


def audit_email_security(domain: str, dkim_selectors: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Run email security audit: DMARC, SPF, DKIM, MTA-STS, TLS-RPT, MX
    """
    domain = normalize_domain(domain)

    results = {
        "domain": domain,
        "audit_type": "email_security",
        "timestamp": datetime.now().isoformat(),
        "checks": {},
        "summary": {"ok": 0, "warning": 0, "error": 0},
        "priority_fixes": [],
    }

    checks = [
        ("dmarc", check_dmarc),
        ("spf", check_spf),
        ("dkim", lambda d: check_dkim(d, selectors=dkim_selectors)),
        ("mx", check_mx),
        ("mta_sts", check_mta_sts),
        ("tls_rpt", check_tls_rpt),
    ]

    for check_name, check_func in checks:
        try:
            check_result = check_func(domain)
        except Exception as e:
            check_result = {
                "check": check_name.upper(),
                "status": "error",
                "issues": [f"Check failed due to exception: {e}"],
                "warnings": [],
                "recommendations": [],
            }

        results["checks"][check_name] = check_result
        status = check_result.get("status", "unknown")

        if status in results["summary"]:
            results["summary"][status] += 1

    results["priority_fixes"] = build_priority_fixes(results["checks"])
    return results


def audit_dns_security(domain: str, dkim_selectors: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Run full DNS security audit: all email checks plus DNS-specific checks
    """
    domain = normalize_domain(domain)
    
    results = {
        "audit_type": "full_dns_security",
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "checks": {},
        "summary": {"ok": 0, "warning": 0, "error": 0},
        "priority_fixes": [],
    }

    checks = [
        # Email
        ("mx", check_mx),
        ("dmarc", check_dmarc),
        ("spf", check_spf),
        ("dkim", lambda d: check_dkim(d, selectors=dkim_selectors)),
        ("mta_sts", check_mta_sts),
        ("tls_rpt", check_tls_rpt),
        # DNS Security
        ("dnssec", check_dnssec),
        ("caa", check_caa),
        ("ns", check_ns),
        ("zone_transfer", check_zone_transfer),
        ("subdomain_takeover", check_subdomain_takeover),
    ]

    for name, check_func in checks:
        try:
            check_result = check_func(domain)
            results["checks"][name] = check_result
            status = check_result.get("status", "unknown")
            if status in results["summary"]:
                results["summary"][status] += 1
        except Exception as e:
            results["checks"][name] = {
                "check": name,
                "status": "error",
                "issues": [f"Check failed: {str(e)}"],
                "warnings": [],
                "recommendations": [],
            }
            results["summary"]["error"] += 1

    results["priority_fixes"] = build_priority_fixes(results["checks"])
    return results


def format_report(results: Dict[str, Any], output_format: str = "full") -> str:
    """
    Format audit results as readable text.
    output_format: 'full' or 'summary'
    """
    lines = []
    domain = results["domain"]
    audit_type = results.get("audit_type", "audit")

    lines.append("=" * 70)
    lines.append(f"  DNS SECURITY AUDIT: {domain}")
    lines.append(f"  Scope: {audit_type.replace('_', ' ').title()}")
    lines.append("=" * 70)
    lines.append("")

    # Summary
    summary = results["summary"]
    total = summary['ok'] + summary['warning'] + summary['error']
    lines.append(f"SUMMARY: {total} checks performed")
    lines.append(f"  ✅ {summary['ok']} Passed  |  ⚠️  {summary['warning']} Warnings  |  🔴 {summary['error']} Failed")
    lines.append("")

    if output_format == "summary":
        # Short format - just status per check
        lines.append("RESULTS:")
        lines.append("-" * 40)
        for name, check in results["checks"].items():
            status = check.get("status", "unknown")
            icon = {"ok": "✅", "warning": "⚠️ ", "error": "🔴"}.get(status, "❓")
            status_word = {"ok": "PASS", "warning": "WARN", "error": "FAIL"}.get(status, "???")
            lines.append(f"  {icon} {name.upper():15} {status_word}")

        if results["priority_fixes"]:
            lines.append("")
            lines.append("TOP FIXES:")
            for fix in results["priority_fixes"][:3]:
                first_line = fix.split("\n")[0]
                if len(first_line) > 70:
                    first_line = first_line[:67] + "..."
                lines.append(f"  → {first_line}")

    else:
        # Full verbose format
        for name, check in results["checks"].items():
            status = check.get("status", "unknown")
            icon = {"ok": "✅", "warning": "⚠️ ", "error": "🔴"}.get(status, "❓")
            status_word = {"ok": "PASSED", "warning": "WARNING", "error": "FAILED"}.get(status, "UNKNOWN")

            lines.append("=" * 70)
            lines.append(f"{icon} {check.get('check', name.upper())}: {status_word}")
            lines.append("=" * 70)

            # Show record location if present
            if check.get("record_location"):
                lines.append(f"  Location: {check['record_location']}")

            # Show record/data (handle multiline properly)
            record = check.get("record")
            if record:
                lines.append("")
                lines.append("  RECORD DATA:")
                record_str = str(record)
                for rec_line in record_str.split("\n"):
                    lines.append(f"    {rec_line}")

            # Show DNS lookup count for SPF
            if check.get("dns_lookups") is not None:
                lines.append("")
                lookups = check["dns_lookups"]
                limit = check.get("lookup_limit", 10)
                lines.append(f"  DNS Lookups: {lookups}/{limit} (RFC 7208 limit)")
                if check.get("includes_followed"):
                    inc_list = check['includes_followed'][:5]
                    lines.append(f"  Includes traced: {', '.join(inc_list)}")
                    if len(check.get("includes_followed", [])) > 5:
                        lines.append(f"    ... and {len(check['includes_followed']) - 5} more")

            # Show syntax errors if any
            syntax_errors = check.get("syntax_errors", [])
            if syntax_errors:
                lines.append("")
                lines.append("  SYNTAX ERRORS:")
                for err in syntax_errors:
                    lines.append(f"    ✗ {err}")

            # Show status messages (informational)
            warnings = check.get("warnings", [])
            if warnings:
                lines.append("")
                lines.append("  STATUS:")
                for warning in warnings:
                    warn_lines = warning.split("\n")
                    lines.append(f"    ℹ️  {warn_lines[0]}")
                    for extra in warn_lines[1:]:
                        lines.append(f"       {extra}")

            # Show issues (actual problems)
            issues = check.get("issues", [])
            if issues:
                lines.append("")
                lines.append("  ISSUES:")
                for issue in issues:
                    issue_lines = issue.split("\n")
                    lines.append(f"    🔴 {issue_lines[0]}")
                    for extra in issue_lines[1:]:
                        lines.append(f"       {extra}")

            # Show recommendations
            recommendations = check.get("recommendations", [])
            if recommendations:
                lines.append("")
                lines.append("  RECOMMENDATIONS:")
                for rec in recommendations:
                    rec_lines = rec.split("\n")
                    lines.append(f"    → {rec_lines[0]}")
                    for extra in rec_lines[1:]:
                        lines.append(f"      {extra}")

            lines.append("")

        # Priority fixes at the end
        if results["priority_fixes"]:
            lines.append("=" * 70)
            lines.append("  PRIORITY FIXES (address these first)")
            lines.append("=" * 70)
            for i, fix in enumerate(results["priority_fixes"], 1):
                fix_lines = fix.split("\n")
                lines.append(f"  {i}. {fix_lines[0]}")
                for extra in fix_lines[1:]:
                    lines.append(f"     {extra}")

    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------
# CLI Entry Point
# ------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dns_tools.py <domain> [email|dns] [full|summary]")
        sys.exit(1)

    target_domain = sys.argv[1]
    scope = sys.argv[2] if len(sys.argv) > 2 else "email"
    output = sys.argv[3] if len(sys.argv) > 3 else "full"

    if scope == "dns":
        audit_results = audit_dns_security(target_domain)
    else:
        audit_results = audit_email_security(target_domain)

    print(format_report(audit_results, output))