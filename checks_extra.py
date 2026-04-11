"""
Hardened MTA-STS / TLS-RPT / BIMI Validators
DNS Security Auditor
"""

import ipaddress
import re
import socket
import defusedxml.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


_BLOCKED_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),     # Carrier-Grade NAT
    ipaddress.ip_network('198.18.0.0/15'),      # Benchmark testing
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
    ipaddress.ip_network('::ffff:0:0/96'),      # IPv4-mapped IPv6
]


def _resolve_and_validate(hostname: str) -> str:
    """Resolve hostname to IP, reject private/internal addresses.
    Returns the validated IP string.
    Raises ValueError if the IP is blocked or resolution fails."""
    try:
        results = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not results:
            raise ValueError(f"DNS resolution failed for {hostname}")
        ip_str = results[0][4][0]
        ip = ipaddress.ip_address(ip_str)
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                raise ValueError(f"Resolved IP {ip_str} is in blocked range {network}")
        return ip_str
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {hostname}: {e}")


def _safe_fetch(url: str, timeout: float = 10.0, **kwargs) -> "requests.Response":
    """Fetch a URL with SSRF protection. Resolves hostname once,
    validates the IP, then connects directly to the pinned IP.
    Raises ValueError if the target is a private/internal address."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"No hostname in URL: {url}")

    ip = _resolve_and_validate(hostname)

    # Rewrite URL to connect to pinned IP, set Host header
    pinned_url = url.replace(f"://{hostname}", f"://{ip}", 1)
    headers = kwargs.pop("headers", {})
    headers["Host"] = hostname

    return requests.get(
        pinned_url,
        headers=headers,
        timeout=timeout,
        allow_redirects=False,
        verify=False,  # Can't verify cert when connecting to IP directly
        **kwargs,
    )

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def _get_resolver(timeout: float = 5.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def _lookup_ttl(name: str, rdtype: str = "TXT") -> Optional[int]:
    """Look up the TTL for a DNS record. Returns None on any failure."""
    if not DNS_AVAILABLE:
        return None
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, rdtype)
        return answers.rrset.ttl if answers.rrset else None
    except dns.exception.DNSException:
        return None


def _lookup_txt(name: str) -> List[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            parts = []
            for s in rdata.strings:
                parts.append(s.decode("utf-8") if isinstance(s, bytes) else str(s))
            records.append("".join(parts))
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def _lookup_records(name: str, rdtype: str) -> List[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, rdtype)
        return [str(rdata).rstrip(".") for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def _make_issue(severity: str, issue: str, plain_english: str,
                impact: str = "", fix: str = "") -> Dict[str, str]:
    return {
        "severity": severity,
        "issue": issue,
        "plain_english": plain_english,
        "impact": impact,
        "fix": fix,
    }


# ============================================================
# MTA-STS VALIDATOR (RFC 8461)
# ============================================================

def _validate_mta_sts_txt(record: str) -> Tuple[Dict[str, str], List[Dict]]:
    issues = []
    tags = {}
    parts = [p.strip() for p in record.split(";") if p.strip()]

    for part in parts:
        if "=" not in part:
            issues.append(_make_issue(
                "warning", f"Malformed MTA-STS tag: '{part}'",
                "MTA-STS tags must be in key=value format.",
                "Tag will be ignored.",
                f"Fix syntax: ensure '{part}' uses key=value format.",
            ))
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key in tags:
            issues.append(_make_issue(
                "warning", f"Duplicate MTA-STS tag: '{key}'",
                f"The tag '{key}' appears more than once.",
                "Behavior is undefined for duplicate tags.",
                f"Remove the duplicate '{key}' tag.",
            ))
            continue
        tags[key] = value

    if "v" not in tags:
        issues.append(_make_issue(
            "error", "Missing required 'v' tag in MTA-STS TXT record",
            "The MTA-STS TXT record must contain 'v=STSv1'.",
            "Record will not be recognized as MTA-STS.",
            "Add 'v=STSv1' to the TXT record.",
        ))
    elif tags["v"].upper() != "STSV1":
        issues.append(_make_issue(
            "error", f"Invalid MTA-STS version: v={tags['v']}",
            f"MTA-STS version must be 'STSv1'. Found '{tags['v']}'.",
            "Record will not be processed.",
            "Change to 'v=STSv1'.",
        ))

    if "id" not in tags:
        issues.append(_make_issue(
            "error", "Missing required 'id' tag in MTA-STS TXT record",
            "The 'id' tag is required and must change whenever the policy is updated.",
            "Senders will not know when the policy changes.",
            "Add an 'id' value, e.g., id=20240101.",
        ))
    elif not tags["id"]:
        issues.append(_make_issue(
            "error", "Empty 'id' value in MTA-STS TXT record",
            "The id must be a non-empty string.",
            "Senders cannot track policy changes.",
            "Set id to a unique value like a timestamp: id=20240101T120000",
        ))

    valid_tags = {"v", "id"}
    for key in tags:
        if key not in valid_tags:
            issues.append(_make_issue(
                "warning", f"Unknown MTA-STS TXT tag: '{key}'",
                "Valid MTA-STS TXT tags are: v, id.",
                "This tag will be ignored.",
                f"Remove '{key}' from the record.",
            ))

    return tags, issues


def _validate_mta_sts_policy(policy_text: str, domain: str) -> Tuple[Dict[str, Any], List[Dict]]:
    issues = []
    policy = {
        "version": None, "mode": None,
        "mx_patterns": [], "max_age": None, "raw": policy_text,
    }
    seen_keys = set()
    lines = policy_text.strip().splitlines()

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            issues.append(_make_issue(
                "warning", f"Malformed policy line {line_num}: '{line}'",
                "Policy lines must be in 'key: value' format.",
                "This line will be ignored.",
                f"Fix line {line_num} to use 'key: value' format.",
            ))
            continue

        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "version":
            policy["version"] = value
            if value != "STSv1":
                issues.append(_make_issue(
                    "error", f"Invalid policy version: '{value}'",
                    "Policy file version must be 'STSv1'.",
                    "Policy will not be processed by senders.",
                    "Change to 'version: STSv1'.",
                ))
        elif key == "mode":
            policy["mode"] = value.lower()
            valid_modes = {"enforce", "testing", "none"}
            if value.lower() not in valid_modes:
                issues.append(_make_issue(
                    "error", f"Invalid MTA-STS mode: '{value}'",
                    "Valid modes are: enforce, testing, none.",
                    "Policy behavior is undefined.",
                    "Set mode to 'enforce', 'testing', or 'none'.",
                ))
            elif value.lower() == "none":
                issues.append(_make_issue(
                    "info", "MTA-STS mode is 'none' (disabled)",
                    "Mode 'none' tells senders the domain is not using MTA-STS.",
                    "No TLS enforcement on inbound mail.",
                    "Set mode to 'testing' to start monitoring, then 'enforce'.",
                ))
            elif value.lower() == "testing":
                issues.append(_make_issue(
                    "info", "MTA-STS mode is 'testing'",
                    "Senders will attempt TLS but not reject on failure.",
                    "TLS is preferred but not required.",
                    "Move to mode=enforce once TLS works reliably.",
                ))
        elif key == "mx":
            policy["mx_patterns"].append(value)
        elif key == "max_age":
            try:
                max_age_val = int(value)
                policy["max_age"] = max_age_val
                if max_age_val < 86400:
                    issues.append(_make_issue(
                        "warning",
                        f"max_age is very short: {max_age_val} seconds",
                        "A very short max_age means frequent re-fetching.",
                        "Brief window of protection.",
                        "Set max_age to at least 86400 (1 day). Recommended: 604800 (1 week).",
                    ))
                elif max_age_val > 31557600:
                    issues.append(_make_issue(
                        "info",
                        f"max_age is very long: {max_age_val} seconds",
                        "Senders cache the policy for a long time.",
                        "Policy changes take a long time to propagate.",
                        "Consider max_age of 604800 (1 week) to 2592000 (30 days).",
                    ))
            except ValueError:
                policy["max_age"] = -1
                issues.append(_make_issue(
                    "error", f"max_age is not a number: '{value}'",
                    "max_age must be an integer (seconds).",
                    "Policy may not be processed correctly.",
                    "Set max_age to a number, e.g., max_age: 604800",
                ))
        else:
            issues.append(_make_issue(
                "warning", f"Unknown policy field: '{key}'",
                "Valid fields are: version, mode, mx, max_age.",
                "This field will be ignored.",
                f"Remove '{key}' from the policy file.",
            ))
        if key != "mx" and key in seen_keys:
            issues.append(_make_issue(
                "error", f"Duplicate policy field: '{key}'",
                "RFC 8461 requires each non-mx field to appear at most once.",
                "The second value silently overwrites the first.",
                f"Remove the duplicate '{key}' line.",
            ))
        seen_keys.add(key)

    if policy["version"] is None:
        issues.append(_make_issue("error", "Missing 'version' in policy file",
            "The policy file must contain 'version: STSv1'.", "", "Add 'version: STSv1'."))
    if policy["mode"] is None:
        issues.append(_make_issue("error", "Missing 'mode' in policy file",
            "The policy file must specify a mode.", "", "Add 'mode: enforce'."))
    if not policy["mx_patterns"]:
        issues.append(_make_issue("error", "No 'mx' entries in policy file",
            "The policy file must list at least one MX hostname pattern.", "",
            "Add mx lines, e.g., 'mx: mail.yourdomain.com'."))
    if policy["max_age"] is None:
        issues.append(_make_issue("error", "Missing 'max_age' in policy file",
            "max_age is required.", "", "Add 'max_age: 604800'."))

    if policy["mx_patterns"]:
        actual_mx = _lookup_records(domain, "MX")
        actual_mx_hosts = []
        for mx_rec in actual_mx:
            parts = mx_rec.split(None, 1)
            if len(parts) == 2:
                actual_mx_hosts.append(parts[1].rstrip(".").lower())
        unmatched_patterns = []
        for pattern in policy["mx_patterns"]:
            pattern_lower = pattern.lower().rstrip(".")
            matched = False
            for mx_host in actual_mx_hosts:
                if pattern_lower.startswith("*."):
                    suffix = pattern_lower[1:]  # e.g. ".example.com"
                    if (
                        mx_host.endswith(suffix) and "." not in mx_host[:-len(suffix)]
                        and len(mx_host) > len(suffix.lstrip("."))
                    ):
                        matched = True
                        break
                else:
                    if mx_host == pattern_lower:
                        matched = True
                        break
            if not matched:
                unmatched_patterns.append(pattern)
        if unmatched_patterns and actual_mx_hosts:
            patterns_str = ", ".join(f"'{p}'" for p in unmatched_patterns)
            issues.append(_make_issue(
                "warning",
                f"MTA-STS mx pattern{'s' if len(unmatched_patterns) > 1 else ''} {patterns_str} {'do' if len(unmatched_patterns) > 1 else 'does'}n't match actual MX records",
                f"Actual MX records are: {', '.join(actual_mx_hosts)}.",
                "Potential mail delivery failure.",
                "Update the mx lines to match your actual MX hostnames.",
            ))

    return policy, issues


def check_mta_sts(domain: str) -> Dict[str, Any]:
    result = {
        "check": "MTA-STS", "domain": domain,
        "txt_record": None, "txt_tags": {},
        "policy_url": None, "policy": None,
        "policy_mode": None, "policy_mx": [], "policy_max_age": None,
        "status": "ok", "issues": [], "warnings": [], "recommendations": [],
    }

    if not DNS_AVAILABLE:
        result["status"] = "error"
        result["issues"].append(_make_issue("error", "DNS library not available",
            "Cannot perform DNS lookups.", "", "pip install dnspython"))
        return result

    txt_name = f"_mta-sts.{domain}"
    all_txt = _lookup_txt(txt_name)
    sts_records = [r for r in all_txt if r.strip().lower().startswith("v=stsv1")]

    if not sts_records:
        result["status"] = "warning"
        result["issues"].append(_make_issue(
            "warning", "No MTA-STS TXT record found",
            f"No TXT record found at '_mta-sts.{domain}'.",
            "Email may be transmitted without encryption.",
            f"Add a TXT record at '_mta-sts.{domain}' with value: v=STSv1; id=20240101",
        ))
        return result

    if len(sts_records) > 1:
        result["issues"].append(_make_issue(
            "error", f"Multiple MTA-STS TXT records found ({len(sts_records)})",
            "There should be exactly one MTA-STS TXT record.", "",
            "Remove duplicate records.",
        ))

    sts_record = sts_records[0]
    result["txt_record"] = sts_record
    txt_tags, txt_issues = _validate_mta_sts_txt(sts_record)
    result["txt_tags"] = txt_tags
    result["issues"].extend(txt_issues)

    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    result["policy_url"] = policy_url

    if REQUESTS_AVAILABLE:
        try:
            try:
                resp = _safe_fetch(policy_url, timeout=10)
            except ValueError as e:
                result["issues"].append(_make_issue(
                    "warning", "MTA-STS host resolves to a private/reserved IP",
                    f"mta-sts.{domain}: {e}",
                    "Cannot verify MTA-STS policy.",
                    f"Ensure mta-sts.{domain} points to a public IP address.",
                ))
                result["status"] = "warning"
                return result
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if "text/plain" not in content_type and content_type:
                    result["issues"].append(_make_issue(
                        "warning",
                        f"Policy Content-Type is '{content_type}' (expected text/plain)",
                        "RFC 8461 specifies text/plain.", "",
                        "Serve the file as text/plain.",
                    ))
                policy_data, policy_issues = _validate_mta_sts_policy(resp.text, domain)
                result["policy"] = policy_data
                result["policy_mode"] = policy_data.get("mode")
                result["policy_mx"] = policy_data.get("mx_patterns", [])
                result["policy_max_age"] = policy_data.get("max_age")
                result["issues"].extend(policy_issues)
            elif resp.status_code == 404:
                result["issues"].append(_make_issue(
                    "error", "MTA-STS policy file not found (HTTP 404)",
                    "DNS record exists but policy file is missing.",
                    "MTA-STS will not function.",
                    f"Create the policy file at {policy_url}",
                ))
            else:
                result["issues"].append(_make_issue(
                    "error", f"Policy file returned HTTP {resp.status_code}",
                    "The policy file returned an error.",
                    "MTA-STS will not function.",
                    f"Ensure {policy_url} returns HTTP 200.",
                ))
        except requests.exceptions.SSLError:
            result["issues"].append(_make_issue(
                "error", "SSL/TLS error fetching MTA-STS policy",
                f"HTTPS connection to mta-sts.{domain} failed.",
                "MTA-STS will not function.",
                f"Install a valid TLS certificate for mta-sts.{domain}.",
            ))
        except requests.exceptions.ConnectionError:
            result["issues"].append(_make_issue(
                "error", f"Cannot connect to mta-sts.{domain}",
                f"The host mta-sts.{domain} is not reachable.",
                "MTA-STS will not function.",
                f"Set up a web server at mta-sts.{domain} with HTTPS.",
            ))
        except requests.exceptions.Timeout:
            result["issues"].append(_make_issue(
                "warning", "Timeout fetching MTA-STS policy",
                "The policy file server took too long.", "",
                "Ensure the web server responds quickly.",
            ))
        except requests.exceptions.RequestException as e:
            result["issues"].append(_make_issue(
                "warning", f"Error fetching policy: {str(e)[:200]}",
                "Could not retrieve the MTA-STS policy file.", "",
                f"Verify {policy_url} is accessible.",
            ))

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    for issue in result["issues"]:
        fix = issue.get("fix")
        if fix and fix not in result["recommendations"]:
            result["recommendations"].append(fix)

    result["ttl"] = _lookup_ttl(f"_mta-sts.{domain}")
    return result


# ============================================================
# TLS-RPT VALIDATOR (RFC 8460)
# ============================================================

_TLSRPT_VALID_TAGS = {"v", "rua"}


def _validate_tls_rpt_record(record: str) -> Tuple[Dict[str, str], List[Dict]]:
    issues = []
    tags = {}
    parts = [p.strip() for p in record.split(";") if p.strip()]

    for part in parts:
        if "=" not in part:
            issues.append(_make_issue("warning", f"Malformed TLS-RPT tag: '{part}'",
                "Tags must be in key=value format.", "", f"Fix the syntax of '{part}'."))
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key in tags:
            issues.append(_make_issue("warning", f"Duplicate TLS-RPT tag: '{key}'",
                f"'{key}' appears more than once.", "", f"Remove the duplicate."))
            continue
        if key not in _TLSRPT_VALID_TAGS:
            issues.append(_make_issue("warning", f"Unknown TLS-RPT tag: '{key}'",
                "Valid tags are: v, rua.", "", f"Remove '{key}'."))
        tags[key] = value

    if "v" not in tags:
        issues.append(_make_issue("error", "Missing required 'v' tag",
            "TLS-RPT record must start with 'v=TLSRPTv1'.", "", "Add 'v=TLSRPTv1'."))
    elif tags["v"].upper() != "TLSRPTV1":
        issues.append(_make_issue("error", f"Invalid TLS-RPT version: v={tags['v']}",
            "Version must be 'TLSRPTv1'.", "", "Change to 'v=TLSRPTv1'."))

    if "rua" not in tags:
        issues.append(_make_issue("error", "Missing required 'rua' tag",
            "TLS-RPT must specify where to send reports.", "",
            "Add rua=mailto:tls-reports@yourdomain.com"))
    else:
        uris = [u.strip() for u in tags["rua"].split(",") if u.strip()]
        for uri in uris:
            uri_lower = uri.lower()
            if uri_lower.startswith("mailto:"):
                email = uri[7:]
                if "@" not in email:
                    issues.append(_make_issue("error", f"Invalid email in rua: '{uri}'",
                        "Must contain a valid email.", "", "Fix the email format."))
            elif uri_lower.startswith("https:"):
                parsed = urlparse(uri)
                if not parsed.netloc:
                    issues.append(_make_issue("error", f"Invalid HTTPS URI: '{uri}'",
                        "Must be a valid URL.", "", "Fix the URL format."))
            else:
                issues.append(_make_issue("error", f"Invalid rua URI scheme: '{uri}'",
                    "Must use mailto: or https:.", "",
                    "Use mailto: or https:// format."))

    return tags, issues


def check_tls_rpt(domain: str) -> Dict[str, Any]:
    result = {
        "check": "TLS-RPT", "domain": domain,
        "record": None, "records_found": 0, "tags": {},
        "report_destinations": [],
        "status": "ok", "issues": [], "warnings": [], "recommendations": [],
    }

    if not DNS_AVAILABLE:
        result["status"] = "error"
        result["issues"].append(_make_issue("error", "DNS library not available",
            "Cannot perform DNS lookups.", "", "pip install dnspython"))
        return result

    txt_name = f"_smtp._tls.{domain}"
    all_txt = _lookup_txt(txt_name)
    rpt_records = [r for r in all_txt if r.strip().lower().startswith("v=tlsrptv1")]

    if not rpt_records:
        result["status"] = "warning"
        result["issues"].append(_make_issue(
            "warning", "No TLS-RPT record found",
            f"No TXT record at '_smtp._tls.{domain}'.",
            "No visibility into encryption issues.",
            f"Add TXT at _smtp._tls.{domain}: v=TLSRPTv1; rua=mailto:tls-reports@{domain}",
        ))
        return result

    result["records_found"] = len(rpt_records)
    if len(rpt_records) > 1:
        result["issues"].append(_make_issue("error",
            f"Multiple TLS-RPT records ({len(rpt_records)})",
            "Should be exactly one.", "", "Remove duplicates."))

    record = rpt_records[0]
    result["record"] = record
    tags, tag_issues = _validate_tls_rpt_record(record)
    result["tags"] = tags
    result["issues"].extend(tag_issues)

    if "rua" in tags:
        result["report_destinations"] = [u.strip() for u in tags["rua"].split(",") if u.strip()]

    # MTA-STS synergy check
    mta_sts_txt = _lookup_txt(f"_mta-sts.{domain}")
    has_mta_sts = any(r.strip().lower().startswith("v=stsv1") for r in mta_sts_txt)
    if not has_mta_sts:
        result["issues"].append(_make_issue(
            "info", "TLS-RPT configured but MTA-STS is not",
            "TLS-RPT works best alongside MTA-STS.",
            "Limited value without MTA-STS or DANE.",
            "Consider implementing MTA-STS alongside TLS-RPT.",
        ))

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    for issue in result["issues"]:
        fix = issue.get("fix")
        if fix and fix not in result["recommendations"]:
            result["recommendations"].append(fix)

    result["ttl"] = _lookup_ttl(f"_smtp._tls.{domain}")
    return result


# ============================================================
# BIMI VALIDATOR
# ============================================================

def _validate_bimi_record(record: str) -> Tuple[Dict[str, str], List[Dict]]:
    issues = []
    tags = {}
    parts = [p.strip() for p in record.split(";") if p.strip()]

    for part in parts:
        if "=" not in part:
            issues.append(_make_issue("warning", f"Malformed BIMI tag: '{part}'",
                "BIMI tags must be in key=value format.", "", f"Fix '{part}'."))
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key in tags:
            issues.append(_make_issue("warning", f"Duplicate BIMI tag: '{key}'",
                f"'{key}' appears more than once.", "", f"Remove duplicate."))
            continue
        tags[key] = value

    valid_tags = {"v", "l", "a"}
    for key in tags:
        if key not in valid_tags:
            issues.append(_make_issue("warning", f"Unknown BIMI tag: '{key}'",
                "Valid BIMI tags are: v, l, a.", "", f"Remove '{key}'."))

    if "v" not in tags:
        issues.append(_make_issue("error", "Missing 'v' tag",
            "BIMI record must have 'v=BIMI1'.", "", "Add 'v=BIMI1'."))
    elif tags["v"].upper() != "BIMI1":
        issues.append(_make_issue("error", f"Invalid version: v={tags['v']}",
            "Must be 'BIMI1'.", "", "Change to 'v=BIMI1'."))

    if "l" not in tags:
        issues.append(_make_issue("warning", "Missing 'l' (logo) tag",
            "The l= tag specifies your SVG logo URL.", "",
            "Add l=https://yourdomain.com/logo.svg"))
    elif not tags["l"]:
        issues.append(_make_issue("info", "Empty 'l' (logo) tag",
            "No logo at this selector.", "", ""))
    else:
        logo_url = tags["l"]
        parsed = urlparse(logo_url)
        if parsed.scheme.lower() != "https":
            issues.append(_make_issue("error", "Logo URL is not HTTPS",
                "Must use HTTPS.", "", "Change to HTTPS."))
        if not logo_url.lower().endswith(".svg"):
            issues.append(_make_issue("warning", "Logo URL does not end in .svg",
                "BIMI logos must be SVG Tiny PS format.", "", "Use an SVG file with baseProfile='tiny-ps'."))

    if "a" in tags and tags["a"]:
        vmc_url = tags["a"]
        parsed = urlparse(vmc_url)
        if parsed.scheme.lower() != "https":
            issues.append(_make_issue("error", "VMC URL is not HTTPS",
                "Must use HTTPS.", "", "Change to HTTPS."))
    elif "a" not in tags:
        issues.append(_make_issue("info", "No VMC tag",
            "Gmail requires a VMC for BIMI logos.", "",
            "Obtain a VMC from DigiCert or Entrust."))

    return tags, issues


def check_bimi(domain: str, dmarc_enforcing_override: bool = None) -> Dict[str, Any]:
    result = {
        "check": "BIMI", "domain": domain,
        "record": None, "records_found": 0, "tags": {},
        "logo_url": None, "vmc_url": None, "selector": "default",
        "status": "ok", "issues": [], "warnings": [], "recommendations": [],
    }

    if not DNS_AVAILABLE:
        result["status"] = "error"
        result["issues"].append(_make_issue("error", "DNS library not available",
            "Cannot perform DNS lookups.", "", "pip install dnspython"))
        return result

    bimi_name = f"default._bimi.{domain}"
    all_txt = _lookup_txt(bimi_name)
    bimi_records = [r for r in all_txt if r.strip().lower().startswith("v=bimi1")]

    if not bimi_records:
        result["status"] = "info"
        result["records_found"] = 0
        result["issues"].append(_make_issue(
            "info", "No BIMI record found",
            f"No BIMI TXT record at 'default._bimi.{domain}'.",
            "No brand logo in recipients' inboxes.",
            f"Add TXT at 'default._bimi.{domain}': v=BIMI1; l=https://yourdomain.com/logo.svg;",
        ))
        return result

    result["records_found"] = len(bimi_records)
    if len(bimi_records) > 1:
        result["issues"].append(_make_issue("error",
            f"Multiple BIMI records ({len(bimi_records)})",
            "Should be one per selector.", "", "Remove duplicates."))

    record = bimi_records[0]
    result["record"] = record
    tags, tag_issues = _validate_bimi_record(record)
    result["tags"] = tags
    result["issues"].extend(tag_issues)
    result["logo_url"] = tags.get("l") or None
    result["vmc_url"] = tags.get("a") or None

    # DMARC prerequisite check
    # Use override from audit orchestrator (accounts for inherited policies)
    if dmarc_enforcing_override is not None:
        dmarc_found = True
        dmarc_enforcing = dmarc_enforcing_override
    else:
        dmarc_records = _lookup_txt(f"_dmarc.{domain}")
        dmarc_found = False
        dmarc_enforcing = False
        for rec in dmarc_records:
            if rec.strip().lower().startswith("v=dmarc1"):
                dmarc_found = True
                rec_lower = rec.lower()
                if "p=quarantine" in rec_lower or "p=reject" in rec_lower:
                    dmarc_enforcing = True
                break

    if not dmarc_found:
        result["issues"].append(_make_issue(
            "error", "BIMI requires DMARC, but no DMARC record found",
            "Email clients require DMARC enforcement before displaying BIMI logos.",
            "BIMI logos will not be displayed.",
            "Implement DMARC first, then set up BIMI.",
        ))
    elif not dmarc_enforcing:
        result["issues"].append(_make_issue(
            "warning", "DMARC not at enforcement (BIMI requires p=quarantine or p=reject)",
            "Your DMARC policy is likely 'none' (monitoring only).",
            "Most clients won't display BIMI logos.",
            "Move DMARC to p=quarantine or p=reject.",
        ))

    # Logo accessibility and SVG validation
    result["svg_validated"] = None
    result["svg_profile"] = None

    if REQUESTS_AVAILABLE and result["logo_url"]:
        try:
            try:
                resp = _safe_fetch(
                    result["logo_url"], timeout=10,
                    stream=True,
                    headers={"Accept": "image/svg+xml, */*"},
                )
            except ValueError as e:
                result["issues"].append(_make_issue(
                    "warning", "BIMI logo URL resolves to a private/reserved IP",
                    f"The logo URL points to a non-public address: {e}", "",
                    "Ensure the logo URL points to a public server.",
                ))
                resp = None

            if resp is not None:
                if resp.status_code != 200:
                    result["issues"].append(_make_issue(
                        "warning", f"Logo URL returned HTTP {resp.status_code}",
                        "Logo is not accessible.", "",
                        "Ensure the logo URL returns HTTP 200.",
                    ))
                else:
                    ct = resp.headers.get("Content-Type", "")
                    if "svg" not in ct.lower() and "xml" not in ct.lower():
                        result["issues"].append(_make_issue(
                            "warning", f"Logo Content-Type is '{ct}' (expected image/svg+xml)",
                            "Should be served as image/svg+xml.", "",
                            "Configure server to serve .svg as image/svg+xml.",
                        ))

                    # Read up to 1MB for SVG validation
                    svg_bytes = b""
                    for chunk in resp.iter_content(chunk_size=8192):
                        svg_bytes += chunk
                        if len(svg_bytes) > 1_048_576:
                            result["issues"].append(_make_issue(
                                "warning", "BIMI logo exceeds 1MB",
                                "The SVG file is larger than 1MB, which may cause delivery issues.",
                                "Large logos slow down email rendering.",
                                "Optimize the SVG to reduce file size below 1MB.",
                            ))
                            break
                    resp.close()

                    # Parse and validate SVG
                    if svg_bytes:
                        try:
                            svg_text = svg_bytes.decode("utf-8", errors="replace")
                            root = ET.fromstring(svg_text)
                            svg_ns = "http://www.w3.org/2000/svg"
                            tag_local = root.tag.split("}")[-1] if "}" in root.tag else root.tag

                            if tag_local.lower() != "svg":
                                result["issues"].append(_make_issue(
                                    "error", "BIMI logo is not a valid SVG (root element is not <svg>)",
                                    "The file does not appear to be an SVG image.",
                                    "BIMI logos must be SVG format.",
                                    "Replace with a valid SVG file.",
                                ))
                                result["svg_validated"] = False
                            else:
                                result["svg_validated"] = True

                                # Check baseProfile
                                base_profile = root.get("baseProfile", "").lower()
                                result["svg_profile"] = base_profile or None
                                if base_profile == "tiny-ps":
                                    result["issues"].append(_make_issue(
                                        "good", f"SVG baseProfile is '{root.get('baseProfile')}'",
                                        "The SVG declares the correct profile for BIMI.",
                                        "", "",
                                    ))
                                else:
                                    result["issues"].append(_make_issue(
                                        "warning",
                                        f"SVG baseProfile is '{root.get('baseProfile') or 'missing'}' (expected 'tiny-ps')",
                                        "Gmail requires SVG Tiny PS profile. Without the correct baseProfile, "
                                        "the logo may not display in email clients.",
                                        "Logo may be rejected by Gmail and other strict BIMI implementations.",
                                        "Set baseProfile=\"tiny-ps\" on the root <svg> element.",
                                    ))

                                # Check viewBox
                                if not root.get("viewBox"):
                                    result["issues"].append(_make_issue(
                                        "warning", "SVG missing viewBox attribute",
                                        "The viewBox attribute is needed for proper scaling.",
                                        "Logo may not render correctly at different sizes.",
                                        "Add a viewBox attribute to the root <svg> element.",
                                    ))

                                # Gmail/Google Workspace compatibility: fixed pixel dimensions
                                raw_w = root.get("width")
                                raw_h = root.get("height")
                                relative_units = ("%", "em", "rem", "vw", "vh")

                                def _is_relative(val):
                                    if not val:
                                        return True
                                    v = val.strip().lower()
                                    return any(u in v for u in relative_units)

                                if _is_relative(raw_w) or _is_relative(raw_h):
                                    result["issues"].append(_make_issue(
                                        "warning",
                                        "SVG uses relative or missing dimensions (Gmail compatibility)",
                                        f"SVG has width='{raw_w or 'missing'}' height='{raw_h or 'missing'}'. "
                                        "Google and Gmail require fixed pixel values (e.g., width='96' height='96'). "
                                        "Logo may not display even though the SVG is technically valid.",
                                        "Logo may silently fail to display in Gmail.",
                                        "Set fixed pixel dimensions on the root <svg> element, e.g., width=\"96\" height=\"96\".",
                                    ))

                                # Gmail/Google Workspace compatibility: minimum 96x96 pixels
                                def _parse_px(val):
                                    if not val:
                                        return None
                                    v = val.strip().lower().replace("px", "")
                                    if any(u in v for u in relative_units):
                                        return None
                                    try:
                                        return float(v)
                                    except ValueError:
                                        return None

                                explicit_w = _parse_px(raw_w)
                                explicit_h = _parse_px(raw_h)

                                viewbox_w = None
                                viewbox_h = None
                                vb = root.get("viewBox")
                                if vb:
                                    try:
                                        parts = vb.replace(",", " ").split()
                                        if len(parts) == 4:
                                            viewbox_w = float(parts[2])
                                            viewbox_h = float(parts[3])
                                    except ValueError:
                                        pass

                                check_w = explicit_w if explicit_w is not None else viewbox_w
                                check_h = explicit_h if explicit_h is not None else viewbox_h
                                from_viewbox_only = (
                                    explicit_w is None and explicit_h is None
                                    and viewbox_w is not None and viewbox_h is not None
                                )

                                if check_w is not None and check_h is not None:
                                    if check_w < 96 or check_h < 96:
                                        size_desc = f"{check_w:g}x{check_h:g}"
                                        source_note = " (from viewBox)" if from_viewbox_only else ""
                                        result["issues"].append(_make_issue(
                                            "warning",
                                            "SVG dimensions below Google's 96x96 minimum (Gmail compatibility)",
                                            f"SVG dimensions {size_desc}{source_note} are below Google's minimum "
                                            "96x96 pixel requirement. Logo may not display in Gmail even though "
                                            "the SVG is technically valid.",
                                            "Logo may silently fail to display in Gmail.",
                                            "Resize the SVG so both width and height are at least 96 pixels.",
                                        ))

                                # Check for <script> elements (security risk)
                                script_tags = root.iter(f"{{{svg_ns}}}script")
                                script_tags_no_ns = root.iter("script")
                                has_script = False
                                for _ in script_tags:
                                    has_script = True
                                    break
                                if not has_script:
                                    for _ in script_tags_no_ns:
                                        has_script = True
                                        break
                                if has_script:
                                    result["issues"].append(_make_issue(
                                        "error", "SVG contains <script> elements",
                                        "BIMI SVGs must not contain scripts. Email clients will reject this.",
                                        "Logo will be rejected by all BIMI implementations.",
                                        "Remove all <script> elements from the SVG.",
                                    ))
                                    result["svg_validated"] = False

                                # Check for external references
                                has_external_ref = False
                                for elem in root.iter():
                                    for attr in ("href", "{http://www.w3.org/1999/xlink}href"):
                                        val = elem.get(attr, "")
                                        if val and (val.startswith("http://") or val.startswith("https://")):
                                            has_external_ref = True
                                            break
                                    if has_external_ref:
                                        break
                                if has_external_ref:
                                    result["issues"].append(_make_issue(
                                        "warning", "SVG contains external href references",
                                        "External references in BIMI SVGs may cause the logo to be rejected.",
                                        "Email clients may block external resource loading.",
                                        "Embed all resources directly in the SVG (inline images, fonts, etc.).",
                                    ))

                        except ET.ParseError:
                            result["issues"].append(_make_issue(
                                "warning", "BIMI logo is not valid XML",
                                "The SVG file could not be parsed as XML.",
                                "Logo will not display in email clients.",
                                "Fix XML syntax errors in the SVG file.",
                            ))
                            result["svg_validated"] = False
        except (requests.exceptions.RequestException, OSError):
            result["issues"].append(_make_issue(
                "info", "Could not verify BIMI logo URL",
                "Logo URL could not be reached.", "",
                "Verify the logo URL is publicly accessible.",
            ))

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"
    elif any(s == "info" for s in severities) and result["records_found"] > 0:
        result["status"] = "ok"

    for issue in result["issues"]:
        fix = issue.get("fix")
        if fix and fix not in result["recommendations"]:
            result["recommendations"].append(fix)

    result["ttl"] = _lookup_ttl(f"default._bimi.{domain}")
    return result
