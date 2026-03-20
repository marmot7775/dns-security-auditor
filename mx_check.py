"""
MX Analysis Module - DNS Security Auditor
Comprehensive MX record checking with provider detection,
priority analysis, STARTTLS support, reverse DNS, and RFC compliance.

Usage:
    from mx_check import check_mx
    result = check_mx("example.com")
    result = check_mx("example.com", deep_scan=True)
"""

import re
import socket
import ssl
import smtplib
import ipaddress
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ============================================================
# MX Provider Fingerprints
# ============================================================

MX_PROVIDERS = [
    (r"\.mail\.protection\.outlook\.com$", "Microsoft 365"),
    (r"\.olc\.protection\.outlook\.com$", "Microsoft 365 (GCC)"),
    (r"\.google\.com$", "Google Workspace"),
    (r"\.googlemail\.com$", "Google Workspace"),
    (r"aspmx\.l\.google\.com$", "Google Workspace"),
    (r"\.pphosted\.com$", "Proofpoint"),
    (r"\.ppe-hosted\.com$", "Proofpoint Essentials"),
    (r"\.mimecast\.com$", "Mimecast"),
    (r"\.mimecast-offshore\.com$", "Mimecast"),
    (r"\.barracudanetworks\.com$", "Barracuda"),
    (r"\.iphmx\.com$", "Cisco Email Security"),
    (r"\.sophos\.com$", "Sophos"),
    (r"\.reflexion\.net$", "Sophos (Reflexion)"),
    (r"\.mailcontrol\.com$", "Forcepoint"),
    (r"\.messagelabs\.com$", "Symantec/Broadcom"),
    (r"\.tmes\.trendmicro\.com$", "Trend Micro"),
    (r"\.zoho\.com$", "Zoho Mail"),
    (r"\.zohomail\.com$", "Zoho Mail"),
    (r"\.fastmail\.com$", "Fastmail"),
    (r"\.messagingengine\.com$", "Fastmail"),
    (r"\.yahoodns\.net$", "Yahoo Mail"),
    (r"\.protonmail\.ch$", "ProtonMail"),
    (r"\.proton\.me$", "Proton Mail"),
    (r"\.emailsrvr\.com$", "Rackspace"),
    (r"\.amazonaws\.com$", "Amazon SES"),
    (r"\.awsapps\.com$", "Amazon WorkMail"),
    (r"\.secureserver\.net$", "GoDaddy"),
    (r"\.privateemail\.com$", "Namecheap"),
    (r"\.hostinger\.", "Hostinger"),
    (r"\.icloud\.com$", "Apple iCloud"),
    (r"\.migadu\.com$", "Migadu"),
    (r"\.mtasv\.net$", "Postmark"),
    (r"\.mailgun\.org$", "Mailgun"),
    (r"\.sendgrid\.net$", "SendGrid"),
    (r"\.spamexperts\.com$", "SpamExperts"),
    (r"\.antispamcloud\.com$", "SpamExperts"),
    (r"\.mx\.cloudflare\.net$", "Cloudflare Email Routing"),
    (r"\.cloudflare\.net$", "Cloudflare"),
]

COMPILED_PROVIDERS = [(re.compile(pat, re.IGNORECASE), name) for pat, name in MX_PROVIDERS]


# ============================================================
# Helpers
# ============================================================

def _get_resolver(timeout: float = 5.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def _make_issue(severity: str, issue: str, plain_english: str,
                impact: str = "", fix: str = "") -> Dict[str, str]:
    return {
        "severity": severity,
        "issue": issue,
        "plain_english": plain_english,
        "impact": impact,
        "fix": fix,
    }


def _detect_provider(hostname: str) -> Optional[str]:
    h = hostname.lower().rstrip(".")
    for pattern, provider in COMPILED_PROVIDERS:
        if pattern.search(h):
            return provider
    return None


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def _resolve_host(hostname: str) -> Dict[str, Any]:
    result = {"a": [], "aaaa": [], "resolved": False}
    resolver = _get_resolver()
    try:
        answers = resolver.resolve(hostname, "A")
        result["a"] = [str(r) for r in answers]
        result["resolved"] = True
    except Exception:
        pass
    try:
        answers = resolver.resolve(hostname, "AAAA")
        result["aaaa"] = [str(r) for r in answers]
        result["resolved"] = True
    except Exception:
        pass
    return result


def _check_ptr(ip: str) -> Dict[str, Any]:
    result = {"ip": ip, "ptr": None, "fcrdns": False}
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = _get_resolver()
        answers = resolver.resolve(rev_name, "PTR")
        ptr_name = str(answers[0]).rstrip(".")
        result["ptr"] = ptr_name
        fwd = _resolve_host(ptr_name)
        all_ips = fwd["a"] + fwd["aaaa"]
        if ip in all_ips:
            result["fcrdns"] = True
    except Exception:
        pass
    return result


def _check_starttls(hostname: str, port: int = 25, timeout: float = 10.0) -> Dict[str, Any]:
    result = {
        "hostname": hostname,
        "supports_starttls": False,
        "tls_version": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_valid": None,
        "error": None,
    }
    try:
        server = smtplib.SMTP(timeout=timeout)
        server.connect(hostname, port)
        server.ehlo()
        if server.has_extn("starttls"):
            result["supports_starttls"] = True
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            server.starttls(context=context)
            server.ehlo()
            result["tls_version"] = server.sock.version()
            cert = server.sock.getpeercert(binary_form=False)
            if cert:
                subj = cert.get("subject", ())
                for rdn in subj:
                    for attr_type, attr_val in rdn:
                        if attr_type == "commonName":
                            result["cert_subject"] = attr_val
                issuer = cert.get("issuer", ())
                for rdn in issuer:
                    for attr_type, attr_val in rdn:
                        if attr_type in ("organizationName", "commonName"):
                            result["cert_issuer"] = attr_val
                            break
                    if result["cert_issuer"]:
                        break
                not_after = cert.get("notAfter")
                if not_after:
                    from email.utils import parsedate_to_datetime
                    try:
                        expiry = parsedate_to_datetime(not_after)
                        result["cert_expiry"] = expiry.isoformat()
                        result["cert_valid"] = expiry > datetime.now(expiry.tzinfo)
                    except Exception:
                        result["cert_expiry"] = not_after
        server.quit()
    except smtplib.SMTPServerDisconnected:
        result["error"] = "Server disconnected"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused (port 25 blocked)"
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


# ============================================================
# Main MX Check
# ============================================================

def check_mx(domain: str, deep_scan: bool = False) -> Dict[str, Any]:
    result = {
        "check": "MX Records", "domain": domain,
        "records": [], "record_count": 0, "providers": [],
        "status": "ok", "issues": [], "warnings": [],
        "recommendations": [], "mx_details": [],
    }

    if not DNS_AVAILABLE:
        result["status"] = "error"
        result["issues"].append(_make_issue("error", "DNS library not available",
            "Cannot perform DNS lookups.", "", "pip install dnspython"))
        return result

    resolver = _get_resolver()
    raw_mx = []

    try:
        answers = resolver.resolve(domain, "MX")
        for rdata in answers:
            priority = rdata.preference
            host = str(rdata.exchange).rstrip(".")
            raw_mx.append((priority, host))
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        result["status"] = "error"
        result["issues"].append(_make_issue(
            "error", f"Domain '{domain}' does not exist (NXDOMAIN)",
            "This domain is not registered or has no DNS records.",
            "No email can be received.",
            "Verify the domain name is correct."))
        return result
    except Exception as e:
        result["status"] = "error"
        result["issues"].append(_make_issue(
            "error", f"DNS query failed: {str(e)[:200]}",
            "Could not query MX records.", "", "Check DNS connectivity."))
        return result

    if not raw_mx:
        result["status"] = "warning"
        result["issues"].append(_make_issue(
            "warning", "No MX records found",
            f"No MX records for '{domain}'. Senders will fall back to A record.",
            "Email delivery is unreliable.",
            "Add at least one MX record."))
        return result

    raw_mx.sort(key=lambda x: x[0])
    result["records"] = [f"{p} {h}" for p, h in raw_mx]
    result["record_count"] = len(raw_mx)

    # Null MX check (RFC 7505)
    if len(raw_mx) == 1 and raw_mx[0][0] == 0 and raw_mx[0][1] in (".", ""):
        result["status"] = "info"
        result["issues"].append(_make_issue(
            "info", "Null MX record (RFC 7505)",
            "This domain explicitly declares it does not accept email.",
            "Senders get a clean rejection.", ""))
        return result

    # Analyze each MX host
    seen_providers = set()
    priorities = [p for p, _ in raw_mx]

    for priority, hostname in raw_mx:
        mx_detail = {
            "priority": priority, "hostname": hostname,
            "provider": None, "resolved": False,
            "ips": [], "ptr_results": [],
        }

        if _is_ip_address(hostname):
            result["issues"].append(_make_issue(
                "error", f"MX points to IP address: {hostname}",
                "RFC 5321 requires MX to point to hostnames, not IPs.",
                "Some servers will refuse delivery.",
                "Create a hostname and point the MX there."))
            result["mx_details"].append(mx_detail)
            continue

        provider = _detect_provider(hostname)
        if provider:
            mx_detail["provider"] = provider
            if provider not in seen_providers:
                seen_providers.add(provider)
                result["providers"].append(provider)

        resolution = _resolve_host(hostname)
        mx_detail["resolved"] = resolution["resolved"]
        mx_detail["ips"] = resolution["a"] + resolution["aaaa"]

        if not resolution["resolved"]:
            result["issues"].append(_make_issue(
                "error", f"MX host '{hostname}' does not resolve",
                f"'{hostname}' has no A or AAAA records.",
                "Mail delivery will fail for this MX.",
                f"Add A/AAAA records for '{hostname}'."))

        # PTR/FCrDNS data is collected but not flagged as an issue.
        # PTR matters for outbound sending IPs, not inbound MX hosts.
        for ip in mx_detail["ips"]:
            ptr_result = _check_ptr(ip)
            mx_detail["ptr_results"].append(ptr_result)

        result["mx_details"].append(mx_detail)

    # Redundancy check
    if len(raw_mx) == 1:
        result["issues"].append(_make_issue(
            "warning", "Only one MX record (no redundancy)",
            "If your mail server goes down, all email queues and may bounce.",
            "Single point of failure.",
            "Add a secondary MX record for failover."))

    # Duplicate priorities
    from collections import Counter
    dupes = {p: c for p, c in Counter(priorities).items() if c > 1}
    for p, count in dupes.items():
        hosts = [h for pri, h in raw_mx if pri == p]
        result["warnings"].append(
            f"Priority {p} shared by {count} hosts ({', '.join(hosts)}).")

    # Deep scan
    if deep_scan:
        result["deep_scan_results"] = []
        for mx_detail in result["mx_details"]:
            if mx_detail["ips"]:
                tls_result = _check_starttls(mx_detail["hostname"])
                mx_detail["starttls"] = tls_result
                result["deep_scan_results"].append(tls_result)
                if tls_result.get("error"):
                    result["issues"].append(_make_issue(
                        "info", f"STARTTLS check failed for {mx_detail['hostname']}",
                        f"Error: {tls_result['error']}", "",
                        "Verify port 25 and STARTTLS."))
                elif not tls_result["supports_starttls"]:
                    result["issues"].append(_make_issue(
                        "warning", f"No STARTTLS on {mx_detail['hostname']}",
                        "Email received in plaintext.",
                        "Inbound email is unencrypted.",
                        "Enable STARTTLS on the mail server."))
                elif tls_result.get("cert_valid") is False:
                    result["issues"].append(_make_issue(
                        "warning", f"Expired cert on {mx_detail['hostname']}",
                        f"Expired: {tls_result.get('cert_expiry', 'unknown')}.",
                        "Strict senders may refuse delivery.",
                        "Renew the TLS certificate."))

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    for issue in result["issues"]:
        fix = issue.get("fix")
        if fix and fix not in result["recommendations"]:
            result["recommendations"].append(fix)

    return result
