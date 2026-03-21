"""
Email Header Analyzer
=====================
Parses raw email headers and produces a structured analysis
including authentication results, mail journey, identity checks,
and deliverability diagnosis.

All analysis is performed locally on the server. No email content
is stored or logged.
"""

import email
import email.utils
import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# Provider identification from hostnames/IPs
_PROVIDER_PATTERNS = {
    "google.com": "Google",
    "gmail.com": "Google",
    "googleapis.com": "Google",
    "google": "Google",
    "outlook.com": "Microsoft",
    "microsoft.com": "Microsoft",
    "hotmail.com": "Microsoft",
    "protection.outlook.com": "Microsoft",
    "office365": "Microsoft",
    "amazonses.com": "Amazon SES",
    "amazonaws.com": "Amazon",
    "sendgrid.net": "SendGrid",
    "mailgun.org": "Mailgun",
    "mailchimp.com": "Mailchimp",
    "mandrillapp.com": "Mandrill",
    "sparkpostmail.com": "SparkPost",
    "postmarkapp.com": "Postmark",
    "mimecast.com": "Mimecast",
    "proofpoint.com": "Proofpoint",
    "pphosted.com": "Proofpoint",
    "barracuda": "Barracuda",
    "messagelabs": "Broadcom",
    "sophos": "Sophos",
    "zoho.com": "Zoho",
    "fastmail.com": "Fastmail",
    "icloud.com": "Apple",
    "apple.com": "Apple",
    "yahoo.com": "Yahoo",
    "ymail.com": "Yahoo",
    "cloudflare.com": "Cloudflare",
    "mailjet.com": "Mailjet",
    "sendinblue.com": "Brevo",
    "hubspot.com": "HubSpot",
    "salesforce.com": "Salesforce",
    "freshdesk.com": "Freshworks",
    "zendesk.com": "Zendesk",
    "intercom-mail.com": "Intercom",
    "constantcontact.com": "Constant Contact",
}

# Header glossary for inline education
HEADER_GLOSSARY = {
    "From": "The sender's email address as shown in your email client. This is what DMARC protects, but it can be set to any value without proper authentication.",
    "Return-Path": "The actual sender address used for bounce notifications. This is what SPF checks. It is often different from the From address, especially with marketing tools.",
    "Received": "Each Received header is a stamp added by a mail server that handled this email. Reading them bottom-to-top traces the email's path from sender to your inbox.",
    "Authentication-Results": "The receiving mail server's verdict on whether SPF, DKIM, and DMARC passed or failed for this message.",
    "DKIM-Signature": "A cryptographic signature proving this email has not been tampered with since leaving the sender's server.",
    "ARC-Authentication-Results": "When email is forwarded (like through a mailing list), ARC preserves the original authentication results so they are not lost.",
    "ARC-Message-Signature": "Part of the ARC chain that signs the message content, preserving integrity through forwarding hops.",
    "ARC-Seal": "Seals the ARC chain at each hop, preventing tampering with the forwarding authentication record.",
    "Received-SPF": "The SPF check result at this specific mail server hop.",
    "X-Spam-Score": "A numerical score assigned by the spam filter. Higher numbers mean more likely to be spam.",
    "X-Spam-Status": "The spam filter's verdict for this message, including the score and which rules matched.",
    "X-Mailer": "The software used to compose or send this email.",
    "User-Agent": "The email client or software used to compose this message.",
    "Message-ID": "A unique identifier for this specific email. Useful for tracking delivery issues with your email provider.",
    "X-Google-DKIM": "Google's internal DKIM signature, separate from the sender's own DKIM.",
}

# Sample headers for the "try it" button
SAMPLE_HEADERS = """Delivered-To: user@gmail.com
Received: by 2002:a05:6a00:2287:b0:6e0:d5f8:c0a with SMTP id cr7csp312456pfb;
        Sat, 21 Mar 2026 09:41:03 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IEW7example
X-Received: by 2002:a17:906:d4c2:b0:a46:43b2:5e12 with SMTP id a640c23a62f3a-a4643b25e12mr1234567866b.12.1742571663123;
        Sat, 21 Mar 2026 09:41:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742571663; cv=none;
        d=google.com; s=arc-20240116;
        b=abc123example
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240116;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=abcdef123456; b=xyz789example
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@example.com header.s=selector1 header.b=abc12345;
       spf=pass (google.com: domain of bounce@em.example.com designates 198.51.100.50 as permitted sender) smtp.mailfrom=bounce@em.example.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=example.com
Return-Path: <bounce@em.example.com>
Received: from mail-out.example.com (mail-out.example.com. [198.51.100.50])
        by mx.google.com with ESMTPS id a640c23a62f3a-a46example
        for <user@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Mar 2026 09:41:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of bounce@em.example.com designates 198.51.100.50 as permitted sender) client-ip=198.51.100.50;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=selector1 header.b=abc12345;
       spf=pass (google.com: domain of bounce@em.example.com designates 198.51.100.50 as permitted sender) smtp.mailfrom=bounce@em.example.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector1;
        h=from:to:subject:date:message-id:mime-version;
        bh=abcdef123456; b=longbase64signaturestring
Received: by mail-internal.example.com (Postfix) with ESMTP id ABC123DEF456;
        Sat, 21 Mar 2026 09:41:01 -0700 (PDT)
From: Example Notifications <noreply@example.com>
To: user@gmail.com
Subject: Your weekly report is ready
Date: Sat, 21 Mar 2026 09:41:00 -0700
Message-ID: <abc123@mail-internal.example.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8"""


def analyze_headers(raw_headers: str) -> Dict[str, Any]:
    """Parse raw email headers and produce a structured analysis.

    Args:
        raw_headers: The raw email header text (from "Show Original" or similar)

    Returns:
        Dict with: journey, identity, auth_summary, diagnosis, dkim_signatures,
                   arc_chain, from_domain, glossary_keys, headers_present
    """
    if not raw_headers or not raw_headers.strip():
        return {"error": True, "error_message": "No headers provided."}

    # Limit input size (headers should not exceed ~100KB)
    if len(raw_headers) > 200_000:
        return {"error": True, "error_message": "Input too large. Please paste only the email headers, not the full message body."}

    try:
        parsed = email.message_from_string(raw_headers)
    except Exception as e:
        log.debug("Header parse error: %s", e)
        return {"error": True, "error_message": "Could not parse the provided text as email headers."}

    # Check we actually got some headers
    if not parsed.keys():
        return {"error": True, "error_message": "No email headers found in the provided text. Make sure you are pasting the raw headers, not the email body."}

    result: Dict[str, Any] = {"error": False}

    # Extract key headers
    from_header = parsed.get("From", "")
    return_path = parsed.get("Return-Path", "")
    received_spf = parsed.get("Received-SPF", "")

    # Parse all instances of multi-value headers
    received_headers = parsed.get_all("Received") or []
    auth_results_headers = parsed.get_all("Authentication-Results") or []
    dkim_sig_headers = parsed.get_all("DKIM-Signature") or []
    arc_auth_headers = parsed.get_all("ARC-Authentication-Results") or []
    arc_seal_headers = parsed.get_all("ARC-Seal") or []
    arc_msg_sig_headers = parsed.get_all("ARC-Message-Signature") or []

    # Track which headers are present for glossary
    headers_present = []
    for key in parsed.keys():
        norm = key.strip()
        if norm not in headers_present:
            headers_present.append(norm)

    result["headers_present"] = headers_present

    # --- From domain extraction ---
    from_domain = _extract_domain(from_header)
    return_path_domain = _extract_domain(return_path)
    result["from_header"] = from_header.strip()
    result["from_domain"] = from_domain
    result["return_path"] = return_path.strip().strip("<>")
    result["return_path_domain"] = return_path_domain

    # --- DKIM Signatures ---
    dkim_signatures = []
    for sig in dkim_sig_headers:
        dkim_signatures.append(_parse_dkim_signature(sig))
    result["dkim_signatures"] = dkim_signatures

    # --- Authentication Results ---
    auth_summary = _parse_auth_results(auth_results_headers)
    result["auth_summary"] = auth_summary

    # --- Received-SPF ---
    result["received_spf"] = _parse_received_spf(received_spf)

    # --- ARC Chain ---
    arc_chain = _parse_arc_chain(arc_auth_headers, arc_seal_headers, arc_msg_sig_headers)
    result["arc_chain"] = arc_chain

    # --- Mail Journey (Received headers, bottom-to-top) ---
    journey = _parse_journey(received_headers)
    result["journey"] = journey

    # --- Identity Check ---
    dkim_domains = [s.get("d", "") for s in dkim_signatures if s.get("d")]
    identity = _build_identity_check(
        from_domain, return_path_domain, dkim_domains, auth_summary
    )
    result["identity"] = identity

    # --- Deliverability Diagnosis ---
    spam_headers = {
        "x_spam_score": parsed.get("X-Spam-Score", ""),
        "x_spam_status": parsed.get("X-Spam-Status", ""),
        "x_spam_flag": parsed.get("X-Spam-Flag", ""),
        "bcl": parsed.get("X-Microsoft-Antispam", ""),
        "scl": parsed.get("X-MS-Exchange-Organization-SCL", ""),
    }
    diagnosis = _build_diagnosis(
        auth_summary, identity, journey, spam_headers,
        from_header, return_path, dkim_signatures
    )
    result["diagnosis"] = diagnosis

    # --- DMARCbis callout ---
    result["dmarcbis_note"] = _build_dmarcbis_note(auth_summary, from_domain)

    # --- Glossary (only for headers present in this email) ---
    glossary = []
    for key in headers_present:
        # Match against known glossary entries
        for gkey, desc in HEADER_GLOSSARY.items():
            if key.lower() == gkey.lower() or key.lower().startswith(gkey.lower()):
                glossary.append({"header": key, "description": desc})
                break
    result["glossary"] = glossary

    # --- Additional metadata ---
    result["subject"] = parsed.get("Subject", "")
    result["date"] = parsed.get("Date", "")
    result["message_id"] = parsed.get("Message-ID", "")
    x_mailer = parsed.get("X-Mailer") or parsed.get("User-Agent") or ""
    result["mailer"] = x_mailer.strip()

    return result


# ============================================================
# Header Parsing Helpers
# ============================================================


def _extract_domain(header_value: str) -> str:
    """Extract the domain from a From or Return-Path header."""
    if not header_value:
        return ""
    # Try email.utils first
    _, addr = email.utils.parseaddr(header_value)
    if addr and "@" in addr:
        return addr.split("@", 1)[1].lower().strip().rstrip(">").rstrip(".")
    # Fallback: regex
    match = re.search(r'@([A-Za-z0-9._-]+\.[A-Za-z]{2,})', header_value)
    if match:
        return match.group(1).lower().strip(".")
    return ""


def _identify_provider(hostname: str) -> Optional[str]:
    """Identify mail provider from a hostname."""
    if not hostname:
        return None
    h = hostname.lower().rstrip(".")
    for pattern, name in _PROVIDER_PATTERNS.items():
        if pattern in h:
            return name
    return None


def _parse_dkim_signature(sig: str) -> Dict[str, str]:
    """Parse a DKIM-Signature header into its components."""
    result = {}
    # Normalize whitespace (DKIM headers are often folded)
    sig = re.sub(r'\s+', ' ', sig.strip())
    for part in sig.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, val = part.partition("=")
            key = key.strip().lower()
            val = val.strip()
            if key in ("v", "a", "d", "s", "c", "q", "h", "bh", "b", "t", "x", "l"):
                result[key] = val
    return result


def _parse_auth_results(headers: List[str]) -> Dict[str, Any]:
    """Parse Authentication-Results headers into structured results."""
    summary = {
        "spf": {"result": "none", "detail": ""},
        "dkim": {"result": "none", "detail": "", "domain": "", "selector": ""},
        "dmarc": {"result": "none", "detail": "", "policy": "", "disposition": ""},
        "raw": [],
    }

    for header in headers:
        summary["raw"].append(header.strip())
        h = header.lower()

        # SPF
        spf_match = re.search(r'spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)', h)
        if spf_match and summary["spf"]["result"] == "none":
            summary["spf"]["result"] = spf_match.group(1)
            # Extract detail
            detail_match = re.search(r'spf\s*=\s*\w+\s*(\([^)]*\))', h)
            if detail_match:
                summary["spf"]["detail"] = detail_match.group(1)
            mailfrom_match = re.search(r'smtp\.mailfrom\s*=\s*([^\s;]+)', h)
            if mailfrom_match:
                summary["spf"]["mailfrom"] = mailfrom_match.group(1)

        # DKIM
        dkim_match = re.search(r'dkim\s*=\s*(pass|fail|none|neutral|temperror|permerror|policy)', h)
        if dkim_match and summary["dkim"]["result"] == "none":
            summary["dkim"]["result"] = dkim_match.group(1)
            d_match = re.search(r'header\.(?:i|d)\s*=\s*@?([^\s;,]+)', h)
            if d_match:
                summary["dkim"]["domain"] = d_match.group(1).lstrip("@")
            s_match = re.search(r'header\.s\s*=\s*([^\s;,]+)', h)
            if s_match:
                summary["dkim"]["selector"] = s_match.group(1)
            b_match = re.search(r'header\.b\s*=\s*([^\s;,]+)', h)
            if b_match:
                summary["dkim"]["body_hash_prefix"] = b_match.group(1)

        # DMARC
        dmarc_match = re.search(r'dmarc\s*=\s*(pass|fail|none|bestguesspass|temperror|permerror)', h)
        if dmarc_match and summary["dmarc"]["result"] == "none":
            summary["dmarc"]["result"] = dmarc_match.group(1)
            policy_match = re.search(r'p\s*=\s*(none|quarantine|reject)', h)
            if policy_match:
                summary["dmarc"]["policy"] = policy_match.group(1).upper()
            dis_match = re.search(r'dis\s*=\s*(\w+)', h)
            if dis_match:
                summary["dmarc"]["disposition"] = dis_match.group(1).upper()
            detail_match = re.search(r'dmarc\s*=\s*\w+\s*(\([^)]*\))', h)
            if detail_match:
                summary["dmarc"]["detail"] = detail_match.group(1)

    return summary


def _parse_received_spf(header: str) -> Dict[str, str]:
    """Parse a Received-SPF header."""
    if not header:
        return {"result": "none", "detail": ""}
    h = header.strip()
    result_match = re.match(r'(pass|fail|softfail|neutral|none|temperror|permerror)', h, re.IGNORECASE)
    return {
        "result": result_match.group(1).lower() if result_match else "unknown",
        "detail": h,
    }


def _parse_arc_chain(auth_headers: List[str], seal_headers: List[str], msg_sig_headers: List[str]) -> Dict[str, Any]:
    """Parse ARC chain headers."""
    if not auth_headers and not seal_headers:
        return {"present": False, "hops": 0}

    hops = max(len(auth_headers), len(seal_headers), len(msg_sig_headers))

    # Check chain validity from seals
    chain_valid = True
    cv_values = []
    for seal in seal_headers:
        cv_match = re.search(r'cv\s*=\s*(none|pass|fail)', seal, re.IGNORECASE)
        if cv_match:
            cv = cv_match.group(1).lower()
            cv_values.append(cv)
            if cv == "fail":
                chain_valid = False

    return {
        "present": True,
        "hops": hops,
        "chain_valid": chain_valid,
        "cv_values": cv_values,
        "status": "valid" if chain_valid else "broken",
    }


def _parse_timestamp(date_str: str) -> Optional[datetime]:
    """Try to parse a date string from a Received header."""
    if not date_str:
        return None
    # Clean up common artifacts
    date_str = date_str.strip().rstrip(";").strip()
    # Remove day name prefix if present (e.g., "Sat, ")
    date_str = re.sub(r'^[A-Za-z]{3},?\s*', '', date_str)
    try:
        return email.utils.parsedate_to_datetime(date_str)
    except Exception:
        pass
    # Try common formats
    for fmt in (
        "%d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S %Z",
        "%d %b %Y %H:%M:%S",
    ):
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    return None


def _parse_journey(received_headers: List[str]) -> Dict[str, Any]:
    """Parse Received headers into a human-readable mail journey.

    Received headers are in reverse order (newest first), so we reverse them
    to get the actual chronological journey.
    """
    hops = []

    for i, header in enumerate(reversed(received_headers)):
        hop = _parse_single_received(header, i + 1)
        hops.append(hop)

    # Calculate timing deltas
    for i in range(1, len(hops)):
        prev_ts = hops[i - 1].get("timestamp_parsed")
        curr_ts = hops[i].get("timestamp_parsed")
        if prev_ts and curr_ts:
            delta = (curr_ts - prev_ts).total_seconds()
            hops[i]["delta_seconds"] = round(delta, 1)
            if delta > 300:
                hops[i]["delay_level"] = "red"
                minutes = int(delta // 60)
                hops[i]["delay_note"] = f"Unusual delay: {minutes} minute{'s' if minutes != 1 else ''}"
            elif delta > 30:
                hops[i]["delay_level"] = "amber"
                hops[i]["delay_note"] = f"Delay: {round(delta, 1)}s"
            else:
                hops[i]["delay_level"] = "normal"

    # Total transit time
    total_seconds = None
    if len(hops) >= 2:
        first_ts = hops[0].get("timestamp_parsed")
        last_ts = hops[-1].get("timestamp_parsed")
        if first_ts and last_ts:
            total_seconds = round((last_ts - first_ts).total_seconds(), 1)

    # Detect internal vs external hops
    _tag_internal_hops(hops)

    return {
        "hops": [{k: v for k, v in h.items() if k != "timestamp_parsed"} for h in hops],
        "hop_count": len(hops),
        "total_seconds": total_seconds,
    }


def _parse_single_received(header: str, hop_number: int) -> Dict[str, Any]:
    """Parse a single Received header into structured hop info."""
    hop: Dict[str, Any] = {"hop": hop_number, "raw": header.strip()}

    # Extract 'from' server
    from_match = re.search(r'from\s+(\S+)', header, re.IGNORECASE)
    if from_match:
        hop["from_host"] = from_match.group(1).rstrip(")")

    # Extract IP from parenthetical
    ip_match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', header)
    if ip_match:
        hop["ip"] = ip_match.group(1)

    # Extract 'by' server
    by_match = re.search(r'by\s+(\S+)', header, re.IGNORECASE)
    if by_match:
        hop["by_host"] = by_match.group(1).rstrip(")")

    # Extract protocol (ESMTP, ESMTPS, etc.)
    proto_match = re.search(r'with\s+(E?SMTP\S*)', header, re.IGNORECASE)
    if proto_match:
        proto = proto_match.group(1).upper()
        hop["protocol"] = proto
        hop["tls"] = "S" in proto  # ESMTPS = TLS

    # Extract timestamp (typically after the semicolon)
    ts_match = re.search(r';\s*(.+)$', header, re.DOTALL)
    if ts_match:
        ts_str = ts_match.group(1).strip()
        hop["timestamp_raw"] = ts_str
        parsed_ts = _parse_timestamp(ts_str)
        if parsed_ts:
            hop["timestamp_parsed"] = parsed_ts
            hop["timestamp"] = parsed_ts.isoformat()

    # Identify provider
    for host_key in ("from_host", "by_host"):
        host = hop.get(host_key, "")
        provider = _identify_provider(host)
        if provider:
            hop[f"{host_key}_provider"] = provider
            if "provider" not in hop:
                hop["provider"] = provider

    # Generate human-readable description
    hop["description"] = _describe_hop(hop)

    return hop


def _describe_hop(hop: Dict) -> str:
    """Generate a human-readable description for a hop."""
    provider = hop.get("provider")
    by_host = hop.get("by_host", "")
    from_host = hop.get("from_host", "")

    if hop.get("hop") == 1 and from_host:
        host_label = provider or from_host
        return f"Originated at {host_label}"

    if provider:
        return f"{provider}'s mail server"

    if by_host:
        return by_host

    return "Mail server"


def _tag_internal_hops(hops: List[Dict]):
    """Tag hops as internal (same org) or external (different org)."""
    for i, hop in enumerate(hops):
        if i == 0:
            hop["internal"] = False
            continue
        prev_provider = hops[i - 1].get("provider")
        curr_provider = hop.get("provider")
        if prev_provider and curr_provider and prev_provider == curr_provider:
            hop["internal"] = True
        else:
            hop["internal"] = False


def _build_identity_check(
    from_domain: str,
    return_path_domain: str,
    dkim_domains: List[str],
    auth_summary: Dict,
) -> Dict[str, Any]:
    """Build the identity check showing the three identity layers."""
    spf_result = auth_summary.get("spf", {}).get("result", "none")
    dkim_result = auth_summary.get("dkim", {}).get("result", "none")
    dmarc_result = auth_summary.get("dmarc", {}).get("result", "none")

    # SPF alignment (return-path domain vs from domain)
    spf_aligned = False
    if from_domain and return_path_domain:
        spf_aligned = (
            return_path_domain == from_domain
            or return_path_domain.endswith("." + from_domain)
            or from_domain.endswith("." + return_path_domain)
        )

    # DKIM alignment (dkim d= vs from domain)
    dkim_aligned = False
    aligned_dkim_domain = ""
    for dd in dkim_domains:
        if dd == from_domain or dd.endswith("." + from_domain) or from_domain.endswith("." + dd):
            dkim_aligned = True
            aligned_dkim_domain = dd
            break

    # Determine alignment type used by DMARC
    alignment_method = ""
    if dmarc_result == "pass":
        if dkim_aligned and dkim_result == "pass":
            alignment_method = "DKIM aligned with From domain"
        elif spf_aligned and spf_result == "pass":
            alignment_method = "SPF aligned with From domain"
        elif dkim_result == "pass" and spf_result == "pass":
            alignment_method = "Both SPF and DKIM aligned"
        else:
            alignment_method = "Alignment details not available"

    return {
        "mail_from": return_path_domain or "(not set)",
        "header_from": from_domain or "(not set)",
        "dkim_domains": dkim_domains,
        "spf_authenticated": return_path_domain if spf_result == "pass" else None,
        "spf_result": spf_result,
        "dkim_authenticated": aligned_dkim_domain or (dkim_domains[0] if dkim_domains else None) if dkim_result == "pass" else None,
        "dkim_result": dkim_result,
        "dmarc_result": dmarc_result,
        "dmarc_policy": auth_summary.get("dmarc", {}).get("policy", ""),
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "alignment_method": alignment_method,
    }


def _build_diagnosis(
    auth_summary: Dict,
    identity: Dict,
    journey: Dict,
    spam_headers: Dict,
    from_header: str,
    return_path: str,
    dkim_signatures: List[Dict],
) -> Dict[str, Any]:
    """Build the deliverability diagnosis with a top-level verdict."""
    problems = []
    indicators = []

    spf_result = auth_summary.get("spf", {}).get("result", "none")
    dkim_result = auth_summary.get("dkim", {}).get("result", "none")
    dmarc_result = auth_summary.get("dmarc", {}).get("result", "none")
    dmarc_policy = auth_summary.get("dmarc", {}).get("policy", "").lower()

    # --- Authentication failures ---
    if spf_result == "fail":
        problems.append({
            "type": "spf_fail",
            "severity": "high",
            "title": "SPF authentication failed",
            "detail": (
                f"The sending server is not authorized by the sender domain's SPF record. "
                f"SPF hard fail means the domain explicitly does not authorize this sender."
            ),
            "fix": "Add the sending server or service to the domain's SPF record.",
        })
    elif spf_result == "softfail":
        problems.append({
            "type": "spf_softfail",
            "severity": "medium",
            "title": "SPF softfail",
            "detail": (
                "SPF softfail (~all) means the sending server is not fully authorized. "
                "This often triggers spam filters, especially at Gmail and Microsoft."
            ),
            "fix": "Update the SPF record to fully authorize the sending service, or change ~all to -all after confirming all legitimate senders are included.",
        })
    elif spf_result == "none":
        problems.append({
            "type": "spf_missing",
            "severity": "medium",
            "title": "No SPF record found",
            "detail": "The sending domain has no SPF record. Receivers cannot verify the sending server is authorized.",
            "fix": "Publish an SPF record for the sending domain.",
        })

    if dkim_result == "fail":
        sel_info = ""
        if dkim_signatures:
            sel_info = f" Selector: {dkim_signatures[0].get('s', 'unknown')}, Domain: {dkim_signatures[0].get('d', 'unknown')}."
        problems.append({
            "type": "dkim_fail",
            "severity": "high",
            "title": "DKIM signature verification failed",
            "detail": (
                f"DKIM signature could not be verified.{sel_info} "
                f"Possible causes: key rotation, message modification in transit, or forwarding."
            ),
            "fix": "Verify the DKIM key is published correctly and the signing configuration matches.",
        })
    elif dkim_result == "none" and not dkim_signatures:
        problems.append({
            "type": "dkim_missing",
            "severity": "medium",
            "title": "No DKIM signature",
            "detail": (
                "This email has no DKIM signature. Most major providers (Gmail, Outlook, Yahoo) "
                "heavily penalize unsigned emails in their spam filtering."
            ),
            "fix": "Enable DKIM signing for the sending domain or service.",
        })

    if dmarc_result == "fail":
        problems.append({
            "type": "dmarc_fail",
            "severity": "high",
            "title": "DMARC authentication failed",
            "detail": _explain_dmarc_fail(identity, spf_result, dkim_result),
            "fix": "Ensure either SPF or DKIM passes AND aligns with the From domain.",
        })
        if dmarc_policy in ("quarantine", "reject"):
            problems.append({
                "type": "dmarc_enforcement",
                "severity": "critical",
                "title": f"DMARC policy enforced: {dmarc_policy}",
                "detail": (
                    f"The sending domain's DMARC policy is p={dmarc_policy}. "
                    f"The receiver {'quarantined (sent to spam)' if dmarc_policy == 'quarantine' else 'rejected'} "
                    f"this email because authentication failed."
                ),
                "fix": "Fix the authentication issue above before the domain's policy will allow delivery.",
            })
    elif dmarc_result == "none":
        problems.append({
            "type": "dmarc_missing",
            "severity": "medium",
            "title": "No DMARC policy",
            "detail": (
                "The sending domain has no DMARC record. Without DMARC, receivers have no policy "
                "guidance and many default to treating the email with suspicion."
            ),
            "fix": "Publish a DMARC record for the sending domain. Start with p=none to monitor.",
        })

    # --- Spam indicators ---
    x_spam_score = spam_headers.get("x_spam_score", "")
    if x_spam_score:
        try:
            score = float(x_spam_score)
            if score >= 5.0:
                indicators.append({
                    "type": "spam_score_high",
                    "title": f"High spam score: {score}",
                    "detail": "The spam filter assigned a high score to this message.",
                })
        except (ValueError, TypeError):
            pass

    x_spam_status = spam_headers.get("x_spam_status", "")
    if x_spam_status.lower().startswith("yes"):
        indicators.append({
            "type": "spam_flagged",
            "title": "Flagged as spam by content filter",
            "detail": f"The receiving server's spam filter flagged this email: {x_spam_status[:100]}",
        })

    # --- Spoofing indicators ---
    from_domain = identity.get("header_from", "")
    rp_domain = identity.get("mail_from", "")
    if (from_domain and rp_domain and from_domain != rp_domain
            and not rp_domain.endswith("." + from_domain)
            and dkim_result != "pass"):
        indicators.append({
            "type": "possible_spoofing",
            "title": "Sender mismatch without DKIM verification",
            "detail": (
                f"The visible sender ({from_domain}) does not match the actual sending "
                f"server ({rp_domain}), and there is no valid DKIM signature to verify "
                f"the message. This is a common spoofing pattern."
            ),
        })

    # All authentication failed
    if spf_result in ("fail", "softfail", "none") and dkim_result in ("fail", "none") and dmarc_result in ("fail", "none"):
        indicators.append({
            "type": "all_auth_failed",
            "title": "All authentication checks failed or missing",
            "detail": (
                "Every authentication mechanism (SPF, DKIM, DMARC) either failed or was not present. "
                "This email is likely spoofed or sent from an unauthorized server."
            ),
        })

    # --- Journey anomalies ---
    hops = journey.get("hops", [])
    for hop in hops:
        if hop.get("delay_level") == "red":
            indicators.append({
                "type": "routing_delay",
                "title": f"Unusual delay at hop {hop.get('hop', '?')}",
                "detail": hop.get("delay_note", "Extended delay detected between hops."),
            })

    total_time = journey.get("total_seconds")
    if total_time and total_time > 120:
        minutes = int(total_time // 60)
        indicators.append({
            "type": "slow_delivery",
            "title": f"Slow delivery: {minutes} minute{'s' if minutes != 1 else ''}",
            "detail": (
                f"This email took {minutes} minute{'s' if minutes != 1 else ''} to reach its destination. "
                f"Normal transit is under 30 seconds. There may have been a greylisting delay or queue backup."
            ),
        })

    # --- Determine top-level verdict ---
    verdict = _determine_verdict(problems, indicators, auth_summary)

    return {
        "verdict": verdict,
        "problems": problems,
        "indicators": indicators,
    }


def _explain_dmarc_fail(identity: Dict, spf_result: str, dkim_result: str) -> str:
    """Explain why DMARC failed."""
    from_domain = identity.get("header_from", "unknown")
    parts = [
        f"DMARC failed because neither SPF nor DKIM aligned with the From domain ({from_domain})."
    ]
    rp_domain = identity.get("mail_from", "")
    if rp_domain:
        spf_align = "aligned" if identity.get("spf_aligned") else "not aligned"
        parts.append(f"SPF authenticated {rp_domain} ({spf_result}, {spf_align}).")

    dkim_domains = identity.get("dkim_domains", [])
    if dkim_domains:
        dkim_align = "aligned" if identity.get("dkim_aligned") else "not aligned"
        parts.append(f"DKIM signed by {', '.join(dkim_domains)} ({dkim_result}, {dkim_align}).")
    else:
        parts.append("No DKIM signature present.")

    return " ".join(parts)


def _determine_verdict(problems: List[Dict], indicators: List[Dict], auth_summary: Dict) -> Dict[str, str]:
    """Determine the top-level diagnosis verdict."""
    spf = auth_summary.get("spf", {}).get("result", "none")
    dkim = auth_summary.get("dkim", {}).get("result", "none")
    dmarc = auth_summary.get("dmarc", {}).get("result", "none")
    dmarc_policy = auth_summary.get("dmarc", {}).get("policy", "").lower()

    # Check for spoofing
    has_spoofing = any(i.get("type") in ("possible_spoofing", "all_auth_failed") for i in indicators)
    if has_spoofing:
        return {
            "level": "danger",
            "title": "This email may be spoofed",
            "summary": (
                "Multiple authentication checks failed or are missing, and the visible sender "
                "does not match the actual sending infrastructure. Treat this email with caution."
            ),
        }

    # Check for enforcement rejection
    has_enforcement = any(p.get("type") == "dmarc_enforcement" for p in problems)
    if has_enforcement:
        action = "quarantined (sent to spam)" if dmarc_policy == "quarantine" else "rejected"
        return {
            "level": "danger",
            "title": f"This email was likely {action}",
            "summary": (
                f"Authentication failed and the sender's domain enforces a DMARC policy of p={dmarc_policy}. "
                f"The receiving server {'sent this to spam' if dmarc_policy == 'quarantine' else 'rejected this email'}."
            ),
        }

    # Check for spam-likely
    critical_problems = [p for p in problems if p.get("severity") in ("high", "critical")]
    spam_indicators = [i for i in indicators if i.get("type") in ("spam_flagged", "spam_score_high")]

    if critical_problems or spam_indicators:
        return {
            "level": "warning",
            "title": "This email likely landed in spam",
            "summary": _summarize_problems(problems, indicators),
        }

    # Medium problems
    medium_problems = [p for p in problems if p.get("severity") == "medium"]
    if medium_problems:
        return {
            "level": "caution",
            "title": "Minor authentication gaps detected",
            "summary": _summarize_problems(problems, indicators),
        }

    # All good
    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        return {
            "level": "healthy",
            "title": "This email passed all authentication checks",
            "summary": (
                "SPF, DKIM, and DMARC all passed. This email was sent from an authorized server, "
                "has a valid cryptographic signature, and properly aligns with the sender's domain policy."
            ),
        }

    return {
        "level": "info",
        "title": "Authentication results are mixed",
        "summary": _summarize_problems(problems, indicators),
    }


def _summarize_problems(problems: List[Dict], indicators: List[Dict]) -> str:
    """Build a summary string from the most important problems."""
    parts = []
    for p in problems[:2]:
        parts.append(p.get("title", ""))
    if len(problems) > 2:
        parts.append(f"and {len(problems) - 2} more issue{'s' if len(problems) - 2 != 1 else ''}")
    return ". ".join(parts) + "." if parts else "See details below."


def _build_dmarcbis_note(auth_summary: Dict, from_domain: str) -> Optional[Dict]:
    """Build a note about how DMARCbis would evaluate this email differently."""
    dmarc_result = auth_summary.get("dmarc", {}).get("result", "none")
    dmarc_policy = auth_summary.get("dmarc", {}).get("policy", "").lower()

    notes = []

    if dmarc_result == "pass" and dmarc_policy == "none":
        notes.append(
            "Under DMARCbis, domains in testing mode (p=none) with the t=y flag "
            "would explicitly signal that DMARC is being tested. Receivers that "
            "support DMARCbis can handle this differently from a production p=none."
        )

    if dmarc_result == "none":
        notes.append(
            "Under DMARCbis, the tree walk algorithm (Section 4.10) changes how "
            "the organizational domain is resolved. This could affect which DMARC "
            "policy applies to this domain."
        )

    if not notes:
        return None

    return {
        "title": "What would DMARCbis change?",
        "notes": notes,
        "would_change": dmarc_result == "none",
    }


def get_sample_headers() -> str:
    """Return sample headers for the try-it-out feature."""
    return SAMPLE_HEADERS
