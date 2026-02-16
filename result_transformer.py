"""
Result Transformer
==================
Converts raw audit module outputs into the uniform card format
expected by the frontend.

Each card looks like:
{
    "name": "DMARC",
    "status": "pass" | "warn" | "fail",
    "pill_label": optional override for the status pill text,
    "verdict": "one-line summary for the collapsed card header",
    "record": "the raw DNS record string (shown in monospace block)",
    "explanation": "HTML-safe plain-English explanation",
    "details": [
        {"type": "error|warning|info|good", "text": "..."}
    ],
    "fix": "HTML-safe recommended action (shown in blue fix block)"
}
"""

from typing import Any, Dict, List, Optional
from datetime import datetime

from dkim_formatter import analyze_dkim_key_strength


# ============================================================
# Status mapping helpers
# ============================================================

def _map_status(raw_status: str) -> str:
    """Map module statuses to frontend's pass/warn/fail."""
    mapping = {
        "ok": "pass",
        "pass": "pass",
        "good": "pass",
        "info": "pass",
        "warning": "warn",
        "warn": "warn",
        "error": "fail",
        "fail": "fail",
        "critical": "fail",
    }
    return mapping.get(raw_status.lower(), "warn")


def _issue_to_detail(issue: Dict) -> Dict[str, str]:
    """Convert a module issue dict to a frontend detail item."""
    severity = issue.get("severity", "info").lower()
    type_map = {
        "error": "error",
        "critical": "error",
        "warning": "warning",
        "warn": "warning",
        "info": "info",
        "good": "good",
        "ok": "good",
    }
    return {
        "type": type_map.get(severity, "info"),
        "text": issue.get("plain_english") or issue.get("issue", ""),
    }


def _first_fix(issues: List[Dict]) -> Optional[str]:
    """Extract the first actionable fix from issues list."""
    for issue in issues:
        fix = issue.get("fix")
        if fix:
            return fix
    return None


# ============================================================
# DMARC
# ============================================================

def transform_dmarc(raw: Dict) -> Dict:
    status = _map_status(raw.get("status", "error"))
    policy = raw.get("policy", "")
    record = raw.get("record")
    pill_label = None

    # Build verdict
    if not record:
        verdict = "No DMARC record found"
        pill_label = "Missing"
    elif policy == "reject":
        verdict = "Policy: reject (strongest)"
    elif policy == "quarantine":
        pct = raw.get("pct", 100)
        verdict = f"Policy: quarantine"
        if pct and pct < 100:
            verdict += f" ({pct}%)"
    elif policy == "none":
        verdict = "Policy: none (monitoring only)"
    else:
        verdict = f"Policy: {policy}" if policy else "Invalid record"

    # Build explanation
    if not record:
        explanation = (
            f"No DMARC record exists at <strong>_dmarc.{raw.get('domain', '')}</strong>. "
            f"DMARC is the single most important email security record — it tells receiving mail servers "
            f"(Gmail, Outlook, Yahoo) how to handle emails that fail SPF and DKIM authentication. "
            f"Without it, anyone can send emails impersonating your domain with no consequences, "
            f"and you have zero visibility into who is sending as your domain."
        )
    elif policy == "none":
        explanation = (
            f"Your DMARC policy is set to <strong>none</strong> (monitoring only). "
            f"Emails that fail SPF and DKIM checks are still delivered normally. "
            f"You get aggregate reports for visibility, but there is no protection against spoofing."
        )
    elif policy == "quarantine":
        explanation = (
            f"Your DMARC policy is <strong>quarantine</strong>. Emails that fail authentication "
            f"are routed to the recipient's spam folder. This provides good protection, but "
            f"<strong>p=reject</strong> is the strongest option."
        )
    elif policy == "reject":
        explanation = (
            f"Your DMARC policy is <strong>reject</strong> - the gold standard. "
            f"Emails that fail authentication are blocked entirely and never reach the recipient."
        )
    else:
        explanation = f"DMARC record found but the policy value is unexpected: '{policy}'."

    # Reporting note
    if record and not raw.get("rua"):
        explanation += (
            " <strong>Note:</strong> No aggregate reporting (rua) is configured, "
            "so you have no visibility into authentication results."
        )

    # Details
    details = []
    if record:
        if policy == "reject":
            details.append({"type": "good", "text": "Policy p=reject provides maximum protection"})
        elif policy == "quarantine":
            details.append({"type": "good", "text": "Policy p=quarantine sends failures to spam"})
        elif policy == "none":
            details.append({"type": "warning", "text": "Policy p=none provides no enforcement"})

        if raw.get("rua"):
            details.append({"type": "good", "text": "Aggregate reporting (rua) is configured"})
        else:
            details.append({"type": "warning", "text": "No aggregate reporting (rua) configured"})

        if raw.get("ruf"):
            details.append({"type": "good", "text": "Forensic reporting (ruf) is configured"})

        if raw.get("sp"):
            details.append({"type": "info", "text": f"Subdomain policy: sp={raw['sp']}"})

        pct = raw.get("pct")
        if pct is not None and pct < 100:
            details.append({"type": "warning", "text": f"Only {pct}% of failing emails are enforced"})
    else:
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))

    # Fix
    domain_name = raw.get("domain", "")
    if not record:
        fix = (
            f"Add this TXT record at <strong>_dmarc.{domain_name}</strong>:<br>"
            f"<code>v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain_name}; fo=1</code><br><br>"
            f"Start with <strong>p=none</strong> to collect aggregate reports without affecting delivery. "
            f"Once you've confirmed all legitimate senders pass SPF/DKIM, move to "
            f"<strong>p=quarantine</strong> then <strong>p=reject</strong>."
        )
    elif policy == "none":
        fix = (
            "Review your DMARC aggregate reports to confirm all legitimate senders pass authentication. "
            "Then upgrade to <strong>p=quarantine</strong>, and ultimately <strong>p=reject</strong> "
            "for full spoofing protection."
        )
    else:
        fix = _first_fix(raw.get("issues", []))

    return {
        "name": "DMARC",
        "status": status,
        "pill_label": pill_label if not record else None,
        "verdict": verdict,
        "record": record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
    }


# ============================================================
# SPF
# ============================================================

def transform_spf(raw: Dict) -> Dict:
    status = _map_status(raw.get("status", "error"))
    record = raw.get("record")
    pill_label = None

    # Verdict
    if not record:
        verdict = "No SPF record found"
        pill_label = "Missing"
    else:
        all_mech = raw.get("all_mechanism", "")
        if all_mech == "+all":
            verdict = "SPF misconfigured (+all)"
        else:
            verdict = "SPF record configured"

    # Explanation
    if not record:
        explanation = (
            "No SPF record found. SPF lists which mail servers are authorized to send email "
            "for your domain. Without it, receiving servers have no way to verify if a message "
            "actually came from your mail infrastructure."
        )
    else:
        all_mech = raw.get("all_mechanism", "")
        lookups = raw.get("lookup_count", 0)

        if all_mech == "-all":
            explanation = (
                "SPF record uses <strong>-all</strong> (hard fail), which tells receivers to "
                "reject email from unauthorized servers. This is the strongest SPF policy."
            )
        elif all_mech == "~all":
            explanation = (
                "SPF record uses <strong>~all</strong> (soft fail), which marks unauthorized "
                "email as suspicious but still delivers it. This is acceptable when paired with DMARC enforcement."
            )
        elif all_mech == "?all":
            explanation = (
                "SPF record uses <strong>?all</strong> (neutral), which provides essentially "
                "no protection. Unauthorized senders are treated the same as authorized ones."
            )
        elif all_mech == "+all":
            explanation = (
                "<strong>WARNING:</strong> SPF record uses <strong>+all</strong>, which authorizes "
                "the entire internet to send email as your domain. This is almost certainly a misconfiguration."
            )
        else:
            explanation = "SPF record found."

        if lookups and lookups > 8:
            explanation += (
                f" <strong>Note:</strong> SPF uses {lookups} DNS lookups "
                f"({'at the 10-lookup limit' if lookups == 10 else 'EXCEEDS the 10-lookup limit' if lookups > 10 else 'approaching the 10-lookup limit'}). "
                f"RFC 7208 limits SPF to 10 DNS lookups to prevent performance issues."
            )

    # Details
    details = []
    if record:
        lookups = raw.get("lookup_count", 0)
        if lookups <= 8:
            details.append({"type": "good", "text": f"{lookups} DNS lookups (well within the 10-lookup limit)"})
        elif lookups <= 10:
            details.append({"type": "warning", "text": f"{lookups} DNS lookups ({'at' if lookups == 10 else 'near'} the 10-lookup limit)"})
        else:
            details.append({"type": "error", "text": f"{lookups} DNS lookups (EXCEEDS the 10-lookup limit!)"})

        all_mech = raw.get("all_mechanism", "")
        if all_mech == "-all":
            details.append({"type": "good", "text": "Hard fail (-all) provides strong anti-spoofing protection"})
        elif all_mech == "~all":
            details.append({"type": "good", "text": "Soft fail (~all) marks unauthorized senders as suspicious"})
        elif all_mech == "?all":
            details.append({"type": "warning", "text": "Neutral (?all) provides no protection"})
        elif all_mech == "+all":
            details.append({"type": "error", "text": "+all authorizes ALL senders (misconfiguration!)"})

        includes = raw.get("include_count", 0)
        if includes:
            details.append({"type": "info", "text": f"{includes} include mechanism{'s' if includes != 1 else ''}"})

        ip4_count = raw.get("ip4_count", 0)
        ip6_count = raw.get("ip6_count", 0)
        if ip4_count or ip6_count:
            parts = []
            if ip4_count:
                parts.append(f"{ip4_count} IPv4")
            if ip6_count:
                parts.append(f"{ip6_count} IPv6")
            details.append({"type": "info", "text": f"Direct IP authorization: {', '.join(parts)}"})
    else:
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))

    fix = _first_fix(raw.get("issues", []))
    if not fix and record:
        all_mech = raw.get("all_mechanism", "")
        lookups = raw.get("lookup_count", 0)
        if all_mech in ("?all", "+all") and lookups and lookups > 10:
            fix = (
                "Change the all mechanism to <strong>-all</strong> or <strong>~all</strong>. "
                "Also reduce SPF lookups to 10 or fewer by flattening includes or removing unused services."
            )
        elif all_mech in ("?all", "+all"):
            fix = "Change the all mechanism to <strong>-all</strong> (hard fail) or <strong>~all</strong> (soft fail)."
        elif lookups and lookups > 10:
            fix = (
                "Reduce SPF lookups to 10 or fewer. Options: flatten includes to direct IP addresses, "
                "remove unused services, or use an SPF flattening tool."
            )

    return {
        "name": "SPF",
        "status": status,
        "pill_label": pill_label if not record else None,
        "verdict": verdict,
        "record": record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
    }


# ============================================================
# DKIM
# ============================================================

def transform_dkim(raw: Dict, domain: str) -> Dict:
    found = raw.get("found_selectors", [])
    tested = raw.get("tested_count", 0)

    if not found:
        return {
            "name": "DKIM",
            "status": "warn",
            "pill_label": "Not detected",
            "verdict": f"No DKIM keys detected ({tested} selectors tested)",
            "record": None,
            "explanation": (
                "No DKIM signing keys were detected among the {tested} common selectors tested. "
                "This does not necessarily mean DKIM is not configured — your provider may use "
                "custom or non-standard selectors that weren't in our test list. "
                "DKIM adds a cryptographic signature to outgoing emails that proves the message "
                "hasn't been tampered with and verifies the sending domain."
            ).format(tested=tested),
            "details": [
                {"type": "warning", "text": f"Tested {tested} common selectors — no public keys found in DNS"},
                {"type": "info", "text": "DKIM selectors are provider-specific and not publicly enumerable"},
                {"type": "info", "text": "The DKIM public key is a TXT record in DNS at selector._domainkey.{domain}".format(domain=domain)},
            ],
            "fix": (
                "Verify DKIM signing is enabled and confirm the public key TXT record is published in DNS at "
                "<strong>selector._domainkey.{domain}</strong>. "
                "Your email provider can tell you which selector name to use."
            ).format(domain=domain),
        }

    # Build details for each found key
    details = []
    vendor_names = set()
    weak_keys = []
    for sel in found:
        selector = sel.get("selector", "unknown")
        sel_record = sel.get("record", "")
        vendor = sel.get("vendor")
        key_type = sel.get("key_type", "")

        # Analyze key strength
        key_analysis = analyze_dkim_key_strength(sel_record)
        bits = key_analysis.get("key_bits", 0)
        strength = key_analysis.get("status", "unknown")

        vendor_str = f" ({vendor})" if vendor else ""
        if vendor:
            vendor_names.add(vendor)

        if strength == "weak":
            details.append({
                "type": "warning",
                "text": f"{selector}: {bits}-bit {key_analysis.get('key_type', 'RSA')} key{vendor_str} - upgrade recommended"
            })
            weak_keys.append(selector)
        elif strength == "strong":
            details.append({
                "type": "good",
                "text": f"{selector}: {bits}-bit {key_analysis.get('key_type', 'RSA')} key{vendor_str}"
            })
        else:
            details.append({
                "type": "info",
                "text": f"{selector}: key found{vendor_str}"
            })

    details.append({"type": "info", "text": f"Tested {tested} selectors"})

    # Verdict — one piece of data only
    verdict = f"{len(found)} key{'s' if len(found) != 1 else ''} found"

    # Status
    status = "pass"
    if weak_keys:
        status = "warn"

    # Explanation
    explanation = (
        f"Found <strong>{len(found)}</strong> DKIM public key{'s' if len(found) != 1 else ''} "
        f"published in DNS."
    )
    if vendor_names:
        explanation += f" Vendors detected: {', '.join(sorted(vendor_names))}."
    explanation += (
        " Each key is a TXT record at <strong>selector._domainkey.{domain}</strong> that receiving "
        "servers use to verify the cryptographic signature on incoming email."
    ).format(domain=domain)
    if raw.get("discovery_method") == "spf_intelligent":
        explanation += " Used SPF-based intelligent discovery for faster, targeted results."

    # Fix
    fix = None
    if weak_keys:
        selectors_str = ", ".join(weak_keys)
        fix = (
            f"Upgrade the following 1024-bit keys to 2048-bit or stronger: "
            f"<strong>{selectors_str}</strong>. Contact the corresponding provider to rotate these keys."
        )

    return {
        "name": "DKIM",
        "status": status,
        "verdict": verdict,
        "record": None,  # DKIM has multiple records, shown in details
        "explanation": explanation,
        "details": details,
        "fix": fix,
    }


# ============================================================
# MX
# ============================================================

def transform_mx(raw: Dict) -> Dict:
    status = _map_status(raw.get("status", "error"))
    records = raw.get("records", [])
    providers = raw.get("providers", [])
    count = raw.get("record_count", 0)

    if not records:
        return {
            "name": "MX Records",
            "status": "fail",
            "pill_label": "Missing",
            "verdict": "No MX records found",
            "record": None,
            "explanation": (
                "No MX records exist for this domain. MX records tell other mail servers "
                "where to deliver email addressed to your domain. Without them, email delivery "
                "falls back to the domain's A record, which is unreliable."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": "Add at least one MX record pointing to your mail server.",
        }

    # Verdict — one piece of data only
    if providers:
        verdict = ", ".join(providers)
    else:
        verdict = f"{count} host{'s' if count != 1 else ''}"

    # Record display (all MX records)
    record = "\n".join(records)

    # Explanation
    if count >= 2:
        explanation = f"MX records are properly configured with <strong>{count} hosts</strong> for redundancy."
    else:
        explanation = "Only one MX record found. A single mail server is a single point of failure."
    if providers:
        explanation += f" Provider: {', '.join(providers)}."

    # Details
    details = []
    for mx_detail in raw.get("mx_details", []):
        hostname = mx_detail.get("hostname", "")
        priority = mx_detail.get("priority", 0)
        provider = mx_detail.get("provider", "")
        resolved = mx_detail.get("resolved", False)

        provider_note = f" [{provider}]" if provider else ""
        if resolved:
            # Check FCrDNS
            ptr_ok = all(p.get("fcrdns", False) for p in mx_detail.get("ptr_results", []) if p.get("ptr"))
            if ptr_ok:
                details.append({"type": "good", "text": f"Priority {priority}: {hostname}{provider_note} (resolves, FCrDNS valid)"})
            else:
                details.append({"type": "good", "text": f"Priority {priority}: {hostname}{provider_note} (resolves)"})
        else:
            details.append({"type": "error", "text": f"Priority {priority}: {hostname} does not resolve (dangling MX)"})

    if count >= 2:
        details.append({"type": "good", "text": "Multiple MX hosts provide failover redundancy"})
    elif count == 1:
        details.append({"type": "warning", "text": "Single MX host - no failover if it goes down"})

    # Add any issues not already covered
    for issue in raw.get("issues", []):
        severity = issue.get("severity", "info")
        text = issue.get("plain_english") or issue.get("issue", "")
        if "dangling" not in text.lower() and "single" not in text.lower():
            details.append(_issue_to_detail(issue))

    fix = _first_fix(raw.get("issues", []))

    return {
        "name": "MX Records",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
    }


# ============================================================
# MTA-STS
# ============================================================

def transform_mta_sts(raw: Dict, domain: str) -> Dict:
    raw_status = raw.get("status", "warning")
    status = _map_status(raw_status)
    txt_record = raw.get("txt_record")
    policy_mode = raw.get("policy_mode")

    # MTA-STS in enforce mode with no errors should be pass
    if policy_mode == "enforce" and raw_status != "error":
        status = "pass"

    if not txt_record:
        return {
            "name": "MTA-STS",
            "status": "fail",
            "pill_label": "Missing",
            "verdict": "No MTA-STS record found",
            "record": None,
            "explanation": (
                "MTA-STS tells sending mail servers to only deliver email over encrypted TLS "
                "connections. Without it, an attacker could intercept email in transit via a "
                "TLS downgrade attack."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": (
                f"Add a TXT record at <strong>_mta-sts.{domain}</strong> with value "
                f"<strong>v=STSv1; id={datetime.now().strftime('%Y%m%d')}</strong> and host a policy "
                f"file at <strong>https://mta-sts.{domain}/.well-known/mta-sts.txt</strong>"
            ),
        }

    # Has record
    if policy_mode == "enforce":
        verdict = "Mode: enforce (TLS required)"
    elif policy_mode == "testing":
        verdict = "Mode: testing (monitoring)"
    elif policy_mode == "none":
        verdict = "Mode: none (disabled)"
    else:
        verdict = f"Mode: {policy_mode}" if policy_mode else "Record found"

    explanation = ""
    if policy_mode == "enforce":
        explanation = (
            "MTA-STS is in <strong>enforce</strong> mode. Sending servers are required to use "
            "TLS encryption when delivering email to your domain. Connections that can't establish "
            "TLS will fail rather than fall back to plaintext."
        )
    elif policy_mode == "testing":
        explanation = (
            "MTA-STS is in <strong>testing</strong> mode. Senders will attempt TLS but won't "
            "reject delivery if TLS fails. You'll receive TLS-RPT reports to monitor issues. "
            "Move to enforce mode once you've confirmed TLS works reliably."
        )
    elif policy_mode == "none":
        explanation = "MTA-STS is configured but set to <strong>none</strong>, which disables it."

    details = [_issue_to_detail(i) for i in raw.get("issues", [])]
    fix = _first_fix(raw.get("issues", []))
    if not fix and policy_mode == "testing":
        fix = "Move to mode=enforce once TLS-RPT reports confirm reliable TLS delivery."

    return {
        "name": "MTA-STS",
        "status": status,
        "verdict": verdict,
        "record": txt_record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
    }


# ============================================================
# TLS-RPT
# ============================================================

def transform_tls_rpt(raw: Dict, domain: str) -> Dict:
    status = _map_status(raw.get("status", "warning"))
    record = raw.get("record")

    if not record:
        return {
            "name": "TLS-RPT",
            "status": "fail",
            "pill_label": "Missing",
            "verdict": "No TLS-RPT record found",
            "record": None,
            "explanation": (
                "TLS-RPT (TLS Reporting) gives you visibility into TLS delivery failures. "
                "Without it, you have no way to know if email to your domain is being "
                "downgraded to plaintext or failing TLS negotiation."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": (
                f"Add a TXT record at <strong>_smtp._tls.{domain}</strong> with value "
                f"<strong>v=TLSRPTv1; rua=mailto:tls-reports@{domain}</strong>"
            ),
        }

    destinations = raw.get("report_destinations", [])
    verdict = f"Reports to {len(destinations)} destination{'s' if len(destinations) != 1 else ''}"

    explanation = (
        "TLS-RPT is configured. Sending mail servers will report TLS connection failures "
        "when delivering to your domain, giving you visibility into encryption issues."
    )
    if destinations:
        explanation += f" Reports are sent to: {', '.join(destinations[:3])}."

    details = [_issue_to_detail(i) for i in raw.get("issues", [])]
    if destinations:
        details.insert(0, {"type": "good", "text": f"Report delivery configured ({len(destinations)} destination{'s' if len(destinations) != 1 else ''})"})

    fix = _first_fix(raw.get("issues", []))

    return {
        "name": "TLS-RPT",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
    }


# ============================================================
# BIMI
# ============================================================

def transform_bimi(raw: Dict, domain: str) -> Dict:
    status = _map_status(raw.get("status", "info"))
    record = raw.get("record")
    records_found = raw.get("records_found", 0)

    if not record and records_found == 0:
        # BIMI is optional, so "not found" is a soft warning, not a failure
        return {
            "name": "BIMI",
            "status": "warn",
            "pill_label": "Not configured",
            "verdict": "No BIMI record found",
            "record": None,
            "explanation": (
                "BIMI (Brand Indicators for Message Identification) displays your brand logo "
                "next to emails in supporting clients like Gmail and Apple Mail. "
                "It requires DMARC enforcement (p=quarantine or p=reject) as a prerequisite."
            ),
            "details": [
                {"type": "info", "text": "BIMI requires DMARC policy of quarantine or reject"},
                {"type": "info", "text": "Gmail requires a Verified Mark Certificate (VMC) from DigiCert or Entrust"},
            ],
            "fix": (
                f"First ensure DMARC is at p=reject, then publish a BIMI record at "
                f"<strong>default._bimi.{domain}</strong> pointing to your SVG logo."
            ),
        }

    logo_url = raw.get("logo_url")
    vmc_url = raw.get("vmc_url")
    if vmc_url:
        verdict = "VMC verified"
    elif logo_url:
        verdict = "Logo configured"
    else:
        verdict = "Record found"

    explanation = "BIMI record is published."
    if logo_url:
        explanation += " Your brand logo URL is configured."
    if vmc_url:
        explanation += " A Verified Mark Certificate (VMC) is referenced."
    elif not vmc_url:
        explanation += (
            " <strong>Note:</strong> No VMC (Verified Mark Certificate) is specified. "
            "Gmail requires a VMC for BIMI logo display."
        )

    details = [_issue_to_detail(i) for i in raw.get("issues", [])]
    fix = _first_fix(raw.get("issues", []))

    return {
        "name": "BIMI",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
    }


# ============================================================
# DNSSEC
# ============================================================

def transform_dnssec(raw: Dict) -> Dict:
    has_dnssec = raw.get("has_dnssec", False)

    if has_dnssec:
        return {
            "name": "DNSSEC",
            "status": "pass",
            "verdict": "DNSSEC enabled",
            "record": None,
            "explanation": (
                "DNSSEC is enabled. Your DNS records are cryptographically signed, "
                "preventing cache poisoning and DNS spoofing attacks."
            ),
            "details": [
                {"type": "good", "text": "DNSKEY records found (DNSSEC active)"},
            ],
            "fix": None,
        }
    else:
        return {
            "name": "DNSSEC",
            "status": "warn",
            "pill_label": "Not enabled",
            "verdict": "DNSSEC not configured",
            "record": None,
            "explanation": (
                "DNSSEC cryptographically signs your DNS records to prevent spoofing and "
                "cache poisoning attacks. While not required for email authentication, "
                "it strengthens overall DNS security."
            ),
            "details": [
                {"type": "warning", "text": "No DNSKEY records found"},
                {"type": "info", "text": "DNSSEC requires support from both your registrar and DNS host"},
            ],
            "fix": (
                "Enable DNSSEC through your domain registrar or DNS hosting provider. "
                "Most major registrars support one-click DNSSEC activation."
            ),
        }
