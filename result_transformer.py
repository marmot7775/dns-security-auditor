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

        # Append all issues from the audit engine (syntax_errors already merged into issues)
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))
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
    elif raw.get("syntax_errors") or any(i.get("severity") == "error" for i in raw.get("issues", [])):
        # Prioritize syntax/error fixes over generic policy advice
        fix = _first_fix(raw.get("syntax_errors", [])) or _first_fix(raw.get("issues", []))
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
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)
        if all_mech == "+all":
            verdict = "SPF misconfigured (+all)"
        elif lookups > 10:
            verdict = f"SPF over lookup limit ({lookups}/10)"
        elif not all_mech:
            verdict = "SPF record configured (no all mechanism)"
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
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)

        if all_mech == "-all":
            explanation = (
                "SPF record ends with <strong>-all</strong> (hardfail). "
                "Receivers are instructed to reject email from servers not listed in this record."
            )
        elif all_mech == "~all":
            explanation = (
                "SPF record ends with <strong>~all</strong> (softfail). "
                "Email from unlisted servers is accepted but tagged as suspicious. "
                "Most domains pair this with a DMARC policy that determines the final disposition."
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
        elif not all_mech:
            explanation = (
                "SPF record uses a <strong>redirect</strong> modifier instead of an explicit "
                "<strong>all</strong> mechanism. The SPF evaluation is delegated to another domain's record."
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

        all_mech = raw.get("all_mechanism") or ""
        if all_mech == "-all":
            details.append({"type": "good", "text": "-all (hardfail) \u2014 unauthorized servers are rejected"})
        elif all_mech == "~all":
            details.append({"type": "good", "text": "~all (softfail) \u2014 unauthorized senders are flagged but mail is still delivered"})
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

        # Append all issues from the audit engine (syntax_errors already merged into issues)
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))
    else:
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))

    fix = _first_fix(raw.get("issues", []))
    if not fix and record:
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)
        if all_mech in ("?all", "+all") and lookups and lookups > 10:
            fix = (
                "Change the all mechanism to <strong>-all</strong> (hardfail) or <strong>~all</strong> (softfail). "
                "Also reduce SPF lookups to 10 or fewer by flattening includes or removing unused services."
            )
        elif all_mech in ("?all", "+all"):
            fix = "Change the all mechanism to <strong>-all</strong> (hardfail) or <strong>~all</strong> (softfail)."
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

    # Append any issues from the audit engine
    for issue in raw.get("issues", []):
        details.append(_issue_to_detail(issue))

    # Verdict — one piece of data only
    verdict = f"{len(found)} key{'s' if len(found) != 1 else ''} found"

    # Status
    status = "pass"
    if weak_keys:
        status = "warn"
    # Downgrade status if audit engine found errors or warnings
    if raw.get("syntax_errors") or any(i.get("severity") == "error" for i in raw.get("issues", [])):
        status = "fail"
    elif status == "pass" and any(i.get("severity") == "warning" for i in raw.get("issues", [])):
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
    if raw.get("syntax_errors"):
        fix = _first_fix(raw.get("syntax_errors", []))
    elif weak_keys:
        selectors_str = ", ".join(weak_keys)
        fix = (
            f"Upgrade the following 1024-bit keys to 2048-bit or stronger: "
            f"<strong>{selectors_str}</strong>. Contact the corresponding provider to rotate these keys."
        )
    elif raw.get("issues"):
        fix = _first_fix(raw.get("issues", []))

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

    # Verdict — meaningful at a glance
    provider_str = ", ".join(providers) if providers else ""
    if count == 1:
        verdict = f"Single MX host{' — ' + provider_str if provider_str else ''}"
    elif provider_str:
        verdict = provider_str
    else:
        verdict = f"{count} hosts"

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
    algorithms = raw.get("algorithms", [])
    key_count = raw.get("key_count", 0)
    has_ds = raw.get("has_ds", False)
    issues = raw.get("issues", [])
    status = _map_status(raw.get("status", "ok"))

    if not has_dnssec:
        details = [
            {"type": "warning", "text": "No DNSKEY records found"},
            {"type": "info", "text": "DNSSEC requires support from both your registrar and DNS host"},
        ]
        for issue in issues:
            details.append(_issue_to_detail(issue))

        return {
            "name": "DNSSEC",
            "status": "warn",
            "pill_label": "Not enabled",
            "verdict": "DNSSEC not configured",
            "record": None,
            "explanation": (
                "DNSSEC cryptographically signs your DNS records to prevent spoofing and "
                "cache poisoning attacks. While not required for email authentication, "
                "it strengthens overall DNS security and is increasingly expected for "
                "security-conscious organizations."
            ),
            "details": details,
            "fix": (
                "Enable DNSSEC through your domain registrar or DNS hosting provider. "
                "Most major registrars support one-click DNSSEC activation."
            ),
        }

    # Has DNSSEC
    details = []
    details.append({"type": "good", "text": f"DNSKEY records found ({key_count} key{'s' if key_count != 1 else ''})"})

    if has_ds:
        details.append({"type": "good", "text": "DS record present at parent (chain of trust anchored)"})
    else:
        details.append({"type": "warning", "text": "No DS record at parent zone (chain may not validate)"})

    # Show algorithms
    for algo in algorithms:
        if algo.get("deprecated"):
            details.append({"type": "error", "text": f"Algorithm {algo['number']}: {algo['name']}"})
        elif algo.get("legacy"):
            details.append({"type": "warning", "text": f"Algorithm {algo['number']}: {algo['name']}"})
        else:
            details.append({"type": "good", "text": f"Algorithm {algo['number']}: {algo['name']}"})

    # Append issues from audit engine (skip algorithm issues already shown above)
    for issue in issues:
        text = (issue.get("issue") or "").lower()
        if "algorithm" not in text:
            details.append(_issue_to_detail(issue))

    # Verdict
    if algorithms:
        algo_names = [a["name"].split(" (")[0] for a in algorithms]
        verdict = f"DNSSEC enabled ({', '.join(algo_names)})"
    else:
        verdict = "DNSSEC enabled"

    # Downgrade status if issues exist
    if any(a.get("deprecated") for a in algorithms):
        status = "fail"
    elif not has_ds:
        status = "warn"

    fix = _first_fix(issues)
    if not fix and not has_ds:
        fix = "Add a DS record at your domain registrar to complete the DNSSEC chain of trust."

    return {
        "name": "DNSSEC",
        "status": status,
        "verdict": verdict,
        "record": None,
        "explanation": (
            "DNSSEC is enabled. Your DNS records are cryptographically signed, "
            "preventing cache poisoning and DNS spoofing attacks. Resolvers can "
            "verify that DNS responses have not been tampered with."
        ),
        "details": details,
        "fix": fix,
    }


# ============================================================
# CAA
# ============================================================

def transform_caa(raw: Dict, domain: str) -> Dict:
    record_count = raw.get("record_count", 0)
    records = raw.get("records", [])
    authorized_cas = raw.get("authorized_cas", [])
    wildcard_cas = raw.get("wildcard_cas", [])
    has_issue = raw.get("has_issue", False)
    has_issuewild = raw.get("has_issuewild", False)
    has_iodef = raw.get("has_iodef", False)
    iodef_destinations = raw.get("iodef_destinations", [])
    issues = raw.get("issues", [])
    status = _map_status(raw.get("status", "warning"))

    if record_count == 0:
        details = []
        for issue in issues:
            details.append(_issue_to_detail(issue))
        if not details:
            details.append({"type": "warning", "text": "Any Certificate Authority can issue certificates for this domain"})

        return {
            "name": "CAA",
            "status": "warn",
            "pill_label": "Not configured",
            "verdict": "No CAA records found",
            "record": None,
            "explanation": (
                "CAA (Certification Authority Authorization) records specify which Certificate Authorities "
                "are allowed to issue SSL/TLS certificates for your domain. Without CAA records, any CA "
                "can issue certificates, increasing the risk of unauthorized or fraudulent certificate issuance."
            ),
            "details": details,
            "fix": (
                f'Add a CAA record: <strong>0 issue "letsencrypt.org"</strong> (replace with your CA). '
                f'Add <strong>0 iodef "mailto:security@{domain}"</strong> to receive violation alerts.'
            ),
        }

    # Has CAA records
    record_display = "\n".join(r["raw"] for r in records)

    # Build details
    details = []

    if authorized_cas:
        for ca in authorized_cas:
            details.append({"type": "good", "text": f"Authorized CA: {ca}"})
    elif has_issue:
        details.append({"type": "info", "text": "Certificate issuance restricted (issue \";\")"})

    if wildcard_cas:
        for ca in wildcard_cas:
            details.append({"type": "good", "text": f"Wildcard CA: {ca}"})
    elif has_issuewild:
        details.append({"type": "info", "text": "Wildcard issuance blocked (issuewild \";\")"})

    if has_iodef:
        for dest in iodef_destinations:
            details.append({"type": "good", "text": f"Violation reports: {dest}"})
    
    if has_issue and has_issuewild and has_iodef:
        details.append({"type": "good", "text": "Complete CAA configuration (issue + issuewild + iodef)"})

    # Append issues
    for issue in issues:
        details.append(_issue_to_detail(issue))

    # Verdict
    if authorized_cas:
        if len(authorized_cas) == 1:
            verdict = f"Restricted to {authorized_cas[0]}"
        else:
            verdict = f"{len(authorized_cas)} CAs authorized"
    else:
        verdict = "Certificate issuance restricted"

    # Status logic
    if any(i.get("severity") == "error" for i in issues):
        status = "fail"
    elif record_count > 0 and has_issue:
        status = "pass"

    fix = _first_fix(issues)

    return {
        "name": "CAA",
        "status": status,
        "verdict": verdict,
        "record": record_display,
        "explanation": (
            "CAA records restrict which Certificate Authorities can issue SSL/TLS certificates "
            "for your domain. This prevents unauthorized CAs from issuing certificates that "
            "could be used in man-in-the-middle attacks."
        ),
        "details": details,
        "fix": fix,
    }


# ============================================================
# DANE
# ============================================================

def transform_dane(raw: Dict, domain: str) -> Dict:
    has_tlsa = raw.get("has_tlsa", False)
    dnssec_ok = raw.get("dnssec_validated", False)
    mx_checked = raw.get("mx_hosts_checked", 0)
    mx_with_tlsa = raw.get("mx_hosts_with_tlsa", 0)
    tlsa_records = raw.get("tlsa_records", [])
    issues = raw.get("issues", [])

    # No MX hosts to check
    if mx_checked == 0:
        return {
            "name": "DANE",
            "status": "pass",
            "pill_label": "N/A",
            "verdict": "No MX hosts to check",
            "record": None,
            "explanation": (
                "DANE (DNS-Based Authentication of Named Entities) publishes TLSA records "
                "to let sending servers verify mail server TLS certificates via DNS. "
                "This domain has no MX records, so there are no mail servers to protect with DANE."
            ),
            "details": [{"type": "info", "text": "No MX hosts — DANE check not applicable"}],
            "fix": None,
        }

    # Has TLSA but no DNSSEC
    if has_tlsa and not dnssec_ok:
        details = []
        for hr in tlsa_records:
            if hr.get("found"):
                for rec in hr.get("records", []):
                    details.append({
                        "type": "info",
                        "text": f"{hr['mx_host']}: {rec['usage_name']}, {rec['selector_name']}, {rec['matching_type_name']}"
                    })
        details.append({
            "type": "error",
            "text": "TLSA records found but DNSSEC is not enabled — DANE is ineffective"
        })
        for issue in issues:
            if "dnssec" not in (issue.get("issue") or "").lower():
                details.append(_issue_to_detail(issue))

        return {
            "name": "DANE",
            "status": "warn",
            "verdict": f"TLSA found but DNSSEC missing",
            "record": None,
            "explanation": (
                "DANE TLSA records are published for your MX hosts, but DNSSEC is not enabled. "
                "Without DNSSEC, an attacker can spoof or strip TLSA records, completely defeating DANE. "
                "RFC 7672-compliant senders will ignore these TLSA records until DNSSEC is active."
            ),
            "details": details,
            "fix": "Enable DNSSEC for your domain before relying on DANE. Once DNSSEC is active, your existing TLSA records will become effective.",
        }

    # Has TLSA + DNSSEC
    if has_tlsa and dnssec_ok:
        details = []
        for hr in tlsa_records:
            if hr.get("found"):
                for rec in hr.get("records", []):
                    details.append({
                        "type": "good",
                        "text": f"{hr['mx_host']}: {rec['usage_name']}, {rec['selector_name']}, {rec['matching_type_name']}"
                    })
            elif hr.get("error"):
                details.append({"type": "warning", "text": f"{hr['mx_host']}: {hr['error']}"})

        if mx_with_tlsa == mx_checked:
            details.append({"type": "good", "text": f"All {mx_checked} MX host{'s' if mx_checked != 1 else ''} have TLSA records"})
        else:
            missing = [h["mx_host"] for h in tlsa_records if not h["found"] and not h.get("error")]
            if missing:
                details.append({"type": "warning", "text": f"Missing DANE on: {', '.join(missing)}"})

        details.append({"type": "good", "text": "DNSSEC is enabled — DANE chain of trust is valid"})

        for issue in issues:
            details.append(_issue_to_detail(issue))

        status = "pass"
        if any(i.get("severity") == "warning" for i in issues) or mx_with_tlsa < mx_checked:
            status = "warn"

        verdict = f"DANE-protected ({mx_with_tlsa}/{mx_checked} MX hosts)"
        fix = _first_fix(issues)
        if not fix and mx_with_tlsa < mx_checked:
            missing = [h["mx_host"] for h in tlsa_records if not h["found"]]
            fix = f"Add TLSA records for: {', '.join(missing)}"

        return {
            "name": "DANE",
            "status": status,
            "verdict": verdict,
            "record": None,
            "explanation": (
                "DANE is configured and secured with DNSSEC. Sending mail servers that support "
                "DANE can verify your mail server's TLS certificate through DNS, preventing "
                "man-in-the-middle attacks even if a Certificate Authority is compromised."
            ),
            "details": details,
            "fix": fix,
        }

    # No TLSA, has MX
    details = [
        {"type": "warning", "text": f"Checked {mx_checked} MX host{'s' if mx_checked != 1 else ''} — no TLSA records found"},
    ]
    if dnssec_ok:
        details.append({"type": "good", "text": "DNSSEC is enabled — ready for DANE deployment"})
    else:
        details.append({"type": "info", "text": "DNSSEC is also required for DANE to work"})

    for issue in issues:
        details.append(_issue_to_detail(issue))

    # Build example TLSA record using first MX host
    example_host = tlsa_records[0]["mx_host"] if tlsa_records else "mail.example.com"
    fix = (
        f"Publish a TLSA record for each MX host. Example for {example_host}:<br>"
        f"<strong>_25._tcp.{example_host}</strong> IN TLSA <strong>3 1 1 &lt;SHA-256 hash of server certificate SPKI&gt;</strong><br><br>"
        f"Usage 3 (DANE-EE), selector 1 (SPKI), matching type 1 (SHA-256) is the recommended configuration per RFC 7672."
    )
    if not dnssec_ok:
        fix += " <strong>Note:</strong> Enable DNSSEC first — DANE requires it."

    return {
        "name": "DANE",
        "status": "warn",
        "pill_label": "Not configured",
        "verdict": "No DANE TLSA records",
        "record": None,
        "explanation": (
            "DANE (DNS-Based Authentication of Named Entities) uses TLSA records to let sending "
            "mail servers verify your mail server's TLS certificate through DNS. This provides "
            "stronger security than relying on Certificate Authorities alone, and complements MTA-STS."
        ),
        "details": details,
        "fix": fix,
    }


# ============================================================
# Nameservers
# ============================================================

def transform_nameservers(raw: Dict) -> Dict:
    ns_count = raw.get("ns_count", 0)
    nameservers = raw.get("nameservers", [])
    providers = raw.get("providers", [])
    networks = raw.get("networks", [])
    issues = raw.get("issues", [])
    status = _map_status(raw.get("status", "ok"))

    if ns_count == 0:
        details = []
        for issue in issues:
            details.append(_issue_to_detail(issue))

        return {
            "name": "Nameservers",
            "status": "fail",
            "pill_label": "Missing",
            "verdict": "No nameservers found",
            "record": None,
            "explanation": (
                "No nameserver records could be found for this domain. Nameservers are the "
                "foundation of DNS -- without them, nothing works: no website, no email, nothing."
            ),
            "details": details,
            "fix": "Configure NS records with your domain registrar.",
        }

    # Build record display
    record_lines = []
    for ns in nameservers:
        ips = []
        if ns.get("ipv4"):
            ips.extend(ns["ipv4"])
        if ns.get("ipv6"):
            ips.extend(ns["ipv6"])
        ip_str = f" ({', '.join(ips)})" if ips else ""
        record_lines.append(f"{ns['hostname']}{ip_str}")
    record = "\n".join(record_lines)

    # Details
    details = []

    # NS count
    if ns_count >= 3:
        details.append({"type": "good", "text": f"{ns_count} nameservers configured (good redundancy)"})
    elif ns_count == 2:
        details.append({"type": "good", "text": "2 nameservers configured (minimum redundancy)"})
    elif ns_count == 1:
        details.append({"type": "error", "text": "Only 1 nameserver (single point of failure)"})

    # Resolution status
    resolving = [ns for ns in nameservers if ns.get("resolves")]
    not_resolving = [ns for ns in nameservers if not ns.get("resolves")]
    if not_resolving:
        for ns in not_resolving:
            details.append({"type": "error", "text": f"{ns['hostname']} does not resolve (lame delegation)"})
    if resolving:
        for ns in resolving:
            ipv4_str = ", ".join(ns.get("ipv4", []))
            ipv6_count = len(ns.get("ipv6", []))
            ip_info = ipv4_str
            if ipv6_count:
                ip_info += f" + {ipv6_count} IPv6"
            if ip_info:
                details.append({"type": "good", "text": f"{ns['hostname']} resolves ({ip_info})"})
            else:
                details.append({"type": "good", "text": f"{ns['hostname']} resolves"})

    # Network diversity
    if len(networks) >= 2:
        details.append({"type": "good", "text": f"Network diversity: {len(networks)} distinct /24 networks"})

    # Providers
    if providers:
        if len(providers) >= 2:
            details.append({"type": "good", "text": f"Multi-provider: {', '.join(providers)}"})
        else:
            details.append({"type": "info", "text": f"Provider: {providers[0]}"})

    # IPv6
    has_ipv6 = any(ns.get("ipv6") for ns in nameservers)
    if has_ipv6:
        details.append({"type": "good", "text": "IPv6 nameserver support (AAAA records present)"})

    # Append issues (skip ones already covered by hardcoded details above)
    covered_keywords = {"only one nameserver", "lame delegation", "does not resolve"}
    for issue in issues:
        text = (issue.get("issue") or "").lower()
        if not any(kw in text for kw in covered_keywords):
            details.append(_issue_to_detail(issue))

    # Verdict
    if providers:
        verdict = ", ".join(providers)
    else:
        verdict = f"{ns_count} nameserver{'s' if ns_count != 1 else ''}"

    # Fix
    fix = _first_fix(issues)

    return {
        "name": "Nameservers",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": (
            f"Found <strong>{ns_count}</strong> nameserver{'s' if ns_count != 1 else ''} for this domain. "
            "Nameservers are the foundation of your DNS -- they answer every query for your domain. "
            "Redundancy and network diversity are critical to prevent outages."
        ),
        "details": details,
        "fix": fix,
    }
