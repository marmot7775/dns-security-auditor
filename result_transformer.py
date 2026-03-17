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
from datetime import datetime, timezone

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

def transform_dmarc(raw: Dict, tree_walk: Optional[Dict] = None) -> Dict:
    status = _map_status(raw.get("status", "error"))
    policy = raw.get("policy", "")
    record = raw.get("record")
    pill_label = None

    # Check if this domain inherits policy via tree walk
    inherited = (
        not record
        and tree_walk
        and tree_walk.get("policy_source")
        and tree_walk.get("is_subdomain")
    )
    inherited_policy = tree_walk.get("effective_policy") if inherited else None
    inherited_source = tree_walk.get("policy_source") if inherited else None

    # Build verdict
    if inherited:
        verdict = f"Inherited: {inherited_policy} (from {inherited_source})"
        if inherited_policy == "reject":
            status = "pass"
        elif inherited_policy == "quarantine":
            status = "pass"
        elif inherited_policy == "none":
            status = "warn"
        pill_label = "Inherited"
    elif not record:
        verdict = "No DMARC record found"
        pill_label = "Missing"
    elif policy == "reject":
        verdict = "Policy: reject (strongest)"
    elif policy == "quarantine":
        pct = raw.get("pct", 100)
        verdict = "Policy: quarantine"
        if pct and pct < 100:
            verdict += f" ({pct}%)"
    elif policy == "none":
        verdict = "Policy: none (monitoring only)"
    else:
        verdict = f"Policy: {policy}" if policy else "Invalid record"

    # Build explanation
    if inherited:
        applied_tag = tree_walk.get("applied_tag", "p")
        tag_label = {"sp": "subdomain policy (sp=)", "np": "non-existent subdomain policy (np=)", "p": "domain policy (p=)"}.get(applied_tag, f"{applied_tag}=")
        _adoption_note = (
            " However, policy inheritance via tree walk is a DMARCbis feature. "
            "Receivers still using RFC 7489 may not honor it. For the strongest protection, "
            "publish a dedicated DMARC record for this subdomain."
        )
        if inherited_policy == "reject":
            explanation = (
                f"This subdomain does not have its own DMARC record at "
                f"<strong>_dmarc.{raw.get('domain', '')}</strong>, but it inherits "
                f"<strong>p=reject</strong> from <strong>{inherited_source}</strong> "
                f"via the {tag_label} tag. "
                f"This is the gold standard. Emails that fail authentication are blocked entirely."
                + _adoption_note
            )
        elif inherited_policy == "quarantine":
            explanation = (
                f"This subdomain does not have its own DMARC record at "
                f"<strong>_dmarc.{raw.get('domain', '')}</strong>, but it inherits "
                f"<strong>p=quarantine</strong> from <strong>{inherited_source}</strong> "
                f"via the {tag_label} tag. "
                f"Emails that fail authentication are routed to the recipient's spam folder."
                + _adoption_note
            )
        elif inherited_policy == "none":
            explanation = (
                f"This subdomain does not have its own DMARC record at "
                f"<strong>_dmarc.{raw.get('domain', '')}</strong>, but it inherits "
                f"<strong>p=none</strong> from <strong>{inherited_source}</strong> "
                f"via the {tag_label} tag. "
                f"This is monitoring only. Failed emails are still delivered normally."
                + _adoption_note
            )
        else:
            explanation = (
                f"This subdomain inherits DMARC policy <strong>{inherited_policy}</strong> "
                f"from <strong>{inherited_source}</strong>."
                + _adoption_note
            )
    elif not record:
        explanation = (
            f"No DMARC record exists at <strong>_dmarc.{raw.get('domain', '')}</strong>. "
            f"DMARC tells receiving mail servers "
            f"(Gmail, Outlook, Yahoo) how to handle emails that fail SPF and DKIM authentication. "
            f"Without it, anyone can send emails impersonating your domain with no consequences, "
            f"and you have no visibility into who is sending as your domain."
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
    if inherited:
        applied_tag = tree_walk.get("applied_tag", "p")
        if inherited_policy == "reject":
            details.append({"type": "good", "text": f"Effective policy: reject (inherited from {inherited_source})"})
        elif inherited_policy == "quarantine":
            details.append({"type": "good", "text": f"Effective policy: quarantine (inherited from {inherited_source})"})
        elif inherited_policy == "none":
            details.append({"type": "warning", "text": f"Effective policy: none (inherited from {inherited_source})"})

        details.append({"type": "info", "text": f"No record at _dmarc.{raw.get('domain', '')}. Policy found via tree walk"})
        details.append({"type": "info", "text": f"Applied tag: {applied_tag}= from {inherited_source}"})

        if tree_walk.get("org_domain"):
            details.append({"type": "info", "text": f"Organizational domain: {tree_walk['org_domain']}"})

    elif record:
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
    if inherited:
        if inherited_policy == "none":
            fix = (
                f"The inherited policy from <strong>{inherited_source}</strong> is p=none (monitoring only). "
                f"Either upgrade the parent domain's policy to p=quarantine or p=reject, "
                f"or publish a dedicated DMARC record at <strong>_dmarc.{domain_name}</strong> with a stronger policy."
            )
        elif inherited_policy == "quarantine":
            fix = (
                f"This subdomain is protected by p=quarantine inherited from <strong>{inherited_source}</strong>. "
                f"If you control the parent domain, consider upgrading to p=reject for maximum protection. "
                f"Alternatively, you can publish a dedicated record at <strong>_dmarc.{domain_name}</strong>."
            )
        else:
            # reject — no fix needed
            fix = None
    elif not record:
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

    # For inherited policy, show the parent's record
    display_record = record
    if inherited and not display_record:
        # Pull record from tree walk steps
        for step in (tree_walk.get("steps") or []):
            if step.get("found") and step.get("record"):
                display_record = step["record"]
                break

    # Fix records — copy-paste-ready DNS records
    fix_records = []
    if not record and not inherited:
        fix_records.append({
            "type": "TXT",
            "host": f"_dmarc.{domain_name}",
            "value": f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain_name}; fo=1",
            "comment": "Start with p=none to monitor, then upgrade to p=quarantine, then p=reject",
        })
    elif record and policy == "none":
        fix_records.append({
            "type": "TXT",
            "host": f"_dmarc.{domain_name}",
            "value": f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain_name}; fo=1",
            "comment": "Upgrade to p=reject only after confirming all legitimate senders pass SPF/DKIM",
        })
    elif inherited and inherited_policy == "none":
        fix_records.append({
            "type": "TXT",
            "host": f"_dmarc.{domain_name}",
            "value": f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain_name}; fo=1",
            "comment": "Publish a dedicated record with stronger enforcement than the inherited p=none",
        })

    return {
        "name": "DMARC",
        "status": status,
        "pill_label": pill_label,
        "verdict": verdict,
        "record": display_record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": fix_records if fix_records else None,
    }


# ============================================================
# SPF
# ============================================================

def _is_null_spf(record: str) -> bool:
    """Detect a null SPF record: v=spf1 -all or v=spf1 ~all with no senders.
    This is an intentional signal meaning 'this domain does not send email.'"""
    if not record:
        return False
    parts = record.strip().lower().split()
    # v=spf1 followed by only an all mechanism, nothing else
    if len(parts) == 2 and parts[0] == "v=spf1" and parts[1] in ("-all", "~all"):
        return True
    return False


def transform_spf(raw: Dict, has_mx: bool = True) -> Dict:
    status = _map_status(raw.get("status", "error"))
    record = raw.get("record")
    pill_label = None
    null_spf = _is_null_spf(record)

    # Verdict
    if null_spf:
        verdict = "Null SPF (domain does not send email)"
        pill_label = "No mail"
    elif not record and not has_mx:
        verdict = "No SPF record (no mail)"
        pill_label = "No mail"
    elif not record:
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
    if null_spf:
        all_mech = raw.get("all_mechanism") or ""
        explanation = (
            f"This domain publishes a null SPF record (<strong>v=spf1 {all_mech}</strong>), "
            f"which explicitly declares that no servers are authorized to send email for this domain. "
            f"This is correct configuration for domains that do not send email."
        )
    elif not record and not has_mx:
        explanation = (
            "No SPF record found, but this domain also has no MX records, "
            "which means it does not send or receive email. "
            "For best practice, consider publishing a null SPF record "
            "(<strong>v=spf1 -all</strong>) to explicitly signal that this domain does not send email."
        )
    elif not record:
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
    if null_spf:
        all_mech = raw.get("all_mechanism") or ""
        details.append({"type": "good", "text": f"Null SPF record (v=spf1 {all_mech})"})
        details.append({"type": "good", "text": "Explicitly declares this domain does not send email"})
        status = "pass"
    elif not record and not has_mx:
        details.append({"type": "info", "text": "No SPF record and no MX records"})
        details.append({"type": "info", "text": "This domain does not appear to send or receive email"})
        status = "warn"
    elif record:
        lookups = raw.get("lookup_count", 0)
        if lookups <= 8:
            details.append({"type": "good", "text": f"{lookups} DNS lookups (well within the 10-lookup limit)"})
        elif lookups <= 10:
            details.append({"type": "warning", "text": f"{lookups} DNS lookups ({'at' if lookups == 10 else 'near'} the 10-lookup limit)"})
        else:
            details.append({"type": "error", "text": f"{lookups} DNS lookups (EXCEEDS the 10-lookup limit!)"})

        all_mech = raw.get("all_mechanism") or ""
        if all_mech == "-all":
            details.append({"type": "good", "text": "-all (hardfail). Unauthorized servers are rejected"})
        elif all_mech == "~all":
            details.append({"type": "good", "text": "~all (softfail). Unauthorized senders are flagged but mail is still delivered"})
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

    # Fix
    fix = None
    if null_spf:
        # Null SPF is correct, no fix needed
        pass
    elif not record and not has_mx:
        fix = (
            "Publish a null SPF record (<strong>v=spf1 -all</strong>) to explicitly signal "
            "that this domain does not send email. This is a best practice that helps prevent spoofing."
        )
    else:
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

    # Fix records
    fix_records = []
    domain_name = raw.get("domain", "")
    if null_spf:
        # Already correct, no fix records
        pass
    elif not record and not has_mx:
        fix_records.append({
            "type": "TXT",
            "host": domain_name,
            "value": "v=spf1 -all",
            "comment": "Null SPF record. Declares this domain does not send email",
        })
    elif not record:
        fix_records.append({
            "type": "TXT",
            "host": domain_name,
            "value": "v=spf1 ~all",
            "comment": "Starter record. Add your mail server IPs and include mechanisms before tightening to -all",
        })
    elif record:
        all_mech = raw.get("all_mechanism") or ""
        if all_mech == "+all":
            # Replace +all with ~all in the existing record
            fixed_record = record.replace("+all", "~all")
            fix_records.append({
                "type": "TXT",
                "host": domain_name,
                "value": fixed_record,
                "comment": "Replaced dangerous +all with ~all (softfail)",
            })
        elif all_mech == "?all":
            fixed_record = record.replace("?all", "~all")
            fix_records.append({
                "type": "TXT",
                "host": domain_name,
                "value": fixed_record,
                "comment": "Replaced neutral ?all with ~all (softfail)",
            })

    return {
        "name": "SPF",
        "status": status,
        "pill_label": pill_label if not record else None,
        "verdict": verdict,
        "record": record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": fix_records if fix_records else None,
    }


# ============================================================
# DKIM
# ============================================================

def transform_dkim(raw: Dict, domain: str, has_mx: bool = True) -> Dict:
    found = raw.get("found_selectors", [])
    tested = raw.get("tested_count", 0)

    if not found:
        # No DKIM keys found. If the domain has no MX records it doesn't send email,
        # so the absence of DKIM keys is expected and not actionable.
        if not has_mx:
            return {
                "name": "DKIM",
                "status": "pass",
                "pill_label": "N/A",
                "verdict": "No mail domain",
                "record": None,
                "explanation": (
                    "This domain has no MX records, so it does not send or receive email. "
                    "DKIM signing is not applicable."
                ),
                "details": [
                    {"type": "info", "text": "No MX records - domain does not handle email"},
                    {"type": "info", "text": "DKIM is only relevant for domains that send email"},
                ],
                "fix": None,
                "fix_records": None,
            }

        return {
            "name": "DKIM",
            "status": "warn",
            "pill_label": "Not detected",
            "verdict": f"No DKIM keys detected ({tested} selectors tested)",
            "record": None,
            "explanation": (
                "No DKIM signing keys were found after checking {tested} common selectors. "
                "This does not necessarily mean DKIM is not configured. Your provider may use "
                "custom or non-standard selectors that weren't in our test list. "
                "DKIM adds a cryptographic signature to outgoing emails that proves the message "
                "hasn't been tampered with and verifies the sending domain."
            ).format(tested=tested),
            "details": [
                {"type": "warning", "text": f"Tested {tested} common selectors, but no public keys found in DNS"},
                {"type": "info", "text": "DKIM selectors are provider-specific and not publicly enumerable"},
                {"type": "info", "text": "The DKIM public key is a TXT record in DNS at selector._domainkey.{domain}".format(domain=domain)},
            ],
            "fix": (
                "Verify DKIM signing is enabled and confirm the public key TXT record is published in DNS at "
                "<strong>selector._domainkey.{domain}</strong>. "
                "Your email provider can tell you which selector name to use."
            ).format(domain=domain),
            "fix_records": None,  # DKIM keys must be generated by the email provider
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
        "fix_records": None,  # DKIM keys are generated by email providers, not manually
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
            "status": "warn",
            "pill_label": "None",
            "verdict": "No MX records found",
            "record": None,
            "explanation": (
                "No MX records exist for this domain. If this domain is not intended to "
                "receive email, this is expected and no action is needed. If the domain "
                "should receive email, MX records tell other mail servers where to deliver "
                "messages addressed to it."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": (
                "If this domain should receive email, add an MX record pointing to your "
                "mail server. If it is not meant to receive email, no action is required."
            ),
            "fix_records": None,  # MX records depend on the user's mail infrastructure
        }

    # Verdict — meaningful at a glance
    provider_str = ", ".join(providers) if providers else ""
    if count == 1:
        verdict = f"Single MX host{' (' + provider_str + ')' if provider_str else ''}"
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
        "fix_records": None,
    }


# ============================================================
# MTA-STS
# ============================================================

def transform_mta_sts(raw: Dict, domain: str, has_mx: bool = True) -> Dict:
    raw_status = raw.get("status", "warning")
    status = _map_status(raw_status)
    txt_record = raw.get("txt_record")
    policy_mode = raw.get("policy_mode")

    # MTA-STS in enforce mode with no errors should be pass
    if policy_mode == "enforce" and raw_status != "error":
        status = "pass"

    if not txt_record:
        # MTA-STS protects inbound delivery, so it is only relevant for domains with MX records.
        if not has_mx:
            return {
                "name": "MTA-STS",
                "status": "pass",
                "pill_label": "N/A",
                "verdict": "No mail domain",
                "record": None,
                "explanation": (
                    "MTA-STS protects inbound email delivery by requiring TLS encryption. "
                    "This domain has no MX records, so it does not receive email and "
                    "MTA-STS is not applicable."
                ),
                "details": [
                    {"type": "info", "text": "No MX records - domain does not receive email"},
                    {"type": "info", "text": "MTA-STS is only relevant for domains with MX records"},
                ],
                "fix": None,
                "fix_records": None,
            }

        sts_id = datetime.now(timezone.utc).strftime('%Y%m%d')
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
                f"Consider implementing MTA-STS to enforce TLS for inbound email. "
                f"Add a TXT record at <strong>_mta-sts.{domain}</strong> with value "
                f"<strong>v=STSv1; id={sts_id}</strong> and host a policy "
                f"file at <strong>https://mta-sts.{domain}/.well-known/mta-sts.txt</strong>"
            ),
            "fix_records": [{
                "type": "TXT",
                "host": f"_mta-sts.{domain}",
                "value": f"v=STSv1; id={sts_id}",
                "comment": "Also host a policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt".format(domain=domain),
            }],
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
        "fix_records": None,
    }


# ============================================================
# TLS-RPT
# ============================================================

def transform_tls_rpt(raw: Dict, domain: str, has_mx: bool = True) -> Dict:
    status = _map_status(raw.get("status", "warning"))
    record = raw.get("record")

    if not record:
        # TLS-RPT reports on inbound TLS delivery issues, so it only makes sense for
        # domains that receive email (i.e. have MX records).
        if not has_mx:
            return {
                "name": "TLS-RPT",
                "status": "pass",
                "pill_label": "N/A",
                "verdict": "No mail domain",
                "record": None,
                "explanation": (
                    "TLS-RPT reports on TLS encryption failures during inbound email delivery. "
                    "This domain has no MX records, so it does not receive email and "
                    "TLS-RPT is not applicable."
                ),
                "details": [
                    {"type": "info", "text": "No MX records - domain does not receive email"},
                    {"type": "info", "text": "TLS-RPT is only relevant for domains with MX records"},
                ],
                "fix": None,
                "fix_records": None,
            }

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
                f"Consider adding TLS-RPT to gain visibility into TLS delivery failures. "
                f"Add a TXT record at <strong>_smtp._tls.{domain}</strong> with value "
                f"<strong>v=TLSRPTv1; rua=mailto:tls-reports@{domain}</strong>"
            ),
            "fix_records": [{
                "type": "TXT",
                "host": f"_smtp._tls.{domain}",
                "value": f"v=TLSRPTv1; rua=mailto:tls-reports@{domain}",
                "comment": "Replace tls-reports@{domain} with your preferred reporting address".format(domain=domain),
            }],
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
        "fix_records": None,
    }


# ============================================================
# BIMI
# ============================================================

def transform_bimi(raw: Dict, domain: str, has_mx: bool = True) -> Dict:
    status = _map_status(raw.get("status", "info"))
    record = raw.get("record")
    records_found = raw.get("records_found", 0)

    if not record and records_found == 0:
        # BIMI is an email branding feature, so it only applies to domains that send email.
        if not has_mx:
            return {
                "name": "BIMI",
                "status": "pass",
                "pill_label": "N/A",
                "verdict": "No mail domain",
                "record": None,
                "explanation": (
                    "BIMI displays a brand logo next to emails in supporting mail clients. "
                    "This domain has no MX records, so it does not handle email and "
                    "BIMI is not applicable."
                ),
                "details": [
                    {"type": "info", "text": "No MX records - domain does not handle email"},
                    {"type": "info", "text": "BIMI is only relevant for domains that send email"},
                ],
                "fix": None,
                "fix_records": None,
            }

        # BIMI is optional, so "not found" is a soft warning, not a failure
        return {
            "name": "BIMI",
            "status": "warn",
            "pill_label": "Not configured",
            "verdict": "No BIMI record found",
            "record": None,
            "explanation": (
                "BIMI (Brand Indicators for Message Identification) is not a security protocol. "
                "It is a brand trust and recognition feature that displays your logo next to "
                "emails in supporting clients like Gmail and Apple Mail, helping recipients "
                "identify legitimate messages from your organization at a glance. "
                "It requires DMARC enforcement (p=quarantine or p=reject) as a prerequisite."
            ),
            "details": [
                {"type": "info", "text": "BIMI is about brand trust and recognition, not security"},
                {"type": "info", "text": "Requires DMARC policy of quarantine or reject"},
                {"type": "info", "text": "Gmail requires a Verified Mark Certificate (VMC) from DigiCert or Entrust"},
            ],
            "fix": (
                f"If you want your brand logo displayed in email clients, ensure DMARC is at p=quarantine or p=reject "
                f"(with pct=100), then publish a BIMI record at "
                f"<strong>default._bimi.{domain}</strong> pointing to your SVG logo."
            ),
            "fix_records": [{
                "type": "TXT",
                "host": f"default._bimi.{domain}",
                "value": "v=BIMI1; l=https://example.com/logo.svg;",
                "comment": "Replace URL with your brand's SVG logo (must be a Tiny P/S SVG). Add a= for VMC if using Gmail",
            }],
        }

    logo_url = raw.get("logo_url")
    vmc_url = raw.get("vmc_url")
    if vmc_url:
        verdict = "VMC verified"
    elif logo_url:
        verdict = "Logo configured"
    else:
        verdict = "Record found"

    explanation = "BIMI record is published. BIMI is a brand trust and recognition feature, not a security protocol."
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
        "fix_records": None,
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
                "Consider enabling DNSSEC through your domain registrar or DNS hosting provider. "
                "Most major registrars support one-click DNSSEC activation."
            ),
            "fix_records": None,  # DNSSEC requires registrar/DNS provider activation, not manual DNS records
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
        "fix_records": None,
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
                f"Consider adding CAA records to restrict which certificate authorities can issue "
                f"certificates for your domain. Set the issue tag to your CA (for example, letsencrypt.org) "
                f"and add an iodef tag to receive violation alerts."
            ),
            "fix_records": [
                {
                    "type": "CAA",
                    "host": domain,
                    "value": '0 issue "letsencrypt.org"',
                    "comment": "Replace letsencrypt.org with your Certificate Authority",
                },
                {
                    "type": "CAA",
                    "host": domain,
                    "value": f'0 iodef "mailto:security@{domain}"',
                    "comment": "Receive alerts when an unauthorized CA attempts to issue a certificate",
                },
            ],
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
        "fix_records": None,
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
            "details": [{"type": "info", "text": "No MX hosts. DANE check not applicable"}],
            "fix": None,
            "fix_records": None,
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
            "text": "TLSA records found but DNSSEC is not enabled, so DANE is ineffective"
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
            "fix_records": None,  # DNSSEC activation required first; TLSA records already exist
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

        details.append({"type": "good", "text": "DNSSEC is enabled and the DANE chain of trust is valid"})

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
            "fix_records": None,
        }

    # No TLSA, has MX
    details = [
        {"type": "warning", "text": f"Checked {mx_checked} MX host{'s' if mx_checked != 1 else ''}, but no TLSA records found"},
    ]
    if dnssec_ok:
        details.append({"type": "good", "text": "DNSSEC is enabled and ready for DANE deployment"})
    else:
        details.append({"type": "info", "text": "DNSSEC is also required for DANE to work"})

    for issue in issues:
        details.append(_issue_to_detail(issue))

    # Build example TLSA record using first MX host
    example_host = tlsa_records[0]["mx_host"] if tlsa_records else "mail.example.com"
    fix = (
        "Consider publishing DANE TLSA records for your MX hosts to add DNS-based certificate "
        "verification for inbound email."
    )
    if not dnssec_ok:
        fix += " <strong>Note:</strong> DNSSEC must be enabled before DANE can take effect."

    # Generate example TLSA fix record for the no-TLSA case
    dane_fix_records = None
    if tlsa_records:
        example_host = tlsa_records[0]["mx_host"]
        dane_fix_records = [{
            "type": "TLSA",
            "host": f"_25._tcp.{example_host}",
            "value": "3 1 1 <SHA-256 hash of your mail server certificate SPKI>",
            "comment": "Usage 3 (DANE-EE), Selector 1 (SPKI), Matching 1 (SHA-256). Generate hash with: openssl x509 -noout -pubkey -in cert.pem | openssl pkey -pubin -outform DER | openssl dgst -sha256",
        }]

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
        "fix_records": dane_fix_records,
    }


# ============================================================
# Nameservers
# ============================================================

def _is_subdomain(domain: str) -> bool:
    """Return True if the domain appears to be a subdomain (3 or more labels)."""
    if not domain:
        return False
    labels = domain.rstrip(".").split(".")
    return len(labels) >= 3


def transform_nameservers(raw: Dict, domain: str = "") -> Dict:
    ns_count = raw.get("ns_count", 0)
    nameservers = raw.get("nameservers", [])
    providers = raw.get("providers", [])
    networks = raw.get("networks", [])
    issues = raw.get("issues", [])
    status = _map_status(raw.get("status", "ok"))

    if ns_count == 0:
        if _is_subdomain(domain):
            return {
                "name": "Nameservers",
                "status": "pass",
                "pill_label": "Inherited",
                "verdict": "Nameservers inherited from parent zone",
                "record": None,
                "explanation": (
                    "This is a subdomain, so it uses the nameservers from its parent zone. "
                    "This is normal. Subdomains do not need their own NS delegation unless "
                    "they are a separate DNS zone."
                ),
                "details": [
                    {"type": "info", "text": "Subdomain - NS records are at the parent zone level"},
                ],
                "fix": None,
                "fix_records": None,
            }

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
                "foundation of DNS. Without them, nothing works: no website, no email, no DNS resolution."
            ),
            "details": details,
            "fix": "Configure NS records with your domain registrar.",
            "fix_records": None,
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
            "Nameservers are the foundation of your DNS. They answer every query for your domain. "
            "Redundancy and network diversity are critical to prevent outages."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
    }


# ============================================================
# Certificate Transparency
# ============================================================

def transform_ct(raw: Dict, domain: str) -> Dict:
    total = raw.get("total_certs", 0)
    active = raw.get("active_certs", 0)
    issuers = raw.get("issuers", [])
    wildcards = raw.get("wildcards", [])
    expiring = raw.get("expiring_soon", [])
    expired = raw.get("expired_recent", [])
    subdomains = raw.get("subdomains_found", [])
    caa_mismatches = raw.get("caa_mismatches", [])
    issues = raw.get("issues", [])

    # No certs found
    if total == 0:
        return {
            "name": "Certificate Transparency",
            "status": "pass",
            "pill_label": "No certs",
            "verdict": "No certificates found in CT logs",
            "record": None,
            "explanation": (
                "No certificates were found in Certificate Transparency logs for this domain. "
                "This likely means the domain has never had HTTPS configured."
            ),
            "details": [
                {"type": "info", "text": "No certificates found in public CT logs"},
            ],
            "fix": None,
            "fix_records": None,
        }

    # Determine status
    status = "pass"
    pill_label = None
    if caa_mismatches:
        status = "warn"
        pill_label = "CAA mismatch"
    elif expiring:
        status = "warn"
        pill_label = "Expiring"
    else:
        pill_label = f"{active} cert{'s' if active != 1 else ''}"

    # Verdict
    issuer_summary = ", ".join(i["name"] for i in issuers[:2])
    if len(issuers) > 2:
        issuer_summary += f" +{len(issuers) - 2} more"
    verdict = f"{active} active cert{'s' if active != 1 else ''} from {len(issuers)} issuer{'s' if len(issuers) != 1 else ''}"

    # Explanation
    explanation = (
        f"Found <strong>{total}</strong> certificate{'s' if total != 1 else ''} in Certificate Transparency logs, "
        f"of which <strong>{active}</strong> {'are' if active != 1 else 'is'} currently active."
    )
    if caa_mismatches:
        explanation += (
            " <strong>Warning:</strong> Some certificates were issued by CAs not authorized by your CAA records."
        )

    # Details
    details = []
    details.append({"type": "good", "text": f"{active} active certificates from {len(issuers)} issuer{'s' if len(issuers) != 1 else ''}"})

    # Issuer breakdown
    issuer_parts = []
    for i in issuers[:5]:
        issuer_parts.append(f"{i['name']} ({i['count']})")
    if issuer_parts:
        details.append({"type": "info", "text": f"Issuers: {', '.join(issuer_parts)}"})

    # CAA mismatches
    for mm in caa_mismatches:
        details.append({
            "type": "warning",
            "text": f"CAA allows [{', '.join(mm['caa_allows'])}] but certs found from {mm['cert_issuer']}",
        })

    # Wildcards
    if wildcards:
        details.append({"type": "info", "text": f"{len(wildcards)} wildcard certificate{'s' if len(wildcards) != 1 else ''} found"})

    # Expiring
    for exp in expiring[:3]:
        details.append({
            "type": "warning",
            "text": f"Expiring in {exp['days_left']} days: {exp['common_name']}",
        })

    # Certificate sprawl
    if len(issuers) > 5:
        details.append({"type": "info", "text": f"Certificates from {len(issuers)} different CAs. Consider consolidating"})

    # Subdomains
    if subdomains:
        details.append({"type": "info", "text": f"{len(subdomains)} unique subdomain{'s' if len(subdomains) != 1 else ''} discovered via CT"})

    # Append raw issues
    for issue in issues:
        details.append(_issue_to_detail(issue))

    # Fix (only for CAA mismatches)
    fix = None
    if caa_mismatches:
        mismatched_cas = ", ".join(mm["cert_issuer"] for mm in caa_mismatches[:3])
        fix = (
            f"Update your CAA record to include <strong>{mismatched_cas}</strong>, "
            f"or revoke certificates from unauthorized CAs. If these are older certs issued "
            f"before CAA was configured, they will naturally expire."
        )

    return {
        "name": "Certificate Transparency",
        "status": status,
        "pill_label": pill_label,
        "verdict": verdict,
        "record": None,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
    }


# ============================================================
# Blacklist
# ============================================================

def transform_blacklist(raw: Dict, domain: str) -> Dict:
    ips_checked = raw.get("ips_checked", [])
    ip_results = raw.get("ip_results", [])
    domain_results = raw.get("domain_results", [])
    total_listings = raw.get("total_listings", 0)
    issues = raw.get("issues", [])

    DELIST_URLS = {
        "Spamhaus ZEN": "https://check.spamhaus.org/",
        "Spamhaus DBL": "https://check.spamhaus.org/",
        "Barracuda BRBL": "https://www.barracudacentral.org/lookups",
        "SpamCop": "https://www.spamcop.net/bl.shtml",
    }

    # No MX IPs to check
    if not ips_checked and not domain_results:
        return {
            "name": "Blacklist",
            "status": "pass",
            "pill_label": "N/A",
            "verdict": "No MX servers to check",
            "record": None,
            "explanation": (
                "No MX server IPs were available to check against DNS-based blocklists. "
                "This domain may not have MX records configured."
            ),
            "details": [{"type": "info", "text": "No MX servers to check against blocklists"}],
            "fix_records": None,
            "fix": None,
        }

    # Determine status and collect listings
    tier1_listed = False
    tier2_only = False
    listed_names = []

    for ip_result in ip_results:
        for listing in ip_result.get("listings", []):
            if listing.get("listed"):
                list_name = listing["list"]
                listed_names.append(list_name)
                if list_name in ("Spamhaus ZEN", "Barracuda BRBL"):
                    tier1_listed = True
                else:
                    tier2_only = True

    for dr in domain_results:
        if dr.get("listed"):
            list_name = dr["list"]
            listed_names.append(list_name)
            if list_name == "Spamhaus DBL":
                tier1_listed = True
            else:
                tier2_only = True

    if tier1_listed:
        status = "fail"
        pill_label = "Listed"
    elif tier2_only:
        status = "warn"
        pill_label = "Listed"
    else:
        status = "pass"
        pill_label = "Clean"

    # Total lists checked
    total_lists = len(ip_results[0].get("listings", [])) if ip_results else 0
    total_lists += len(domain_results)

    # Verdict
    if total_listings > 0:
        verdict = f"Listed on {total_listings} blocklist{'s' if total_listings != 1 else ''}"
    else:
        verdict = f"Clean on all {total_lists} blocklists checked"

    # Explanation
    if total_listings > 0:
        if tier1_listed:
            explanation = (
                f"<strong>Warning:</strong> This domain's mail servers are listed on {total_listings} "
                f"blocklist{'s' if total_listings != 1 else ''}. "
                "Major blocklist listings (Spamhaus, Barracuda) cause significant email "
                "deliverability problems. Many receiving servers will reject or spam-folder your mail."
            )
        else:
            explanation = (
                f"This domain's mail servers appear on {total_listings} secondary "
                f"blocklist{'s' if total_listings != 1 else ''}. "
                "These have less impact than major lists but may still affect deliverability "
                "with some receivers."
            )
    else:
        explanation = (
            f"Checked {len(ips_checked)} IP{'s' if len(ips_checked) != 1 else ''} and the domain "
            f"against {total_lists} DNS-based blocklists. No listings found. Your mail server "
            "reputation is clean."
        )

    # Details
    details = []

    # Per-IP results
    for ip_result in ip_results:
        ip = ip_result["ip"]
        mx_host = ip_result.get("mx_host", "")
        host_label = f"{mx_host} ({ip})" if mx_host else ip

        any_listed = False
        for listing in ip_result.get("listings", []):
            if listing.get("listed"):
                any_listed = True
                meaning = listing.get("meaning", "Listed")
                details.append({
                    "type": "error" if listing["list"] in ("Spamhaus ZEN", "Barracuda BRBL") else "warning",
                    "text": f"{host_label}: {listing['list']}: {meaning}",
                })
            elif listing.get("error"):
                details.append({"type": "info", "text": f"{host_label}: {listing['list']}: lookup failed"})

        if not any_listed:
            details.append({"type": "good", "text": f"{host_label}: clean on all IP blocklists"})

    # Domain results
    for dr in domain_results:
        if dr.get("listed"):
            meaning = dr.get("meaning", "Listed")
            details.append({"type": "error", "text": f"{domain}: {dr['list']}: {meaning}"})
        else:
            details.append({"type": "good", "text": f"{domain}: clean on {dr['list']}"})

    # Append raw issues
    for issue in issues:
        details.append(_issue_to_detail(issue))

    # Fix
    fix = None
    if total_listings > 0:
        delist_parts = []
        seen_urls = set()
        for name in listed_names:
            url = DELIST_URLS.get(name)
            if url and url not in seen_urls:
                seen_urls.add(url)
                delist_parts.append(f"<strong>{name}</strong>: <a href=\"{url}\" target=\"_blank\" rel=\"noopener\">{url}</a>")
        if delist_parts:
            fix = "Request delisting from each blocklist:<br>" + "<br>".join(delist_parts)
            fix += "<br><br>Investigate the root cause (compromised account, open relay, or spam complaint spike) before requesting removal."
        else:
            fix = "Investigate the root cause of the listing and contact the blocklist operator for removal."

    return {
        "name": "Blacklist",
        "status": status,
        "pill_label": pill_label,
        "verdict": verdict,
        "record": None,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
    }
