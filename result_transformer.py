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

    # Build verdict and override status based on policy
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
        verdict = "No DMARC policy published"
        status = "fail"
        pill_label = "Missing"
    elif policy == "reject":
        verdict = "p=reject -- receivers requested to reject failures"
        # p=reject is always a pass regardless of what the audit engine returned
        # (the engine may flag "warning" for missing rua, but the policy itself is correct)
        status = "pass"
    elif policy == "quarantine":
        pct = raw.get("pct", 100)
        verdict = "p=quarantine -- failures sent to spam"
        if pct is not None and pct < 100:
            verdict += f" (pct={pct})"
        # p=quarantine is enforcing; treat as pass even if rua is absent
        status = "pass"
    elif policy == "none":
        verdict = "p=none -- monitoring only, no enforcement"
        status = "warn"
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
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{raw.get('domain', '')}</strong>, but inherits "
                f"<strong>p=reject</strong> from <strong>{inherited_source}</strong> "
                f"via the {tag_label} tag. "
                f"Receivers that honor DMARC are requested to reject messages where neither "
                f"SPF nor DKIM passes with aligned domains (RFC 7489 Section 6.3)."
                + _adoption_note
            )
        elif inherited_policy == "quarantine":
            explanation = (
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{raw.get('domain', '')}</strong>, but inherits "
                f"<strong>p=quarantine</strong> from <strong>{inherited_source}</strong> "
                f"via the {tag_label} tag. "
                f"Receivers that honor DMARC are requested to route failures to the spam folder."
                + _adoption_note
            )
        elif inherited_policy == "none":
            explanation = (
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{raw.get('domain', '')}</strong>, but inherits "
                f"<strong>p=none</strong> from <strong>{inherited_source}</strong> "
                f"via the {tag_label} tag. "
                f"This is monitoring only -- receivers take no enforcement action, but aggregate reports "
                f"provide visibility into authentication results."
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
            f"DMARC (RFC 7489) lets you tell receivers how to handle messages where neither "
            f"SPF nor DKIM passes with a domain that aligns with your From address. "
            f"Without it, receivers have no policy to act on, "
            f"and you receive no aggregate reports about who is using your domain to send email."
        )
    elif policy == "none":
        explanation = (
            f"Your DMARC policy is <strong>p=none</strong> -- monitoring only. "
            f"Receivers take no enforcement action on messages that fail alignment, but "
            f"aggregate reports (rua) give you visibility into authentication results. "
            f"This is the right starting point for understanding your email ecosystem before enforcing."
        )
    elif policy == "quarantine":
        explanation = (
            f"Your DMARC policy is <strong>p=quarantine</strong>. Receivers that honor DMARC "
            f"are requested to route messages to the spam folder when neither SPF nor DKIM "
            f"passes with an aligned domain. DMARC requires only one of SPF or DKIM to pass "
            f"with alignment -- DKIM is preferred because it survives mail forwarding."
        )
    elif policy == "reject":
        explanation = (
            f"Your DMARC policy is <strong>p=reject</strong>. Receivers that honor DMARC "
            f"are requested to reject messages where neither SPF nor DKIM passes with an "
            f"aligned domain. Major mailbox providers (Gmail, Outlook, Yahoo) honor this policy. "
            f"DMARC requires only one of SPF or DKIM to pass with alignment -- "
            f"DKIM is the more resilient mechanism because it survives mail forwarding."
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
            details.append({"type": "good", "text": "Policy p=reject -- receivers requested to reject authentication failures"})
        elif policy == "quarantine":
            details.append({"type": "good", "text": "Policy p=quarantine -- receivers requested to send failures to spam"})
        elif policy == "none":
            details.append({"type": "warning", "text": "Policy p=none -- monitoring only, no enforcement requested"})

        report_dests = raw.get("report_destinations")
        if report_dests and raw.get("rua"):
            rua_dests = [d for d in report_dests if d["type"] == "rua"]
            unauthorized = [d for d in rua_dests if d.get("authorized") is False]
            if unauthorized:
                details.append({
                    "type": "error",
                    "text": (
                        f"Aggregate reporting (rua): {len(rua_dests)} destination(s), "
                        f"{len(unauthorized)} NOT authorized (reports silently dropped)"
                    ),
                })
            else:
                details.append({
                    "type": "good",
                    "text": f"Aggregate reporting (rua): {len(rua_dests)} destination(s), all authorized",
                })
        elif raw.get("rua"):
            details.append({"type": "good", "text": "Aggregate reporting (rua) is configured"})
        else:
            details.append({"type": "warning", "text": "No aggregate reporting (rua) configured"})

        if report_dests and raw.get("ruf"):
            details.append({
                "type": "info",
                "text": "Forensic reporting (ruf) configured (note: most major providers no longer send forensic reports)",
            })
        elif raw.get("ruf"):
            details.append({"type": "good", "text": "Forensic reporting (ruf) is configured"})

        if raw.get("sp"):
            details.append({"type": "info", "text": f"Subdomain policy: sp={raw['sp']}"})

        pct = raw.get("pct")
        if pct is not None and pct < 100:
            details.append({"type": "warning", "text": f"pct={pct} -- policy applied to only {pct}% of failing messages (note: pct is deprecated in DMARCbis)"})

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
                f"Either move the parent domain to an enforcement policy, "
                f"or publish a dedicated DMARC record at <strong>_dmarc.{domain_name}</strong>."
            )
        elif inherited_policy == "quarantine":
            fix = (
                f"This subdomain inherits p=quarantine from <strong>{inherited_source}</strong>. "
                f"To request rejection instead of spam delivery, upgrade the parent domain's policy "
                f"or publish a dedicated record at <strong>_dmarc.{domain_name}</strong> with p=reject."
            )
        else:
            # reject — no fix needed
            fix = None
    elif not record:
        fix = (
            f"Publish a TXT record at <strong>_dmarc.{domain_name}</strong>. "
            f"Start with <strong>p=none</strong> and an <strong>rua</strong> address to receive "
            f"aggregate reports. These reports will show you which sources send mail using your "
            f"domain and whether they pass SPF/DKIM alignment. Move to an enforcement policy "
            f"only after you understand your sending ecosystem."
        )
    elif raw.get("syntax_errors") or any(i.get("severity") == "error" for i in raw.get("issues", [])):
        # Prioritize syntax/error fixes over generic policy advice
        fix = _first_fix(raw.get("syntax_errors", [])) or _first_fix(raw.get("issues", []))
    elif policy == "none":
        fix = (
            "Review your DMARC aggregate reports to identify all legitimate senders and confirm "
            "they pass SPF or DKIM with aligned domains. Once you are confident in your sender "
            "inventory, move to an enforcement policy (<strong>p=quarantine</strong> or <strong>p=reject</strong>)."
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

    # Fix records -- copy-paste DNS records for missing records only
    # Policy upgrades (none -> reject) are intentionally excluded because
    # they oversimplify a process that depends on mail volume and sender inventory.
    fix_records = []
    if not record and not inherited:
        fix_records.append({
            "type": "TXT",
            "host": f"_dmarc.{domain_name}",
            "value": f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain_name}; fo=1",
            "comment": "Start with p=none to monitor. Upgrade to enforcement only after reviewing aggregate reports.",
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
        verdict = "No authorized IP list published"
        pill_label = "Missing"
    else:
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)
        if all_mech == "+all":
            verdict = "Authorizes the entire internet to send as you"
        elif lookups > 10:
            verdict = f"Broken -- exceeds lookup limit ({lookups}/10)"
        elif not all_mech and raw.get("has_redirect"):
            verdict = "Authorized senders via redirect"
        elif not all_mech:
            verdict = "Configured but missing an all mechanism"
        else:
            verdict = "Authorized IP list published"

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
            "No SPF record found. SPF (RFC 7208) specifies which IP addresses are authorized "
            "to send email for your domain. Without it, receiving servers cannot use SPF to "
            "validate whether a message originated from your mail infrastructure."
        )
    else:
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)

        if all_mech == "-all":
            explanation = (
                "SPF record ends with <strong>-all</strong> (hardfail), declaring that servers "
                "not listed in this record are not authorized to send mail for your domain. "
                "SPF results feed into DMARC alignment evaluation -- enforcement decisions "
                "are made at the DMARC policy layer, not by SPF alone."
            )
        elif all_mech == "~all":
            explanation = (
                "SPF record ends with <strong>~all</strong> (softfail), indicating that servers "
                "not listed in this record are not authorized but should not be outright rejected. "
                "Like -all, the SPF result feeds into DMARC alignment evaluation -- "
                "enforcement decisions are made at the DMARC policy layer."
            )
        elif all_mech == "?all":
            explanation = (
                "SPF record uses <strong>?all</strong> (neutral). Per RFC 7208, this means the domain "
                "makes no assertion about unlisted servers. A neutral result does not pass SPF, "
                "so it cannot contribute to DMARC alignment."
            )
        elif all_mech == "+all":
            explanation = (
                "<strong>WARNING:</strong> SPF record uses <strong>+all</strong>, which authorizes "
                "the entire internet to send email as your domain. This is almost certainly a misconfiguration."
            )
        elif not all_mech and raw.get("has_redirect"):
            explanation = (
                "SPF record uses a <strong>redirect</strong> modifier instead of an explicit "
                "<strong>all</strong> mechanism. The SPF evaluation is delegated to another domain's record."
            )
        elif not all_mech:
            explanation = (
                "SPF record is missing an <strong>all</strong> mechanism. Per RFC 7208 Section 4.7, "
                "if processing reaches the end of the record without a match, the result is neutral. "
                "This means unlisted servers produce no SPF pass and cannot contribute to DMARC alignment."
            )
        else:
            explanation = "SPF record found."

        if lookups and lookups > 8:
            explanation += (
                f" <strong>Note:</strong> SPF requires {lookups} DNS lookups "
                f"({'at' if lookups == 10 else 'exceeding' if lookups > 10 else 'approaching'} the 10-lookup limit). "
                f"RFC 7208 Section 4.6.4 limits SPF evaluation to 10 DNS-querying mechanisms "
                f"(include, a, mx, ptr, exists). Exceeding this limit causes a PermError, "
                f"which receivers may treat as SPF failure."
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
            details.append({"type": "good", "text": "-all (hardfail) -- declares no other servers are authorized"})
        elif all_mech == "~all":
            details.append({"type": "good", "text": "~all (softfail) -- unlisted servers are not authorized"})
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
            "Publish a null SPF record (<strong>v=spf1 -all</strong>) to explicitly declare "
            "that no IP addresses are authorized to send email for this domain."
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

    # Fix records -- copy-paste DNS records for missing records only
    # SPF mechanism changes (+all -> ~all) are excluded because they require
    # verifying all legitimate senders first.
    fix_records = []
    domain_name = raw.get("domain", "")
    if null_spf:
        pass
    elif not record and not has_mx:
        fix_records.append({
            "type": "TXT",
            "host": domain_name,
            "value": "v=spf1 -all",
            "comment": "Null SPF -- declares this domain does not send email",
        })
    elif not record:
        fix_records.append({
            "type": "TXT",
            "host": domain_name,
            "value": "v=spf1 ~all",
            "comment": "Placeholder that blocks all senders. Replace ~all with your authorized mail servers and includes before deploying.",
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
                "DKIM (RFC 6376) adds a cryptographic signature to outgoing email covering "
                "specified headers and the message body. Receivers verify this signature using "
                "the public key published in DNS to confirm the message was not altered in transit."
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

    # ARC informational note (RFC 8617)
    details.append({"type": "info", "text": "DKIM is a prerequisite for ARC (RFC 8617), which preserves authentication across mail forwarding"})

    # Append any issues from the audit engine
    for issue in raw.get("issues", []):
        details.append(_issue_to_detail(issue))

    # Verdict
    verdict = f"{len(found)} DKIM public key{'s' if len(found) != 1 else ''} published in DNS"

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
        explanation += f" Sending providers detected: {', '.join(sorted(vendor_names))}."
    explanation += (
        " Each key is a TXT record at <strong>selector._domainkey.{domain}</strong>. "
        "Receiving servers retrieve this key to verify the DKIM signature on incoming messages "
        "(RFC 6376). Note: this audit confirms the public key exists in DNS -- "
        "it does not test live message signatures."
    ).format(domain=domain)
    if raw.get("discovery_method") == "spf_intelligent":
        explanation += " Selectors were targeted using SPF-based sender discovery."

    # Fix
    fix = None
    if raw.get("syntax_errors"):
        fix = _first_fix(raw.get("syntax_errors", []))
    elif weak_keys:
        selectors_str = ", ".join(weak_keys)
        fix = (
            f"The following selectors use 1024-bit keys, which are below current recommendations: "
            f"<strong>{selectors_str}</strong>. "
            f"Key rotation is provider-specific -- check your email provider's documentation "
            f"for how to generate and publish a new 2048-bit or Ed25519 key pair."
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
        explanation = f"MX records are configured with <strong>{count} hosts</strong> for redundancy."
    else:
        explanation = (
            "Only one MX record is configured. If this host becomes unavailable, inbound email "
            "delivery will fail until it recovers. Some providers handle redundancy internally "
            "behind a single hostname, but this cannot be verified from DNS alone."
        )
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
                "MTA-STS (RFC 8461) lets you declare that SMTP connections to your domain's MX hosts "
                "must use authenticated TLS. Without it, SMTP's opportunistic TLS (STARTTLS) is "
                "vulnerable to downgrade attacks where a network attacker strips the TLS negotiation, "
                "causing email to be delivered in plaintext."
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
                "comment": "Also requires a policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt".format(domain=domain),
            }],
        }

    # Has record
    if policy_mode == "enforce":
        verdict = "Inbound email must use encryption"
    elif policy_mode == "testing":
        verdict = "Monitoring TLS -- not yet enforcing"
    elif policy_mode == "none":
        verdict = "Configured but disabled"
    else:
        verdict = f"Mode: {policy_mode}" if policy_mode else "Record found"

    explanation = ""
    if policy_mode == "enforce":
        explanation = (
            "MTA-STS is in <strong>enforce</strong> mode (RFC 8461). Sending servers that "
            "support MTA-STS are required to use authenticated TLS when delivering to your domain. "
            "If TLS cannot be established, delivery fails rather than falling back to plaintext."
        )
    elif policy_mode == "testing":
        explanation = (
            "MTA-STS is in <strong>testing</strong> mode. Senders attempt TLS but will not "
            "refuse delivery if TLS fails. TLS-RPT reports will capture any failures. "
            "Move to <strong>enforce</strong> mode once you've confirmed reliable TLS delivery."
        )
    elif policy_mode == "none":
        explanation = (
            "MTA-STS is configured but the policy mode is set to <strong>none</strong>, "
            "which disables enforcement. The record has no protective effect in this state."
        )

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
                "TLS-RPT (RFC 8460) enables receiving servers to report SMTP TLS delivery failures "
                "back to you. Without it, you have no visibility into whether inbound email is "
                "encountering TLS negotiation problems. TLS-RPT complements MTA-STS and DANE by "
                "surfacing delivery issues that those policies may be causing or encountering."
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
        "TLS-RPT (RFC 8460) is configured. Sending mail servers that support the protocol "
        "will report SMTP TLS failures to your specified destinations, giving you visibility "
        "into encryption issues on inbound delivery. This is particularly useful alongside "
        "MTA-STS or DANE to detect delivery problems caused by TLS policy enforcement."
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
                "It is a brand recognition feature that displays your logo next to emails in "
                "supporting clients (Gmail, Apple Mail, Yahoo Mail). "
                "BIMI is currently a draft standard, not a published RFC. "
                "It requires DMARC at p=quarantine or p=reject as a prerequisite."
            ),
            "details": [
                {"type": "info", "text": "BIMI is about brand recognition, not security"},
                {"type": "info", "text": "Requires DMARC policy of p=quarantine or p=reject at pct=100"},
                {"type": "info", "text": "Gmail requires a Verified Mark Certificate (VMC); Apple Mail does not"},
            ],
            "fix": (
                f"To display your brand logo in supporting mail clients, ensure DMARC is at "
                f"p=quarantine or p=reject (with pct=100), then publish a BIMI record at "
                f"<strong>default._bimi.{domain}</strong> pointing to an SVG Tiny P/S logo. "
                f"A VMC is required for Gmail logo display but not for all clients."
            ),
            "fix_records": [{
                "type": "TXT",
                "host": f"default._bimi.{domain}",
                "value": "v=BIMI1; l=https://example.com/logo.svg;",
                "comment": "Replace URL with your SVG logo (Tiny P/S profile required). A VMC is required for Gmail display but not all clients.",
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

    explanation = "BIMI record is published. BIMI is a brand recognition feature, not a security protocol."
    if logo_url:
        explanation += " Your brand logo URL is configured."
    if vmc_url:
        explanation += " A Verified Mark Certificate (VMC) is referenced."
    elif not vmc_url:
        explanation += (
            " <strong>Note:</strong> No VMC (Verified Mark Certificate) is referenced. "
            "Gmail requires a VMC for BIMI logo display; other clients (e.g. Apple Mail) do not."
        )

    details = [_issue_to_detail(i) for i in raw.get("issues", [])]

    # Add SVG validation summary to details
    svg_validated = raw.get("svg_validated")
    svg_profile = raw.get("svg_profile")
    if svg_validated is True:
        if svg_profile in ("tiny-ps", "tiny"):
            details.append({"type": "good", "text": f"SVG validated (profile: {svg_profile})"})
        elif svg_profile:
            details.append({"type": "warning", "text": f"SVG parsed but profile is '{svg_profile}' (expected tiny-ps)"})
        else:
            details.append({"type": "warning", "text": "SVG parsed but baseProfile not declared (expected tiny-ps)"})
    elif svg_validated is False:
        details.append({"type": "error", "text": "SVG validation failed"})
        status = "fail"

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
            {"type": "info", "text": "DNSSEC requires support from both your registrar and DNS hosting provider"},
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
                "DNSSEC (RFC 4033/4034/4035) cryptographically signs DNS records so that "
                "resolvers can verify responses have not been tampered with, preventing cache "
                "poisoning and DNS spoofing. It is also a prerequisite for DANE. "
                "Enabling DNSSEC requires coordination between your registrar (for the DS record) "
                "and your DNS hosting provider (for DNSKEY records and zone signing)."
            ),
            "details": details,
            "fix": (
                "Enable DNSSEC through your DNS hosting provider, then publish the DS record "
                "at your domain registrar to complete the chain of trust. "
                "Many registrars and DNS hosts support this through their control panels."
            ),
            "fix_records": None,  # DNSSEC requires registrar/DNS provider activation, not manual DNS records
        }

    # Has DNSSEC
    details = []
    details.append({"type": "good", "text": f"DNSKEY records found ({key_count} key{'s' if key_count != 1 else ''})"})

    chain_valid = raw.get("chain_valid")
    chain_details = raw.get("chain_details", [])

    if has_ds:
        details.append({"type": "good", "text": "DS record present at parent (chain of trust anchored)"})
        # Chain verification result
        if chain_valid is True:
            details.append({"type": "good", "text": "DS digest matches DNSKEY (chain of trust verified)"})
        elif chain_valid is False:
            details.append({"type": "error", "text": "DS digest does NOT match any DNSKEY (broken chain -- validating resolvers will return SERVFAIL)"})
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
        verdict = f"DNS records cryptographically signed ({', '.join(algo_names)})"
    else:
        verdict = "DNS records cryptographically signed"

    # Downgrade status if issues exist
    if any(a.get("deprecated") for a in algorithms):
        status = "fail"
    elif chain_valid is False:
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
            "DNSSEC is enabled. Your DNS records are cryptographically signed per "
            "RFC 4033/4034/4035, allowing validating resolvers to confirm that responses "
            "have not been tampered with. This prevents cache poisoning and DNS spoofing, "
            "and is required for DANE to function."
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
                "CAA records (RFC 8659) specify which Certificate Authorities are authorized "
                "to issue TLS certificates for your domain. Compliant CAs must check CAA records "
                "before issuance. Without CAA records, any compliant CA may issue certificates "
                "for your domain -- there is no restriction to enforce."
            ),
            "details": details,
            "fix": (
                f"Add CAA records to restrict which CAs may issue certificates for your domain. "
                f"Use the <code>issue</code> tag for your CA (for example, <code>letsencrypt.org</code>), "
                f"<code>issuewild</code> to control wildcard issuance, and "
                f"<code>iodef</code> to receive violation reports."
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
                    "comment": "Alerts you when an unauthorized CA attempts issuance",
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
            "CAA records (RFC 8659) restrict which Certificate Authorities may issue TLS certificates "
            "for your domain. Compliant CAs check these records before issuance and must not issue "
            "if they are not listed. Certificate Transparency logs can be used to detect issuance "
            "by CAs not authorized in your CAA records."
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
                "DANE (RFC 7672) publishes TLSA records that allow sending servers to verify "
                "your mail server's TLS certificate directly via DNS, without relying on a CA. "
                "This domain has no MX records, so DANE is not applicable."
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
                "DANE requires DNSSEC (RFC 7672 Section 2.2) -- without it, an attacker can forge "
                "or strip TLSA records, completely defeating the authentication. "
                "Senders that implement RFC 7672 will ignore TLSA records that are not DNSSEC-validated."
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
            missing = [h["mx_host"] for h in tlsa_records if not h["found"] and not h.get("error")]
            fix = f"Add TLSA records for: {', '.join(missing)}"

        return {
            "name": "DANE",
            "status": status,
            "verdict": verdict,
            "record": None,
            "explanation": (
                "DANE (RFC 7672) is configured and backed by DNSSEC. Sending mail servers that "
                "implement RFC 7672 can verify your mail server's TLS certificate through DNS-based "
                "TLSA records, independent of the Certificate Authority infrastructure. "
                "This allows senders to authenticate the TLS certificate without relying on the "
                "public CA trust model."
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
            "DANE (RFC 7672) uses TLSA records to let sending mail servers verify your mail "
            "server's TLS certificate through DNS, without depending on the CA infrastructure. "
            "DANE requires DNSSEC to be effective -- without it, TLSA records cannot be trusted. "
            "DANE and MTA-STS serve complementary roles for enforcing SMTP TLS."
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

    # Resolution and authoritative status
    resolving = [ns for ns in nameservers if ns.get("resolves")]
    not_resolving = [ns for ns in nameservers if not ns.get("resolves")]
    if not_resolving:
        for ns in not_resolving:
            details.append({"type": "error", "text": f"{ns['hostname']} does not resolve (lame delegation)"})
    if resolving:
        for ns in resolving:
            ip = ns.get("ipv4", [""])[0] if ns.get("ipv4") else ""
            ip_part = f" ({ip})" if ip else ""
            auth = ns.get("authoritative")
            rtt = ns.get("response_time_ms")
            if auth is True:
                rtt_str = f", {rtt}ms" if rtt is not None else ""
                details.append({"type": "good", "text": f"{ns['hostname']}{ip_part} -- authoritative{rtt_str}"})
            elif auth is False:
                details.append({"type": "error", "text": f"{ns['hostname']}{ip_part} -- NOT authoritative (lame delegation)"})
            else:
                # auth is None -- query failed or not attempted
                ipv4_str = ", ".join(ns.get("ipv4", []))
                ipv6_count = len(ns.get("ipv6", []))
                ip_info = ipv4_str
                if ipv6_count:
                    ip_info += f" + {ipv6_count} IPv6"
                if ip_info:
                    details.append({"type": "good", "text": f"{ns['hostname']} resolves ({ip_info})"})
                else:
                    details.append({"type": "good", "text": f"{ns['hostname']} resolves"})

    # SOA serial consistency
    soa_consistent = raw.get("soa_serials_consistent")
    soa_serial = raw.get("soa_serial")
    if soa_consistent is True and soa_serial is not None:
        details.append({"type": "good", "text": f"SOA serials consistent ({soa_serial})"})
    elif soa_consistent is False:
        details.append({"type": "warning", "text": "SOA serial mismatch across nameservers (zone sync issue)"})

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
            "Nameservers are authoritative for your DNS zone -- they answer queries for all your "
            "DNS records. Multiple nameservers on distinct network paths reduce the risk of a "
            "single point of failure causing a full DNS outage for your domain."
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
    raw_status = raw.get("status", "info")
    unavailable_reason = raw.get("unavailable_reason")

    # Query failed or data was unavailable -- distinguish from a genuine empty result
    if raw_status in ("warning", "unavailable") and total == 0:
        if unavailable_reason == "response_too_large":
            verdict = "CT log query unavailable (too many certificates)"
            explanation = (
                "The Certificate Transparency log query returned more data than could be processed. "
                "This domain has a very large number of certificates on record. "
                "Use crt.sh directly to browse certificates for this domain."
            )
            detail_text = "CT log response too large to analyze automatically"
        else:
            verdict = "CT log query unavailable"
            explanation = (
                "The Certificate Transparency log could not be queried at this time. "
                "This may be a temporary issue with the crt.sh service."
            )
            detail_text = issues[0]["plain_english"] if issues else "CT log query failed"
        return {
            "name": "Certificate Transparency",
            "status": "warn",
            "pill_label": "Unavailable",
            "verdict": verdict,
            "record": None,
            "explanation": explanation,
            "details": [
                {"type": "warning", "text": detail_text},
            ],
            "fix": None,
            "fix_records": None,
        }

    # No certs found (genuine empty result, not an error)
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
        f"Found <strong>{total}</strong> certificate{'s' if total != 1 else ''} in Certificate Transparency logs "
        f"(RFC 6962), of which <strong>{active}</strong> {'are' if active != 1 else 'is'} currently active. "
        f"CT logs provide a publicly auditable record of all certificates issued for your domain."
    )
    if caa_mismatches:
        explanation += (
            " <strong>Note:</strong> Some certificates were issued by CAs not listed in your CAA records. "
            "This may indicate issuance before CAA was configured, or a CAA policy gap."
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
            f"Review certificates from <strong>{mismatched_cas}</strong>. "
            f"If these CAs should be authorized, add them to your CAA record. "
            f"If they should not be, consider requesting revocation. "
            f"Certificates issued before CAA records were in place will expire naturally."
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
                f"This domain's mail servers are listed on {total_listings} "
                f"blocklist{'s' if total_listings != 1 else ''}. "
                "Major blocklists (Spamhaus, Barracuda) are widely used by receiving servers and "
                "listings can significantly affect deliverability. Listings can result from spam "
                "activity, compromised accounts, or false positives -- investigate before requesting removal."
            )
        else:
            explanation = (
                f"This domain's mail servers appear on {total_listings} secondary "
                f"blocklist{'s' if total_listings != 1 else ''}. "
                "Secondary listings have less industry-wide impact than major lists but may still "
                "affect deliverability with some receivers. Verify the listing reason before acting."
            )
    else:
        explanation = (
            f"Checked {len(ips_checked)} IP{'s' if len(ips_checked) != 1 else ''} and the domain "
            f"against {total_lists} DNS-based blocklists. No listings found."
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
            fix += (
                "<br><br>Before requesting removal, identify the reason for the listing. "
                "Common causes include a compromised sending account, misconfigured open relay, "
                "a spike in spam complaints, or -- in some cases -- a false positive. "
                "Removing the underlying cause first reduces the chance of re-listing."
            )
        else:
            fix = "Review the listing reason with each blocklist operator and request removal once the underlying issue is resolved."

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
