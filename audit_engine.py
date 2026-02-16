"""
Audit Engine
=============
Orchestrates all security checks for a domain.
Each check runs independently -- if one fails, the others still complete.
Assembles results for the security scorer and transforms everything
into the frontend's expected format.
"""

import re
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional

import dns.resolver
import dns.exception

from checks_extra import check_mta_sts, check_tls_rpt, check_bimi
from mx_check import check_mx
from spf_recursive import count_spf_lookups
from advanced_fingerprinting import AdvancedVendorFingerprinter
from security_scoring import EmailSecurityScorer
from dkim_formatter import analyze_dkim_key_strength
from dkim_key_age import DKIMKeyAgeAnalyzer
from dkim_tag_analyzer import DKIMTagAnalyzer
from dmarc_tree_walk import dmarc_tree_walk
from spf_intelligence import smart_dkim_check

from result_transformer import (
    transform_dmarc,
    transform_spf,
    transform_dkim,
    transform_mx,
    transform_mta_sts,
    transform_tls_rpt,
    transform_bimi,
    transform_dnssec,
)


# ============================================================
# DNS Helpers
# ============================================================

def _get_resolver(timeout: float = 5.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def _lookup_txt(name: str) -> List[str]:
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
    except Exception:
        return []


# ============================================================
# Individual Raw Checks (DMARC and SPF written fresh here)
# ============================================================

def _raw_check_dmarc(domain: str) -> Dict[str, Any]:
    """Check DMARC record with comprehensive syntax validation.

    Syntax checks based on:
      - dmarc.org "Common Problems With DMARC Records" (2016)
      - dmarcchecker.app top-1M domain study
      - RFC 7489 Section 6.3 (formal grammar)
      - dmarcian "Top 5 DMARC Deployment Mistakes"
    """
    import re

    VALID_POLICIES = {"none", "quarantine", "reject"}
    VALID_ADKIM_ASPF = {"r", "s"}
    VALID_FO = {"0", "1", "d", "s"}
    VALID_RF = {"afrf"}
    # Tags defined in DMARCbis (draft-ietf-dmarc-dmarcbis-41, Section 4.7)
    # np, psd, t are new; pct, rf, ri are removed from DMARCbis
    KNOWN_TAGS = {"v", "p", "sp", "np", "rua", "ruf", "adkim", "aspf", "fo", "psd", "t"}
    # Tags from RFC 7489 that DMARCbis removes — recognize but flag
    DEPRECATED_TAGS = {"pct", "rf", "ri"}

    result = {
        "check": "DMARC",
        "domain": domain,
        "record": None,
        "policy": None,
        "pct": None,
        "rua": None,
        "ruf": None,
        "sp": None,
        "np": None,
        "adkim": None,
        "aspf": None,
        "fo": None,
        "t": None,
        "psd": None,
        "status": "ok",
        "issues": [],
        "syntax_errors": [],
        "recommendations": [],
    }

    def _add_issue(severity, issue, plain_english, fix):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    def _add_syntax(issue, plain_english, fix):
        """Syntax errors are always severity=error."""
        result["syntax_errors"].append({
            "severity": "error",
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    # ── Step 1: Lookup ──────────────────────────────────────────
    dmarc_recs = _lookup_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in dmarc_recs if r.strip().lower().startswith("v=dmarc")]

    if not dmarc_records:
        result["status"] = "error"
        _add_issue(
            "error",
            "No DMARC record found",
            f"No DMARC record exists at '_dmarc.{domain}'. Without DMARC, "
            "anyone can send emails pretending to be from your domain.",
            f"Add a TXT record at _dmarc.{domain} with: "
            f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; fo=1",
        )
        return result

    # ── Step 2: Multiple records = none valid (RFC 7489) ────────
    if len(dmarc_records) > 1:
        result["status"] = "error"
        _add_issue(
            "error",
            f"Multiple DMARC records found ({len(dmarc_records)})",
            "RFC 7489 requires exactly one DMARC record per domain. "
            "When multiple records exist, DMARC processing aborts entirely — "
            "none of them are valid. This is the same as having no DMARC at all.",
            "Remove duplicate DMARC records so only one remains.",
        )
        return result

    record = dmarc_records[0]
    result["record"] = record

    # ── Step 3: Structural / formatting syntax checks ───────────
    # These run BEFORE tag parsing because they can make parsing unreliable.

    # 3a. "DMARC" must be uppercase (dmarc.org: non-negotiable)
    # The version tag value is case-sensitive per RFC 7489 §6.3
    stripped = record.strip()
    if stripped.startswith("v=dmarc1") and not stripped.startswith("v=DMARC1"):
        _add_syntax(
            "Version tag 'DMARC' is not uppercase",
            "The DMARC specification requires 'DMARC1' in uppercase. "
            "Lowercase 'dmarc1' may be ignored by some receivers.",
            "Change to v=DMARC1 (uppercase).",
        )

    # 3b. Missing version number: v=DMARC instead of v=DMARC1
    if re.match(r"v=DMARC\s*[;]", stripped, re.IGNORECASE) or \
       stripped.upper().startswith("V=DMARC;") or \
       stripped.upper().rstrip() == "V=DMARC":
        _add_syntax(
            "Version tag missing '1': v=DMARC instead of v=DMARC1",
            "The record says 'v=DMARC' but is missing the required '1'. "
            "Receivers will not recognize this as a valid DMARC record.",
            "Change to v=DMARC1.",
        )

    # 3c. Separator errors (dmarc.org: colons, slashes, missing semicolons)
    # Check for colons used as separators (v=DMARC1: p=none: ...)
    if re.search(r"DMARC1\s*:", stripped, re.IGNORECASE):
        _add_syntax(
            "Colons used as tag separators instead of semicolons",
            "DMARC tags must be separated by semicolons (;), not colons (:). "
            "This record will not be parsed correctly by any receiver.",
            "Replace all colons between tags with semicolons.",
        )

    # Check for forward-slash separators (v=DMARC1/; p=none/;)
    if "/;" in record:
        _add_syntax(
            "Forward-slash characters before semicolons",
            "The record contains '/;' sequences, likely confusing forward-slash "
            "with backslash escaping. Receivers will not parse this correctly.",
            "Remove all forward-slash characters from the record.",
        )

    # Check for backslash-escaped semicolons (v=DMARC1\;p=none\;)
    if "\\;" in record:
        _add_syntax(
            "Backslash-escaped semicolons in record",
            "Semicolons should not be escaped with backslashes in DMARC records. "
            "Some DNS software adds these, but they break DMARC parsing.",
            "Remove backslash characters. Use plain semicolons as separators.",
        )

    # Check for no separators at all (v=DMARC1 p=none pct=100)
    if ";" not in record and " p=" in record.lower():
        _add_syntax(
            "No semicolon separators between tags",
            "DMARC tags must be separated by semicolons. This record uses spaces "
            "only, which means receivers cannot parse the tags.",
            "Add semicolons between each tag: v=DMARC1; p=none; ...",
        )

    # 3e. Commas used as tag separators (dmarcchecker.app: bonkerscorner.com example)
    # Pattern: value, tag= (e.g., "adkim=r, aspf=r, pct=100")
    if re.search(r'=[^\s;,]+\s*,\s*[a-z]+=', record, re.IGNORECASE):
        _add_syntax(
            "Commas used as tag separators instead of semicolons",
            "DMARC tags must be separated by semicolons (;). Commas (,) are only "
            "valid inside rua/ruf tags to list multiple report addresses. "
            "Using commas between tags causes everything after the first comma "
            "to be misinterpreted or ignored.",
            "Replace commas between tags with semicolons.",
        )

    # 3f. Stray quotes wrapping the record
    if stripped.startswith('"') or stripped.startswith('\\"') or \
       stripped.startswith("'") or stripped.endswith('"') or stripped.endswith("'"):
        _add_syntax(
            "Record contains stray quotation marks",
            "The DMARC record has quote characters that are part of the DNS value. "
            "Quotes are used by some DNS interfaces for entry, but should not appear "
            "in the actual record data.",
            "Remove leading/trailing quotation marks from the DNS TXT value.",
        )

    # ── Step 4: Parse tags ──────────────────────────────────────
    tags = {}
    tag_positions = []  # Track order for v= and p= position checks
    seen_tags = {}      # Track duplicates

    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            key_clean = key.strip().lower()
            value_clean = value.strip()

            # Track tag order
            tag_positions.append(key_clean)

            # Check for duplicate tags
            if key_clean in seen_tags:
                _add_syntax(
                    f"Duplicate tag: '{key_clean}' appears multiple times",
                    f"The tag '{key_clean}' is defined more than once. "
                    "RFC 7489 does not define behavior for duplicate tags, so "
                    "different receivers may use different values — unpredictable results.",
                    f"Remove the duplicate '{key_clean}' tag. Keep only one.",
                )
            seen_tags[key_clean] = value_clean

            # Check for unknown/misspelled tags
            if key_clean not in KNOWN_TAGS and key_clean not in DEPRECATED_TAGS:
                _add_syntax(
                    f"Unknown tag: '{key_clean}'",
                    f"The tag '{key_clean}' is not defined in the DMARC specification. "
                    "It will be ignored by receivers. This may be a typo "
                    "(e.g., 'plicy' instead of 'p', 'rau' instead of 'rua').",
                    f"Check spelling. Valid DMARC tags are: {', '.join(sorted(KNOWN_TAGS))}.",
                )
            elif key_clean in DEPRECATED_TAGS:
                _add_issue(
                    "info",
                    f"Deprecated tag: '{key_clean}' (removed in DMARCbis)",
                    f"The '{key_clean}' tag was part of RFC 7489 but has been removed "
                    "in DMARCbis (draft-ietf-dmarc-dmarcbis). Receivers will ignore it. "
                    "It won't cause errors, but it's dead weight in your record.",
                    f"Remove the '{key_clean}' tag to keep your record clean.",
                )

            tags[key_clean] = value_clean
        else:
            # Fragment without '=' — could be bare mailto: or junk
            if "mailto:" in part.lower():
                _add_syntax(
                    f"Bare mailto: address without tag prefix",
                    "A 'mailto:' address appears without a rua= or ruf= tag prefix. "
                    "Receivers will ignore it — no reports will be sent.",
                    "Change to: rua=mailto:address@example.com",
                )

    # ── Step 5: Tag ordering checks ─────────────────────────────
    # 5a. v= must be first tag (RFC 7489 §6.3, dmarc.org)
    if tag_positions and tag_positions[0] != "v":
        _add_syntax(
            "Version tag (v=DMARC1) is not the first tag",
            "RFC 7489 requires v=DMARC1 to be the very first tag in the record. "
            "If it appears anywhere else, receivers may ignore the entire record.",
            "Move v=DMARC1 to the beginning of the record.",
        )

    # 5b. p= must immediately follow v= (dmarc.org, Valimail)
    if len(tag_positions) >= 2 and tag_positions[0] == "v" and tag_positions[1] != "p":
        _add_syntax(
            f"Policy tag (p=) is not the second tag (found '{tag_positions[1]}=' instead)",
            "RFC 7489 requires the policy tag (p=) to appear immediately after "
            "v=DMARC1. Some receivers may skip DMARC processing if this order "
            "is wrong.",
            "Move p= to be the second tag, right after v=DMARC1.",
        )

    # ── Step 6: Extract and validate individual tag values ──────

    # 6a. Policy (p=) — required tag
    raw_policy = tags.get("p", "")
    policy = raw_policy.lower()
    result["policy"] = policy

    if not raw_policy:
        # DMARCbis §4.10.1: If p= missing but rua= present, treat as p=none
        if tags.get("rua"):
            _add_issue(
                "warning",
                "Missing policy tag (p=) — treated as p=none per DMARCbis",
                "This record has no explicit policy tag. Because a rua= tag is present, "
                "DMARCbis-compliant receivers will treat this as p=none (monitoring only). "
                "However, some older receivers following RFC 7489 may ignore the record entirely.",
                "Add an explicit p=none (or p=quarantine / p=reject) to the record.",
            )
            policy = "none"
            result["policy"] = policy
        else:
            _add_syntax(
                "Missing required policy tag (p=) and no rua= tag",
                "Every DMARC record must include a policy tag. Without p= or rua=, "
                "receivers will ignore this record entirely. "
                "This is the same as having no DMARC record at all.",
                "Add a policy tag. Start with p=none for monitoring, and add "
                "rua=mailto:dmarc-reports@yourdomain.com to receive aggregate reports.",
            )
    elif policy not in VALID_POLICIES:
        # Check for common misspellings (dmarc.org dataset)
        suggestions = {
            "monitor": "p=monitor was used in early DMARC drafts but was replaced by p=none before publication.",
            "quarintine": "Misspelling of 'quarantine'.",
            "quarantaine": "Misspelling of 'quarantine'.",
            "quaranteen": "Misspelling of 'quarantine'.",
            "qurantine": "Misspelling of 'quarantine'.",
            "blocked": "'blocked' is not a valid DMARC policy.",
            "block": "'block' is not a valid DMARC policy.",
            "deny": "'deny' is not a valid DMARC policy.",
            "discard": "'discard' is not a valid DMARC policy.",
            "accept": "'accept' is not a valid DMARC policy.",
        }
        hint = suggestions.get(policy, "")
        extra = f" {hint}" if hint else ""
        _add_syntax(
            f"Invalid policy value: p={raw_policy}",
            f"'{raw_policy}' is not a valid DMARC policy.{extra} "
            "Only three values are allowed: none, quarantine, or reject.",
            "Change to p=none, p=quarantine, or p=reject.",
        )

    # 6b. Subdomain policy (sp=)
    raw_sp = tags.get("sp", "")
    sp = raw_sp.lower() if raw_sp else None
    result["sp"] = sp
    if raw_sp and sp not in VALID_POLICIES:
        _add_syntax(
            f"Invalid subdomain policy: sp={raw_sp}",
            f"'{raw_sp}' is not a valid subdomain policy. Same rules as p= apply.",
            "Change to sp=none, sp=quarantine, or sp=reject.",
        )

    # 6b2. Non-existent subdomain policy (np=) — DMARCbis §4.7
    raw_np = tags.get("np", "")
    np_val = raw_np.lower() if raw_np else None
    result["np"] = np_val
    if raw_np and np_val not in VALID_POLICIES:
        _add_syntax(
            f"Invalid non-existent subdomain policy: np={raw_np}",
            f"'{raw_np}' is not a valid np policy. Same rules as p= apply. "
            "The np tag controls policy for subdomains that don't exist in DNS.",
            "Change to np=none, np=quarantine, or np=reject.",
        )

    # 6b3. Test mode (t=) — DMARCbis §4.7, replaces pct for rollout
    raw_t = tags.get("t", "")
    if raw_t and raw_t.lower() not in ("y", "n"):
        _add_syntax(
            f"Invalid test mode value: t={raw_t}",
            "The t tag only accepts 'y' (testing) or 'n' (enforce). "
            f"'{raw_t}' is not valid.",
            "Use t=y to test (policy drops one level) or t=n / omit the tag to enforce.",
        )

    # 6b4. PSD flag (psd=) — DMARCbis §4.7
    raw_psd = tags.get("psd", "")
    if raw_psd and raw_psd.lower() not in ("y", "n", "u"):
        _add_syntax(
            f"Invalid PSD flag value: psd={raw_psd}",
            "The psd tag only accepts 'y' (is a PSD), 'n' (not a PSD, is an "
            "Organizational Domain), or 'u' (unknown/default). "
            f"'{raw_psd}' is not valid.",
            "Use psd=y, psd=n, or psd=u (or omit the tag — 'u' is the default).",
        )
    result["psd"] = raw_psd.lower() if raw_psd else None

    # 6c. rua (aggregate reports)
    raw_rua = tags.get("rua", "")
    result["rua"] = raw_rua if raw_rua else None
    if raw_rua:
        # Check each address has mailto: prefix
        rua_addrs = [a.strip() for a in raw_rua.split(",")]
        for addr in rua_addrs:
            if addr and not addr.lower().startswith("mailto:"):
                _add_issue(
                    "warning",
                    f"rua address missing 'mailto:' prefix: {addr}",
                    "DMARC requires report addresses to be written as URIs with "
                    "a mailto: prefix. Without it, receivers won't send aggregate "
                    "reports to this address — you lose visibility.",
                    f"Change to: rua=mailto:{addr}",
                )

    # 6d. ruf (forensic reports)
    raw_ruf = tags.get("ruf", "")
    result["ruf"] = raw_ruf if raw_ruf else None
    if raw_ruf:
        ruf_addrs = [a.strip() for a in raw_ruf.split(",")]
        for addr in ruf_addrs:
            if addr and not addr.lower().startswith("mailto:"):
                _add_issue(
                    "warning",
                    f"ruf address missing 'mailto:' prefix: {addr}",
                    "DMARC requires report addresses to be written as URIs with "
                    "a mailto: prefix. Note: most major providers no longer send "
                    "forensic reports due to privacy concerns, so this is low priority.",
                    f"Change to: ruf=mailto:{addr}",
                )

    # 6e. adkim (DKIM alignment)
    raw_adkim = tags.get("adkim", "")
    result["adkim"] = raw_adkim.lower() if raw_adkim else None
    if raw_adkim and raw_adkim.lower() not in VALID_ADKIM_ASPF:
        _add_syntax(
            f"Invalid adkim value: adkim={raw_adkim}",
            "DKIM alignment mode must be 'r' (relaxed) or 's' (strict). "
            f"'{raw_adkim}' is not valid.",
            "Change to adkim=r (relaxed, recommended) or adkim=s (strict).",
        )

    # 6f. aspf (SPF alignment)
    raw_aspf = tags.get("aspf", "")
    result["aspf"] = raw_aspf.lower() if raw_aspf else None
    if raw_aspf and raw_aspf.lower() not in VALID_ADKIM_ASPF:
        _add_syntax(
            f"Invalid aspf value: aspf={raw_aspf}",
            "SPF alignment mode must be 'r' (relaxed) or 's' (strict). "
            f"'{raw_aspf}' is not valid.",
            "Change to aspf=r (relaxed, recommended) or aspf=s (strict).",
        )

    # 6g. pct (percentage) — deprecated in DMARCbis, replaced by t= tag
    # Still validate if present since current receivers still honor it
    raw_pct = tags.get("pct", "")
    if raw_pct:
        try:
            pct_val = int(raw_pct)
            if pct_val < 0 or pct_val > 100:
                _add_syntax(
                    f"pct value out of range: pct={raw_pct}",
                    "The pct tag must be an integer between 0 and 100.",
                    "Change to a value between 0 and 100.",
                )
                result["pct"] = pct_val  # Store it anyway for reporting
            else:
                result["pct"] = pct_val
        except (ValueError, TypeError):
            _add_syntax(
                f"pct is not a valid integer: pct={raw_pct}",
                f"The pct tag value '{raw_pct}' is not a number. "
                "Receivers will likely ignore this and default to 100.",
                "Change to a whole number between 0 and 100 (e.g., pct=100).",
            )
            result["pct"] = 100  # Default per RFC
    else:
        result["pct"] = 100  # Default per RFC 7489

    # 6h. fo (failure reporting options)
    raw_fo = tags.get("fo", "")
    result["fo"] = raw_fo if raw_fo else None
    if raw_fo:
        fo_values = [v.strip() for v in raw_fo.split(":")]
        for fv in fo_values:
            if fv and fv not in VALID_FO:
                _add_syntax(
                    f"Invalid fo value: '{fv}' in fo={raw_fo}",
                    "The fo tag only accepts: 0 (all fail), 1 (any fail), "
                    "d (DKIM fail), s (SPF fail). Values are colon-separated.",
                    "Use fo=1 (recommended — reports on any authentication failure).",
                )

    # 6i. rf (report format)
    raw_rf = tags.get("rf", "")
    if raw_rf and raw_rf.lower() not in VALID_RF:
        _add_syntax(
            f"Invalid report format: rf={raw_rf}",
            "The only valid report format is 'afrf' (Authentication Failure "
            "Reporting Format). This is also the default if rf is omitted.",
            "Remove the rf tag (afrf is the default) or set rf=afrf.",
        )

    # 6j. ri (reporting interval)
    raw_ri = tags.get("ri", "")
    if raw_ri:
        try:
            ri_val = int(raw_ri)
            if ri_val < 0:
                _add_syntax(
                    f"Negative reporting interval: ri={raw_ri}",
                    "The ri tag must be a positive integer (seconds).",
                    "Use ri=86400 (daily, the default) or remove the tag.",
                )
        except (ValueError, TypeError):
            _add_syntax(
                f"ri is not a valid integer: ri={raw_ri}",
                f"The ri tag value '{raw_ri}' is not a number.",
                "Use ri=86400 (daily) or remove the tag to use the default.",
            )

    # ── Step 7: Policy-level issues (warnings, not syntax errors) ──

    if policy == "none":
        _add_issue(
            "warning",
            "DMARC policy is none (monitoring only)",
            "Policy p=none instructs receivers to deliver all email normally, "
            "even when authentication fails. This is the correct first step — "
            "it lets you collect data via aggregate reports — but it provides "
            "no protection against spoofing. Failed emails still reach inboxes.",
            "Review aggregate reports to identify all legitimate senders, then "
            "upgrade to p=quarantine, and ultimately p=reject.",
        )
    elif policy == "quarantine":
        pct = result["pct"]
        if pct is not None and pct < 100:
            _add_issue(
                "warning",
                f"DMARC pct={pct}% (partial enforcement)",
                f"Only {pct}% of messages that fail authentication are quarantined. "
                f"The remaining {100 - pct}% are still delivered normally, as if "
                "the policy were p=none.",
                "Increase pct to 100 once you've confirmed legitimate mail is passing.",
            )
    elif policy == "reject":
        pct = result["pct"]
        if pct is not None and pct < 100:
            _add_issue(
                "warning",
                f"DMARC pct={pct}% on reject policy (partial enforcement)",
                f"Only {pct}% of messages that fail authentication are rejected. "
                f"The remaining {100 - pct}% fall back to quarantine behavior.",
                "Increase pct to 100 for full reject enforcement.",
            )

    # DMARCbis t=y test mode (replaces pct for rollout)
    raw_t_val = tags.get("t", "")
    result["t"] = raw_t_val.lower() if raw_t_val else None
    if raw_t_val and raw_t_val.lower() == "y" and policy in ("quarantine", "reject"):
        effective = "none" if policy == "quarantine" else "quarantine"
        _add_issue(
            "warning",
            f"DMARC test mode active (t=y) — policy effectively {effective}",
            f"The t=y tag signals DMARCbis-aware receivers to apply the policy "
            f"one level below {policy}. In practice, receivers will treat this as "
            f"p={effective}. This is the DMARCbis replacement for the pct= rollout.",
            f"Remove t=y (or set t=n) once you're confident in your authentication "
            f"to apply the full p={policy} policy.",
        )

    # Missing rua — critical visibility gap
    if not result["rua"]:
        severity = "error" if policy in ("quarantine", "reject") else "warning"
        if policy in ("quarantine", "reject"):
            plain = (
                f"You are enforcing DMARC at p={policy} with no aggregate reporting. "
                "This means you're blocking or quarantining failed email but have no "
                "visibility into what's being affected. If a legitimate service fails "
                "authentication, you won't know until users report missing email."
            )
        else:
            plain = (
                "Without a rua tag, you receive no aggregate reports. You have no "
                "visibility into who is sending email as your domain or whether "
                "authentication is passing or failing."
            )
        _add_issue(
            severity,
            "No aggregate reporting (rua) configured",
            plain,
            f"Add rua=mailto:dmarc-reports@{domain} — or use a DMARC reporting "
            "service like dmarcian, EasyDMARC, or Valimail for readable dashboards.",
        )

    # ── Step 8: Merge syntax errors into issues and set final status ──
    # Syntax errors are always severity=error and go into the main issues list
    for se in result["syntax_errors"]:
        result["issues"].append(se)

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    return result


def _raw_check_spf(domain: str) -> Dict[str, Any]:
    """Check SPF record with lookup counting, mechanism analysis, and syntax validation.

    Syntax checks based on:
      - RFC 7208 (SPF specification)
      - openspf.org common errors
      - dmarc.org / dmarcian deployment guidance
    """
    import re
    import ipaddress

    # Known mechanisms that consume a DNS lookup (RFC 7208 §4.6.4)
    LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
    # Known mechanisms/modifiers (anything else is likely a typo)
    KNOWN_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
    KNOWN_MODIFIERS = {"redirect", "exp"}

    result = {
        "check": "SPF",
        "domain": domain,
        "record": None,
        "all_mechanism": None,
        "lookup_count": 0,
        "include_count": 0,
        "ip4_count": 0,
        "ip6_count": 0,
        "mechanisms": [],
        "status": "ok",
        "issues": [],
        "syntax_errors": [],
        "recommendations": [],
    }

    def _add_issue(severity, issue, plain_english, fix):
        result["issues"].append({
            "severity": severity,
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    def _add_syntax(issue, plain_english, fix):
        """Syntax errors are always severity=error."""
        result["syntax_errors"].append({
            "severity": "error",
            "issue": issue,
            "plain_english": plain_english,
            "fix": fix,
        })

    # ── Step 1: Lookup ──────────────────────────────────────────
    all_txt = _lookup_txt(domain)
    spf_records = [r for r in all_txt if r.strip().lower().startswith("v=spf1")]

    if not spf_records:
        result["status"] = "error"
        _add_issue(
            "error",
            "No SPF record found",
            "No SPF record tells receivers which servers can send your email.",
            f"Add TXT record at {domain}: v=spf1 include:YOUR_PROVIDER -all",
        )
        return result

    # ── Step 2: Multiple records = permerror (RFC 7208) ─────────
    if len(spf_records) > 1:
        result["status"] = "error"
        _add_issue(
            "error",
            f"Multiple SPF records ({len(spf_records)})",
            "RFC 7208 requires exactly one SPF record per domain. "
            "When multiple records exist, SPF returns a permanent error (permerror) — "
            "none of them are valid. This is the same as having no SPF at all.",
            "Merge into a single SPF record.",
        )
        return result

    record = spf_records[0]
    result["record"] = record

    # ── Step 3: Parse mechanisms and run syntax checks ──────────
    parts = record.split()
    all_mech = None
    include_count = 0
    ip4_count = 0
    ip6_count = 0
    has_redirect = False
    has_all = False
    seen_mechanisms = []

    for part in parts:
        # Skip the version tag
        if part.lower() == "v=spf1":
            continue

        # Strip qualifier prefix (+, -, ~, ?)
        qualifier = ""
        raw = part
        if raw and raw[0] in "+-~?":
            qualifier = raw[0]
            raw = raw[1:]

        raw_lower = raw.lower()

        # ── Check for spaces in mechanism syntax ────────────
        # Spaces between mechanism, colon, and value break parsing.
        # This is detected at the record level since split() already
        # separates on spaces. A token like "ip4:" with no value means
        # the value ended up as a separate token.
        if raw_lower.rstrip(":") in ("ip4", "ip6", "include", "exists", "a", "mx") and raw.endswith(":"):
            _add_syntax(
                f"Space after '{raw}' separates it from its value",
                f"'{part}' has a colon but no value — there may be a space between "
                "the mechanism and its argument. SPF mechanisms cannot have spaces "
                "between the name, colon, and value.",
                f"Remove the space: write as one token, e.g., ip4:1.2.3.4",
            )

        # ── Identify mechanism type ─────────────────────────
        if "=" in raw_lower:
            # Modifier (redirect=, exp=)
            mod_name, _, mod_value = raw.partition("=")
            mod_name_lower = mod_name.lower()

            if mod_name_lower == "redirect":
                has_redirect = True
                if not mod_value:
                    _add_syntax(
                        "Empty redirect= modifier (no domain specified)",
                        "The redirect= modifier has no domain value. "
                        "SPF will not know where to redirect lookups.",
                        "Specify a domain: redirect=_spf.example.com",
                    )
            elif mod_name_lower == "exp":
                pass  # exp= is informational, no validation needed
            elif mod_name_lower not in KNOWN_MODIFIERS:
                _add_syntax(
                    f"Unknown modifier: '{mod_name}'",
                    f"'{mod_name}' is not a recognized SPF modifier. "
                    "It may be a typo or misplaced DMARC/DKIM tag.",
                    f"Valid SPF modifiers are: redirect, exp.",
                )

        elif ":" in raw_lower:
            # Mechanism with value (include:, ip4:, ip6:, a:, mx:, etc.)
            mech_name, _, mech_value = raw.partition(":")
            mech_name_lower = mech_name.lower()

            if mech_name_lower == "include":
                include_count += 1
                if not mech_value:
                    _add_syntax(
                        "Empty include: mechanism (no domain specified)",
                        "An include: mechanism has no domain. SPF cannot look up "
                        "an empty domain — this wastes a DNS lookup and always fails.",
                        "Add a domain or remove the empty include.",
                    )
                seen_mechanisms.append(part)

            elif mech_name_lower == "ip4":
                ip4_count += 1
                # Validate IP address
                try:
                    if "/" in mech_value:
                        net = ipaddress.IPv4Network(mech_value, strict=False)
                        prefix = net.prefixlen
                        if prefix <= 16:
                            _add_issue(
                                "warning",
                                f"Overly broad SPF range: ip4:{mech_value} (/{prefix} = {net.num_addresses:,} addresses)",
                                f"This authorizes {net.num_addresses:,} IP addresses to send as your domain. "
                                "Broad ranges weaken SPF by authorizing far more servers than intended.",
                                "Narrow the range to only the IPs your mail servers actually use.",
                            )
                    else:
                        ipaddress.IPv4Address(mech_value)
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                    _add_syntax(
                        f"Invalid IPv4 address: ip4:{mech_value}",
                        f"'{mech_value}' is not a valid IPv4 address or CIDR range.",
                        "Use a valid IP like ip4:192.0.2.1 or range like ip4:192.0.2.0/24.",
                    )
                seen_mechanisms.append(part)

            elif mech_name_lower == "ip6":
                ip6_count += 1
                try:
                    if "/" in mech_value:
                        net = ipaddress.IPv6Network(mech_value, strict=False)
                        prefix = net.prefixlen
                        if prefix <= 48:
                            _add_issue(
                                "warning",
                                f"Overly broad SPF range: ip6:{mech_value} (/{prefix})",
                                f"This IPv6 range is very broad and authorizes a large number of addresses.",
                                "Narrow the range to only the IPs your mail servers actually use.",
                            )
                    else:
                        ipaddress.IPv6Address(mech_value)
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                    _add_syntax(
                        f"Invalid IPv6 address: ip6:{mech_value}",
                        f"'{mech_value}' is not a valid IPv6 address or CIDR range.",
                        "Use a valid IPv6 address like ip6:2001:db8::1 or range like ip6:2001:db8::/32.",
                    )
                seen_mechanisms.append(part)

            elif mech_name_lower == "ptr":
                _add_issue(
                    "warning",
                    f"Deprecated 'ptr' mechanism: {part}",
                    "The ptr mechanism is deprecated and no longer in use. "
                    "Receivers may ignore it.",
                    "Remove the ptr mechanism. Use ip4:/ip6: or include: instead.",
                )
                seen_mechanisms.append(part)

            elif mech_name_lower in KNOWN_MECHANISMS:
                seen_mechanisms.append(part)

            else:
                _add_syntax(
                    f"Unknown mechanism: '{mech_name}'",
                    f"'{mech_name}' is not a recognized SPF mechanism. "
                    "This may be a typo (e.g., 'inclde' instead of 'include').",
                    f"Valid mechanisms: {', '.join(sorted(KNOWN_MECHANISMS))}.",
                )

        else:
            # Bare mechanism (all, a, mx, ptr)
            mech_lower = raw_lower

            if mech_lower == "all":
                has_all = True
                effective_qualifier = qualifier if qualifier else "+"
                all_mech = effective_qualifier + "all"

            elif mech_lower == "ptr":
                _add_issue(
                    "warning",
                    "Deprecated 'ptr' mechanism",
                    "The ptr mechanism is deprecated and no longer in use. "
                    "Receivers may ignore it.",
                    "Remove the ptr mechanism. Use ip4:/ip6: or include: instead.",
                )
                seen_mechanisms.append(part)

            elif mech_lower in KNOWN_MECHANISMS:
                seen_mechanisms.append(part)

            elif mech_lower not in KNOWN_MECHANISMS:
                # Unknown bare token
                _add_syntax(
                    f"Unknown mechanism: '{raw}'",
                    f"'{raw}' is not a recognized SPF mechanism or modifier.",
                    f"Valid mechanisms: {', '.join(sorted(KNOWN_MECHANISMS))}.",
                )

    # ── Step 4: Cross-mechanism checks ──────────────────────────

    # redirect= is ignored when 'all' is present (common misconfiguration)
    if has_redirect and has_all:
        _add_issue(
            "warning",
            "Both 'redirect=' and 'all' present — redirect is ignored",
            "When an SPF record contains both a redirect= modifier and an 'all' "
            "mechanism, the redirect is ignored entirely. The 'all' mechanism "
            "takes precedence. If you intended to redirect SPF evaluation to "
            "another domain, the 'all' mechanism is preventing that.",
            "Remove either redirect= or the 'all' mechanism, depending on your intent.",
        )

    # ── Step 5: Recursive SPF lookup count ──────────────────────
    spf_recursive_result = count_spf_lookups(domain)
    lookup_count = spf_recursive_result["total_lookups"]

    result["lookup_count"] = lookup_count
    result["include_count"] = include_count
    result["ip4_count"] = ip4_count
    result["ip6_count"] = ip6_count
    result["all_mechanism"] = all_mech
    result["spf_chain"] = spf_recursive_result.get("chain", [])
    result["spf_recursive"] = spf_recursive_result

    # ── Step 6: Lookup limit checks ─────────────────────────────
    if lookup_count > 10:
        _add_issue(
            "error",
            f"SPF exceeds 10-lookup limit ({lookup_count} lookups)",
            "RFC 7208 limits SPF to 10 DNS lookups. Exceeding this causes "
            "SPF to return a permanent error (permerror) — it fails entirely, "
            "as if no SPF record existed.",
            "Reduce lookups by flattening includes to IP addresses or removing unused services.",
        )
    elif lookup_count == 10:
        _add_issue(
            "warning",
            "SPF is at the 10-lookup limit",
            "Adding any more includes or mechanisms that require DNS lookups "
            "will push SPF over the limit, causing it to fail entirely.",
            "Consider SPF flattening to free up lookup slots.",
        )

    # ── Step 7: 'all' mechanism checks ──────────────────────────
    if all_mech == "+all":
        _add_issue(
            "error",
            "SPF uses +all (authorizes everyone)",
            "The +all mechanism authorizes the entire internet to send email "
            "as your domain. This completely defeats the purpose of SPF.",
            "Change +all to -all (hard fail) or ~all (soft fail).",
        )
    elif all_mech == "?all":
        _add_issue(
            "warning",
            "SPF uses ?all (neutral)",
            "The ?all mechanism provides no opinion about unauthorized senders. "
            "It does not protect your domain from spoofing.",
            "Change ?all to -all or ~all.",
        )
    elif not all_mech:
        _add_issue(
            "warning",
            "No 'all' mechanism found",
            "SPF records should end with an 'all' mechanism to define what happens "
            "to mail from servers not listed in the record. Without it, the default "
            "is neutral (?all) — no protection.",
            "Add -all to the end of the SPF record.",
        )

    # ── Step 8: Merge syntax errors into issues and set final status ──
    for se in result["syntax_errors"]:
        result["issues"].append(se)

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    return result


def _raw_check_dnssec(domain: str) -> Dict[str, Any]:
    """Check if DNSSEC is enabled."""
    result = {"has_dnssec": False}
    try:
        resolver = _get_resolver()
        resolver.resolve(domain, "DNSKEY")
        result["has_dnssec"] = True
    except Exception:
        result["has_dnssec"] = False
    return result


# ============================================================
# Main Audit Orchestrator
# ============================================================

def run_full_audit(domain: str) -> Dict[str, Any]:
    """
    Run all security checks and return the complete audit result
    in the format expected by the frontend.

    Each check runs in a try/except so one failure doesn't kill the audit.
    """
    start_time = datetime.now()
    checks = []
    raw_results = {}
    errors = []

    # --- 1. DMARC ---
    try:
        raw_dmarc = _raw_check_dmarc(domain)
        raw_results["dmarc"] = raw_dmarc
        checks.append(transform_dmarc(raw_dmarc))
    except Exception as e:
        errors.append(f"DMARC: {str(e)}")
        checks.append(_error_card("DMARC", e))

    # --- DMARC Tree Walk (dmarcbis-41 Section 4.10) ---
    tree_walk_result = None
    try:
        tree_walk_result = dmarc_tree_walk(domain)
    except Exception as e:
        errors.append(f"Tree Walk: {str(e)}")

    # --- 2. SPF ---
    spf_record = None
    try:
        raw_spf = _raw_check_spf(domain)
        raw_results["spf"] = raw_spf
        spf_record = raw_spf.get("record")
        checks.append(transform_spf(raw_spf))
    except Exception as e:
        errors.append(f"SPF: {str(e)}")
        checks.append(_error_card("SPF", e))

    # --- 3. MX Records ---
    try:
        raw_mx = check_mx(domain)
        raw_results["mx"] = raw_mx
        checks.append(transform_mx(raw_mx))
    except Exception as e:
        errors.append(f"MX: {str(e)}")
        checks.append(_error_card("MX Records", e))

    # --- 4. MTA-STS ---
    try:
        raw_mta_sts = check_mta_sts(domain)
        raw_results["mta_sts"] = raw_mta_sts
        checks.append(transform_mta_sts(raw_mta_sts, domain))
    except Exception as e:
        errors.append(f"MTA-STS: {str(e)}")
        checks.append(_error_card("MTA-STS", e))

    # --- 5. TLS-RPT ---
    try:
        raw_tls_rpt = check_tls_rpt(domain)
        raw_results["tls_rpt"] = raw_tls_rpt
        checks.append(transform_tls_rpt(raw_tls_rpt, domain))
    except Exception as e:
        errors.append(f"TLS-RPT: {str(e)}")
        checks.append(_error_card("TLS-RPT", e))

    # --- 6. BIMI ---
    try:
        raw_bimi = check_bimi(domain)
        raw_results["bimi"] = raw_bimi
        checks.append(transform_bimi(raw_bimi, domain))
    except Exception as e:
        errors.append(f"BIMI: {str(e)}")
        checks.append(_error_card("BIMI", e))

    # --- 7. DNSSEC ---
    try:
        raw_dnssec = _raw_check_dnssec(domain)
        raw_results["dnssec"] = raw_dnssec
        checks.append(transform_dnssec(raw_dnssec))
    except Exception as e:
        errors.append(f"DNSSEC: {str(e)}")
        checks.append(_error_card("DNSSEC", e))

    # --- 8. DKIM (runs last - scans 1000+ selectors, other results load first) ---
    try:
        raw_dkim = smart_dkim_check(domain, spf_record)
        raw_results["dkim"] = raw_dkim
        checks.insert(2, transform_dkim(raw_dkim, domain))
    except Exception as e:
        errors.append(f"DKIM: {str(e)}")
        checks.insert(2, _error_card("DKIM", e))

    # --- Security Score ---
    score_result = _calculate_score(raw_results, domain)

    # --- Vendor Fingerprinting ---
    vendors = _get_vendors(raw_results, domain)

    # --- Priority Fixes ---
    priority_fixes = _build_priority_fixes(checks, score_result)

    # --- Assemble final response ---
    elapsed = (datetime.now() - start_time).total_seconds()

    return {
        "domain": domain,
        "timestamp": start_time.isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "score": {
            "total": score_result.get("total_score", 0),
            "grade": score_result.get("grade", "?"),
        },
        "checks": checks,
        "priority_fixes": priority_fixes,
        "vendors": vendors,
        "tree_walk": tree_walk_result,
        "errors": errors if errors else None,
    }


# ============================================================
# Score Calculation
# ============================================================

def _calculate_score(raw_results: Dict, domain: str) -> Dict:
    """Build the audit_results dict that EmailSecurityScorer expects."""
    try:
        # DMARC results
        raw_dmarc = raw_results.get("dmarc", {})
        dmarc_for_scorer = {
            "record": raw_dmarc.get("record"),
            "policy": raw_dmarc.get("policy", ""),
            "pct": raw_dmarc.get("pct", 100),
            "rua": raw_dmarc.get("rua"),
            "ruf": raw_dmarc.get("ruf"),
            "sp": raw_dmarc.get("sp"),
            "domain": domain,
        }

        # SPF results
        raw_spf = raw_results.get("spf", {})
        spf_for_scorer = {
            "record": raw_spf.get("record"),
            "all": raw_spf.get("all_mechanism", ""),
            "lookup_count": raw_spf.get("lookup_count", 0),
            "include_count": raw_spf.get("include_count", 0),
        }

        # DKIM results
        raw_dkim = raw_results.get("dkim", {})
        dkim_for_scorer = {
            "found_selectors": raw_dkim.get("found_selectors", []),
        }

        # Key age analysis
        key_age = {"overdue": 0, "due_soon": 0, "current": 0}
        try:
            analyzer = DKIMKeyAgeAnalyzer(domain)
            for sel in raw_dkim.get("found_selectors", []):
                record = sel.get("record", "")
                key_analysis = analyze_dkim_key_strength(record)
                key_size = key_analysis.get("key_bits", 2048)
                result = analyzer.analyze_key(sel.get("selector", ""), record, key_size)
                status = result.get("rotation_status", "UNKNOWN")
                if status == "OVERDUE":
                    key_age["overdue"] += 1
                elif status == "DUE_SOON":
                    key_age["due_soon"] += 1
                elif status == "CURRENT":
                    key_age["current"] += 1
        except Exception:
            pass

        # Vendor fingerprint
        vendor_for_scorer = {"vendors": []}
        try:
            fp = AdvancedVendorFingerprinter(domain)
            fp_result = fp.fingerprint_all()
            vendor_for_scorer["vendors"] = [
                {"vendor": v["vendor"], "confidence": v["confidence"]}
                for v in fp_result.get("vendors", [])
            ]
        except Exception:
            pass

        # MTA-STS / TLS-RPT / BIMI configured flags
        mta_sts_configured = bool(raw_results.get("mta_sts", {}).get("txt_record"))
        tls_rpt_configured = bool(raw_results.get("tls_rpt", {}).get("record"))
        bimi_configured = bool(raw_results.get("bimi", {}).get("record"))

        # Assemble for scorer
        audit_input = {
            "dmarc_results": dmarc_for_scorer,
            "spf_results": spf_for_scorer,
            "dkim_results": dkim_for_scorer,
            "key_age_analysis": key_age,
            "vendor_fingerprint": vendor_for_scorer,
            "mta_sts": {"configured": mta_sts_configured},
            "tls_rpt": {"configured": tls_rpt_configured},
            "bimi": {"configured": bimi_configured},
        }

        scorer = EmailSecurityScorer()
        return scorer.calculate_score(audit_input)

    except Exception as e:
        return {"total_score": 0, "grade": "?", "error": str(e)}


# ============================================================
# Vendor Detection
# ============================================================

def _get_vendors(raw_results: Dict, domain: str) -> List[Dict]:
    """Get vendor list from fingerprinting, formatted for frontend."""
    vendors = []
    try:
        fp = AdvancedVendorFingerprinter(domain)
        fp_result = fp.fingerprint_all()
        for v in fp_result.get("vendors", []):
            confidence = v.get("confidence", 0)
            if confidence >= 0.5:  # Only show meaningful detections
                vendors.append({
                    "name": v["vendor"],
                    "confidence": int(confidence * 100),
                })
    except Exception:
        pass

    # Deduplicate by name, keep highest confidence
    seen = {}
    for v in vendors:
        name = v["name"]
        if name not in seen or v["confidence"] > seen[name]["confidence"]:
            seen[name] = v
    return sorted(seen.values(), key=lambda x: x["confidence"], reverse=True)


# ============================================================
# Priority Fixes
# ============================================================

def _build_priority_fixes(checks: List[Dict], score_result: Dict) -> List[str]:
    """
    Build prioritized fix list from check results and scorer recommendations.
    Maximum 5 items, ordered by severity. Deduplicates by check name.
    """
    fixes = []
    covered_checks = set()

    # Scorer recommendations (already prioritized and more actionable)
    scorer_recs = score_result.get("recommendations", [])
    for rec in scorer_recs:
        # Strip emoji prefixes for clean display
        clean = re.sub(r'^[^\w]*\s*(?:CRITICAL|HIGH|MEDIUM|LOW):\s*', '', rec)
        if clean and clean not in fixes:
            fixes.append(clean)
            # Track which checks are covered to avoid duplicates
            for keyword in ['DMARC', 'SPF', 'DKIM', 'MTA-STS', 'TLS-RPT', 'MX']:
                if keyword.lower() in clean.lower():
                    covered_checks.add(keyword)

    # Check-level fixes (only for checks the scorer didn't already cover)
    for check in checks:
        if check.get("status") == "fail" and check.get("fix"):
            check_name = check.get("name", "")
            if check_name in covered_checks:
                continue
            # Skip error cards (generic retry messages aren't actionable)
            if check.get("pill_label") == "Error":
                continue
            # Strip HTML for the priority list
            fix_text = re.sub(r'<[^>]+>', '', check["fix"])
            # Collapse whitespace from removed HTML tags
            fix_text = re.sub(r'\s+', ' ', fix_text).strip()
            if fix_text and fix_text not in fixes:
                fixes.append(fix_text)

    return fixes[:5]


# ============================================================
# Error Card Helper
# ============================================================

def _error_card(name: str, error: Exception) -> Dict:
    """Generate a card for a check that threw an exception."""
    return {
        "name": name,
        "status": "fail",
        "pill_label": "Error",
        "verdict": "Check failed due to an error",
        "record": None,
        "explanation": f"An unexpected error occurred while running the {name} check. This may be a temporary DNS issue.",
        "details": [
            {"type": "error", "text": f"Error: {str(error)[:200]}"},
        ],
        "fix": "Try running the audit again. If the issue persists, the DNS server may be unresponsive.",
    }
