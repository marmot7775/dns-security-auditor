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

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from html import escape as _e

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
    detail = {
        "type": type_map.get(severity, "info"),
        "text": issue.get("plain_english") or issue.get("issue", ""),
    }
    risk = issue.get("business_risk")
    if risk:
        detail["business_risk"] = risk
    return detail


def _first_fix(issues: List[Dict]) -> Optional[str]:
    """Extract the first actionable fix from issues list."""
    for issue in issues:
        fix = issue.get("fix")
        if fix:
            return fix
    return None


# ============================================================
# Executive Summary (Prompt 16)
# ============================================================

def build_executive_summary(checks: List[Dict], roadmap: Dict) -> Dict:
    """Build the executive summary card shown at the very top of results.

    Returns a dict with: verdict, spoofing_protection, dmarcbis_readiness,
    protocol_coverage, biggest_risk, and has_record_builder.
    """
    check_map = {c.get("name", ""): c for c in checks}
    dmarc = check_map.get("DMARC", {})

    # ── Part 1: One-sentence verdict ─────────────────────────
    attack_surface = dmarc.get("attack_surface")
    health = (dmarc.get("tag_breakdown") or {}).get("health", {})
    health_status = health.get("status", "")
    dmarc_status = dmarc.get("status", "")
    spf_status = check_map.get("SPF", {}).get("status", "")

    # Count protected vectors
    vectors = (attack_surface or {}).get("vectors", [])
    protected_count = sum(1 for v in vectors if v.get("status") == "protected")
    exposed_count = sum(1 for v in vectors if v.get("status") == "exposed")
    partial_count = sum(1 for v in vectors if v.get("status") == "partial")

    if dmarc_status == "fail" and dmarc.get("pill_label") == "Missing":
        if spf_status == "fail":
            verdict = "Your domain has no email authentication. Anyone on the internet can send email pretending to be you."
        else:
            verdict = "Your domain has no DMARC record. SPF alone cannot prevent email spoofing."
    elif health_status == "monitoring":
        verdict = "Your domain is monitoring email authentication but not yet enforcing it. Spoofed email is still delivered."
    elif protected_count == 4:
        if health_status == "ready":
            verdict = "Your domain is well-protected against email spoofing across all attack vectors."
        else:
            verdict = "Your domain blocks spoofed email across all vectors, with minor improvements available."
    elif protected_count >= 3 and exposed_count == 0:
        verdict = "Your domain has strong email authentication with most attack vectors covered."
    elif exposed_count >= 2:
        verdict = "Your domain has significant gaps in email spoofing protection across multiple attack vectors."
    elif exposed_count == 1:
        weakest = [v for v in vectors if v.get("status") == "exposed"]
        vec_name = weakest[0]["name"].lower() if weakest else "one vector"
        verdict = f"Your domain has email authentication but attackers can still exploit {vec_name}."
    elif partial_count > 0:
        verdict = "Your domain partially blocks spoofed email but enforcement could be stronger."
    else:
        verdict = "Your domain has email authentication configured."

    # Check if enforcement exists but no reporting
    if health_status in ("ready", "compatible", "attention"):
        tb = dmarc.get("tag_breakdown") or {}
        cw = tb.get("config_warnings", [])
        has_no_rua = any(w.get("title") == "No aggregate reporting" for w in cw)
        if has_no_rua:
            verdict = "Your domain blocks spoofed email but has no visibility into what is being blocked."

    # ── Part 2: Three key metrics ────────────────────────────

    # Metric 1: Spoofing Protection
    if protected_count == 4:
        spoof_label, spoof_color = "Full", "green"
    elif protected_count == 3:
        spoof_label, spoof_color = "Strong", "green"
    elif protected_count == 2:
        spoof_label, spoof_color = "Partial", "amber"
    elif protected_count == 1:
        spoof_label, spoof_color = "Weak", "red"
    else:
        spoof_label, spoof_color = "None", "red"

    # No attack surface means no DMARC record
    if not attack_surface:
        spoof_label, spoof_color = "None", "red"
        protected_count = 0

    spoofing_protection = {
        "label": spoof_label,
        "color": spoof_color,
        "detail": f"{protected_count}/4 vectors protected",
    }

    # Metric 2: DMARCbis Readiness
    readiness_map = {
        "ready": ("Ready", "green"),
        "compatible": ("Compatible", "blue"),
        "monitoring": ("In Progress", "amber"),
        "attention": ("In Progress", "amber"),
        "misconfigured": ("Action Needed", "red"),
    }
    if health_status and health_status in readiness_map:
        rd_label, rd_color = readiness_map[health_status]
    else:
        rd_label, rd_color = "Action Needed", "red"

    dmarcbis_readiness = {
        "label": rd_label,
        "color": rd_color,
    }

    # Metric 3: Protocol Coverage
    protocol_names = ["DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "DNSSEC", "BIMI", "CAA"]
    configured = 0
    for pname in protocol_names:
        c = check_map.get(pname, {})
        st = c.get("status", "")
        pill = c.get("pill_label", "")
        # Consider configured if not missing/not-configured/fail-with-missing
        if st == "pass" or st == "warn":
            configured += 1
        elif st == "fail" and pill not in ("Missing", "Not configured", ""):
            configured += 1

    total_protocols = len(protocol_names)
    if configured >= 7:
        cov_color = "green"
    elif configured >= 4:
        cov_color = "amber"
    else:
        cov_color = "red"

    protocol_coverage = {
        "configured": configured,
        "total": total_protocols,
        "color": cov_color,
    }

    # ── Part 3: Biggest risk ─────────────────────────────────
    roadmap_items = roadmap.get("items", [])
    if roadmap_items:
        top = roadmap_items[0]
        biggest_risk = top.get("impact", top.get("action", ""))
    else:
        biggest_risk = "No urgent risks found. See the roadmap below for optimization opportunities."

    # ── Part 4: has_record_builder flag ──────────────────────
    has_record_builder = dmarc.get("record_builder") is not None

    # ── Part 5: Deliverability summary ────────────────────────
    dkim_check = check_map.get("DKIM", {})
    spf_check = check_map.get("SPF", {})
    blocklist_check = check_map.get("Blocklist", {})

    deliverability_issues = []
    if dmarc_status == "fail" and dmarc.get("pill_label") == "Missing":
        deliverability_issues.append("no DMARC record")
    elif health_status == "monitoring":
        deliverability_issues.append("DMARC is in monitoring mode (p=none)")

    if spf_status == "fail" and spf_check.get("pill_label") == "Missing":
        deliverability_issues.append("no SPF record")

    spf_lookups = None
    for d in spf_check.get("details", []):
        text = d.get("text", "")
        if "DNS lookups" in text and ("near" in text or "at" in text or "invalid" in text.lower()):
            deliverability_issues.append("SPF lookup count is at or near the limit")
            break

    if blocklist_check.get("status") == "fail":
        deliverability_issues.append("domain is listed on a blocklist")

    if dkim_check.get("status") == "warn" and dkim_check.get("pill_label") == "Unknown":
        pass  # Can't confirm, don't alarm

    if deliverability_issues:
        top_issue = deliverability_issues[0]
        if "blocklist" in top_issue:
            deliverability_summary = f"Your domain is listed on a blocklist. This is likely causing delivery failures right now."
        elif "no DMARC" in top_issue:
            deliverability_summary = "Without DMARC, your business emails may be landing in spam. Gmail and Yahoo now require DMARC for reliable delivery."
        elif "p=none" in top_issue:
            deliverability_summary = "Your DMARC policy is monitoring only (p=none). Gmail, Yahoo, and Outlook may treat your email with more suspicion until you enforce."
        elif "no SPF" in top_issue:
            deliverability_summary = "Without SPF, receivers cannot verify your sending servers. This is a common cause of emails going to spam."
        elif "SPF lookup" in top_issue:
            deliverability_summary = "Your SPF record is near the 10-lookup limit. Adding one more email service could break SPF for all your email."
        else:
            deliverability_summary = f"Your configuration has {len(deliverability_issues)} issue{'s' if len(deliverability_issues) != 1 else ''} that may affect inbox placement."
    else:
        deliverability_summary = "Your configuration looks solid. SPF, DKIM, and DMARC are properly set up, giving you the best chance of reaching inboxes."

    return {
        "verdict": verdict,
        "spoofing_protection": spoofing_protection,
        "dmarcbis_readiness": dmarcbis_readiness,
        "protocol_coverage": protocol_coverage,
        "biggest_risk": biggest_risk,
        "has_record_builder": has_record_builder,
        "deliverability_summary": deliverability_summary,
    }


# ============================================================
# Email Security Roadmap (Prompt 11)
# ============================================================

def build_security_roadmap(checks: List[Dict]) -> Dict:
    """Synthesize all check results into a prioritized action plan.

    Takes the transformed checks list and returns a roadmap with
    4 priority tiers: critical, high, medium, low.
    """
    items: List[Dict] = []
    check_map = {c.get("name", ""): c for c in checks}

    dmarc = check_map.get("DMARC", {})
    spf = check_map.get("SPF", {})
    dkim = check_map.get("DKIM", {})
    mta_sts = check_map.get("MTA-STS", {})
    tls_rpt = check_map.get("TLS-RPT", {})
    dane = check_map.get("DANE", {})

    # ── Critical ────────────────────────────────────────────
    if dmarc.get("status") == "fail" and dmarc.get("pill_label") == "Missing":
        items.append({"priority": "critical", "protocol": "DMARC",
                      "action": "Publish a DMARC record",
                      "impact": "Your domain has no DMARC protection. Anyone can send email as your domain."})

    if spf.get("status") == "fail" and spf.get("pill_label") == "Missing":
        items.append({"priority": "critical", "protocol": "SPF",
                      "action": "Publish an SPF record",
                      "impact": "No SPF record means receivers cannot verify your authorized mail servers."})

    # +all in SPF
    if spf.get("record") and "+all" in (spf.get("record") or ""):
        items.append({"priority": "critical", "protocol": "SPF",
                      "action": "Remove +all from your SPF record",
                      "impact": "+all authorizes every server on the internet to send as your domain."})

    # No rua at any policy
    tb = dmarc.get("tag_breakdown", {})
    if tb:
        cw = tb.get("config_warnings", [])
        for w in cw:
            if w.get("level") == "critical" and w.get("title") == "No aggregate reporting":
                items.append({"priority": "critical", "protocol": "DMARC",
                              "action": "Add aggregate reporting (rua=)",
                              "impact": "Zero visibility into email authentication results."})
                break

    # ── High ────────────────────────────────────────────────
    # Missing p= with rua: interop hazard between RFC 7489 and dmarcbis
    if tb:
        for w in cw:
            if w.get("title") == "Missing p= tag (interop hazard)":
                items.append({"priority": "high", "protocol": "DMARC",
                              "action": "Add explicit p= tag to the DMARC record",
                              "impact": "RFC 7489 receivers ignore this record entirely; dmarcbis receivers treat as p=none. Receiver behavior is split."})
                break

    # p=none with rua (monitoring)
    health = tb.get("health", {}) if tb else {}
    if health.get("status") == "monitoring":
        items.append({"priority": "high", "protocol": "DMARC",
                      "action": "Progress from p=none to enforcement",
                      "impact": "Domain is in monitoring mode. Spoofed mail is still delivered."})

    # DKIM weak keys
    dkim_deep = dkim.get("dkim_deep", {})
    if dkim_deep and dkim_deep.get("has_weak"):
        items.append({"priority": "high", "protocol": "DKIM",
                      "action": "Rotate weak DKIM keys to 2048-bit",
                      "impact": "Weak keys can be factored, allowing forged DKIM signatures."})

    # SPF near limit
    spf_deep = spf.get("spf_deep", {})
    if spf_deep and spf_deep.get("lookup_count", 0) >= 8:
        items.append({"priority": "high", "protocol": "SPF",
                      "action": f"Reduce SPF lookups ({spf_deep['lookup_count']}/10)",
                      "impact": "Exceeding 10 lookups causes SPF to fail entirely."})

    # ── Medium ──────────────────────────────────────────────
    if mta_sts.get("pill_label") == "Not configured":
        items.append({"priority": "medium", "protocol": "MTA-STS",
                      "action": "Configure MTA-STS for TLS enforcement",
                      "impact": "Without MTA-STS, email encryption can be silently stripped."})

    if tls_rpt.get("status") == "fail" or tls_rpt.get("pill_label") == "Not configured":
        items.append({"priority": "medium", "protocol": "TLS-RPT",
                      "action": "Configure TLS-RPT for failure visibility",
                      "impact": "TLS downgrade attacks go undetected."})

    if dane.get("pill_label") == "Not configured":
        items.append({"priority": "medium", "protocol": "DANE",
                      "action": "Consider DANE TLSA records",
                      "impact": "DANE provides CA-independent certificate verification."})

    # DMARCbis readiness gaps
    if health.get("status") in ("compatible", "attention"):
        for reason in health.get("reasons", []):
            items.append({"priority": "medium", "protocol": "DMARC",
                          "action": f"Address: {reason}",
                          "impact": "Record is not fully DMARCbis-ready."})

    # ── Low ─────────────────────────────────────────────────
    bimi = check_map.get("BIMI", {})
    if bimi.get("status") != "pass":
        items.append({"priority": "low", "protocol": "BIMI",
                      "action": "Consider adding BIMI for brand visibility",
                      "impact": "BIMI displays your logo in supported email clients."})

    # Count by tier
    tiers = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        tiers[item["priority"]] = tiers.get(item["priority"], 0) + 1

    total = len(items)
    if total == 0:
        summary = "Your email security meets all current best practices across all protocols."
    else:
        summary = f"{total} recommendation{'s' if total != 1 else ''} across {sum(1 for v in tiers.values() if v > 0)} priority tier{'s' if sum(1 for v in tiers.values() if v > 0) != 1 else ''}."

    return {
        "items": items,
        "tiers": tiers,
        "total": total,
        "summary": summary,
    }


# ============================================================
# TTL Freshness Helpers (Prompt 18, Part 2)
# ============================================================


def format_ttl(ttl: Optional[int]) -> Optional[Dict]:
    """Convert a TTL value into a human-readable freshness indicator."""
    if ttl is None:
        return None

    if ttl < 300:
        category = "very_short"
        label = "Very short TTL"
        detail = "This record changes frequently or was recently modified. Changes propagate in under 5 minutes."
    elif ttl <= 3600:
        minutes = ttl // 60
        category = "short"
        label = "Short TTL"
        detail = f"Changes propagate within {minutes} minute{'s' if minutes != 1 else ''}."
    elif ttl <= 86400:
        hours = ttl // 3600
        category = "standard"
        label = "Standard TTL"
        detail = f"Changes propagate within {hours} hour{'s' if hours != 1 else ''}."
    else:
        hours = ttl // 3600
        days = ttl // 86400
        category = "long"
        label = "Long TTL"
        if days >= 1:
            detail = f"Changes take over {days} day{'s' if days != 1 else ''} to propagate."
        else:
            detail = f"Changes take over {hours} hours to propagate."

    return {
        "ttl": ttl,
        "category": category,
        "label": label,
        "detail": detail,
        "human": _humanize_seconds(ttl),
    }


def _humanize_seconds(seconds: int) -> str:
    """Convert seconds to a human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        m = seconds // 60
        return f"{m}m"
    if seconds < 86400:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h{m}m" if m else f"{h}h"
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    return f"{d}d{h}h" if h else f"{d}d"


# ============================================================
# Change Detection (Prompt 18, Part 1)
# ============================================================


_RECORD_TYPE_LABELS = {
    "dmarc": "DMARC",
    "spf": "SPF",
    "mx": "MX Records",
    "mta-sts": "MTA-STS",
    "tls-rpt": "TLS-RPT",
    "dnssec": "DNSSEC",
    "caa": "CAA",
    "nameservers": "Nameservers",
}


def _classify_change(record_type: str, old_value: str, new_value: str) -> Dict:
    """Analyze what specifically changed between two record values and whether
    the change is an improvement or regression."""
    change = {
        "description": f"{_RECORD_TYPE_LABELS.get(record_type, record_type)} record changed",
        "is_improvement": None,  # True = green, False = red, None = neutral
    }

    if record_type == "dmarc":
        old_tags = _parse_record_tags(old_value)
        new_tags = _parse_record_tags(new_value)

        # Check policy change
        old_p = old_tags.get("p", "")
        new_p = new_tags.get("p", "")
        policy_rank = {"none": 0, "quarantine": 1, "reject": 2}
        if old_p != new_p:
            old_rank = policy_rank.get(old_p.lower(), -1)
            new_rank = policy_rank.get(new_p.lower(), -1)
            if new_rank > old_rank:
                change["description"] = f"Policy upgraded from p={old_p} to p={new_p}"
                change["is_improvement"] = True
            elif new_rank < old_rank:
                change["description"] = f"Policy downgraded from p={old_p} to p={new_p}"
                change["is_improvement"] = False
            else:
                change["description"] = f"Policy changed from p={old_p} to p={new_p}"

        # Check sp change
        old_sp = old_tags.get("sp", "")
        new_sp = new_tags.get("sp", "")
        if old_sp != new_sp and old_p == new_p:
            change["description"] = f"Subdomain policy changed from sp={old_sp or '(absent)'} to sp={new_sp or '(absent)'}"
            sp_old_rank = policy_rank.get(old_sp.lower(), -1) if old_sp else -1
            sp_new_rank = policy_rank.get(new_sp.lower(), -1) if new_sp else -1
            change["is_improvement"] = sp_new_rank > sp_old_rank

        # Check np added
        if "np" not in old_tags and "np" in new_tags:
            change["description"] = f"Added np={new_tags['np']} (DMARCbis tag)"
            change["is_improvement"] = True

        # Check rua added/removed
        if "rua" not in old_tags and "rua" in new_tags:
            change["description"] = "Added aggregate reporting (rua=)"
            change["is_improvement"] = True
        elif "rua" in old_tags and "rua" not in new_tags:
            change["description"] = "Removed aggregate reporting (rua=)"
            change["is_improvement"] = False

    elif record_type == "spf":
        # Check for all-mechanism changes
        old_all = _extract_spf_all(old_value)
        new_all = _extract_spf_all(new_value)
        all_rank = {"+all": 0, "?all": 1, "~all": 2, "-all": 3}
        if old_all != new_all:
            old_rank = all_rank.get(old_all, -1)
            new_rank = all_rank.get(new_all, -1)
            if new_rank > old_rank:
                change["description"] = f"SPF hardened: {old_all} to {new_all}"
                change["is_improvement"] = True
            elif new_rank < old_rank:
                change["description"] = f"SPF weakened: {old_all} to {new_all}"
                change["is_improvement"] = False

    return change


def _parse_record_tags(record: str) -> Dict[str, str]:
    """Parse tag=value pairs from a DMARC-style record."""
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    return tags


def _extract_spf_all(record: str) -> str:
    """Extract the all mechanism from an SPF record."""
    parts = record.strip().split()
    for p in reversed(parts):
        p_lower = p.lower()
        if p_lower in ("+all", "-all", "~all", "?all", "all"):
            return p_lower
    return ""


def _normalize_record_for_comparison(value: str) -> str:
    """Normalize a DNS record string so whitespace-only differences are ignored.

    Strips extra spaces, standardizes semicolon/space patterns (e.g. both
    ``p=quarantine;sp=reject`` and ``p=quarantine; sp=reject`` become the same
    canonical form), and lowercases for comparison purposes.
    """
    import re
    if not value:
        return ""
    # Collapse all runs of whitespace to a single space
    s = re.sub(r'\s+', ' ', value.strip())
    # Standardize semicolons: ensure exactly "; " (semicolon + one space)
    s = re.sub(r'\s*;\s*', '; ', s)
    return s


def build_change_detection(
    raw_results: Dict,
    history: Dict[str, list],
    first_seen: Optional[str],
) -> Optional[Dict]:
    """Build the change detection section from snapshot history.

    Args:
        raw_results: Current raw audit results keyed by check name
        history: Dict of record_type -> list of historical snapshots (newest first)
        first_seen: Timestamp of earliest snapshot for this domain
    """
    if not history:
        return {
            "status": "first_audit",
            "message": "We are now tracking this domain. Run another audit later to detect changes.",
            "changes": [],
            "first_seen": None,
        }

    changes = []

    # Map raw_results keys to snapshot record types
    record_map = {
        "dmarc": ("dmarc", lambda r: r.get("record")),
        "spf": ("spf", lambda r: r.get("record")),
        "mx": ("mx", lambda r: "; ".join(sorted(r.get("records") or []))),
        "mta_sts": ("mta-sts", lambda r: r.get("txt_record")),
        "tls_rpt": ("tls-rpt", lambda r: r.get("record")),
        "dnssec": ("dnssec", lambda r: r.get("dnskey_record")),
        "caa": ("caa", lambda r: "; ".join(sorted(c["raw"] if isinstance(c, dict) else str(c) for c in (r.get("records") or [])))),
        "nameservers": ("nameservers", lambda r: "; ".join(sorted(n["hostname"] if isinstance(n, dict) else str(n) for n in (r.get("nameservers") or [])))),
    }

    for check_key, (record_type, extract_fn) in record_map.items():
        raw = raw_results.get(check_key, {})
        current_value = extract_fn(raw)
        snapshots = history.get(record_type, [])

        if not snapshots:
            continue

        if len(snapshots) >= 2:
            # We have at least two snapshots, meaning at least one change happened
            for i in range(len(snapshots) - 1):
                newer = snapshots[i]
                older = snapshots[i + 1]
                # Compare normalized versions to ignore whitespace-only differences
                # (e.g. semicolon spacing from record normalization across runs)
                norm_newer = _normalize_record_for_comparison(newer["record_value"])
                norm_older = _normalize_record_for_comparison(older["record_value"])
                if norm_newer == norm_older:
                    continue  # Whitespace-only difference, not a real change
                if newer["record_hash"] != older["record_hash"]:
                    classification = _classify_change(
                        record_type, older["record_value"], newer["record_value"]
                    )
                    changes.append({
                        "record_type": record_type,
                        "record_label": _RECORD_TYPE_LABELS.get(record_type, record_type),
                        "timestamp": newer["timestamp"],
                        "old_value": older["record_value"],
                        "new_value": newer["record_value"],
                        "description": classification["description"],
                        "is_improvement": classification["is_improvement"],
                    })

    # Also check DKIM selectors
    for rt, snapshots in history.items():
        if rt.startswith("dkim:") and len(snapshots) >= 2:
            selector = rt.split(":", 1)[1]
            for i in range(len(snapshots) - 1):
                newer = snapshots[i]
                older = snapshots[i + 1]
                # Skip whitespace-only differences
                if _normalize_record_for_comparison(newer["record_value"]) == _normalize_record_for_comparison(older["record_value"]):
                    continue
                if newer["record_hash"] != older["record_hash"]:
                    changes.append({
                        "record_type": rt,
                        "record_label": f"DKIM ({selector})",
                        "timestamp": newer["timestamp"],
                        "old_value": older["record_value"],
                        "new_value": newer["record_value"],
                        "description": f"DKIM key for selector '{selector}' changed (possible rotation)",
                        "is_improvement": True,
                    })

    # Sort changes by timestamp (newest first)
    changes.sort(key=lambda c: c.get("timestamp", ""), reverse=True)

    if not changes:
        # We have snapshots but no changes detected
        latest_ts = first_seen
        for snapshots in history.values():
            if snapshots:
                ts = snapshots[0].get("timestamp", "")
                if ts > (latest_ts or ""):
                    latest_ts = ts

        return {
            "status": "no_changes",
            "message": f"No changes detected since {latest_ts or 'first audit'}",
            "changes": [],
            "first_seen": first_seen,
        }

    return {
        "status": "changes_found",
        "message": f"{len(changes)} record change{'s' if len(changes) != 1 else ''} detected",
        "changes": changes,
        "first_seen": first_seen,
    }


# ============================================================
# Consistency Findings (Prompt 18, Part 4)
# ============================================================


def build_consistency_findings(
    raw_results: Dict,
    checks: List[Dict],
) -> Optional[List[Dict]]:
    """Check for cross-record inconsistencies that suggest partial updates
    or configuration drift.

    Returns a list of finding dicts, or None if no findings.
    """
    findings = []
    check_map = {c.get("name", ""): c for c in checks}

    # 1. SPF includes that resolve to empty/error
    spf_raw = raw_results.get("spf", {})
    spf_deep = check_map.get("SPF", {}).get("spf_deep")
    if spf_deep:
        for mech in spf_deep.get("mechanisms", []):
            if mech.get("type") == "include" and mech.get("provider") is None:
                # Could be decommissioned service, but only flag if we also don't know the provider
                pass  # Covered by SPF deep analysis already

    # 2. MTA-STS MX mismatch
    mta_sts_raw = raw_results.get("mta_sts", {})
    mx_raw = raw_results.get("mx", {})
    mta_sts_mx = mta_sts_raw.get("policy_mx") or []
    actual_mx = []
    for detail in mx_raw.get("mx_details", []):
        host = detail.get("host", "").rstrip(".")
        if host:
            actual_mx.append(host.lower())
    if mta_sts_mx and actual_mx:
        mta_set = {m.lower().lstrip("*.") for m in mta_sts_mx}
        mx_set = set(actual_mx)
        # Check if any actual MX is not covered by MTA-STS
        uncovered = []
        for mx_host in mx_set:
            covered = False
            for pattern in mta_set:
                if mx_host == pattern or mx_host.endswith("." + pattern):
                    covered = True
                    break
            if not covered:
                uncovered.append(mx_host)
        if uncovered:
            findings.append({
                "protocol": "MTA-STS",
                "badge": "Configuration Drift",
                "title": "MTA-STS policy does not cover all MX hosts",
                "detail": (
                    f"Your MTA-STS policy does not list {', '.join(uncovered)}. "
                    f"Senders enforcing MTA-STS may refuse to deliver to "
                    f"{'this host' if len(uncovered) == 1 else 'these hosts'}."
                ),
                "severity": "warning",
            })

    # 3. DKIM selectors that resolve to NXDOMAIN
    dkim_raw = raw_results.get("dkim", {})
    for sel in dkim_raw.get("found_selectors", []):
        if sel.get("status") == "nxdomain" or (not sel.get("record") and sel.get("selector")):
            pass  # Already handled by DKIM check

    # 4. DMARC rua provider vs SPF authorization
    dmarc_raw = raw_results.get("dmarc", {})
    rua = dmarc_raw.get("rua", "")
    spf_record = spf_raw.get("record", "")
    if rua and spf_record:
        # Extract domain from rua mailto:
        import re
        rua_domains = re.findall(r'mailto:[^@]+@([^,;\s]+)', rua)
        for rua_domain in rua_domains:
            rua_domain = rua_domain.lower().rstrip(".")
            domain_val = dmarc_raw.get("domain", "").lower()
            # Only flag if rua domain differs from audited domain
            if rua_domain and rua_domain != domain_val:
                # Check if SPF includes this domain
                if rua_domain not in spf_record.lower():
                    findings.append({
                        "protocol": "DMARC",
                        "badge": "Informational",
                        "title": f"DMARC reports sent to external domain",
                        "detail": (
                            f"Your DMARC aggregate reports are sent to {rua_domain}, "
                            f"which is not authorized in your SPF record. This is normal "
                            f"if they only receive reports, but verify the destination is correct."
                        ),
                        "severity": "info",
                    })

    # 5. CAA vs MTA-STS certificate providers
    caa_raw = raw_results.get("caa", {})
    caa_cas = [ca.lower() for ca in caa_raw.get("authorized_cas", [])]
    if caa_cas and mta_sts_raw.get("policy_mode") == "enforce":
        findings.append({
            "protocol": "CAA",
            "badge": "Informational",
            "title": "CAA records may affect MTA-STS certificate renewal",
            "detail": (
                f"Your CAA records restrict certificate issuance to: {', '.join(caa_raw.get('authorized_cas', []))}. "
                f"Ensure your MTA-STS mail server certificates are issued by one of these authorized CAs, "
                f"or renewal failures could break MTA-STS enforcement."
            ),
            "severity": "info",
        })

    return findings if findings else None


# ============================================================
# Subdomain Discovery & Audit (Prompt 17)
# ============================================================


def build_subdomain_audit(
    raw: Dict,
    policy: Optional[str] = None,
    sp: Optional[str] = None,
    np: Optional[str] = None,
    has_record: bool = False,
) -> Optional[Dict]:
    """Transform raw subdomain probe results into a structured audit section.

    Classifies each discovered subdomain as active mail sender, exists but no
    mail config, or does not exist, and determines the effective DMARC policy.

    Args:
        raw: Output from _audit_subdomains() with "probes" list
        policy: Root domain DMARC p= value (e.g. "reject", "none")
        sp: Root domain sp= value (or None if absent)
        np: Root domain np= value (or None if absent)
        has_record: Whether root domain has a DMARC record at all
    """
    probes = raw.get("probes", [])
    if not probes:
        return None

    # Effective subdomain policy: sp= if set, otherwise falls back to p=
    effective_sp = sp if sp else policy
    # Effective non-existent subdomain policy: np= if set, otherwise sp= then p=
    effective_np = np if np else (sp if sp else policy)

    subdomains = []
    for probe in probes:
        sub = probe.get("subdomain", "")
        exists = probe.get("exists", False)
        has_mx = probe.get("has_mx", False)
        has_spf = probe.get("has_spf", False)
        has_dmarc = probe.get("has_dmarc", False)
        dmarc_record = probe.get("dmarc_record")

        sends_mail = has_mx or has_spf
        mail_reason = []
        if has_mx:
            mail_reason.append("MX")
        if has_spf:
            mail_reason.append("SPF")

        # Determine effective policy
        if has_dmarc and dmarc_record:
            # Parse the subdomain's own DMARC record for its policy
            own_policy = None
            for part in dmarc_record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    own_policy = part[2:].strip().lower()
                    break
            eff_policy = own_policy or "none"
            policy_source = "own"
            policy_display = f"p={eff_policy}"
        elif exists:
            eff_policy = effective_sp or "none"
            policy_source = "inherited_sp"
            if sp:
                policy_display = f"Inherits sp={sp}"
            elif policy:
                policy_display = f"Inherits p={policy}"
            else:
                policy_display = "No DMARC (none)"
        else:
            eff_policy = effective_np or "none"
            policy_source = "inherited_np"
            if np:
                policy_display = f"np={np}"
            elif sp:
                policy_display = f"No np=, fallback sp={sp}"
            elif policy:
                policy_display = f"No np=, fallback p={policy}"
            else:
                policy_display = "No np=, fallback none"

        # Classify
        if exists and sends_mail:
            category = "active_mail"
            category_label = "Active mail sender"
        elif exists:
            category = "exists_no_mail"
            category_label = "Exists, no mail config"
        else:
            category = "nonexistent"
            category_label = "Does not exist"

        # Status: protected / partial / exposed
        if eff_policy == "reject":
            status = "protected"
            status_label = "Protected"
            color = "green"
        elif eff_policy == "quarantine":
            status = "partial"
            status_label = "Quarantine"
            color = "amber"
        else:
            status = "exposed"
            status_label = "Exposed"
            color = "red"

        # If no DMARC record on root at all, everything is exposed
        if not has_record and not has_dmarc:
            status = "exposed"
            status_label = "Exposed"
            color = "red"
            policy_display = "No DMARC record"

        subdomains.append({
            "subdomain": sub,
            "exists": exists,
            "sends_mail": sends_mail,
            "mail_signals": ", ".join(mail_reason) if mail_reason else None,
            "has_own_dmarc": has_dmarc,
            "dmarc_record": dmarc_record,
            "effective_policy": eff_policy,
            "policy_source": policy_source,
            "policy_display": policy_display,
            "category": category,
            "category_label": category_label,
            "status": status,
            "status_label": status_label,
            "color": color,
        })

    # Sort: exposed first, then partial, then protected
    sort_order = {"exposed": 0, "partial": 1, "protected": 2}
    subdomains.sort(key=lambda s: (sort_order.get(s["status"], 3), s["subdomain"]))

    # Summary stats
    total_discovered = sum(1 for s in subdomains if s["exists"])
    total_mail = sum(1 for s in subdomains if s["sends_mail"])
    total_exposed = sum(1 for s in subdomains if s["status"] == "exposed")
    exposed_mail = sum(1 for s in subdomains if s["status"] == "exposed" and s["sends_mail"])
    exposed_exist = sum(1 for s in subdomains if s["status"] == "exposed" and s["exists"] and not s["sends_mail"])
    exposed_nx = sum(1 for s in subdomains if s["status"] == "exposed" and not s["exists"])

    # Build summary lines
    summary_lines = [
        f"{total_discovered} subdomain{'s' if total_discovered != 1 else ''} discovered, "
        f"{total_mail} with mail configuration",
    ]
    if total_exposed > 0:
        summary_lines.append(
            f"{total_exposed} subdomain{'s' if total_exposed != 1 else ''} "
            f"exposed due to policy gaps"
        )

    # Build the "killer insight" callout
    callout = None
    if (policy and policy.lower() in ("reject", "quarantine")
            and (not sp or sp.lower() == "none")
            and exposed_mail > 0):
        callout = (
            f"We found {exposed_mail} active subdomain{'s' if exposed_mail != 1 else ''} "
            f"that inherit{'s' if exposed_mail == 1 else ''} your sp={sp or 'none'} policy. "
            f"{'This subdomain' if exposed_mail == 1 else 'These subdomains'} can be spoofed "
            f"despite your root domain being at p={policy}. "
            f"This is not a theoretical risk: "
            f"{'this is a real subdomain' if exposed_mail == 1 else 'these are real subdomains'} "
            f"with real mail infrastructure."
        )
    elif not has_record and total_discovered > 0:
        callout = (
            f"Your domain has no DMARC record. All {total_discovered} discovered "
            f"subdomain{'s' if total_discovered != 1 else ''} can be freely spoofed."
        )
    elif sp and sp.lower() == "none" and total_discovered > 0 and total_exposed > 0:
        callout = (
            f"Your subdomain policy gap (sp=none) affects "
            f"{total_exposed} real subdomain{'s' if total_exposed != 1 else ''}, "
            f"not just theoretical ones."
        )

    return {
        "subdomains": subdomains,
        "summary_lines": summary_lines,
        "callout": callout,
        "total_probed": len(subdomains),
        "total_discovered": total_discovered,
        "total_mail": total_mail,
        "total_exposed": total_exposed,
        "exposed_mail": exposed_mail,
        "exposed_exist": exposed_exist,
        "exposed_nx": exposed_nx,
    }


# ============================================================
# DMARC
# ============================================================


def _build_dmarcbis_card_data(readiness: Optional[Dict], record: Optional[str]) -> Optional[Dict]:
    """Transform the raw _assess_dmarcbis_readiness output into the
    checklist + suggested-record format consumed by the frontend card.

    Returns None when there is no record (nothing to assess).
    """
    if not readiness or not record:
        return None

    # Parse tags from the record for building suggestions
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    deprecated = readiness.get("deprecated_tags", [])
    new_tags = readiness.get("new_tags", {})

    checklist = []

    # 1. Valid DMARC record
    checklist.append({
        "label": "Valid DMARC record found",
        "status": "pass",
        "detail": None,
    })

    # 2. No deprecated tags (pct, rf, ri). Each entry passes through its
    # source / spec_reference so the frontend can render spec-required
    # findings differently from editorial suggestions.
    dep_names = [d["tag"] for d in deprecated]
    if dep_names:
        dep_details = [
            {
                "tag": d["tag"],
                "reason": d.get("recommendation", ""),
                "source": d.get("source", "editorial"),
                "spec_reference": d.get("spec_reference"),
            }
            for d in deprecated
        ]
        # Worst-case status across deprecated entries: spec_required
        # is rendered as "warn" (a real issue), editorial as "info".
        checklist_status = "warn" if any(d.get("source") == "spec_required" for d in deprecated) else "info"
        checklist.append({
            "label": "No deprecated tags (pct, rf, ri)",
            "status": checklist_status,
            "detail": ", ".join(dep_names),
            "deprecated_details": dep_details,
        })
    else:
        checklist.append({
            "label": "No deprecated tags (pct, rf, ri)",
            "status": "pass",
            "detail": None,
        })

    # 3. NP policy defined + precedence chain
    np_info = new_tags.get("np", {})
    p_val = tags.get("p", "none")
    sp_val = tags.get("sp")
    np_val = np_info.get("value")

    # Build the fallback chain: np → sp → p
    np_chain = []
    if np_val:
        np_chain.append({"tag": "np", "value": np_val, "active": True})
    else:
        np_chain.append({"tag": "np", "value": None, "active": False})
    if sp_val:
        np_chain.append({"tag": "sp", "value": sp_val, "active": not np_val})
    np_chain.append({"tag": "p", "value": p_val, "active": not np_val and not sp_val})

    if np_info.get("present"):
        checklist.append({
            "label": "NP policy defined (non-existent domains)",
            "status": "pass",
            "detail": f"np={np_info['value']}",
            "np_chain": np_chain,
        })
    else:
        fallback_tag = "sp" if sp_val else "p"
        fallback_val = sp_val if sp_val else p_val
        checklist.append({
            "label": "NP policy defined (non-existent domains)",
            # np absence is editorial: dmarcbis-41 §4.7 does not require
            # an explicit np tag. Render as info so the user sees this
            # as advice rather than a spec violation.
            "status": "info",
            "detail": "missing",
            "suggestion": f"np={fallback_val}",
            "np_chain": np_chain,
            "np_fallback_note": f"Non-existent subdomains currently fall back to {fallback_tag}={fallback_val}",
            "source": np_info.get("source", "editorial"),
            "spec_reference": np_info.get("spec_reference"),
            "recommendation": np_info.get("recommendation"),
        })

    # 4. PSD indicator declared
    psd_info = new_tags.get("psd", {})
    if psd_info.get("present") and psd_info.get("value") in ("y", "n"):
        checklist.append({
            "label": "PSD indicator declared",
            "status": "pass",
            "detail": f"psd={psd_info['value']}",
        })
    else:
        psd_val = psd_info.get("value")
        checklist.append({
            "label": "PSD indicator declared",
            "status": "info",
            "detail": f"psd={psd_val}" if psd_val else "u (default)",
            "note": "Most domains should use psd=n (not a public suffix)",
        })

    # Overall status
    raw_status = readiness.get("status", "compatible")
    status_map = {"ready": "compliant", "needs_update": "non_compliant"}
    status = status_map.get(raw_status, "compatible")

    # Build suggested record + changes list
    changes = []
    new_record_tags = dict(tags)

    for dep in deprecated:
        tag_name = dep["tag"]
        if tag_name in new_record_tags:
            val = new_record_tags.pop(tag_name)
            source = dep.get("source", "editorial")
            spec_ref = dep.get("spec_reference")
            if tag_name == "pct":
                if val == "100":
                    reason = "Removed pct (dmarcbis-41 §C.5.2 / §A.6); value was already 100 (default)."
                else:
                    reason = f"Removed pct (dmarcbis-41 §C.5.2 / §A.6); was {val}%. Use t=y for testing instead."
            elif tag_name == "rf":
                reason = "Removed rf (dmarcbis-41 §C.5.2); only afrf was ever defined and dmarcbis receivers will ignore the tag."
            elif tag_name == "ri":
                reason = "Removed ri (dmarcbis-41 §C.5.2); receivers send aggregate reports on their own schedule and dmarcbis receivers will ignore the tag."
            else:
                reason = f"Removed {tag_name}."
            changes.append({
                "type": "removed",
                "tag": tag_name,
                "reason": reason,
                "source": source,
                "spec_reference": spec_ref,
            })

    if not np_info.get("present"):
        np_src_tag = "sp" if "sp" in new_record_tags else "p"
        np_value = new_record_tags.get(np_src_tag, "none")
        new_record_tags["np"] = np_value
        changes.append({
            "type": "added",
            "tag": "np",
            "reason": (
                f"Editorial suggestion (not spec-required): added np from "
                f"{np_src_tag} value to make non-existent subdomain policy "
                f"explicit. dmarcbis-41 §4.7 does not require this."
            ),
            "source": np_info.get("source", "editorial"),
            "spec_reference": np_info.get("spec_reference"),
        })

    # Reconstruct in standard tag order
    tag_order = ["v", "p", "sp", "np", "adkim", "aspf", "psd", "t", "fo", "rua", "ruf"]
    parts = []
    for t in tag_order:
        if t in new_record_tags:
            parts.append(f"{t}={new_record_tags[t]}")
    for t, v in new_record_tags.items():
        if t not in tag_order:
            parts.append(f"{t}={v}")

    suggested_record = "; ".join(parts) if changes else None

    pass_count = sum(1 for c in checklist if c["status"] == "pass")

    return {
        "status": status,
        "checklist": checklist,
        "pass_count": pass_count,
        "total_count": len(checklist),
        "suggested_record": suggested_record,
        "changes": changes,
        "recommendations": readiness.get("recommendations", []),
    }


def transform_dmarc(raw: Dict, tree_walk: Optional[Dict] = None, is_no_mail: bool = False) -> Dict:
    status = _map_status(raw.get("status", "error"))
    policy = raw.get("policy", "")
    record = raw.get("record")
    pill_label = None

    # Check if this domain inherits policy (raw_dmarc fields set by
    # _enrich_dmarc_inheritance using tree walk first, PSL fallback)
    inherited = not record and raw.get("is_subdomain") and raw.get("inherited_policy")
    inherited_policy = raw.get("inherited_policy") if inherited else None
    inherited_source = raw.get("inherited_from") if inherited else None

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
        verdict = "p=reject (authentication failures are rejected)"
        # p=reject is always a pass regardless of what the audit engine returned
        # (the engine may flag "warning" for missing rua, but the policy itself is correct)
        status = "pass"
    elif policy == "quarantine":
        pct = raw.get("pct", 100)
        verdict = "p=quarantine (failures sent to spam)"
        if pct is not None and pct < 100:
            verdict += f" (pct={pct})"
        # p=quarantine is enforcing; treat as pass even if rua is absent
        status = "pass"
    elif policy == "none":
        verdict = "p=none (monitoring only, no enforcement)"
        # p=none with no rua is a critical failure: no enforcement AND no visibility
        if not raw.get("rua"):
            status = "fail"
        else:
            status = "warn"
    else:
        verdict = f"Policy: {policy}" if policy else "Invalid record"
        status = "fail"

    # Syntax errors or engine-level errors override to fail
    if record and not inherited:
        has_syntax_errors = bool(raw.get("syntax_errors"))
        has_engine_errors = any(
            i.get("severity") == "error" for i in raw.get("issues", [])
        )
        if has_syntax_errors or has_engine_errors:
            status = "fail"

    # dmarcbis-41 §4.10.1 policy recovery: invalid p/sp/np with valid
    # rua= is treated as p=none by dmarcbis receivers but may be
    # ignored by RFC 7489 receivers. Surface this distinctly so the
    # user sees it as a spec-recovery state, not as a clean p=none.
    if record and not inherited and raw.get("policy_recovery_applied"):
        pill_label = "Recovery"
        verdict = (
            "Spec recovery applied (dmarcbis-41 §4.10.1): invalid value "
            "masked by rua fallback, treated as p=none."
        )
        if status != "fail":
            status = "warn"

    # Build explanation
    if inherited:
        applied_tag = raw.get("applied_tag", "p")
        tag_label = {"sp": "subdomain policy (sp=)", "np": "non-existent subdomain policy (np=)", "p": "domain policy (p=)"}.get(applied_tag, f"{applied_tag}=")
        _method = raw.get("inheritance_method", "psl")
        if _method == "tree_walk":
            _method_note = (
                " Policy was discovered via the "
                "<a href=\"https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/\" target=\"_blank\" rel=\"noopener\">DMARCbis</a> "
                "DNS tree walk."
            )
        else:
            _method_note = (
                " Policy was discovered via the organizational domain fallback defined in "
                "<a href=\"https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.3\" target=\"_blank\" rel=\"noopener\">RFC 7489 Section 6.6.3</a> "
                "using the Public Suffix List."
            )
        _best_practice = (
            ""
        )
        if inherited_policy == "reject":
            explanation = (
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{_e(raw.get('domain', ''))}</strong>, but inherits "
                f"<strong>p=reject</strong> from the organizational domain "
                f"<strong>{_e(inherited_source)}</strong> via the {tag_label} tag. "
                f"Messages that fail both SPF and DKIM alignment will be rejected."
                + _method_note + _best_practice
            )
        elif inherited_policy == "quarantine":
            explanation = (
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{_e(raw.get('domain', ''))}</strong>, but inherits "
                f"<strong>p=quarantine</strong> from the organizational domain "
                f"<strong>{_e(inherited_source)}</strong> via the {tag_label} tag. "
                f"Messages that fail authentication will be routed to the spam folder."
                + _method_note + _best_practice
            )
        elif inherited_policy == "none":
            explanation = (
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{_e(raw.get('domain', ''))}</strong>, but inherits "
                f"<strong>p=none</strong> from the organizational domain "
                f"<strong>{_e(inherited_source)}</strong> via the {tag_label} tag. "
                f"This is monitoring only; receivers take no enforcement action, but aggregate reports "
                f"provide visibility into authentication results."
                + _method_note + _best_practice
            )
        else:
            explanation = (
                f"This subdomain inherits DMARC policy <strong>{_e(inherited_policy)}</strong> "
                f"from the organizational domain <strong>{_e(inherited_source)}</strong>."
                + _method_note + _best_practice
            )
    elif not record:
        explanation = (
            f"No DMARC record was found at <strong>_dmarc.{_e(raw.get('domain', ''))}</strong>. "
            f"Without DMARC, there is no policy telling receivers how to handle messages that fail authentication. "
            f"Google and Yahoo require bulk senders to publish a "
            f"<a href=\"https://datatracker.ietf.org/doc/html/rfc7489\" target=\"_blank\" rel=\"noopener\">DMARC</a> "
            f"record, and messages without one are more likely to be throttled or sent to spam."
        )
    elif policy == "none":
        explanation = (
            f"Your DMARC policy is set to <strong>p=none</strong> (monitoring mode). "
            f"Your record is technically valid, but it provides no active protection. "
            f"Receivers deliver all mail normally, even when authentication fails. "
            f"While p=none is a necessary starting point for collecting aggregate report data, "
            f"modern security compliance views this as a pre-deployment state. "
            f"To protect deliverability and prevent spoofing, move toward an enforcement policy "
            f"(<strong>p=quarantine</strong> or <strong>p=reject</strong>) once your legitimate "
            f"mail streams are aligned."
        )
    elif policy == "quarantine":
        explanation = (
            f"The enforcing DMARC policy <strong>p=quarantine</strong> requests that mail receivers "
            f"to send messages to spam when neither SPF nor DKIM passes with an aligned domain. "
            f"Only one of SPF or DKIM needs to pass with alignment for the message to be delivered normally. "
            f"DKIM is the more resilient mechanism because it survives mail forwarding."
        )
    elif policy == "reject":
        explanation = (
            f"The enforcing DMARC policy <strong>p=reject</strong> requests that mail receivers "
            f"to reject messages outright when neither SPF nor DKIM passes with an aligned domain. "
            f"Only one of SPF or DKIM needs to pass with alignment for the message to be delivered. "
            f"DKIM is the more resilient mechanism because it survives mail forwarding."
        )
    else:
        explanation = f"DMARC record found but the policy value is unexpected: '{policy}'."

    # Reporting note
    if record and not raw.get("rua"):
        if policy in ("quarantine", "reject"):
            explanation += (
                " <strong>Warning:</strong> No aggregate reporting (rua) is configured. "
                "You are enforcing a policy without seeing who is being affected. "
                "If a legitimate sender (like a payroll system or CRM) fails authentication, "
                "you will not know until users report missing email."
            )
        else:
            explanation += (
                " <strong>Note:</strong> No aggregate reporting (rua) is configured. "
                "Without rua, you have no visibility into who is sending as your domain "
                "or whether authentication is passing."
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

        _detail_method = "DNS tree walk" if raw.get("inheritance_method") == "tree_walk" else "organizational domain lookup"
        details.append({"type": "info", "text": f"No record at _dmarc.{raw.get('domain', '')}. Policy found via {_detail_method}"})
        details.append({"type": "info", "text": f"Applied tag: {applied_tag}= from {inherited_source}"})

        if tree_walk.get("org_domain"):
            details.append({"type": "info", "text": f"Organizational domain: {tree_walk['org_domain']}"})

    elif record:
        if raw.get("policy_recovery_applied"):
            details.append({
                "type": "warning",
                "text": (
                    "Spec recovery applied: invalid value masked by rua fallback. "
                    "dmarcbis-41 §4.10.1 receivers will treat as p=none; older "
                    "RFC 7489 receivers may ignore the record. Fix the offending tag."
                ),
            })
        elif policy == "reject":
            details.append({"type": "good", "text": "Policy p=reject: authentication failures are rejected"})
        elif policy == "quarantine":
            details.append({"type": "good", "text": "Policy p=quarantine: authentication failures are sent to spam"})
        elif policy == "none":
            details.append({"type": "warning", "text": "Policy p=none: monitoring only, no enforcement requested"})

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
                "text": "Forensic reporting (ruf) configured (note: most mailbox providers no longer send failure reports because of PII concerns)",
            })
        elif raw.get("ruf"):
            details.append({"type": "good", "text": "Forensic reporting (ruf) is configured"})

        if raw.get("sp"):
            sp_val = raw["sp"]
            # Flag sp=none when p= is enforcing as a contradiction
            if sp_val == "none" and policy in ("quarantine", "reject"):
                details.append({"type": "warning", "text": f"Subdomain policy sp=none contradicts your p={policy} enforcement. Subdomains are unprotected."})
            else:
                details.append({"type": "info", "text": f"Subdomain policy: sp={sp_val}"})

        pct = raw.get("pct")
        if pct is not None and pct < 100:
            details.append({"type": "warning", "text": f"pct={pct}: policy applied to only {pct}% of failing messages (pct is removed in DMARCbis)"})

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
                f"The inherited policy from <strong>{_e(inherited_source)}</strong> is p=none (monitoring only). "
                f"This provides no enforcement against spoofing."
            )
        else:
            # quarantine or reject inherited, no fix needed
            fix = None
    elif not record:
        if is_no_mail:
            fix = (
                f"This domain is configured to not send or receive email "
                f"(null MX, null SPF, no DKIM). To protect against spoofing, "
                f"publish a DMARC record at <strong>_dmarc.{_e(domain_name)}</strong> with "
                f"<strong>p=reject</strong>. Aggregate reporting (rua) is optional "
                f"because there is no legitimate mail to monitor."
            )
        else:
            fix = (
                f"Publish a DMARC TXT record at <strong>_dmarc.{_e(domain_name)}</strong> with <strong>p=none</strong>. "
                f"Requires an <strong>rua=</strong> reporting address: either your own mailbox "
                f"(reports arrive as compressed XML) or a DMARC reporting service that provides a dashboard."
            )
    elif raw.get("syntax_errors") or any(i.get("severity") == "error" for i in raw.get("issues", [])):
        # Prioritize syntax/error fixes over generic policy advice
        fix = _first_fix(raw.get("syntax_errors", [])) or _first_fix(raw.get("issues", []))
    elif policy == "none":
        if is_no_mail:
            fix = (
                "This domain does not send email. A monitoring policy (p=none) provides "
                "no protection against spoofing. Upgrade to <strong>p=reject</strong> to "
                "reject all mail that fails authentication. Reporting is optional because "
                "there is no legitimate mail to monitor."
            )
        else:
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

    # No copy-paste fix_records for DMARC -- requires choosing a reporting
    # address and understanding the enforcement path.
    fix_records = None

    # Build tag-by-tag breakdown + combo warnings + health verdict
    breakdown_record = display_record or record
    tag_breakdown = None
    if breakdown_record:
        tags_list = _build_dmarc_tag_breakdown(breakdown_record, raw)
        # Parse tags for combo detection
        _parsed = {}
        for part in breakdown_record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                _parsed[k.strip().lower()] = v.strip()
        _pol = _parsed.get("p", "").lower()
        config_warnings = _detect_dangerous_combinations(_parsed, _pol)
        health = _calculate_dmarcbis_health(_parsed, _pol, config_warnings)
        _domain = raw.get("domain", "")
        migration = _build_migration_path(_parsed, _pol, health["status"], domain=_domain)
        why_dmarcbis = _build_why_dmarcbis(_parsed, _pol, health["status"], domain=_domain)
        record_builder = _build_record_builder(
            _parsed, _pol, health["status"], breakdown_record,
            config_warnings, domain=_domain,
        )
        comparison = _build_comparison_intelligence(_parsed, _pol, health["status"], has_record=True)
        tag_breakdown = {
            "health": health,
            "tags": tags_list,
            "config_warnings": config_warnings,
            "migration": migration,
            "record_builder": record_builder,
            "why_dmarcbis": why_dmarcbis,
            "comparison_intelligence": comparison,
        }

    # Record builder for "no record" case (tag_breakdown is None)
    _domain = raw.get("domain", "")
    if not tag_breakdown:
        no_record_builder = _build_record_builder({}, "", "", None, [], domain=_domain)
        no_record_comparison = _build_comparison_intelligence({}, "", "", has_record=False)
    else:
        no_record_builder = None
        no_record_comparison = None

    # Deliverability context
    if not record and not inherited:
        _deliverability = (
            "Without DMARC, Gmail, Yahoo, and Outlook increasingly penalize your domain. "
            "Since February 2024, Google and Yahoo require DMARC for bulk senders. Even non-bulk "
            "senders benefit because DMARC tells receivers you take your email reputation seriously. "
            "If you send marketing emails, sales outreach, or business communications, this gap "
            "is likely hurting your inbox placement right now."
        )
    elif inherited and inherited_policy == "none":
        _deliverability = (
            "Your inherited p=none policy means receivers make their own judgment about suspicious "
            "email from your domain. Gmail and Yahoo may filter or delay messages that fail "
            "authentication. Moving toward enforcement protects your sending reputation."
        )
    elif policy == "none":
        _deliverability = (
            "With p=none, Gmail, Yahoo, and Microsoft decide on their own how to handle "
            "emails that fail authentication from your domain. They often treat unaligned "
            "mail with suspicion. Since February 2024, Google and Yahoo require DMARC for "
            "bulk senders. Moving to p=quarantine or p=reject signals that you control your "
            "email and generally improves inbox placement."
        )
    elif policy == "quarantine":
        _deliverability = (
            "Good for deliverability. Receivers know to quarantine spoofed emails, which "
            "protects your domain's sending reputation. Spoofed emails will not drag down "
            "your legitimate mail's reputation."
        )
    elif policy == "reject":
        _deliverability = (
            "Excellent for deliverability. This is the strongest signal to receivers that "
            "you control your email. Domains with p=reject generally see better inbox placement "
            "because receivers trust them more."
        )
    else:
        _deliverability = None

    return {
        "name": "DMARC",
        "status": status,
        "pill_label": pill_label,
        "verdict": verdict,
        "record": display_record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": fix_records,
        "strict_validation": _build_strict_validation(raw.get("strict_validation")),
        "legacy_validation": _build_strict_validation(raw.get("legacy_validation")),
        "spec_comparison": _build_spec_comparison(
            raw.get("strict_validation"), raw.get("legacy_validation")
        ),
        "attack_surface": _build_attack_surface(raw, display_record or record),
        "tag_breakdown": tag_breakdown,
        "record_builder": no_record_builder,
        "comparison_intelligence": no_record_comparison,
        "dmarcbis_readiness": _build_dmarcbis_card_data(
            raw.get("dmarcbis_readiness"), raw.get("record")
        ),
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": _deliverability,
    }


# ============================================================
# DMARCbis Strict Validation
# ============================================================

_SV_CATEGORY_LABELS = {
    "record_structure": "Record Structure",
    "uri_validation": "URI Validation",
    "external_auth": "External Authorization",
    "tag_values": "Tag Values",
    "dns_integrity": "DNS Integrity",
}

# Display order for categories
_SV_CATEGORY_ORDER = ["record_structure", "uri_validation", "external_auth", "tag_values", "dns_integrity"]


def _build_strict_validation(sv: Optional[Dict]) -> Optional[Dict]:
    """Transform strict validation results for the frontend."""
    if not sv:
        return None

    # Group checks by category
    categories: Dict[str, List[Dict]] = {}
    for check in sv.get("checks", []):
        cat = check["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(check)

    grouped = []
    for cat_key in _SV_CATEGORY_ORDER:
        if cat_key in categories:
            grouped.append({
                "key": cat_key,
                "label": _SV_CATEGORY_LABELS.get(cat_key, cat_key),
                "checks": categories[cat_key],
            })
    # Any categories not in the display order
    for cat_key, checks in categories.items():
        if cat_key not in _SV_CATEGORY_ORDER:
            grouped.append({
                "key": cat_key,
                "label": _SV_CATEGORY_LABELS.get(cat_key, cat_key),
                "checks": checks,
            })

    return {
        "categories": grouped,
        "pass_count": sv["pass_count"],
        "fail_count": sv["fail_count"],
        "warn_count": sv["warn_count"],
        "total_count": sv["total_count"],
        "summary": sv["summary"],
        "has_structural_errors": sv["has_structural_errors"],
    }


def _build_spec_comparison(strict: Optional[Dict], legacy: Optional[Dict]) -> Optional[Dict]:
    """Compare strict (DMARCbis) and legacy (RFC 7489) validation results.

    Returns the delta: which issues are DMARCbis-only, which are in both,
    and summary stats for the toggle UI.
    """
    if not strict or not legacy:
        return None

    strict_checks = strict.get("checks", [])
    legacy_checks = legacy.get("checks", [])

    # Build sets of failure/warn codes for comparison
    strict_fails = {c["code"] + ":" + c["message"][:60] for c in strict_checks if c["status"] == "fail"}
    legacy_fails = {c["code"] + ":" + c["message"][:60] for c in legacy_checks if c["status"] == "fail"}
    strict_warns = {c["code"] + ":" + c["message"][:60] for c in strict_checks if c["status"] == "warn"}
    legacy_warns = {c["code"] + ":" + c["message"][:60] for c in legacy_checks if c["status"] == "warn"}

    strict_issues = strict_fails | strict_warns
    legacy_issues = legacy_fails | legacy_warns

    dmarcbis_only = strict_issues - legacy_issues
    both = strict_issues & legacy_issues

    # Build human-readable list of DMARCbis-only findings
    dmarcbis_only_items = []
    for c in strict_checks:
        key = c["code"] + ":" + c["message"][:60]
        if key in dmarcbis_only and c["status"] in ("fail", "warn"):
            dmarcbis_only_items.append({
                "code": c["code"],
                "message": c["message"],
                "status": c["status"],
            })

    # Determine if legacy passes but strict fails
    legacy_passes = legacy.get("fail_count", 0) == 0
    strict_fails_count = strict.get("fail_count", 0)
    see_the_future = legacy_passes and strict_fails_count > 0

    return {
        "dmarcbis_only_count": len(dmarcbis_only_items),
        "both_count": len(both),
        "dmarcbis_only_items": dmarcbis_only_items,
        "see_the_future": see_the_future,
        "legacy_pass_count": legacy.get("pass_count", 0),
        "legacy_fail_count": legacy.get("fail_count", 0),
        "legacy_warn_count": legacy.get("warn_count", 0),
        "legacy_total_count": legacy.get("total_count", 0),
        "legacy_summary": legacy.get("summary", ""),
        "strict_fail_count": strict_fails_count,
        "strict_summary": strict.get("summary", ""),
    }


# ============================================================
# Attack Surface View
# ============================================================

def _build_attack_surface(raw: Dict, record: Optional[str]) -> Optional[Dict]:
    """Build the 4-vector email spoofing attack surface analysis."""
    if not record:
        return None

    # Parse tags
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "").lower()
    sp = tags.get("sp")
    np_val = tags.get("np")
    rua = tags.get("rua")
    domain = raw.get("domain", "yourdomain.com")

    vectors = []

    # ── Vector 1: Direct Domain Spoofing ────────────────────
    if policy == "reject":
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "protected",
            "color": "green",
            "summary": "Mail failing authentication is blocked.",
            "detail": f"An attacker attempting to send as user@{domain} would have their message rejected by receiving mail servers.",
        }
    elif policy == "quarantine":
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": "Spoofed mail goes to spam but still reaches recipients.",
            "detail": f"Spoofed messages land in spam/junk folders. Recipients may still see and interact with them.",
        }
    else:
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "exposed",
            "color": "red",
            "summary": f"Spoofed mail is delivered normally (p={policy or 'none'}).",
            "detail": f"An attacker could send an email appearing to be from ceo@{domain} to your employees requesting a wire transfer. Without enforcement, this email is delivered to their inbox with no warning.",
        }
    vectors.append(v1)

    # ── Vector 2: Subdomain Spoofing ────────────────────────
    effective_sp = sp if sp else policy
    if effective_sp == "reject":
        v2 = {
            "name": "Subdomain Spoofing",
            "status": "protected",
            "color": "green",
            "summary": f"Subdomains {'use' if sp else 'inherit'} reject policy.",
            "detail": f"Spoofed mail from subdomains like mail.{domain} is blocked.",
        }
    elif effective_sp == "quarantine":
        v2 = {
            "name": "Subdomain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": "Subdomain spoofed mail goes to spam.",
            "detail": f"An attacker sending from support@helpdesk.{domain} would land in spam.",
        }
    else:
        gap_note = ""
        if sp == "none" and policy in ("reject", "quarantine"):
            gap_note = f" Your root domain is protected but subdomains are not. Attackers will use subdomains to bypass your policy."
        v2 = {
            "name": "Subdomain Spoofing",
            "status": "exposed",
            "color": "red",
            "summary": f"Subdomains have no enforcement.{gap_note}",
            "detail": f"An attacker could send from support@helpdesk.{domain} to your customers requesting password resets. The subdomain looks legitimate but has no protection.",
        }
    vectors.append(v2)

    # ── Vector 3: Non-Existent Subdomain Spoofing ───────────
    np_effective = np_val if np_val else (sp if sp else policy)
    np_fallback = np_val is None
    if np_effective == "reject":
        note = ""
        if np_fallback:
            note = " Protected by fallback, but not explicitly. DMARCbis recommends setting np= directly."
        v3 = {
            "name": "Non-Existent Subdomain Spoofing",
            "status": "protected" if not np_fallback else "partial",
            "color": "green" if not np_fallback else "amber",
            "summary": f"Non-existent subdomains {'reject' if not np_fallback else 'inherit reject via fallback'}.{note}",
            "detail": f"Invented subdomains like secure-login.{domain} are blocked.",
        }
    elif np_effective == "quarantine":
        v3 = {
            "name": "Non-Existent Subdomain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": "Non-existent subdomain spoofed mail goes to spam.",
            "detail": f"An attacker inventing secure-portal.{domain} would land in spam.",
        }
    else:
        v3 = {
            "name": "Non-Existent Subdomain Spoofing",
            "status": "exposed",
            "color": "red",
            "summary": "Attackers can invent any subdomain.",
            "detail": f"An attacker could create secure-portal.{domain}, a domain that doesn't exist, and send password phishing emails from it. Attackers prefer non-existent subdomains because they look convincing and many organizations don't realize they need to protect domains that don't exist in DNS.",
        }
    vectors.append(v3)

    # ── Vector 4: Reporting Intelligence Leakage ────────────
    report_dests = raw.get("report_destinations", [])
    has_unauthorized = any(d.get("authorized") is False for d in report_dests)

    if not rua:
        v4 = {
            "name": "Reporting Intelligence",
            "status": "partial",
            "color": "amber",
            "summary": "No reporting configured. No leakage risk, but zero visibility.",
            "detail": "No aggregate reporting means you have no visibility into authentication results, but also no risk of report data being sent to unauthorized parties.",
        }
    elif has_unauthorized:
        v4 = {
            "name": "Reporting Intelligence",
            "status": "exposed",
            "color": "red",
            "summary": "Reports may be sent to an unauthorized destination.",
            "detail": "An unauthorized party could be receiving your DMARC aggregate reports, learning which servers send email for your domain, your IP ranges, and your email volumes.",
        }
    else:
        v4 = {
            "name": "Reporting Intelligence",
            "status": "protected",
            "color": "green",
            "summary": "Reports go to authorized destinations.",
            "detail": "Aggregate reports are sent to verified destinations.",
        }
    vectors.append(v4)

    # ── Overall Score ───────────────────────────────────────
    exposed = [v for v in vectors if v["status"] == "exposed"]
    partial = [v for v in vectors if v["status"] == "partial"]

    if len(exposed) >= 2:
        overall = {"level": "critical", "label": "Critical Risk", "color": "red",
                   "summary": f"This domain has multiple paths for email spoofing attacks."}
    elif len(exposed) == 1:
        overall = {"level": "high", "label": "High Risk", "color": "red",
                   "summary": f"This domain can be spoofed through {exposed[0]['name'].lower()}."}
    elif partial:
        overall = {"level": "moderate", "label": "Moderate Risk", "color": "amber",
                   "summary": "Some attack vectors are exposed."}
    else:
        overall = {"level": "low", "label": "Low Risk", "color": "green",
                   "summary": "This domain has strong email spoofing defenses."}

    # Attacker perspective
    weakest = exposed[0] if exposed else (partial[0] if partial else None)
    attacker_path = ""
    if weakest:
        if weakest["name"] == "Direct Domain Spoofing":
            attacker_path = f"If an attacker wanted to spoof this domain, they would send directly as user@{domain} since the policy is p={policy} and no mail is blocked."
        elif weakest["name"] == "Subdomain Spoofing":
            attacker_path = f"If an attacker wanted to spoof this domain, they would target subdomains like mail.{domain} since subdomain policy is weaker than the root."
        elif weakest["name"] == "Non-Existent Subdomain Spoofing":
            attacker_path = f"If an attacker wanted to spoof this domain, they would target non-existent subdomains like secure-login.{domain} since there is no np= policy to prevent it."
        elif weakest["name"] == "Reporting Intelligence":
            attacker_path = f"An unauthorized party may be receiving aggregate reports revealing your email infrastructure."

    return {
        "overall": overall,
        "vectors": vectors,
        "attacker_path": attacker_path,
    }


# ============================================================
# DMARC Record Breakdown (tag-by-tag decoder)
# ============================================================

_TAG_ORDER = ["v", "p", "sp", "np", "adkim", "aspf", "fo", "rua", "ruf", "pct", "rf", "ri", "psd", "t"]


def _explain_policy_value(value: str) -> str:
    """Shared explanation for p=, sp=, np= policy values."""
    return {
        "reject": (
            "Strongest enforcement. Mail that fails authentication is blocked entirely. "
            "Your domain is protected against spoofing."
        ),
        "quarantine": (
            "Mail that fails authentication is sent to spam. One step below full protection. "
            "Spoofed mail still reaches recipients, just in their junk folder."
        ),
        "none": (
            "Monitoring only: no mail is blocked or quarantined. Spoofed and malicious email "
            "claiming to be from your domain is still delivered to recipients. While monitoring is "
            "the correct first step, the goal is to progress to an enforcing policy "
            "(p=quarantine then p=reject). Without enforcement, your domain can be used to send "
            "phishing or malware to your customers and partners, which can damage your domain's "
            "sending reputation and erode trust with the people you do business with."
        ),
    }.get(value, f"Unknown policy value '{value}'.")


def _build_dmarc_tag_breakdown(record: str, raw: Dict) -> Optional[List[Dict]]:
    """Parse every tag in a DMARC record and return a structured breakdown.

    Each entry:
      tag, value, is_default, is_absent, label, explanation, dmarcbis, warnings
    """
    if not record:
        return None

    # Parse present tags
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "").lower()
    breakdown: List[Dict] = []

    # Determine which tags to show
    shown_tags = list(_TAG_ORDER)
    for tag_name in tags:
        if tag_name not in shown_tags:
            shown_tags.append(tag_name)

    for tag_name in shown_tags:
        present = tag_name in tags
        value = tags.get(tag_name, "")

        entry = _build_tag_entry(tag_name, value, present, tags, policy)
        if entry:
            breakdown.append(entry)

    return breakdown


def _build_tag_entry(tag: str, value: str, present: bool, tags: Dict, policy: str) -> Optional[Dict]:
    """Build a single tag entry with explanation, warnings, and DMARCbis notes."""

    # ── v= ──────────────────────────────────────────────────
    if tag == "v":
        if not present:
            return None
        return _entry(tag, value, False, False, "Version",
                      "Valid DMARC version identifier. Required as the first tag.",
                      "current",
                      dmarcbis_note=(
                          "DMARCbis tightens parsing. This MUST be the first tag. Records that place "
                          "it elsewhere will be rejected by DMARCbis-compliant receivers, even though some "
                          "legacy receivers were lenient about tag ordering."
                      ))

    # ── p= ──────────────────────────────────────────────────
    if tag == "p":
        if not present:
            return None
        e = _entry(tag, value, False, False, "Policy",
                   _explain_policy_value(value), "current",
                   dmarcbis_note=(
                       "DMARCbis clarifies policy semantics and removes ambiguities in how receivers "
                       "interpret these values. The biggest change is replacing pct with the binary t=y "
                       "test mode for safer policy rollout."
                   ))
        if value == "none":
            e["warnings"].append({
                "level": "warning",
                "text": "Monitoring only. No enforcement is applied to messages that fail authentication.",
            })
        return e

    # ── sp= ─────────────────────────────────────────────────
    if tag == "sp":
        note = (
            "DMARCbis clarifies inheritance behavior. The new np= tag extends subdomain protection "
            "to cover non-existent subdomains, something RFC 7489 had no concept of."
        )
        if present:
            e = _entry(tag, value, False, False, "Subdomain Policy",
                       _explain_policy_value(value), "current", dmarcbis_note=note)
            if value == "none" and policy in ("reject", "quarantine"):
                e["warnings"].append({
                    "level": "warning",
                    "text": (
                        "Your subdomains have weaker enforcement than your root domain. "
                        "Attackers will spoof subdomains like mail.yourdomain.com to bypass your policy."
                    ),
                })
            return e
        else:
            p_val = tags.get("p", "none")
            return _entry(tag, None, False, True, "Subdomain Policy",
                          f"Subdomains inherit the root policy (p={p_val}). "
                          f"Setting sp= explicitly removes ambiguity.",
                          "current", dmarcbis_note=note)

    # ── np= (DMARCbis) ─────────────────────────────────────
    if tag == "np":
        note = (
            "This tag is NEW in DMARCbis. RFC 7489 had no way to set policy for subdomains that "
            "don't exist in DNS. Attackers exploit this by inventing subdomains. np= closes that gap. "
            "Currently 0% of the top 1000 domains have adopted this tag."
        )
        if present:
            e = _entry(tag, value, False, False, "Non-Existent Subdomain Policy",
                       _explain_policy_value(value), "new", dmarcbis_note=note)
            if value == "none" and policy == "reject":
                e["warnings"].append({
                    "level": "warning",
                    "text": (
                        "Critical gap. Non-existent subdomains have no enforcement while your root "
                        "domain rejects. Attackers can invent subdomains like "
                        "secure-login.yourdomain.com and spoof mail from them."
                    ),
                })
            return e
        else:
            sp_val = tags.get("sp")
            p_val = tags.get("p", "none")
            resolved = sp_val if sp_val else p_val
            resolved_via = "sp" if sp_val else "p"
            e = _entry(tag, None, False, True, "Non-Existent Subdomain Policy",
                       f"No non-existent subdomain policy. Falls back to sp= (if set), then p=. "
                       f"Current effective policy for non-existent subdomains: {resolved_via}={resolved}.",
                       "new", dmarcbis_note=note)
            chain = [{"tag": "np", "value": None, "active": False}]
            if sp_val:
                chain.append({"tag": "sp", "value": sp_val, "active": True})
                chain.append({"tag": "p", "value": p_val, "active": False})
            else:
                chain.append({"tag": "p", "value": p_val, "active": True})
            e["fallback_chain"] = chain
            e["resolved_value"] = resolved
            if resolved != "reject":
                e["warnings"].append({
                    "level": "warning",
                    "text": (
                        f"Attackers can invent non-existent subdomains like "
                        f"secure-login.yourdomain.com. Without np=, the policy for these is "
                        f"{resolved_via}={resolved}. Consider adding np=reject."
                    ),
                })
            return e

    # ── adkim= ──────────────────────────────────────────────
    if tag == "adkim":
        note = (
            "DMARCbis clarifies alignment edge cases, especially around subdomains and how "
            "organizational domain is determined (now via tree walk instead of PSL)."
        )
        if present:
            explanation = {
                "r": (
                    "Relaxed. Subdomains of the DKIM signing domain satisfy alignment. "
                    "mail.example.com aligns with example.com."
                ),
                "s": (
                    "Strict. The DKIM d= domain must exactly match the From domain. "
                    "More secure but rejects mail signed by a subdomain."
                ),
            }.get(value, f"Unknown DKIM alignment value '{value}'.")
            e = _entry(tag, value, False, False, "DKIM Alignment Mode",
                       explanation, "current", dmarcbis_note=note)
        else:
            e = _entry(tag, "r", True, True, "DKIM Alignment Mode",
                       "Defaults to relaxed (r). Subdomain alignment is permitted.",
                       "current", dmarcbis_note=note)
            value = "r"
        if value == "r" and policy == "reject":
            e["warnings"].append({
                "level": "info",
                "text": (
                    "Consider strict alignment for tighter security at reject enforcement, "
                    "but verify your mail flows first."
                ),
            })
        return e

    # ── aspf= ───────────────────────────────────────────────
    if tag == "aspf":
        note = (
            "DMARCbis explicitly states that DMARC evaluates SPF against the MAIL FROM identity "
            "only, not HELO. RFC 7489 was ambiguous about this."
        )
        if present:
            explanation = {
                "r": "Relaxed. Subdomains of the SPF-authenticated domain satisfy alignment.",
                "s": "Strict. The MAIL FROM domain must exactly match the From domain.",
            }.get(value, f"Unknown SPF alignment value '{value}'.")
            e = _entry(tag, value, False, False, "SPF Alignment Mode",
                       explanation, "current", dmarcbis_note=note)
        else:
            e = _entry(tag, "r", True, True, "SPF Alignment Mode",
                       "Defaults to relaxed (r).",
                       "current", dmarcbis_note=note)
            value = "r"
        if value == "r" and policy == "reject":
            e["warnings"].append({
                "level": "info",
                "text": (
                    "Consider strict alignment for tighter security at reject enforcement, "
                    "but verify your mail flows first."
                ),
            })
        return e

    # ── fo= ─────────────────────────────────────────────────
    if tag == "fo":
        if present:
            explanation = {
                "0": (
                    "Reports only when BOTH SPF and DKIM fail. You miss most failures. "
                    "Set fo=1 for broader visibility."
                ),
                "1": "Reports when either mechanism fails. Recommended.",
                "d": "Reports on DKIM failure regardless of alignment.",
                "s": "Reports on SPF failure regardless of alignment.",
            }.get(value, f"Failure reporting option: {value}.")
            return _entry(tag, value, False, False, "Failure Reporting Options",
                          explanation, "current")
        else:
            return _entry(tag, "0", True, True, "Failure Reporting Options",
                          "Defaults to fo=0. Reports only on complete failure of both mechanisms.",
                          "current")

    # ── rua= ────────────────────────────────────────────────
    if tag == "rua":
        note = (
            "DMARCbis splits reporting into separate RFCs and tightens URI validation. The mailto: "
            "prefix is now strictly required. Bare email addresses are rejected. DMARCbis also "
            "strengthens external reporting authorization checks."
        )
        if present:
            base = (
                f"Aggregate reports are sent to {value}. These show which sources send mail "
                f"as your domain and whether they pass or fail authentication."
            )
            if policy == "reject":
                base += (
                    " These reports are the only way to know if legitimate mail is being silently rejected."
                )
            elif policy == "quarantine":
                base += (
                    " These show what's landing in spam. Check if legitimate senders are affected."
                )
            elif policy == "none":
                base += (
                    " These show every source sending as your domain. Review before moving to enforcement."
                )
            return _entry(tag, value, False, False, "Aggregate Report Recipients",
                          base, "current", dmarcbis_note=note)
        else:
            if policy == "reject":
                msg = (
                    "No reporting. You are rejecting mail with zero visibility. "
                    "Legitimate mail could be silently disappearing."
                )
            elif policy == "quarantine":
                msg = "No reporting. Failing mail goes to spam and you cannot see what's affected."
            else:
                msg = (
                    "No enforcement AND no monitoring. This record serves no purpose."
                )
            e = _entry(tag, None, False, True, "Aggregate Report Recipients",
                       msg, "current", dmarcbis_note=note)
            e["warnings"].append({"level": "warning", "text": msg})
            return e

    # ── ruf= ────────────────────────────────────────────────
    if tag == "ruf":
        note = (
            "Failure reporting is now defined in its own separate RFC under DMARCbis, reflecting "
            "that it's increasingly uncommon in practice."
        )
        if present:
            return _entry(tag, value, False, False, "Forensic Report Recipients",
                          f"Failure reports sent to {value}. Most providers including Google and "
                          f"Microsoft no longer send failure reports due to PII concerns.",
                          "current", dmarcbis_note=note)
        else:
            return _entry(tag, None, False, True, "Forensic Report Recipients",
                          "No failure reporting. Common since most providers don't send them. "
                          "Aggregate reports provide sufficient visibility.",
                          "current", dmarcbis_note=note)

    # ── pct= (deprecated) ──────────────────────────────────
    if tag == "pct":
        if present:
            e = _entry(tag, value, False, False, "Percentage",
                       f"Policy applies to {value}% of failing messages. "
                       "The pct tag is deprecated in DMARCbis. Only values of 0 and 100 were reliably "
                       "honored. DMARCbis replaces this with t=y/t=n for predictable testing. Current "
                       "receivers still honor pct but DMARCbis receivers will ignore it. To migrate: "
                       "use t=y for testing or remove pct for full enforcement.",
                       "deprecated")
            e["warnings"].append({
                "level": "info",
                "text": "Deprecated in DMARCbis. Use t=y for testing or remove pct for full enforcement.",
            })
            return e
        else:
            return _entry(tag, "100", True, True, "Percentage",
                          "Defaults to 100. The pct tag is deprecated in DMARCbis.",
                          "deprecated")

    # ── rf= (deprecated) ───────────────────────────────────
    if tag == "rf":
        if present:
            e = _entry(tag, value, False, False, "Report Format",
                       "Only afrf was ever implemented. Removed in DMARCbis. Safe to remove.",
                       "deprecated")
            e["warnings"].append({"level": "info", "text": "Deprecated in DMARCbis. Safe to remove."})
            return e
        else:
            return _entry(tag, "afrf", True, True, "Report Format",
                          "Defaults to afrf. Deprecated in DMARCbis.",
                          "deprecated")

    # ── ri= (deprecated) ───────────────────────────────────
    if tag == "ri":
        if present:
            suffix = f" ({int(value)//3600}h)" if value.isdigit() else ""
            e = _entry(tag, value, False, False, "Report Interval",
                       f"Requested interval: {value} seconds{suffix}. "
                       "Report intervals were rarely respected. DMARCbis standardizes daily reports. "
                       "Safe to remove.",
                       "deprecated")
            e["warnings"].append({"level": "info", "text": "Deprecated in DMARCbis. Safe to remove."})
            return e
        else:
            return _entry(tag, "86400", True, True, "Report Interval",
                          "Defaults to 86400s (24h). Deprecated in DMARCbis.",
                          "deprecated")

    # ── psd= (DMARCbis) ────────────────────────────────────
    if tag == "psd":
        note = (
            "This tag is NEW in DMARCbis. It replaces reliance on the Public Suffix List (PSL) "
            "for determining organizational domain boundaries. The PSL was maintained manually and "
            "often outdated. psd= lets domain owners declare their own status directly in DNS. "
            "Only 1 domain in the top 1000 has adopted this tag."
        )
        if present:
            explanation = {
                "y": (
                    "This domain declares itself as a Public Suffix Domain (like .com or .co.uk). "
                    "The DNS tree walk stops here and subdomains are treated as separate organizational "
                    "domains that will NOT inherit this DMARC policy. If this domain is not actually a "
                    "public suffix, this is a critical misconfiguration: subdomains lose policy "
                    "inheritance entirely."
                ),
                "n": (
                    "Not a Public Suffix. Subdomains inherit policy normally. "
                    "This is the correct value for most domains."
                ),
                "u": (
                    "Undeclared. Different receivers may handle the DNS tree walk differently: "
                    "some continue walking, others stop. This creates inconsistent enforcement across "
                    "Gmail, Microsoft, Yahoo, and others. Set psd=n explicitly."
                ),
            }.get(value, f"Unknown psd value '{value}'.")
            e = _entry(tag, value, False, False, "Public Suffix Domain", explanation, "new",
                       dmarcbis_note=note)
            if value == "y":
                e["warnings"].append({
                    "level": "warning",
                    "text": (
                        "If this domain is not actually a public suffix, this misconfiguration "
                        "disrupts policy inheritance for all subdomains."
                    ),
                })
            return e
        else:
            return _entry(tag, "u", True, True, "Public Suffix Domain",
                          "Not declared. Receivers fall back to the Public Suffix List or their own "
                          "implementation. Behavior varies. Consider adding psd=n.",
                          "new", dmarcbis_note=note)

    # ── t= (DMARCbis) ──────────────────────────────────────
    if tag == "t":
        note = (
            "This tag is NEW in DMARCbis, replacing the unreliable pct tag. Under RFC 7489, "
            "pct=50 meant 'apply to 50% of failing mail' but receivers implemented this "
            "inconsistently. Only pct=0 and pct=100 were reliable. DMARCbis replaces this with a "
            "clean binary flag: t=y (testing, drop policy one level) or t=n (enforce fully). This "
            "gives domain owners a safe, predictable way to test stricter policies before committing. "
            "0% of the top 1000 domains use this tag yet."
        )
        if present:
            if value == "y":
                explanation = (
                    "Test mode ACTIVE. Your published policy is NOT enforced at full strength. "
                    "p=reject becomes p=quarantine. p=quarantine becomes p=none. "
                    "This also drops sp= and np= one level. Test mode is useful "
                    "during migration but should be temporary."
                )
                e = _entry(tag, value, False, False, "Testing Mode", explanation, "new",
                           dmarcbis_note=note)
                if policy == "none":
                    e["warnings"].append({
                        "level": "info",
                        "text": "t=y on p=none has no effect. p=none cannot drop further. Remove t=y.",
                    })
                return e
            else:
                return _entry(tag, value, False, False, "Testing Mode",
                              "Normal enforcement. Policies applied as published.",
                              "new", dmarcbis_note=note)
        else:
            return _entry(tag, None, False, True, "Testing Mode",
                          "Normal enforcement. Policies applied as published.",
                          "new", dmarcbis_note=note)

    # ── Unknown tag ─────────────────────────────────────────
    if present:
        e = _entry(tag, value, False, False, f"Unknown Tag ({tag})",
                   "This tag is not defined in RFC 7489 or DMARCbis. It may be ignored by receivers.",
                   "current")
        e["warnings"].append({
            "level": "warning",
            "text": f"Unrecognized tag '{tag}' may be ignored by mail receivers.",
        })
        return e

    return None


def _entry(tag: str, value, is_default: bool, is_absent: bool,
           label: str, explanation: str, dmarcbis: str,
           dmarcbis_note: str = None) -> Dict:
    """Helper to build a tag breakdown entry."""
    entry = {
        "tag": tag,
        "value": value,
        "is_default": is_default,
        "is_absent": is_absent,
        "label": label,
        "explanation": explanation,
        "dmarcbis": dmarcbis,
        "warnings": [],
    }
    if dmarcbis_note:
        entry["dmarcbis_note"] = dmarcbis_note
    return entry


# ============================================================
# Dangerous Combination Detection (Prompt 2)
# ============================================================

def _detect_dangerous_combinations(tags: Dict[str, str], policy: str) -> List[Dict]:
    """Check for dangerous tag combinations. Returns a list of warnings
    with level ("critical" or "advisory"), title, and text."""
    warnings: List[Dict] = []
    sp = tags.get("sp")
    np_val = tags.get("np")
    np_present = "np" in tags
    t_val = tags.get("t")
    psd = tags.get("psd")
    fo = tags.get("fo", "0")
    adkim = tags.get("adkim", "r")
    aspf = tags.get("aspf", "r")
    rua = tags.get("rua")
    ruf = tags.get("ruf")
    deprecated_present = [t for t in ("pct", "rf", "ri") if t in tags]

    # Resolve np fallback
    np_resolved = np_val if np_present else (sp if sp else policy)
    np_resolved_via = "np" if np_present else ("sp" if sp else "p")

    # ── RED: Critical ───────────────────────────────────────

    # 0. Missing p= but rua= present. dmarcbis S4.10.1 MUSTs treat-as-p=none;
    # RFC 7489 ignores the record. Same record, two behaviors.
    if not tags.get("p") and rua:
        warnings.append({
            "level": "critical",
            "title": "Missing p= tag (interop hazard)",
            "text": (
                "No explicit p= tag. dmarcbis-compliant receivers treat this as p=none; RFC 7489 "
                "receivers ignore the record entirely. Behavior depends on which spec the receiver "
                "implements. Add an explicit p=none, p=quarantine, or p=reject."
            ),
            "tags": ["p"],
        })

    # 1. Any policy + no rua
    if not rua:
        if policy == "reject":
            msg = (
                "No aggregate reporting configured. At p=reject, you are rejecting mail that "
                "fails authentication with zero visibility. Legitimate mail could be silently "
                "disappearing and you would never know. Add an rua= address immediately."
            )
        elif policy == "quarantine":
            msg = (
                "No aggregate reporting configured. At p=quarantine, failing mail goes to spam "
                "and you cannot see what is being quarantined. Add an rua= address immediately."
            )
        else:
            msg = (
                "No aggregate reporting configured. At p=none, there is no enforcement and no "
                "monitoring. This DMARC record serves no purpose. Add an rua= address immediately."
            )
        warnings.append({"level": "critical", "title": "No aggregate reporting", "text": msg, "tags": ["rua"]})

    # 2. sp=none + p=reject
    if sp == "none" and policy == "reject":
        warnings.append({
            "level": "critical",
            "title": "Subdomain policy gap",
            "text": (
                "Subdomain policy gap. Your root domain rejects spoofed mail but subdomains allow "
                "it through. Attackers will target subdomains like mail.yourdomain.com to bypass your policy."
            ),
            "tags": ["sp", "p"],
        })

    # 3. np=none + p=reject
    if np_val == "none" and policy == "reject":
        warnings.append({
            "level": "critical",
            "title": "Non-existent subdomain gap",
            "text": (
                "Non-existent subdomain gap. Invented subdomains like "
                "secure-login.yourdomain.com have no enforcement while your root domain rejects."
            ),
            "tags": ["np", "p"],
        })

    # 4. np missing + sp=none + p=reject
    if not np_present and sp == "none" and policy == "reject":
        warnings.append({
            "level": "critical",
            "title": "Double policy gap",
            "text": (
                "Double policy gap. Both existing and non-existent subdomains fall back to sp=none. "
                "Your p=reject only protects the root domain."
            ),
            "tags": ["np", "sp", "p"],
        })

    # 5. psd=y
    if psd == "y":
        warnings.append({
            "level": "critical",
            "title": "Public Suffix declaration",
            "text": (
                "This domain claims to be a Public Suffix Domain. If incorrect, the DNS tree walk "
                "stops prematurely and subdomains lose policy inheritance entirely. This is likely a "
                "misconfiguration. Set psd=n if this is a regular domain."
            ),
            "tags": ["psd"],
        })

    # 6. p=none + no rua (already covered by #1 but with specific text)
    # Already handled above in the p=none branch of #1

    # 7. np=reject + p=none
    if np_val == "reject" and policy == "none":
        warnings.append({
            "level": "critical",
            "title": "Contradictory np vs p policy",
            "text": (
                "Stricter policy on non-existent subdomains than the root domain. This is "
                "contradictory: attackers will spoof the root domain directly."
            ),
            "tags": ["np", "p"],
        })

    # 8. sp=reject + p=none
    if sp == "reject" and policy == "none":
        warnings.append({
            "level": "critical",
            "title": "Contradictory sp vs p policy",
            "text": (
                "Stricter policy on subdomains than the root domain. Same contradiction: "
                "the root domain is the easier target."
            ),
            "tags": ["sp", "p"],
        })

    # ── AMBER: Warnings ────────────────────────────────────

    # 9. t=y + p=reject
    if t_val == "y" and policy == "reject":
        warnings.append({
            "level": "advisory",
            "title": "Test mode weakens reject",
            "text": (
                "Test mode reduces your effective policy to p=quarantine. Spoofed mail lands in "
                "spam instead of being blocked. If testing is complete, remove t=y to enforce full rejection."
            ),
            "tags": ["t", "p"],
        })

    # 10. t=y + np=reject
    if t_val == "y" and np_val == "reject":
        warnings.append({
            "level": "advisory",
            "title": "Test mode weakens np=reject",
            "text": (
                "Test mode also drops np=reject to np=quarantine. Non-existent subdomain "
                "spoofing lands in spam instead of being blocked."
            ),
            "tags": ["t", "np"],
        })

    # 11. t=y + p=none
    if t_val == "y" and policy == "none":
        warnings.append({
            "level": "advisory",
            "title": "Test mode on p=none",
            "text": "Test mode on a policy that already permits everything. t=y has no effect here. Remove it.",
            "tags": ["t", "p"],
        })

    # 12. psd=u or absent
    if psd == "u" or "psd" not in tags:
        warnings.append({
            "level": "advisory",
            "title": "Undeclared PSD status",
            "text": (
                "Undeclared PSD status. Different receivers handle the DNS tree walk differently, "
                "creating inconsistent enforcement. Declare psd=n explicitly."
            ),
            "tags": ["psd"],
        })

    # 13. fo=0 + ruf configured
    if fo == "0" and ruf:
        warnings.append({
            "level": "advisory",
            "title": "Underutilized failure reporting",
            "text": (
                "Failure reporting is configured but set to report only when both SPF and DKIM fail. "
                "You are missing most failure data. Set fo=1 to capture all failures."
            ),
            "tags": ["fo", "ruf"],
        })

    # 14. adkim=r + aspf=r + p=reject
    if adkim == "r" and aspf == "r" and policy == "reject":
        warnings.append({
            "level": "advisory",
            "title": "Relaxed alignment at reject",
            "text": (
                "Both alignment modes are relaxed at the strictest enforcement level. Consider "
                "tightening at least one to strict for defense in depth, after verifying your mail "
                "flows support it."
            ),
            "tags": ["adkim", "aspf", "p"],
        })

    # 15. Deprecated tags present
    if deprecated_present:
        warnings.append({
            "level": "advisory",
            "title": "Deprecated tags present",
            "text": (
                f"Deprecated tags found that will be ignored by DMARCbis-compliant receivers. "
                f"Consider removing: {', '.join(deprecated_present)}."
            ),
            "tags": deprecated_present,
        })

    # 16. sp absent + p=reject
    if sp is None and policy == "reject":
        warnings.append({
            "level": "advisory",
            "title": "Implicit subdomain policy",
            "text": (
                "Subdomains inherit p=reject by default, which is correct. But setting sp=reject "
                "explicitly removes ambiguity."
            ),
            "tags": ["sp", "p"],
        })

    # 16. np absent at enforcing policy
    if not np_present and policy in ("reject", "quarantine"):
        warnings.append({
            "level": "advisory",
            "title": "No explicit np= policy",
            "text": (
                f"No explicit non-existent subdomain policy. Falls back to "
                f"{np_resolved_via}={np_resolved}. Consider adding np= to close potential gaps."
            ),
            "tags": ["np"],
        })

    # 17. p=none + rua configured
    if policy == "none" and rua:
        warnings.append({
            "level": "advisory",
            "title": "Monitoring mode",
            "text": (
                "Monitoring mode. Your domain is not protected against spoofing. Mail that fails "
                "authentication is still delivered to recipients. Your domain can be used to send "
                "phishing or malware to your customers and partners, which can damage your sending "
                "reputation and erode trust with the people you do business with. Review your aggregate "
                "reports and progress to p=quarantine then p=reject."
            ),
            "tags": ["p", "rua"],
        })

    # ── BLUE: Informational ────────────────────────────────

    # 18. SPF evaluates MAIL FROM only under DMARCbis
    warnings.append({
        "level": "info",
        "title": "SPF alignment under DMARCbis",
        "text": "Under DMARCbis, SPF alignment is evaluated against the MAIL FROM (envelope sender) identity only, not HELO.",
        "tags": [],
    })

    # 19. p=reject + mailing list risk
    if policy == "reject":
        warnings.append({
            "level": "info",
            "title": "Mailing list participation",
            "text": (
                "p=reject may cause issues with mailing lists that rewrite the From header. "
                "ARC (Authenticated Received Chain) helps, but not all receivers support it yet."
            ),
            "tags": ["p"],
        })

    # 20. DMARCbis reporting split
    warnings.append({
        "level": "info",
        "title": "DMARCbis reporting restructured",
        "text": "DMARCbis splits the specification into three separate RFCs: core mechanism, aggregate reporting, and failure reporting.",
        "tags": [],
    })

    # 21. External reporting destinations
    if rua and "@" in rua:
        # Check if any rua destination is external
        rua_domains = []
        for uri in rua.split(","):
            uri = uri.strip()
            if "mailto:" in uri:
                email = uri.split("mailto:")[1].split("!")[0]
                if "@" in email:
                    rua_domains.append(email.split("@")[1])
        if rua_domains:
            warnings.append({
                "level": "info",
                "title": "External reporting destinations",
                "text": f"Aggregate reports are sent to domain(s): {', '.join(set(rua_domains))}.",
                "tags": ["rua"],
            })

    return warnings


# ============================================================
# DMARCbis Health Verdict (Prompt 3)
# ============================================================

def _calculate_dmarcbis_health(tags: Dict[str, str], policy: str, config_warnings: List[Dict]) -> Dict:
    """Evaluate the record and return one of five verdicts with a badge color
    and one-line summary.

    Returns:
      status   - "ready", "compatible", "monitoring", "attention", "misconfigured"
      label    - display label
      color    - "green", "blue", "amber", "red"
      summary  - one-line explanation
      reasons  - specific tags/combos that determined the verdict
    """
    critical = [w for w in config_warnings if w["level"] == "critical"]
    advisory = [w for w in config_warnings if w["level"] == "advisory"]

    deprecated_present = [t for t in ("pct", "rf", "ri") if t in tags]
    np_present = "np" in tags
    psd_val = tags.get("psd")
    psd_declared = psd_val in ("y", "n")
    t_val = tags.get("t")
    rua = tags.get("rua")
    sp = tags.get("sp")

    # ── Misconfigured (red) ─────────────────────────────────
    # Critical issues that actively undermine the record
    if critical:
        reasons = [w["title"] for w in critical]
        # Build a specific summary from the worst issue
        worst = critical[0]
        return {
            "status": "misconfigured",
            "label": "Misconfigured",
            "color": "red",
            "summary": f"This record has critical issues. {worst['text'].split('.')[0]}.",
            "reasons": reasons,
        }

    # ── Monitoring (amber) ──────────────────────────────────
    # p=none with rua configured
    if policy == "none" and rua:
        return {
            "status": "monitoring",
            "label": "Monitoring",
            "color": "amber",
            "summary": (
                "This domain is in monitoring mode. Mail that fails authentication is still "
                "delivered: your domain is not yet protected against spoofing. Review your "
                "reports and progress toward an enforcing policy."
            ),
            "reasons": ["p=none (monitoring only)"],
        }

    # ── Needs Attention (amber) ─────────────────────────────
    # Enforcing but has dangerous combinations that weaken protection
    # These are the advisory warnings that actually weaken protection:
    _attention_titles = {
        "Test mode weakens reject", "Test mode weakens np=reject",
        "Test mode on p=none", "Undeclared PSD status",
        "Underutilized failure reporting", "Relaxed alignment at reject",
    }
    attention_triggers = [w["title"] for w in advisory if w["title"] in _attention_titles]

    if attention_triggers and policy in ("reject", "quarantine"):
        issues = ", ".join(attention_triggers[:3])
        return {
            "status": "attention",
            "label": "Needs Attention",
            "color": "amber",
            "summary": f"This record has an enforcing policy but {issues} weaken its protection.",
            "reasons": attention_triggers,
        }

    # ── DMARCbis Ready (green) ──────────────────────────────
    # Clean record, fully compliant
    if (policy in ("reject", "quarantine")
            and not deprecated_present
            and np_present
            and psd_declared
            and t_val != "y"
            and rua
            and not critical):
        return {
            "status": "ready",
            "label": "DMARCbis Ready",
            "color": "green",
            "summary": "This record is fully DMARCbis-compliant with no issues detected.",
            "reasons": [],
        }

    # ── DMARCbis Compatible (blue) ──────────────────────────
    # Valid with minor gaps
    reasons = []
    if deprecated_present:
        reasons.append(f"Deprecated tags: {', '.join(deprecated_present)}")
    if not np_present:
        reasons.append("np= not set")
    if not psd_declared:
        reasons.append("psd= not declared")
    if sp is None and policy in ("reject", "quarantine"):
        reasons.append("sp= not set (inherits correctly)")

    improvements = ". ".join(reasons) if reasons else "Minor improvements available"

    return {
        "status": "compatible",
        "label": "DMARCbis Compatible",
        "color": "blue",
        "summary": f"This record works under DMARCbis but has room for improvement. {improvements}.",
        "reasons": reasons,
    }


# ============================================================
# Domain Comparison Intelligence (Prompt 14)
# ============================================================

# Static stats from top 1000 domain scan
_TOP1K = {
    "no_dmarc_pct": 26.0,
    "p_reject_pct": 55.0,
    "p_quarantine_pct": 12.0,
    "p_none_pct": 7.0,
    "np_adoption_pct": 0.0,
    "t_adoption_pct": 0.0,
    "psd_adoption_pct": 0.1,
    "deprecated_still_used_pct": 30.6,
}


def _build_comparison_intelligence(
    tags: Dict[str, str],
    policy: str,
    health_status: str,
    has_record: bool,
) -> Dict:
    """Build a contextual comparison showing where this domain stands
    relative to the top 1000 internet domains.

    Returns:
      position_statement - single punchy sentence
      position_pct       - 0-100 numeric position (higher = better)
      position_label     - e.g. "Ahead of 99.9%"
      adoption_stats     - mini-stat block for DMARCbis adoption
    """

    has_dmarcbis_tags = any(t in tags for t in ("np", "psd", "t"))

    # --- Position statement (one punchy line) ---
    if not has_record:
        statement = (
            "Among the 26% of top 1000 domains with no DMARC protection."
        )
        position_pct = 0
        position_label = "Bottom 26%"

    elif policy == "none" and tags.get("rua"):
        statement = (
            "Monitoring mode. 26% of the top 1000 have no DMARC at all, "
            "so you are ahead of them, but enforcement is the goal."
        )
        position_pct = 30
        position_label = "Ahead of ~26%"

    elif policy == "none" and not tags.get("rua"):
        statement = (
            "This record provides less protection than having no DMARC at all "
            "(which 26% of top domains have) because it creates a false sense of security."
        )
        position_pct = 5
        position_label = "Below baseline"

    elif policy == "quarantine":
        statement = (
            "Stronger enforcement than ~33% of the top 1000."
        )
        position_pct = 55
        position_label = "Ahead of ~33%"

    elif policy == "reject" and has_dmarcbis_tags:
        statement = (
            "Ahead of 99.9% of the top 1000 domains in DMARCbis readiness."
        )
        position_pct = 99
        position_label = "Top 0.1%"

    elif policy == "reject":
        statement = (
            "Stronger than 45% of the top 1000 in enforcement, "
            "but among the 99.9% not yet DMARCbis-ready."
        )
        position_pct = 75
        position_label = "Ahead of ~45%"

    else:
        statement = (
            "This domain has DMARC configured. 26% of the top 1000 have none at all."
        )
        position_pct = 35
        position_label = "Ahead of ~26%"

    # --- DMARCbis adoption mini-stats ---
    adoption_stats = [
        {"tag": "np=", "adoption_pct": _TOP1K["np_adoption_pct"], "label": "np= adoption"},
        {"tag": "t=", "adoption_pct": _TOP1K["t_adoption_pct"], "label": "t= adoption"},
        {"tag": "psd=", "adoption_pct": _TOP1K["psd_adoption_pct"], "label": "psd= adoption"},
        {"tag": "deprecated", "adoption_pct": _TOP1K["deprecated_still_used_pct"], "label": "Still using deprecated tags"},
    ]

    return {
        "position_statement": statement,
        "position_pct": position_pct,
        "position_label": position_label,
        "adoption_stats": adoption_stats,
        "adoption_tagline": (
            "DMARCbis adoption is effectively zero. Early adopters gain a "
            "security advantage and set the standard for their industry."
        ),
    }


# ============================================================
# Migration Wizard
# ============================================================

def _build_why_dmarcbis(tags: Dict[str, str], policy: str, health_status: str, domain: str = "") -> Dict:
    """Build the 'Why DMARCbis?' education section, personalized to this domain's record."""

    sections = []

    # Section 1: What is DMARCbis (always shown)
    sections.append({
        "title": "What is DMARCbis?",
        "content": (
            "DMARCbis is the next version of the DMARC email authentication standard, developed by "
            "the IETF DMARC Working Group to replace RFC 7489. It addresses real-world problems "
            "discovered over a decade of DMARC deployment: inconsistent parsing across receivers, "
            "unreliable percentage-based rollout, no protection for non-existent subdomains, and "
            "dependence on the manually-maintained Public Suffix List."
        ),
    })

    # Section 2: What's new (conditional based on domain's record)
    whats_new = []

    if "pct" in tags:
        whats_new.append(
            "Your record uses the pct tag. DMARCbis deprecates pct because only values of 0 "
            "and 100 were reliably enforced by receivers. It's replaced by t=y/t=n, a clean binary "
            "test mode that predictably drops your policy one level for safe rollout."
        )

    if "np" not in tags:
        whats_new.append(
            f"Your record doesn't have an np= tag. This is a new DMARCbis tag that sets policy for "
            f"non-existent subdomains, domains like secure-login.{domain or 'yourdomain.com'} that "
            f"don't exist but can be spoofed. Under RFC 7489, there was no way to control this."
        )

    if "psd" not in tags:
        whats_new.append(
            "Your record doesn't declare psd=. DMARCbis introduces this tag to replace the Public "
            "Suffix List for determining organizational domain boundaries. The PSL was a manually-maintained "
            "list that was often outdated. psd= lets you declare your own domain's status directly in DNS."
        )

    dep_in_record = [t for t in ("rf", "ri") if t in tags]
    if dep_in_record:
        tag_list = " and ".join(dep_in_record)
        whats_new.append(
            f"Your record uses {tag_list} which {'is' if len(dep_in_record) == 1 else 'are'} deprecated in DMARCbis. "
            f"rf was redundant (only afrf was ever implemented) and ri was rarely respected by receivers."
        )

    # Always-show items
    whats_new.append(
        "DMARCbis tightens record parsing significantly. Records with missing mailto: prefixes, "
        "duplicate tags, empty values, or malformed URIs that older tools silently accepted will "
        "be rejected by DMARCbis-compliant receivers."
    )

    whats_new.append(
        "DMARCbis replaces the DNS tree walk's dependence on the Public Suffix List with the psd= "
        "tag and an 8-query safety limit, making organizational domain resolution more reliable and DNS-native."
    )

    whats_new.append(
        "DMARCbis splits the specification into three separate RFCs: the core mechanism, aggregate "
        "reporting, and failure reporting, reflecting that these are distinct operational concerns."
    )

    sections.append({
        "title": "What changed from RFC 7489?",
        "items": whats_new,
    })

    # Section 3: How does this domain compare
    verdict_scale = [
        {"status": "misconfigured", "label": "Misconfigured", "color": "red"},
        {"status": "monitoring", "label": "Monitoring", "color": "amber"},
        {"status": "attention", "label": "Needs Attention", "color": "amber"},
        {"status": "compatible", "label": "Compatible", "color": "blue"},
        {"status": "ready", "label": "DMARCbis Ready", "color": "green"},
    ]

    sections.append({
        "title": f"How does {domain or 'this domain'} compare?",
        "content": (
            "Based on analysis of the top 1000 internet domains: 26% have no DMARC at all, "
            "~55% are at p=reject, ~12% at p=quarantine, and ~7% at p=none. "
            "0% have adopted DMARCbis-specific tags (np=, t=), only 0.1% use psd=, "
            "and 30.6% still use deprecated tags (pct, rf, ri). "
            f"Your record is currently rated '{health_status}'. Adopting DMARCbis tags now puts you "
            "ahead of the vast majority of the internet."
        ),
        "verdict_scale": verdict_scale,
        "current_verdict": health_status,
        "adoption_stats": [
            {"tag": "np=", "pct": 0.0},
            {"tag": "t=", "pct": 0.0},
            {"tag": "psd=", "pct": 0.1},
            {"tag": "Deprecated tags still in use", "pct": 30.6},
        ],
        "adoption_tagline": (
            "DMARCbis adoption is effectively zero. Early adopters gain a "
            "security advantage and set the standard for their industry."
        ),
    })

    # Section 4: Why does this matter
    sections.append({
        "title": "Why does this matter?",
        "content": (
            "Email authentication isn't just a technical checkbox. When your domain can be spoofed, "
            "attackers can send phishing, malware, and fraudulent messages that appear to come from "
            "your organization. Recipients, your customers, partners, and employees, receive malicious "
            "email that carries your name. This damages your domain's sending reputation (causing "
            "legitimate email to bounce or land in spam), erodes trust with the people you do business "
            "with, and in the worst case can lead to ransomware, data breaches, or financial fraud "
            "traced back to your brand. DMARCbis closes gaps that RFC 7489 left open, especially "
            "around non-existent subdomain spoofing and inconsistent receiver behavior, making "
            "enforcement more reliable and complete."
        ),
    })

    # Section 5: What should I do
    sections.append({
        "title": "What should I do?",
        "content": "See your personalized migration path above for step-by-step instructions to reach DMARCbis Ready status.",
    })

    return {"sections": sections}


def _build_migration_path(tags: Dict[str, str], policy: str, health_status: str, domain: str = "") -> Optional[Dict]:
    """Generate a personalized step-by-step migration path to DMARCbis Ready.

    Returns None if already DMARCbis Ready.
    """
    if health_status == "ready":
        return {"status": "ready", "steps": [], "message": "No migration needed. This record is DMARCbis Ready."}

    steps = []
    step_num = 0
    rua = tags.get("rua")
    sp = tags.get("sp")
    np_val = tags.get("np")
    psd = tags.get("psd")
    fo = tags.get("fo", "0")
    deprecated = [t for t in ("pct", "rf", "ri") if t in tags]

    # Build the current record for before/after
    current_parts = []
    for part_key in ["v", "p", "sp", "np", "adkim", "aspf", "fo", "rua", "ruf", "pct", "rf", "ri", "psd", "t"]:
        if part_key in tags:
            current_parts.append(f"{part_key}={tags[part_key]}")

    rua_placeholder = rua if rua else "mailto:dmarc@yourdomain.com"

    # Step: Add reporting if missing
    if not rua:
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Add aggregate reporting",
            "why": "Without rua=, you have zero visibility into authentication results.",
            "record_after": f"v=DMARC1; p={policy or 'none'}; rua={rua_placeholder}",
            "tags_changed": ["rua"],
        })

    # Step: Review reports (for p=none)
    if policy == "none":
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Review aggregate reports for 2-4 weeks",
            "why": "Identify all legitimate senders and fix their SPF/DKIM alignment before enforcing.",
            "tags_changed": [],
        })

        # Step: Test quarantine
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Test quarantine with t=y",
            "why": "t=y drops the effective policy one level, so p=quarantine with t=y acts like p=none. Safe to test.",
            "record_after": f"v=DMARC1; p=quarantine; t=y; rua={rua_placeholder}",
            "tags_changed": ["p", "t"],
        })

        # Step: Enforce quarantine
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Enforce quarantine by removing t=y",
            "why": "Once reports show no legitimate mail failures, enforce quarantine.",
            "record_after": f"v=DMARC1; p=quarantine; rua={rua_placeholder}",
            "tags_changed": ["t"],
        })

    # Step: Test reject (for quarantine or just-promoted)
    if policy in ("none", "quarantine"):
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Test reject with t=y",
            "why": "p=reject with t=y effectively acts as p=quarantine. Monitor for issues.",
            "record_after": f"v=DMARC1; p=reject; t=y; rua={rua_placeholder}",
            "tags_changed": ["p", "t"],
        })

        # Step: Enforce reject
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Enforce reject by removing t=y",
            "why": "Full protection. Mail failing authentication is blocked.",
            "record_after": f"v=DMARC1; p=reject; rua={rua_placeholder}",
            "tags_changed": ["t"],
        })

    # Step: Fix sp=none gap if present
    if sp == "none" and policy in ("reject", "quarantine"):
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Align subdomain policy: change sp=none to sp=reject",
            "why": "Close the subdomain policy gap. Attackers target subdomains to bypass your root policy.",
            "tags_changed": ["sp"],
        })

    # Step: Set fo=1 if needed
    if fo == "0" or "fo" not in tags:
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Set fo=1 for full failure visibility",
            "why": "fo=0 only reports when both SPF and DKIM fail. fo=1 captures all failures.",
            "tags_changed": ["fo"],
        })

    # Step: Add DMARCbis tags
    dmarcbis_needed = []
    if not np_val:
        dmarcbis_needed.append("np=reject")
    if not sp or sp == "none":
        dmarcbis_needed.append("sp=reject")
    if not psd or psd not in ("y", "n"):
        dmarcbis_needed.append("psd=n")

    if dmarcbis_needed:
        step_num += 1
        steps.append({
            "step": step_num,
            "action": f"Add DMARCbis tags: {', '.join(dmarcbis_needed)}",
            "why": "These tags close gaps in the old standard and prepare for DMARCbis.",
            "tags_changed": [t.split("=")[0] for t in dmarcbis_needed],
        })

    # Step: Remove deprecated tags
    if deprecated:
        step_num += 1
        steps.append({
            "step": step_num,
            "action": f"Remove deprecated tags: {', '.join(deprecated)}",
            "why": "These tags are ignored by DMARCbis receivers. Removing them cleans up the record.",
            "tags_changed": deprecated,
        })

    # Final target record
    target = f"v=DMARC1; p=reject; sp=reject; np=reject; psd=n; fo=1; rua={rua_placeholder}"

    return {
        "status": "migration",
        "steps": steps,
        "total_steps": len(steps),
        "target_record": target,
    }


# ============================================================
# Record Builder ("Fix It For Me")
# ============================================================

# Canonical tag order for generated records
_RECORD_TAG_ORDER = ["v", "p", "sp", "np", "adkim", "aspf", "fo", "psd", "t", "rua", "ruf"]


def _build_record_builder(
    tags: Dict[str, str],
    policy: str,
    health_status: str,
    record: Optional[str],
    config_warnings: List[Dict],
    domain: str = "",
) -> Dict:
    """Build the Record Builder payload.

    Returns a dict with current_record, recommended_record, changes list,
    deploy instructions, and edge-case flags.
    """
    has_record = bool(record and record.strip())

    # ── No existing record ─────────────────────────────────────
    if not has_record:
        safe_domain = domain or "yourdomain.com"
        rec = f"v=DMARC1; p=none; fo=1; rua=mailto:dmarc@{safe_domain}"
        return {
            "mode": "first_record",
            "current_record": None,
            "recommended_record": rec,
            "changes": [{
                "tag": "p", "action": "added", "value": "none",
                "reason": "Start with monitoring to review aggregate reports before enforcing.",
            }, {
                "tag": "fo", "action": "added", "value": "1",
                "reason": "Captures all authentication failures for full visibility.",
            }, {
                "tag": "rua", "action": "added", "value": f"mailto:dmarc@{safe_domain}",
                "reason": "Aggregate reporting address. Replace with your actual address.",
            }],
            "deploy": _deploy_instructions(domain, record),
        }

    # ── Already DMARCbis Ready ─────────────────────────────────
    if health_status == "ready":
        suggestions = _ready_suggestions(tags)
        return {
            "mode": "ready",
            "current_record": record,
            "recommended_record": record,
            "changes": [],
            "suggestions": suggestions,
            "deploy": _deploy_instructions(domain, record),
        }

    # ── Build recommended record from current ──────────────────
    rec_tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            rec_tags[k.strip().lower()] = v.strip()

    changes: list = []

    # 1. Fix policy progression — target is p=reject for DMARCbis Ready
    cur_p = rec_tags.get("p", "none").lower()
    if cur_p != "reject":
        rec_tags["p"] = "reject"
        if cur_p == "quarantine":
            reason = "Upgrade from quarantine to reject for full spoofing protection."
        else:
            reason = "Enforce reject to block spoofed mail. Use t=y if you need a testing period first."
        changes.append({
            "tag": "p", "action": "changed",
            "old": cur_p, "value": "reject",
            "reason": reason,
        })

    # 2. Fix sp
    cur_sp = rec_tags.get("sp", "").lower()
    target_p = rec_tags["p"]
    if cur_sp != target_p:
        old_val = cur_sp if cur_sp else "(not set)"
        rec_tags["sp"] = target_p
        changes.append({
            "tag": "sp", "action": "changed" if cur_sp else "added",
            "old": old_val, "value": target_p,
            "reason": "Closes subdomain policy gap. Matches root domain enforcement.",
        })

    # 3. Add np=
    if "np" not in rec_tags:
        rec_tags["np"] = target_p
        changes.append({
            "tag": "np", "action": "added", "value": target_p,
            "reason": "Protects non-existent subdomains from spoofing (new in DMARCbis).",
        })
    elif rec_tags.get("np", "").lower() == "none" and target_p == "reject":
        rec_tags["np"] = "reject"
        changes.append({
            "tag": "np", "action": "changed",
            "old": "none", "value": "reject",
            "reason": "Closes non-existent subdomain gap. Matches root policy.",
        })

    # 4. Fix fo
    cur_fo = rec_tags.get("fo", "")
    if cur_fo != "1":
        old_val = cur_fo if cur_fo else "(not set)"
        rec_tags["fo"] = "1"
        changes.append({
            "tag": "fo", "action": "changed" if cur_fo else "added",
            "old": old_val, "value": "1",
            "reason": "Captures all authentication failures, not just complete failures.",
        })

    # 5. Add psd=n if missing
    cur_psd = rec_tags.get("psd", "")
    if cur_psd not in ("y", "n"):
        rec_tags["psd"] = "n"
        changes.append({
            "tag": "psd", "action": "added", "value": "n",
            "reason": "Explicitly declares non-public-suffix status for the DNS tree walk.",
        })

    # 6. Remove deprecated tags
    for dep in ("pct", "rf", "ri"):
        if dep in rec_tags:
            dep_reasons = {
                "pct": "Deprecated in DMARCbis. Replaced by t= tag.",
                "rf": "Deprecated in DMARCbis. Only afrf was ever implemented.",
                "ri": "Deprecated in DMARCbis. Receivers standardize on daily reports.",
            }
            changes.append({
                "tag": dep, "action": "removed",
                "old": rec_tags[dep], "value": None,
                "reason": dep_reasons[dep],
            })
            del rec_tags[dep]

    # 7. Remove t=y if present and policy is already reject
    if rec_tags.get("t") == "y" and rec_tags.get("p") == "reject":
        rec_tags.pop("t", None)
        changes.append({
            "tag": "t", "action": "removed",
            "old": "y", "value": None,
            "reason": "Test mode is no longer needed at full reject enforcement.",
        })

    # 8. Fix psd=y if not actually a public suffix
    if rec_tags.get("psd") == "y":
        rec_tags["psd"] = "n"
        # Only add change if not already in the list
        if not any(c["tag"] == "psd" for c in changes):
            changes.append({
                "tag": "psd", "action": "changed",
                "old": "y", "value": "n",
                "reason": "Most domains are not public suffixes. Set psd=n unless you operate a TLD.",
            })

    # Assemble recommended record in canonical order
    rec_parts = []
    for tag_key in _RECORD_TAG_ORDER:
        if tag_key in rec_tags:
            rec_parts.append(f"{tag_key}={rec_tags[tag_key]}")
    # Include any remaining tags not in canonical order (preserve unknowns)
    for tag_key, val in rec_tags.items():
        if tag_key not in _RECORD_TAG_ORDER:
            rec_parts.append(f"{tag_key}={val}")

    recommended = "; ".join(rec_parts)

    return {
        "mode": "fix",
        "current_record": record,
        "recommended_record": recommended,
        "changes": changes,
        "deploy": _deploy_instructions(domain, record),
    }


def _ready_suggestions(tags: Dict[str, str]) -> List[Dict]:
    """Optional suggestions for already-ready records."""
    suggestions = []
    if "ruf" not in tags:
        suggestions.append({
            "tag": "ruf",
            "reason": "Consider adding failure reporting (ruf=) for per-message forensic data.",
        })
    adkim = tags.get("adkim", "r")
    aspf = tags.get("aspf", "r")
    if adkim == "r" and tags.get("p") == "reject":
        suggestions.append({
            "tag": "adkim",
            "reason": "Consider adkim=s (strict alignment) for tighter DKIM validation at p=reject.",
        })
    if aspf == "r" and tags.get("p") == "reject":
        suggestions.append({
            "tag": "aspf",
            "reason": "Consider aspf=s (strict alignment) for tighter SPF validation at p=reject.",
        })
    return suggestions


def _deploy_instructions(domain: str, record: Optional[str]) -> Dict:
    """Build deployment instructions."""
    host = f"_dmarc.{domain}" if domain else "_dmarc.yourdomain.com"
    return {
        "host": host,
        "replace_existing": bool(record and record.strip()),
        "note_ttl": "Changes typically propagate within minutes, depending on your DNS provider's TTL.",
    }


# ============================================================
# SPF
# ============================================================

def _is_null_spf(record: str) -> bool:
    """Detect a null SPF record: v=spf1 -all with no senders.
    Only hardfail (-all) is an explicit declaration that the domain does not send email.
    Softfail (~all) is ambiguous and should not be treated as null SPF."""
    if not record:
        return False
    parts = record.strip().lower().split()
    if len(parts) == 2 and parts[0] == "v=spf1" and parts[1] == "-all":
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
        verdict = "No SPF record published"
        pill_label = "Missing"
    else:
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)
        if all_mech == "+all":
            verdict = "Authorizes the entire internet to send as you"
        elif lookups > 10:
            verdict = f"SPF is invalid ({lookups}/10 lookups). Fails at most receivers."
        elif not all_mech and raw.get("has_redirect"):
            verdict = "SPF configured (via redirect)"
        elif not all_mech:
            verdict = "Configured but missing an all mechanism"
        else:
            verdict = "SPF record configured"

    # Explanation
    if null_spf:
        all_mech = raw.get("all_mechanism") or ""
        explanation = (
            f"This domain publishes a null SPF record (<strong>v=spf1 {_e(all_mech)}</strong>), "
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
            "No SPF record found. SPF (<a href=\"https://datatracker.ietf.org/doc/html/rfc7208\" target=\"_blank\" rel=\"noopener\">RFC 7208</a>) specifies which IP addresses are authorized "
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
                "SPF results feed into DMARC alignment evaluation; enforcement decisions "
                "are made at the DMARC policy layer, not by SPF alone."
            )
        elif all_mech == "~all":
            explanation = (
                "SPF record ends with <strong>~all</strong> (softfail), indicating that servers "
                "not listed in this record are not authorized but should not be outright rejected. "
                "Like -all, the SPF result feeds into DMARC alignment evaluation; "
                "enforcement decisions are made at the DMARC policy layer."
            )
        elif all_mech == "?all":
            explanation = (
                "SPF record uses <strong>?all</strong> (neutral). Per <a href=\"https://datatracker.ietf.org/doc/html/rfc7208\" target=\"_blank\" rel=\"noopener\">RFC 7208</a>, this means the domain "
                "makes no assertion about unlisted servers. A neutral result is not an SPF pass. "
                "Only an SPF pass can satisfy DMARC's SPF alignment requirement."
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
                "SPF record is missing an <strong>all</strong> mechanism. Per <a href=\"https://datatracker.ietf.org/doc/html/rfc7208\" target=\"_blank\" rel=\"noopener\">RFC 7208</a> Section 4.7, "
                "if processing reaches the end of the record without a match, the result is neutral. "
                "This means unlisted servers produce no SPF pass and cannot contribute to DMARC alignment."
            )
        else:
            explanation = "SPF record found."

        if lookups and lookups > 10:
            explanation += (
                f" <strong>Critical:</strong> This SPF record has a PermError because it requires "
                f"{lookups} DNS lookups, exceeding the 10-lookup limit "
                f"(<a href=\"https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4\" target=\"_blank\" rel=\"noopener\">RFC 7208 Section 4.6.4</a>). "
                f"Receiving servers treat an SPF PermError as if no SPF record exists, which "
                f"damages sender reputation. Audit your includes and remove services you no longer use."
            )
        elif lookups and lookups > 8:
            explanation += (
                f" <strong>Note:</strong> SPF uses {lookups} of the allowed 10 DNS lookups "
                f"(<a href=\"https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4\" target=\"_blank\" rel=\"noopener\">RFC 7208 Section 4.6.4</a>). "
                f"{'At the limit. Any addition will cause a PermError.' if lookups == 10 else 'Approaching the limit. Plan for headroom before adding new services.'}"
            )

    # Details
    details = []
    if null_spf:
        all_mech = raw.get("all_mechanism") or ""
        details.append({"type": "good", "text": f"Null SPF record (v=spf1 {_e(all_mech)})"})
        details.append({"type": "good", "text": "Explicitly declares this domain does not send email"})
        status = "pass"
    elif not record and not has_mx:
        details.append({"type": "info", "text": "No SPF record and no MX records"})
        details.append({"type": "info", "text": "This domain does not appear to send or receive email"})
        status = "warn"
    elif not record:
        # No SPF record but domain has MX (sends/receives mail) -- critical failure
        status = "fail"
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))
    elif record:
        lookups = raw.get("lookup_count", 0)
        if lookups <= 8:
            details.append({"type": "good", "text": f"{lookups} DNS lookups (well within the 10-lookup limit)"})
        elif lookups <= 10:
            details.append({"type": "warning", "text": f"{lookups} DNS lookups ({'at' if lookups == 10 else 'near'} the 10-lookup limit)"})
        else:
            details.append({"type": "error", "text": f"{lookups} DNS lookups. SPF is invalid and will fail at most receivers (PermError)."})

        all_mech = raw.get("all_mechanism") or ""
        if all_mech == "-all":
            details.append({"type": "good", "text": "-all (hardfail): declares no other servers are authorized"})
        elif all_mech == "~all":
            details.append({"type": "good", "text": "~all (softfail): unlisted servers are not authorized"})
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

    # Override status based on critical SPF issues
    if record and not null_spf:
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)
        has_engine_errors = any(
            i.get("severity") == "error" for i in raw.get("issues", [])
        )
        if all_mech == "+all":
            status = "fail"
        elif lookups and lookups > 10:
            status = "fail"
        elif has_engine_errors:
            status = "fail"
        elif all_mech in ("-all", "~all") and lookups <= 10 and not has_engine_errors:
            # Lenient parser recovered a valid record with a proper all mechanism
            # and within lookup limits.  Syntax warnings (e.g. missing spaces)
            # should not downgrade the card to "warn" -- show "pass" with the
            # warning details visible in the card body.
            status = "pass"

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
    elif not record:
        fix = (
            "Publish an SPF TXT record listing the IP addresses and services authorized to send "
            "email for your domain. Requires identifying all legitimate senders (mail server, ESP, "
            "marketing platforms) and staying within the 10 DNS lookup limit."
        )
    else:
        fix = _first_fix(raw.get("issues", []))
        if not fix and record:
            all_mech = raw.get("all_mechanism") or ""
            lookups = raw.get("lookup_count", 0)
            if all_mech in ("?all", "+all") and lookups and lookups > 10:
                fix = (
                    "Change the all mechanism to <strong>-all</strong> (hardfail) or <strong>~all</strong> (softfail). "
                    "Also reduce SPF lookups to 10 or fewer by removing includes for services you no longer use "
                    "or consolidating senders."
                )
            elif all_mech in ("?all", "+all"):
                fix = "Change the all mechanism to <strong>-all</strong> (hardfail) or <strong>~all</strong> (softfail)."
            elif lookups and lookups > 10:
                fix = (
                    "Your SPF record has a PermError and is not functional. Reduce to 10 or fewer "
                    "DNS lookups by auditing your includes: remove services you no longer use, "
                    "consolidate senders where possible, and verify each include is still needed."
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
            "comment": "Null SPF: declares this domain does not send email",
        })
    # No copy-paste for starter SPF -- user must identify their authorized senders first

    # Deliverability context
    _deliverability = None
    if null_spf or (not record and not has_mx):
        pass  # No deliverability concern for non-mail domains
    elif not record:
        _deliverability = (
            "Without SPF, receivers cannot verify that your email server is authorized "
            "to send for your domain. This is one of the most common causes of emails "
            "landing in spam. Every major email provider checks SPF."
        )
    elif record:
        _lookups = raw.get("lookup_count", 0)
        _all = raw.get("all_mechanism", "")
        if _all == "+all":
            _deliverability = (
                "DANGER: +all authorizes the entire internet to send email as your domain. "
                "This effectively disables SPF and will severely damage your deliverability. "
                "Fix this immediately."
            )
        elif _lookups and _lookups > 10:
            _deliverability = (
                f"Your SPF record requires {_lookups} DNS lookups, exceeding the 10-lookup limit. "
                f"This means SPF fails completely for all your email, which can cause messages "
                f"to bounce or go to spam. Every email platform you add (Mailchimp, Salesforce, "
                f"HubSpot, SendGrid) consumes lookups. Remove services you no longer use or "
                f"consider an SPF flattening service."
            )
        elif _lookups and _lookups > 8:
            _deliverability = (
                f"Your SPF record uses {_lookups} of 10 allowed DNS lookups. "
                f"{'You are at the limit. Adding one more email service will break SPF for all your email.' if _lookups == 10 else 'You are close to the limit. Plan carefully before adding new sending services like Mailchimp, HubSpot, or SendGrid.'}"
            )
        elif _all == "~all":
            _deliverability = (
                "Softfail (~all) means unauthorized servers are flagged but not blocked. "
                "This is fine during setup, but for production email, consider -all (hard fail) "
                "once you have confirmed all legitimate senders are included."
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
        "fix_records": fix_records if fix_records else None,
        "spf_deep": _build_spf_deep_analysis(raw) if record else None,
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": _deliverability,
    }


# ============================================================
# SPF Deep Analysis (Prompt 7)
# ============================================================

_SPF_PROVIDER_MAP = {
    "_spf.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "servers.mcsv.net": "Mailchimp",
    "_spf.salesforce.com": "Salesforce",
    "mail.zendesk.com": "Zendesk",
    "spf.mandrillapp.com": "Mandrill",
    "_spf.firebasemail.com": "Firebase",
    "spf.messagelabs.com": "Symantec/Broadcom",
    "_spf.intuit.com": "Intuit",
    "hubspot.com": "HubSpot",
    "aspmx.pardot.com": "Pardot/Salesforce",
    "_spf.protonmail.ch": "ProtonMail",
    "spf.constantcontact.com": "Constant Contact",
    "_netblocks.mimecast.com": "Mimecast",
    "pphosted.com": "Proofpoint",
    "_spf.mx.cloudflare.net": "Cloudflare",
    "zoho.com": "Zoho",
    "mktomail.com": "Marketo",
    "outbound.mailhop.org": "DuoCircle",
    "spf.brevo.com": "Brevo",
    "secureserver.net": "GoDaddy",
    "spf.mailkit.eu": "Omnivery/Mailkit",
    "mailkit.eu": "Omnivery/Mailkit",
    "omnivery.com": "Omnivery",
}

_ALL_EXPLANATIONS = {
    "~all": (
        "Unauthorized servers are flagged but mail is delivered. Under DMARC, the SPF result "
        "feeds into alignment evaluation. The DMARC policy determines actual enforcement."
    ),
    "-all": "Unauthorized servers are explicitly rejected. Strongest SPF enforcement.",
    "+all": (
        "This authorizes EVERY server on the internet to send as your domain. "
        "SPF provides zero protection. This is a critical misconfiguration."
    ),
    "?all": "No assertion about unauthorized servers. Provides no protection on its own.",
}


def _build_spf_deep_analysis(raw: Dict) -> Optional[Dict]:
    """Build deep SPF analysis: mechanism breakdown, provider mapping, misconfigs, optimization."""
    record = raw.get("record")
    if not record:
        return None

    import re

    parts = record.strip().split()
    mechanisms = []
    all_mechanism = None
    lookups = raw.get("lookup_count", 0)
    has_ptr = False

    for part in parts:
        if part.lower() == "v=spf1":
            continue

        # Determine type and lookup cost
        p_lower = part.lower()
        cost = 0
        mech_type = "unknown"
        provider = None
        value = part

        if p_lower.startswith("include:"):
            mech_type = "include"
            cost = 1
            domain = part.split(":", 1)[1] if ":" in part else ""
            value = domain
            # Provider lookup
            for pattern, name in _SPF_PROVIDER_MAP.items():
                if pattern in domain.lower():
                    provider = name
                    break
            if not provider:
                provider = "Unknown service"
        elif p_lower.startswith("ip4:"):
            mech_type = "ip4"
            value = part.split(":", 1)[1] if ":" in part else ""
        elif p_lower.startswith("ip6:"):
            mech_type = "ip6"
            value = part.split(":", 1)[1] if ":" in part else ""
        elif p_lower.startswith("redirect="):
            mech_type = "redirect"
            cost = 1
            value = part.split("=", 1)[1] if "=" in part else ""
        elif p_lower.startswith("exists:"):
            mech_type = "exists"
            cost = 1
            value = part.split(":", 1)[1] if ":" in part else ""
        elif p_lower in ("a", "+a") or p_lower.startswith("a:") or p_lower.startswith("a/"):
            mech_type = "a"
            cost = 1
        elif p_lower in ("mx", "+mx") or p_lower.startswith("mx:") or p_lower.startswith("mx/"):
            mech_type = "mx"
            cost = 1
        elif p_lower.startswith("ptr") or p_lower == "ptr":
            mech_type = "ptr"
            cost = 1
            has_ptr = True
        elif p_lower in ("-all", "~all", "+all", "?all"):
            all_mechanism = part
            continue
        else:
            mech_type = "other"

        mechanisms.append({
            "raw": part,
            "type": mech_type,
            "value": value,
            "cost": cost,
            "provider": provider,
        })

    # All-mechanism analysis
    all_explanation = ""
    all_severity = "info"
    if all_mechanism:
        all_explanation = _ALL_EXPLANATIONS.get(all_mechanism.lower(),
                                                 f"Unknown all mechanism: {all_mechanism}")
        if all_mechanism.lower() == "+all":
            all_severity = "critical"
    else:
        all_explanation = ("No all mechanism found. Implicit default is ?all (neutral). "
                          "SPF makes no assertion about unauthorized senders.")
        all_severity = "warning"

    # Misconfigurations
    misconfigs = []

    if has_ptr:
        misconfigs.append({
            "level": "warning",
            "title": "Deprecated ptr mechanism",
            "text": "The ptr mechanism is deprecated in RFC 7208. Slow, unreliable, stresses DNS infrastructure. Replace with explicit ip4: or ip6: mechanisms.",
        })

    if all_mechanism and all_mechanism.lower() == "+all":
        misconfigs.append({
            "level": "critical",
            "title": "Open SPF (+all)",
            "text": "This authorizes EVERY server on the internet to send as your domain. SPF provides zero protection.",
        })

    # Check for broad IP ranges
    for mech in mechanisms:
        if mech["type"] in ("ip4", "ip6") and "/" in mech["value"]:
            cidr = mech["value"].split("/")[-1]
            try:
                prefix = int(cidr)
                if mech["type"] == "ip4" and prefix < 16:
                    hosts = 2 ** (32 - prefix)
                    misconfigs.append({
                        "level": "warning",
                        "title": f"Broad IP range: {mech['value']}",
                        "text": f"This range authorizes {hosts:,} addresses. Verify this is intentional.",
                    })
                elif mech["type"] == "ip6" and prefix < 48:
                    misconfigs.append({
                        "level": "warning",
                        "title": f"Broad IPv6 range: {mech['value']}",
                        "text": "This range is very broad. Verify this is intentional.",
                    })
            except ValueError:
                pass

    # Record length
    if len(record) > 450:
        misconfigs.append({
            "level": "info",
            "title": "Long SPF record",
            "text": f"Record is {len(record)} characters. Long records may cause issues with DNS UDP packet size limits.",
        })

    # Optimization suggestions
    optimizations = []
    if lookups >= 8:
        optimizations.append(
            f"Your SPF record uses {lookups} of 10 allowed lookups. Consider SPF flattening "
            f"where the included domain resolves to static IPs."
        )

    return {
        "mechanisms": mechanisms,
        "all_mechanism": all_mechanism,
        "all_explanation": all_explanation,
        "all_severity": all_severity,
        "lookup_count": lookups,
        "misconfigs": misconfigs,
        "optimizations": optimizations,
        "dmarcbis_note": (
            "Under DMARCbis, SPF alignment is evaluated against the MAIL FROM (envelope sender) "
            "identity only, not HELO. SPF pass alone does not guarantee DMARC pass. The MAIL FROM "
            "domain must also align with the From header domain."
        ),
    }


# ============================================================
# DKIM
# ============================================================

def transform_dkim(raw: Dict, domain: str, has_mx: bool = True) -> Dict:
    # Lazy import avoids the audit_engine ↔ result_transformer cycle.
    from audit_engine import BUSINESS_RISK

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
                "deliverability": None,
            }

        # User provided a specific selector that wasn't found
        selector_not_found = raw.get("selector_not_found")
        if selector_not_found:
            _details = [
                {
                    "type": "error",
                    "text": f"No TXT record at {_e(selector_not_found)}._domainkey.{_e(domain)}",
                    "business_risk": BUSINESS_RISK.get("DKIM_SELECTOR_NOT_FOUND"),
                },
                {"type": "info", "text": "Check your email provider's admin console for the correct selector name"},
            ]
            for issue in raw.get("issues", []):
                _details.append(_issue_to_detail(issue))
            return {
                "name": "DKIM",
                "status": "fail",
                "pill_label": "Not found",
                "verdict": f"Selector '{selector_not_found}' not found",
                "record": None,
                "explanation": (
                    f"No DKIM public key was found at "
                    f"<strong>{_e(selector_not_found)}._domainkey.{_e(domain)}</strong>. "
                    f"Verify the selector name is correct. You can find your DKIM "
                    f"selector in the DKIM-Signature header of a sent message (the s= value)."
                ),
                "details": _details,
                "fix": (
                    f"Verify that DKIM is enabled in your email provider's settings and that the public key "
                    f"TXT record is published at <strong>{_e(selector_not_found)}._domainkey.{_e(domain)}</strong>."
                ),
                "fix_records": None,
                "deliverability": None,
            }

        _unknown_details = [
            {
                "type": "info",
                "text": f"Checked {tested} common selectors, no public keys found",
                "business_risk": BUSINESS_RISK.get("DKIM_NO_KEYS_FOUND"),
            },
            {"type": "info", "text": "DKIM selectors are private and cannot be enumerated from outside"},
            {"type": "info", "text": "Enter your specific selector above for a definitive check"},
        ]
        for issue in raw.get("issues", []):
            _unknown_details.append(_issue_to_detail(issue))
        return {
            "name": "DKIM",
            "status": "warn",
            "pill_label": "Unknown",
            "verdict": "DKIM status cannot be determined externally",
            "record": None,
            "explanation": (
                "DKIM (<a href=\"https://datatracker.ietf.org/doc/html/rfc6376\" "
                "target=\"_blank\" rel=\"noopener\">RFC 6376</a>) is a critical part "
                "of email authentication. It attaches a cryptographic signature to "
                "each outgoing message, allowing receivers to verify the message has "
                "not been altered and that it came from an authorized sender. "
                "However, DKIM public keys are published under provider-specific "
                "selectors that cannot be discovered without knowing the selector name. "
                "This audit checked {tested} common selectors and did not find a match, "
                "but that does not mean DKIM is not configured. "
                "To verify, enter your selector in the field above for a direct lookup."
            ).format(tested=tested),
            "details": _unknown_details,
            "fix": None,
            "fix_records": None,
            "deliverability": (
                "DKIM is the single most important signal for Gmail's spam filters. "
                "Without a confirmed DKIM key, your emails are significantly more likely to be "
                "flagged as spam, even if SPF passes. Most email providers (Google Workspace, "
                "Microsoft 365, Mailchimp, SendGrid) can set up DKIM for you."
            ),
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
            weak_detail = {
                "type": "warning",
                "text": f"{selector}: {bits}-bit {key_analysis.get('key_type', 'RSA')} key{vendor_str} - upgrade recommended",
            }
            # Only attach business_risk to the first weak-key detail to avoid
            # repeating the same callout once per selector.
            if not weak_keys:
                weak_detail["business_risk"] = BUSINESS_RISK.get("DKIM_WEAK_KEY")
            details.append(weak_detail)
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

    if raw.get("timeout_note"):
        details.append({"type": "warning", "text": raw["timeout_note"]})

    # ARC informational note (RFC 8617)
    details.append({"type": "info", "text": "ARC (RFC 8617) extends the DKIM signing mechanism to preserve authentication across mail forwarding"})

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
        "(<a href=\"https://datatracker.ietf.org/doc/html/rfc6376\" target=\"_blank\" rel=\"noopener\">RFC 6376</a>). Note: this audit confirms the public key exists in DNS; "
        "it does not test live message signatures."
    ).format(domain=_e(domain))
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
            f"<strong>{_e(selectors_str)}</strong>. "
            f"Key rotation is provider-specific. Check your email provider's documentation "
            f"for how to generate and publish a new 2048-bit or Ed25519 key pair."
        )
    elif raw.get("issues"):
        fix = _first_fix(raw.get("issues", []))

    # Deliverability context
    if found:
        if weak_keys:
            _deliverability = (
                "Your DKIM keys work but some use 1024-bit strength. Google recommends 2048-bit keys. "
                "While 1024-bit keys will not directly hurt deliverability today, upgrading signals "
                "that you maintain your email infrastructure."
            )
        else:
            _deliverability = (
                "DKIM signing is active, which helps build your domain's sending reputation. "
                "Each signed email that recipients engage with (open, reply, mark as not spam) "
                "strengthens your reputation with that receiver."
            )
    else:
        _deliverability = None

    return {
        "name": "DKIM",
        "status": status,
        "verdict": verdict,
        "record": None,  # DKIM has multiple records, shown in details
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,  # DKIM keys are generated by email providers, not manually
        "dkim_deep": _build_dkim_key_analysis(raw),
        "deliverability": _deliverability,
    }


# ============================================================
# DKIM Key Strength & Rotation Advisory (Prompt 8)
# ============================================================

_DKIM_SELECTOR_PROVIDERS = {
    "google": "Google Workspace", "gapps": "Google Workspace",
    "selector1": "Microsoft 365", "selector2": "Microsoft 365",
    "k1": "Mailchimp", "k2": "Mailchimp", "k3": "Mailchimp",
    "mandrill": "Mandrill",
    "s1": "Generic (Exchange)", "s2": "Generic (Exchange)",
    "ses": "Amazon SES",
    "cm": "Campaign Monitor",
    "zendesk1": "Zendesk", "zendesk2": "Zendesk",
    "hubspot": "HubSpot", "hs1": "HubSpot", "hs2": "HubSpot",
    "sf": "Salesforce", "sf1": "Salesforce", "sf2": "Salesforce",
    "protonmail": "ProtonMail", "protonmail2": "ProtonMail", "protonmail3": "ProtonMail",
    "mg": "Mailgun",
    "dkim": "Generic",
    "default": "Generic",
    "sendgrid": "SendGrid", "smtpapi": "SendGrid", "s1._domainkey": "SendGrid",
    "fm1": "Fastmail", "fm2": "Fastmail", "fm3": "Fastmail",
    "mimecast": "Mimecast",
    "pphosted": "Proofpoint",
    "everlytickey1": "Everlytic", "everlytickey2": "Everlytic",
}


def _build_dkim_key_analysis(raw: Dict) -> Optional[Dict]:
    """Build DKIM key strength analysis, tag breakdown, provider mapping, rotation guidance."""
    found = raw.get("found_selectors", [])
    if not found:
        return None

    keys = []
    has_weak = False
    has_revoked = False
    all_strong = True

    for sel in found:
        selector = sel.get("selector", "unknown")
        sel_record = sel.get("record", "")
        vendor = sel.get("vendor")
        key_analysis = analyze_dkim_key_strength(sel_record)
        bits = key_analysis.get("key_bits", 0)
        key_type = key_analysis.get("key_type", "RSA")
        strength = key_analysis.get("status", "unknown")

        # Key strength rating
        if key_type.lower() == "ed25519":
            rating = "green"
            rating_label = "Modern elliptic curve. Smaller, faster, more secure."
        elif bits >= 2048:
            rating = "green"
            rating_label = "Meets current security recommendations."
            if bits >= 4096:
                rating_label = "Exceeds recommendations. Larger keys increase DNS response size."
        elif bits >= 1024:
            rating = "amber"
            rating_label = "Weak by modern standards. NIST deprecated 1024-bit RSA in 2013. Rotate to 2048-bit."
            has_weak = True
            all_strong = False
        elif bits > 0:
            rating = "red"
            rating_label = "Critical. This key can be factored and forged. Rotate immediately."
            has_weak = True
            all_strong = False
        else:
            rating = "amber"
            rating_label = "Key strength could not be determined."
            all_strong = False

        # Parse DKIM record tags
        dkim_tags = []
        for part in sel_record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                k = k.strip().lower()
                v = v.strip()

                tag_info = {"tag": k, "value": v}
                if k == "v":
                    tag_info["label"] = "Version"
                elif k == "k":
                    tag_info["label"] = "Key type"
                elif k == "p":
                    if not v:
                        tag_info["label"] = "Public key (REVOKED)"
                        tag_info["revoked"] = True
                        has_revoked = True
                    else:
                        tag_info["label"] = "Public key"
                        tag_info["truncated"] = v[:40] + "..." if len(v) > 40 else v
                elif k == "t":
                    if v == "y":
                        tag_info["label"] = "Test mode"
                    elif v == "s":
                        tag_info["label"] = "Strict domain"
                    else:
                        tag_info["label"] = f"Flag: {v}"
                elif k == "h":
                    tag_info["label"] = "Hash algorithm"
                elif k == "s":
                    tag_info["label"] = "Service type"
                else:
                    tag_info["label"] = k

                dkim_tags.append(tag_info)

        # Provider from selector name
        provider = vendor or _DKIM_SELECTOR_PROVIDERS.get(selector.lower())

        keys.append({
            "selector": selector,
            "bits": bits,
            "key_type": key_type,
            "rating": rating,
            "rating_label": rating_label,
            "provider": provider,
            "tags": dkim_tags,
        })

    # Rotation guidance
    if all_strong:
        rotation = "Keys meet standards. Best practice: rotate annually."
    elif has_revoked:
        rotation = "Revoked key detected. Messages signed with this selector fail DKIM."
    elif has_weak:
        weak_selectors = [k["selector"] for k in keys if k["rating"] in ("red", "amber")]
        rotation = (
            f"Rotate {', '.join(weak_selectors)} to 2048-bit. Steps: "
            "1) Generate new key pair, 2) Publish new public key under new selector, "
            "3) Configure mail server to sign with new selector, 4) Revoke old key by emptying p=."
        )
    else:
        rotation = "Review key configuration."

    return {
        "keys": keys,
        "rotation_guidance": rotation,
        "has_weak": has_weak,
    }


# ============================================================
# MX
# ============================================================

def transform_mx(raw: Dict) -> Dict:
    status = _map_status(raw.get("status", "error"))
    records = raw.get("records", [])
    providers = raw.get("providers", [])
    count = raw.get("record_count", 0)

    # Null MX (RFC 7505): "0 ." means domain explicitly does not accept email
    is_null_mx = (count == 1 and records and records[0].strip() in ("0 .", "0  ."))
    if is_null_mx:
        return {
            "name": "MX Records",
            "status": "pass",
            "pill_label": "Null MX",
            "verdict": "Domain does not accept email (RFC 7505)",
            "record": records[0],
            "explanation": (
                "This domain publishes a null MX record (<strong>0 .</strong>) per RFC 7505, "
                "which explicitly declares that it does not accept inbound email. "
                "Sending servers will get a clean rejection rather than attempting delivery."
            ),
            "details": [
                {"type": "good", "text": "Null MX record correctly configured"},
                *[_issue_to_detail(i) for i in raw.get("issues", [])],
            ],
            "fix": None,
            "fix_records": None,
        }

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
                "mail server. If it is not meant to receive email, publish a null MX record "
                "(RFC 7505) to explicitly declare that."
            ),
            "fix_records": [{
                "type": "MX",
                "host": raw.get("domain", ""),
                "value": "0 .",
                "comment": "Null MX (RFC 7505): declares this domain does not accept email",
            }],
        }

    # Verdict: meaningful at a glance
    provider_str = ", ".join(providers) if providers else ""
    if count == 1:
        verdict = f"Single MX host{' (' + provider_str + ')' if provider_str else ''}"
    elif provider_str:
        verdict = provider_str
    else:
        verdict = f"{count} MX hosts configured"

    # Record display (all MX records)
    record = "\n".join(records)

    # Detect major providers with internal redundancy
    _major_mx_providers = {"google", "microsoft", "outlook", "proofpoint", "mimecast", "barracuda", "cloudflare"}
    _is_major_provider = any(
        any(major in p.lower() for major in _major_mx_providers)
        for p in providers
    ) if providers else False

    # Explanation
    if count >= 2:
        explanation = f"MX records are configured with <strong>{count} hosts</strong> for redundancy."
    elif _is_major_provider:
        explanation = (
            f"One MX record is configured, hosted by <strong>{_e(providers[0])}</strong>. "
            f"Major providers like {_e(providers[0])} handle redundancy internally across their infrastructure, "
            f"so a single MX hostname does not indicate a single point of failure."
        )
    else:
        explanation = (
            "Only one MX record is configured. If this host becomes unavailable, inbound email "
            "delivery will fail until it recovers."
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
            details.append({"type": "good", "text": f"Priority {priority}: {hostname}{provider_note} (resolves)"})
        else:
            details.append({"type": "error", "text": f"Priority {priority}: {hostname} does not resolve (dangling MX)"})

    if count >= 2:
        details.append({"type": "good", "text": "Multiple MX hosts provide failover redundancy"})
    elif count == 1 and _is_major_provider:
        details.append({"type": "info", "text": f"Single MX hostname, but {providers[0]} handles redundancy internally"})
    elif count == 1:
        details.append({"type": "warning", "text": "Single MX host with no visible failover. If this host is unavailable, inbound email will queue or bounce."})

    # Add any issues not already covered
    for issue in raw.get("issues", []):
        severity = issue.get("severity", "info")
        text = issue.get("plain_english") or issue.get("issue", "")
        if "dangling" not in text.lower() and "single" not in text.lower():
            details.append(_issue_to_detail(issue))

    fix = _first_fix(raw.get("issues", []))

    # Deliverability context
    _deliverability = None
    if count == 1 and not _is_major_provider:
        _deliverability = (
            "You have only one mail server. If it goes down, incoming emails will queue at "
            "the sender's server for hours or days, and some senders give up after a few retries. "
            "A second MX host provides failover for incoming mail."
        )
    if providers:
        _prov_lower = providers[0].lower() if providers else ""
        if "google" in _prov_lower:
            _deliverability = (_deliverability or "") + (
                " You are using Google Workspace. Check your Postmaster Tools dashboard "
                "(postmaster.google.com) for reputation data and delivery error details."
            )
        elif "microsoft" in _prov_lower or "outlook" in _prov_lower:
            _deliverability = (_deliverability or "") + (
                " You are using Microsoft 365. Verify DKIM is enabled in the Exchange admin "
                "center, as it is not always turned on by default."
            )
    if _deliverability:
        _deliverability = _deliverability.strip()

    return {
        "name": "MX Records",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": _deliverability,
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
                "deliverability": None,
            }

        sts_id = datetime.now(timezone.utc).strftime('%Y%m%d')
        return {
            "name": "MTA-STS",
            "status": "warn",
            "pill_label": "Not configured",
            "verdict": "No MTA-STS record found",
            "record": None,
            "explanation": (
                "While DMARC protects the <em>identity</em> of the sender, "
                "MTA-STS (<a href=\"https://datatracker.ietf.org/doc/html/rfc8461\" target=\"_blank\" rel=\"noopener\">RFC 8461</a>) "
                "protects the <em>connection</em>. It prevents downgrade attacks where a network attacker "
                "forces email to be delivered without encryption. Without MTA-STS, SMTP's opportunistic "
                "TLS (STARTTLS) can be silently stripped, allowing email content to be intercepted in transit."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": (
                f"MTA-STS requires a DNS TXT record at <strong>_mta-sts.{_e(domain)}</strong> and a "
                f"policy file hosted at <strong>https://mta-sts.{_e(domain)}/.well-known/mta-sts.txt</strong>. "
                f"The policy file specifies your MX hosts and the TLS enforcement mode."
            ),
            "fix_records": None,
            "deliverability": (
                "Without MTA-STS, the TLS encryption between mail servers can be silently stripped. "
                "While this does not directly affect spam filtering, some enterprise recipients flag "
                "inbound email that was not delivered over verified TLS."
            ),
        }

    # Has record
    if policy_mode == "enforce":
        verdict = "Inbound email must use encryption"
    elif policy_mode == "testing":
        verdict = "Monitoring TLS, not yet enforcing"
    elif policy_mode == "none":
        verdict = "Configured but disabled"
    else:
        verdict = f"Mode: {policy_mode}" if policy_mode else "Record found"

    explanation = ""
    if policy_mode == "enforce":
        explanation = (
            "MTA-STS is in <strong>enforce</strong> mode (<a href=\"https://datatracker.ietf.org/doc/html/rfc8461\" target=\"_blank\" rel=\"noopener\">RFC 8461</a>). Sending servers that "
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
        "mta_sts_deep": _build_mta_sts_deep(raw, domain) if txt_record else None,
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": None,
    }


def _build_mta_sts_deep(raw: Dict, domain: str) -> Optional[Dict]:
    """MTA-STS deep analysis: mode breakdown, max age, setup guidance."""
    mode = raw.get("policy_mode")
    max_age = raw.get("max_age")
    policy_file = raw.get("policy_file_content")

    mode_explanations = {
        "testing": (
            "Senders attempt TLS but deliver even if it fails. Correct starting point. "
            "Monitor TLS-RPT for failures before enforcing."
        ),
        "enforce": (
            "Senders MUST establish TLS. If TLS fails, mail is NOT delivered. "
            "Strongest downgrade protection. Ensure certificates stay valid."
        ),
        "none": (
            "Explicitly disabled. Signals MTA-STS was previously configured but is now inactive."
        ),
    }

    result: Dict = {
        "mode": mode,
        "mode_explanation": mode_explanations.get(mode, f"Unknown mode: {mode}") if mode else None,
    }

    # Max age analysis
    if max_age is not None:
        try:
            age_secs = int(max_age)
            if age_secs < 86400:
                result["max_age_note"] = f"{age_secs}s ({age_secs//3600}h). Very short cache. DNS outage quickly removes protection."
                result["max_age_level"] = "warning"
            elif age_secs > 2592000:
                result["max_age_note"] = f"{age_secs}s ({age_secs//86400}d). Long cache. Policy changes propagate slowly."
                result["max_age_level"] = "info"
            else:
                result["max_age_note"] = f"{age_secs}s ({age_secs//86400}d). Good range."
                result["max_age_level"] = "pass"
        except (ValueError, TypeError):
            pass

    return result


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
            "status": "warn",
            "pill_label": "Not configured",
            "verdict": "No TLS-RPT record found",
            "record": None,
            "explanation": (
                "Without TLS-RPT (<a href=\"https://datatracker.ietf.org/doc/html/rfc8460\" target=\"_blank\" rel=\"noopener\">RFC 8460</a>), "
                "you have no visibility into encryption failures on inbound email delivery. "
                "If a sending server cannot establish a secure connection with your mail server, "
                "it may fall back to plaintext delivery or fail silently. TLS-RPT provides daily reports "
                "on these failures, allowing you to identify certificate issues or misconfigurations "
                "before they affect delivery."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": (
                f"Publish a TLS-RPT TXT record at <strong>_smtp._tls.{_e(domain)}</strong>. "
                f"Requires a reporting address (<strong>rua=</strong>) that can receive JSON-formatted "
                f"TLS failure reports: either your own mailbox or a reporting service."
            ),
            "fix_records": None,
        }

    destinations = raw.get("report_destinations", [])
    verdict = f"Reports to {len(destinations)} destination{'s' if len(destinations) != 1 else ''}"

    explanation = (
        "TLS-RPT (<a href=\"https://datatracker.ietf.org/doc/html/rfc8460\" target=\"_blank\" rel=\"noopener\">RFC 8460</a>) is configured. Sending mail servers that support the protocol "
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
        "tls_rpt_deep": _build_tls_rpt_deep(raw) if record else None,
        "ttl_info": format_ttl(raw.get("ttl")),
    }


def _build_tls_rpt_deep(raw: Dict) -> Optional[Dict]:
    """TLS-RPT deep analysis: destinations, cross-protocol relationships."""
    destinations = raw.get("destinations", [])

    dest_types = []
    for d in destinations:
        if isinstance(d, str):
            if d.startswith("mailto:"):
                dest_types.append({"type": "mailto", "value": d})
            elif d.startswith("https:"):
                dest_types.append({"type": "https", "value": d})
            else:
                dest_types.append({"type": "unknown", "value": d})

    return {
        "destinations": dest_types,
        "cross_protocol_note": (
            "Without TLS-RPT, a man-in-the-middle stripping encryption from your inbound email "
            "would go undetected."
        ),
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
                "deliverability": None,
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
                {"type": "info", "text": "Requires DMARC policy of p=quarantine or p=reject"},
                {"type": "info", "text": "Gmail accepts a VMC (Verified Mark Certificate) or CMC (Common Mark Certificate). Apple Mail does not require either."},
            ],
            "fix": (
                f"BIMI requires DMARC at p=quarantine or p=reject, an SVG logo in Tiny P/S format "
                f"hosted at a public URL, and a BIMI TXT record at <strong>default._bimi.{_e(domain)}</strong>. "
                f"Gmail requires a VMC (registered trademark) or CMC (domain-validated) certificate."
            ),
            "fix_records": None,
            "deliverability": (
                "BIMI displays your brand logo next to emails in Gmail, Apple Mail, and Yahoo Mail. "
                "It does not directly affect whether email reaches the inbox, but branded emails "
                "see higher open rates. BIMI requires DMARC at p=quarantine or p=reject first."
            ),
        }

    logo_url = raw.get("logo_url")
    vmc_url = raw.get("vmc_url")
    if vmc_url:
        verdict = "Certificate referenced (VMC or CMC)"
    elif logo_url:
        verdict = "Logo configured"
    else:
        verdict = "Record found"

    explanation = "BIMI record is published. BIMI is a brand recognition feature, not a security protocol."
    if logo_url:
        explanation += " Your brand logo URL is configured."
    if vmc_url:
        explanation += " A certificate (VMC or CMC) is referenced in the <strong>a=</strong> tag."
    elif not vmc_url:
        explanation += (
            " <strong>Note:</strong> No certificate is referenced in the <strong>a=</strong> tag. "
            "Gmail requires either a VMC (registered trademark required) or CMC (domain validation only) "
            "for logo display. Other clients like Apple Mail do not require a certificate."
        )

    details = [_issue_to_detail(i) for i in raw.get("issues", [])]

    # Add SVG validation summary to details
    svg_validated = raw.get("svg_validated")
    svg_profile = raw.get("svg_profile")
    if svg_validated is True:
        if svg_profile == "tiny-ps":
            details.append({"type": "good", "text": f"SVG validated (profile: {svg_profile})"})
        elif svg_profile == "tiny":
            details.append({"type": "warning", "text": "SVG profile is 'tiny' but BIMI requires 'tiny-ps'. Gmail and other clients will reject this."})
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
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": None,
    }


# ============================================================
# DNSSEC
# ============================================================

def transform_dnssec(raw: Dict, domain: str = "") -> Dict:
    has_dnssec = raw.get("has_dnssec", False)
    dnssec_state = raw.get("dnssec_state", "insecure")
    algorithms = raw.get("algorithms", [])
    key_count = raw.get("key_count", 0)
    has_ds = raw.get("has_ds", False)
    validated_by_resolver = raw.get("validated_by_resolver", False)
    issues = raw.get("issues", [])
    status = _map_status(raw.get("status", "ok"))

    # Bogus state: DNSSEC is configured but signatures fail validation.
    # This is an availability issue, not just a security one — render it
    # with a fail status and a clear, actionable fix.
    if dnssec_state == "bogus":
        details = []
        for issue in issues:
            details.append(_issue_to_detail(issue))
        bogus_fix = (
            f"Run 'delv {_e(domain)}' locally for a chain analysis, or open "
            f"<a href=\"https://dnsviz.net/d/{_e(domain)}/dnssec/\" target=\"_blank\" rel=\"noopener\">"
            f"https://dnsviz.net/d/{_e(domain)}/dnssec/</a> in a browser. "
            f"If a key rollover is in progress, coordinate with your registrar "
            f"to update the DS record at the parent zone."
        )
        return {
            "name": "DNSSEC",
            "status": "fail",
            "pill_label": "Bogus",
            "verdict": "DNSSEC validation failure (zone is bogus)",
            "record": None,
            "explanation": (
                "DNSSEC is configured but its signatures fail to validate. "
                "Validating resolvers (Cloudflare 1.1.1.1, Quad9 9.9.9.9, "
                "Google 8.8.8.8 in DNSSEC mode) return SERVFAIL for this "
                "domain, so users behind those resolvers cannot reach it. "
                "Common causes: expired RRSIGs, an orphaned DS record at the "
                "parent after a key rollover, or a KSK/ZSK mismatch."
            ),
            "details": details,
            "fix": bogus_fix,
            "fix_records": None,
            "ttl_info": format_ttl(raw.get("ttl")),
        }

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
                "DNSSEC (<a href=\"https://datatracker.ietf.org/doc/html/rfc4033\" target=\"_blank\" rel=\"noopener\">RFC 4033</a>/4034/4035) cryptographically signs DNS records so that "
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
            "ttl_info": format_ttl(raw.get("ttl")),
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
            details.append({"type": "error", "text": "DS digest does NOT match any DNSKEY (chain of trust not valid; validating resolvers will return SERVFAIL)"})
    elif not validated_by_resolver:
        # No direct DS evidence and no AD-bit corroboration: real warning.
        # When AD is set the audit engine emits an info-level annotation
        # which is rendered below by the issues loop.
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

    # signed_unanchored: DNSKEY published but no DS at parent. Effectively
    # insecure for end users behind validating resolvers, so render with
    # warn status and a distinct pill — never green.
    if dnssec_state == "signed_unanchored":
        verdict = "DNSKEY published but unanchored (no DS at parent)"

    # Downgrade status if issues exist. AD-bit corroboration keeps the
    # DNSSEC card at "pass" even when DS isn't directly observable.
    if any(a.get("deprecated") for a in algorithms):
        status = "fail"
    elif chain_valid is False:
        status = "fail"
    elif dnssec_state == "signed_unanchored":
        status = "warn"
    elif not has_ds and not validated_by_resolver:
        status = "warn"

    fix = _first_fix(issues)
    if not fix and not has_ds and not validated_by_resolver:
        fix = "Add a DS record at your domain registrar to complete the DNSSEC chain of trust."

    result = {
        "name": "DNSSEC",
        "status": status,
        "verdict": verdict,
        "record": None,
        "explanation": (
            "DNSSEC is enabled. Your DNS records are cryptographically signed per "
            "<a href=\"https://datatracker.ietf.org/doc/html/rfc4033\" target=\"_blank\" rel=\"noopener\">RFC 4033</a>/4034/4035, allowing validating resolvers to confirm that responses "
            "have not been tampered with. This prevents cache poisoning and DNS spoofing, "
            "and is required for DANE to function."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
    }
    if dnssec_state == "signed_unanchored":
        result["pill_label"] = "Signed but unanchored"
    return result


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
                "CAA records (<a href=\"https://datatracker.ietf.org/doc/html/rfc8659\" target=\"_blank\" rel=\"noopener\">RFC 8659</a>) specify which Certificate Authorities are authorized "
                "to issue TLS certificates for your domain. Compliant CAs must check CAA records "
                "before issuance. Without CAA records, any compliant CA may issue certificates "
                "for your domain. There is no restriction to enforce."
            ),
            "details": details,
            "fix": (
                f"Publish CAA records specifying which Certificate Authorities may issue certificates "
                f"for your domain. Requires knowing which CA(s) you use. Use <code>issue</code> to "
                f"authorize your CA, <code>issuewild</code> for wildcard policy, and <code>iodef</code> "
                f"to receive violation alerts."
            ),
            "fix_records": None,
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
            "CAA records (<a href=\"https://datatracker.ietf.org/doc/html/rfc8659\" target=\"_blank\" rel=\"noopener\">RFC 8659</a>) restrict which Certificate Authorities may issue TLS certificates "
            "for your domain. Compliant CAs check these records before issuance and must not issue "
            "if they are not listed. Certificate Transparency logs can be used to detect issuance "
            "by CAs not authorized in your CAA records."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
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
                "DANE (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a>) publishes TLSA records that allow sending servers to verify "
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
                "DANE requires DNSSEC (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a> Section 2.2). Without it, an attacker can forge "
                "or strip TLSA records, completely defeating the authentication. "
                "Senders that implement RFC 7672 will ignore TLSA records that are not DNSSEC-validated."
            ),
            "details": details,
            "fix": "Enable DNSSEC for your domain before relying on DANE. Once DNSSEC is active, your existing TLSA records will become effective.",
            "fix_records": None,  # DNSSEC activation required first; TLSA records already exist
            "ttl_info": format_ttl(raw.get("ttl")),
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
                "DANE (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a>) is configured and backed by DNSSEC. Sending mail servers that "
                "implement RFC 7672 can verify your mail server's TLS certificate through DNS-based "
                "TLSA records, independent of the Certificate Authority infrastructure. "
                "This allows senders to authenticate the TLS certificate without relying on the "
                "public CA trust model."
            ),
            "details": details,
            "fix": fix,
            "fix_records": None,
            "dane_deep": _build_dane_deep(tlsa_records, dnssec_ok),
            "ttl_info": format_ttl(raw.get("ttl")),
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
    fix_parts = [
        "DANE implementation requires multiple steps:<br>"
        "<strong>1.</strong> DNSSEC must be enabled and validated for your domain.<br>"
        "<strong>2.</strong> Generate a TLSA record containing the SHA-256 hash of your mail server's "
        "TLS certificate (SPKI). The record goes at <strong>_25._tcp.&lt;mx-host&gt;</strong>.<br>"
        "<strong>3.</strong> TLSA records must be updated every time you rotate your mail server's TLS certificate, "
        "or use DANE-TA (usage 2) to pin the CA certificate instead."
    ]
    if not dnssec_ok:
        fix_parts.insert(0, "<strong>Prerequisite:</strong> DNSSEC is not enabled. DANE cannot function without it.<br><br>")

    fix = "".join(fix_parts)

    return {
        "name": "DANE",
        "status": "warn",
        "pill_label": "Not configured",
        "verdict": "No DANE TLSA records",
        "record": None,
        "explanation": (
            "DANE (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a>) uses TLSA records to let sending mail servers verify your mail "
            "server's TLS certificate through DNS, without depending on the CA infrastructure. "
            "DANE requires DNSSEC to be effective. Without it, TLSA records cannot be trusted. "
            "DANE and MTA-STS serve complementary roles for enforcing SMTP TLS."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
        "dane_deep": _build_dane_deep(tlsa_records, dnssec_ok),
        "ttl_info": format_ttl(raw.get("ttl")),
    }


# ============================================================
# DANE Deep Analysis (Prompt 10)
# ============================================================

_TLSA_USAGE = {
    0: ("PKIX-TA", "CA constraint with standard validation."),
    1: ("PKIX-EE", "End entity with CA validation."),
    2: ("DANE-TA", "Trust anchor. Specified cert trusted as CA without standard trust store."),
    3: ("DANE-EE", "End entity. Pins the exact certificate. Most common for SMTP."),
}

_TLSA_SELECTOR = {
    0: ("Full cert", "Full certificate matched."),
    1: ("SPKI", "Public key only. Recommended. Allows cert renewal without TLSA update."),
}

_TLSA_MATCHING = {
    0: ("Exact", "Exact match."),
    1: ("SHA-256", "SHA-256 hash. Recommended."),
    2: ("SHA-512", "SHA-512 hash."),
}


def _build_dane_deep(tlsa_records: List[Dict], dnssec_ok: bool) -> Optional[Dict]:
    """DANE/TLSA deep analysis: field breakdown, DNSSEC dependency, MX coverage."""
    if not tlsa_records:
        return None

    # DNSSEC gate
    if dnssec_ok and any(r.get("found") for r in tlsa_records):
        dnssec_status = {"status": "pass", "text": "DANE fully functional."}
    elif not dnssec_ok and any(r.get("found") for r in tlsa_records):
        dnssec_status = {"status": "fail", "text": (
            "DANE is INEFFECTIVE. Without DNSSEC, attackers can forge TLSA records. "
            "Senders implementing RFC 7672 will ignore non-DNSSEC TLSA records."
        )}
    elif dnssec_ok:
        dnssec_status = {"status": "partial", "text": (
            "DNSSEC active. Your domain supports DANE. Adding TLSA records provides "
            "certificate verification independent of CAs."
        )}
    else:
        dnssec_status = {"status": "info", "text": "Neither DNSSEC nor DANE configured."}

    # MX coverage
    hosts_with = [r["mx_host"] for r in tlsa_records if r.get("found")]
    hosts_without = [r["mx_host"] for r in tlsa_records if not r.get("found") and not r.get("error")]

    # Parse TLSA fields from records that were found
    parsed_tlsa = []
    for r in tlsa_records:
        if not r.get("found") or not r.get("records"):
            continue
        for rec in r.get("records", []):
            try:
                # Records are dicts with usage/selector/matching_type keys
                if isinstance(rec, dict):
                    usage = int(rec.get("usage", -1))
                    selector = int(rec.get("selector", -1))
                    matching = int(rec.get("matching_type", -1))
                else:
                    # Legacy fallback: raw string "usage selector matching data"
                    parts = rec.strip().split()
                    if len(parts) < 4:
                        continue
                    usage = int(parts[0])
                    selector = int(parts[1])
                    matching = int(parts[2])

                usage_info = _TLSA_USAGE.get(usage, ("Unknown", f"Usage {usage}"))
                sel_info = _TLSA_SELECTOR.get(selector, ("Unknown", f"Selector {selector}"))
                match_info = _TLSA_MATCHING.get(matching, ("Unknown", f"Matching {matching}"))

                is_best = usage == 3 and selector == 1 and matching == 1
                rotation_safe = selector == 1

                parsed_tlsa.append({
                    "mx_host": r["mx_host"],
                    "usage": usage, "usage_label": usage_info[0], "usage_desc": usage_info[1],
                    "selector": selector, "selector_label": sel_info[0], "selector_desc": sel_info[1],
                    "matching": matching, "matching_label": match_info[0], "matching_desc": match_info[1],
                    "is_best_practice": is_best,
                    "rotation_safe": rotation_safe,
                })
            except (ValueError, IndexError, TypeError):
                pass

    return {
        "dnssec_status": dnssec_status,
        "hosts_with_tlsa": hosts_with,
        "hosts_without_tlsa": hosts_without,
        "parsed_records": parsed_tlsa,
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
                details.append({"type": "good", "text": f"{ns['hostname']}{ip_part}: authoritative{rtt_str}"})
            elif auth is False:
                details.append({"type": "error", "text": f"{ns['hostname']}{ip_part}: NOT authoritative (lame delegation)"})
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
            "Nameservers are authoritative for your DNS zone. They answer queries for all your "
            "DNS records. Multiple nameservers on distinct network paths reduce the risk of a "
            "single point of failure causing a full DNS outage for your domain."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
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
            verdict = "CT data unavailable (tool limitation)"
            explanation = (
                "The external Certificate Transparency log service (crt.sh) could not be reached. "
                "This is a limitation of this audit tool, not an issue with your domain."
            )
            detail_text = "External CT log query timed out. This does not reflect your domain's configuration."
        return {
            "name": "Certificate Transparency",
            "status": "pass",
            "pill_label": "Skipped",
            "verdict": verdict,
            "record": None,
            "explanation": explanation,
            "details": [
                {"type": "info", "text": detail_text},
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
        f"(<a href=\"https://datatracker.ietf.org/doc/html/rfc6962\" target=\"_blank\" rel=\"noopener\">RFC 6962</a>), of which <strong>{active}</strong> {'are' if active != 1 else 'is'} currently active. "
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
            f"Review certificates from <strong>{_e(mismatched_cas)}</strong>. "
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
    domain_results = raw.get("domain_results", [])
    issues = raw.get("issues", [])

    DELIST_URLS = {
        "Spamhaus DBL": "https://check.spamhaus.org/",
    }

    # No domain results available
    if not domain_results:
        return {
            "name": "Blocklist",
            "status": "pass",
            "pill_label": "N/A",
            "verdict": "No blocklist data available",
            "record": None,
            "explanation": "Domain blocklist check could not be completed.",
            "details": [{"type": "info", "text": "No blocklist results available"}],
            "fix_records": None,
            "fix": None,
        }

    # Determine status from domain-based results only
    listed = False
    listed_names = []
    has_errors = False

    for dr in domain_results:
        if dr.get("listed"):
            listed = True
            list_name = dr["list"]
            listed_names.append(list_name)
        if dr.get("error"):
            has_errors = True

    if listed:
        status = "fail"
        pill_label = "Listed"
    elif has_errors:
        status = "warn"
        pill_label = "Unavailable"
    else:
        status = "pass"
        pill_label = "Clean"

    total_lists = len(domain_results)
    total_listings = len(listed_names)

    # Verdict
    if total_listings > 0:
        verdict = f"Listed on {total_listings} domain blocklist{'s' if total_listings != 1 else ''}"
    elif has_errors:
        verdict = "Blocklist check could not be completed"
    else:
        verdict = f"Clean on {total_lists} domain blocklist{'s' if total_lists != 1 else ''}"

    # Explanation
    if total_listings > 0:
        explanation = (
            f"This domain is listed on {total_listings} domain-based "
            f"blocklist{'s' if total_listings != 1 else ''}. "
            "Domain blocklists (like Spamhaus DBL) list domains directly associated with spam, "
            "phishing, or malware. A listing can affect deliverability. "
            "Investigate the cause before requesting removal."
        )
    elif has_errors:
        explanation = (
            "One or more blocklist queries were blocked, likely due to rate limiting "
            "on the public Spamhaus DNS mirror. This does not mean the domain is listed "
            "or clean. You can verify manually at https://check.spamhaus.org/."
        )
    else:
        explanation = (
            f"Checked the domain against {total_lists} domain-based "
            f"blocklist{'s' if total_lists != 1 else ''}. No listings found."
        )

    # Details
    details = []

    for dr in domain_results:
        if dr.get("listed"):
            meaning = dr.get("meaning", "Listed")
            details.append({"type": "error", "text": f"{domain}: {dr['list']}: {meaning}"})
        elif dr.get("error"):
            details.append({"type": "warning", "text": f"{domain}: {dr['list']}: {dr['error']}"})
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
                delist_parts.append(f"<strong>{_e(name)}</strong>: <a href=\"{_e(url)}\" target=\"_blank\" rel=\"noopener\">{_e(url)}</a>")
        if delist_parts:
            fix = "Request delisting from each blocklist:<br>" + "<br>".join(delist_parts)
            fix += (
                "<br><br>Before requesting removal, identify the reason for the listing. "
                "Common causes include a compromised sending account, misconfigured open relay, "
                "a spike in spam complaints, or in some cases a false positive. "
                "Removing the underlying cause first reduces the chance of re-listing."
            )
        else:
            fix = "Review the listing reason with each blocklist operator and request removal once the underlying issue is resolved."

    # Deliverability context
    if total_listings > 0:
        _deliverability = (
            "CRITICAL: Your domain is on a blocklist. This is likely causing widespread delivery "
            "failures right now. Emails may be bouncing or going directly to spam at major providers. "
            "This often happens when a compromised account or aggressive outreach triggers spam reports. "
            "Investigate the root cause before requesting delisting."
        )
    elif has_errors:
        _deliverability = (
            "The blocklist check was inconclusive due to query restrictions. "
            "This does not indicate a problem with your domain. "
            "Check manually at https://check.spamhaus.org/ for a definitive answer."
        )
    else:
        _deliverability = (
            "Your domain is clean on the blocklists we check. Note that Gmail, Outlook, and Yahoo "
            "maintain their own internal reputation systems that are not publicly visible. "
            "Blocklist clearance is a good baseline but does not guarantee inbox placement."
        )

    return {
        "name": "Blocklist",
        "status": status,
        "pill_label": pill_label,
        "verdict": verdict,
        "record": None,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
        "deliverability": _deliverability,
    }


# ============================================================
# Provider Intelligence (Prompt 19)
# ============================================================

# --- Provider detection rules ---

_PROVIDER_MX_PATTERNS: List[Tuple[str, str, str]] = [
    # (substring in MX host, provider_id, category)
    (".google.com", "google_workspace", "mailbox"),
    (".googlemail.com", "google_workspace", "mailbox"),
    (".mail.protection.outlook.com", "microsoft_365", "mailbox"),
    (".pphosted.com", "proofpoint", "gateway"),
    (".mimecast.com", "mimecast", "gateway"),
    (".barracudanetworks.com", "barracuda", "gateway"),
    (".zoho.com", "zoho", "mailbox"),
    (".protonmail.ch", "protonmail", "mailbox"),
    (".fastmail.com", "fastmail", "mailbox"),
]

_PROVIDER_SPF_PATTERNS: List[Tuple[str, str, str]] = [
    ("include:_spf.google.com", "google_workspace", "mailbox"),
    ("include:spf.protection.outlook.com", "microsoft_365", "mailbox"),
    ("include:pphosted.com", "proofpoint", "gateway"),
    ("include:_netblocks.mimecast.com", "mimecast", "gateway"),
    ("include:spf.barracudanetworks.com", "barracuda", "gateway"),
    ("include:zoho.com", "zoho", "mailbox"),
    ("include:_spf.protonmail.ch", "protonmail", "mailbox"),
    ("include:spf.messagingengine.com", "fastmail", "mailbox"),
    ("include:amazonses.com", "amazon_ses", "sending"),
    # Sending services
    ("include:sendgrid.net", "sendgrid", "sending"),
    ("include:servers.mcsv.net", "mailchimp", "sending"),
    ("include:mailgun.org", "mailgun", "sending"),
    ("include:mandrillapp.com", "mandrill", "sending"),
    ("include:hubspot.com", "hubspot", "sending"),
    ("include:_spf.salesforce.com", "salesforce", "sending"),
    ("include:mail.zendesk.com", "zendesk", "sending"),
    ("include:email.freshdesk.com", "freshdesk", "sending"),
    ("include:ccsend.com", "constant_contact", "sending"),
    ("include:_spf.createsend.com", "campaign_monitor", "sending"),
]

_PROVIDER_DKIM_SELECTORS: Dict[str, Tuple[str, str]] = {
    "google": ("google_workspace", "mailbox"),
    "selector1": ("microsoft_365", "mailbox"),
    "selector2": ("microsoft_365", "mailbox"),
    "s1": ("sendgrid", "sending"),
    "s2": ("sendgrid", "sending"),
    "k1": ("mailchimp", "sending"),
    "mandrill": ("mandrill", "sending"),
    "hubspot": ("hubspot", "sending"),
    "salesforce": ("salesforce", "sending"),
    "zendesk1": ("zendesk", "sending"),
    "zendesk2": ("zendesk", "sending"),
    "protonmail": ("protonmail", "mailbox"),
    "fm1": ("fastmail", "mailbox"),
    "fm2": ("fastmail", "mailbox"),
    "fm3": ("fastmail", "mailbox"),
}

_PROVIDER_META: Dict[str, Dict] = {
    "google_workspace": {
        "name": "Google Workspace",
        "category": "mailbox",
        "badge_class": "pi-badge-google",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": True,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": False,
            "bimi": True,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Google Workspace supports 2048-bit DKIM. Enable in "
                    "Admin Console > Apps > Google Workspace > Gmail > Authenticate Email."
                ),
            },
            {
                "topic": "DMARC",
                "text": (
                    "Google recommends setting up rua= first, monitoring for 2 weeks, "
                    "then moving to enforcement."
                ),
            },
            {
                "topic": "Known issue",
                "text": (
                    "Google rewrites the envelope sender for forwarded mail, which can "
                    "break SPF alignment. DKIM is the more reliable alignment mechanism."
                ),
            },
        ],
    },
    "microsoft_365": {
        "name": "Microsoft 365",
        "category": "mailbox",
        "badge_class": "pi-badge-microsoft",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": True,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": True,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Enable DKIM signing in Microsoft 365 Defender > "
                    "Email Authentication > DKIM. Both selector1 and selector2 "
                    "should be published."
                ),
            },
            {
                "topic": "DMARC",
                "text": (
                    "Microsoft DMARC reporting can be configured in the "
                    "Microsoft 365 admin center."
                ),
            },
            {
                "topic": "Known issue",
                "text": (
                    "Microsoft 365 uses selector1 and selector2 DKIM selectors. "
                    "Both must be rotated when key rotation is needed."
                ),
            },
        ],
    },
    "proofpoint": {
        "name": "Proofpoint",
        "category": "gateway",
        "badge_class": "pi-badge-proofpoint",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": True,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "Gateway",
                "text": (
                    "Proofpoint acts as a mail gateway. DMARC alignment depends on "
                    "Proofpoint's configuration of envelope sender and DKIM signing."
                ),
            },
            {
                "topic": "SPF efficiency",
                "text": (
                    "Proofpoint's macro-based SPF "
                    "(%{ir}.%{v}.%{d}.spf.has.pphosted.com) is efficient, "
                    "using only 1 DNS lookup regardless of IP count."
                ),
            },
        ],
    },
    "mimecast": {
        "name": "Mimecast",
        "category": "gateway",
        "badge_class": "pi-badge-mimecast",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": True,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "Gateway",
                "text": (
                    "Mimecast acts as a mail gateway. Ensure DKIM signing is "
                    "configured in Mimecast to maintain alignment through the gateway."
                ),
            },
        ],
    },
    "barracuda": {
        "name": "Barracuda",
        "category": "gateway",
        "badge_class": "pi-badge-barracuda",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "Gateway",
                "text": (
                    "Barracuda acts as a mail gateway. Verify DKIM signing "
                    "is configured to preserve alignment."
                ),
            },
        ],
    },
    "zoho": {
        "name": "Zoho Mail",
        "category": "mailbox",
        "badge_class": "pi-badge-zoho",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": False,
            "bimi": True,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Zoho supports 2048-bit DKIM. Enable in Zoho Mail Admin > "
                    "Email Authentication > DKIM."
                ),
            },
        ],
    },
    "protonmail": {
        "name": "ProtonMail",
        "category": "mailbox",
        "badge_class": "pi-badge-protonmail",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": False,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "ProtonMail automatically manages DKIM signing with "
                    "2048-bit keys for custom domains."
                ),
            },
        ],
    },
    "fastmail": {
        "name": "Fastmail",
        "category": "mailbox",
        "badge_class": "pi-badge-fastmail",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": True,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": False,
            "bimi": True,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Fastmail automatically manages DKIM keys (fm1, fm2, fm3 selectors) "
                    "and supports automatic key rotation."
                ),
            },
        ],
    },
    "amazon_ses": {
        "name": "Amazon SES",
        "category": "sending",
        "badge_class": "pi-badge-ses",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Amazon SES uses Easy DKIM with automatic 2048-bit key rotation. "
                    "Enable in SES Console > Verified Identities > Authentication."
                ),
            },
        ],
    },
    "sendgrid": {
        "name": "SendGrid",
        "category": "sending",
        "badge_class": "pi-badge-sendgrid",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "SendGrid supports automated domain authentication with DKIM. "
                    "Configure in Settings > Sender Authentication."
                ),
            },
        ],
    },
    "mailchimp": {
        "name": "Mailchimp",
        "category": "sending",
        "badge_class": "pi-badge-mailchimp",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Mailchimp requires custom DKIM (k1 selector) for authenticated "
                    "sending. Set up in Account > Domains > Verify."
                ),
            },
        ],
    },
    "mailgun": {
        "name": "Mailgun",
        "category": "sending",
        "badge_class": "pi-badge-mailgun",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "mandrill": {
        "name": "Mandrill",
        "category": "sending",
        "badge_class": "pi-badge-mandrill",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "hubspot": {
        "name": "HubSpot",
        "category": "sending",
        "badge_class": "pi-badge-hubspot",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "salesforce": {
        "name": "Salesforce",
        "category": "sending",
        "badge_class": "pi-badge-salesforce",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "zendesk": {
        "name": "Zendesk",
        "category": "sending",
        "badge_class": "pi-badge-zendesk",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "freshdesk": {
        "name": "Freshdesk",
        "category": "sending",
        "badge_class": "pi-badge-freshdesk",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "constant_contact": {
        "name": "Constant Contact",
        "category": "sending",
        "badge_class": "pi-badge-constantcontact",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "campaign_monitor": {
        "name": "Campaign Monitor",
        "category": "sending",
        "badge_class": "pi-badge-campaignmonitor",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
}

_CATEGORY_LABELS = {
    "mailbox": "Email Provider",
    "gateway": "Security Gateway",
    "sending": "Sending Service",
}

_FEATURE_LABELS = {
    "dkim_2048": "DKIM 2048-bit",
    "dkim_auto_rotation": "DKIM auto-rotation",
    "arc": "ARC (forwarding)",
    "mta_sts": "MTA-STS",
    "tls_rpt": "TLS-RPT",
    "dane": "DANE",
    "bimi": "BIMI",
}


def _detect_providers(raw_results: Dict) -> Dict[str, Dict]:
    """Detect email providers from MX, SPF, and DKIM data.

    Returns dict of provider_id -> {source: set of detection sources}.
    """
    detected: Dict[str, Dict] = {}

    def _add(pid: str, source: str, category: str):
        if pid not in detected:
            detected[pid] = {"sources": set(), "category": category}
        detected[pid]["sources"].add(source)

    # MX records
    mx_raw = raw_results.get("mx", {})
    mx_records = mx_raw.get("records", []) or []
    for rec in mx_records:
        host = rec.split()[-1].lower() if rec else ""
        for pattern, pid, cat in _PROVIDER_MX_PATTERNS:
            if pattern in host:
                _add(pid, "MX", cat)

    # SPF record
    spf_raw = raw_results.get("spf", {})
    spf_record = (spf_raw.get("record") or "").lower()
    for pattern, pid, cat in _PROVIDER_SPF_PATTERNS:
        if pattern in spf_record:
            _add(pid, "SPF", cat)

    # Also check for Proofpoint macro-based SPF
    if "pphosted.com" in spf_record:
        _add("proofpoint", "SPF", "gateway")

    # DKIM selectors
    dkim_raw = raw_results.get("dkim", {})
    found_selectors = dkim_raw.get("found_selectors", []) or []
    for sel in found_selectors:
        sel_name = (sel.get("selector") or "").lower()
        if sel_name in _PROVIDER_DKIM_SELECTORS:
            pid, cat = _PROVIDER_DKIM_SELECTORS[sel_name]
            _add(pid, "DKIM", cat)
        # Amazon SES pattern: selectors containing "ses"
        if "ses" in sel_name and "amazon_ses" not in detected:
            _add("amazon_ses", "DKIM", "sending")

    return detected


def _check_domain_features(raw_results: Dict, checks: List[Dict]) -> Dict[str, str]:
    """Check which security features the domain has enabled.

    Returns feature_id -> "yes" | "no" | "unknown".
    """
    result = {}
    check_map = {(c.get("name") or "").upper(): c for c in checks}

    # DKIM 2048-bit: check if any found key is >= 2048 bits
    dkim_raw = raw_results.get("dkim", {})
    found_selectors = dkim_raw.get("found_selectors", []) or []
    has_2048 = False
    has_any_dkim = bool(found_selectors)
    for sel in found_selectors:
        rec = sel.get("record", "")
        if rec:
            analysis = analyze_dkim_key_strength(rec)
            if analysis.get("key_bits", 0) >= 2048:
                has_2048 = True
                break
    if has_any_dkim:
        result["dkim_2048"] = "yes" if has_2048 else "no"
    else:
        result["dkim_2048"] = "unknown"

    # DKIM auto-rotation: cannot determine from DNS alone
    result["dkim_auto_rotation"] = "unknown"

    # ARC: cannot determine from DNS alone (header-based)
    result["arc"] = "n/a"

    # MTA-STS
    mta_sts_check = check_map.get("MTA-STS", {})
    mta_sts_status = mta_sts_check.get("status", "")
    if mta_sts_status == "pass":
        result["mta_sts"] = "yes"
    elif mta_sts_status in ("fail", "warn"):
        result["mta_sts"] = "no"
    else:
        result["mta_sts"] = "unknown"

    # TLS-RPT
    tls_rpt_check = check_map.get("TLS-RPT", {})
    tls_rpt_status = tls_rpt_check.get("status", "")
    if tls_rpt_status == "pass":
        result["tls_rpt"] = "yes"
    elif tls_rpt_status in ("fail", "warn"):
        result["tls_rpt"] = "no"
    else:
        result["tls_rpt"] = "unknown"

    # DANE
    dane_check = check_map.get("DANE", {})
    dane_status = dane_check.get("status", "")
    if dane_status == "pass":
        result["dane"] = "yes"
    elif dane_status in ("fail", "warn"):
        result["dane"] = "no"
    else:
        result["dane"] = "unknown"

    # BIMI
    bimi_check = check_map.get("BIMI", {})
    bimi_status = bimi_check.get("status", "")
    if bimi_status == "pass":
        result["bimi"] = "yes"
    elif bimi_status in ("fail", "warn"):
        result["bimi"] = "no"
    else:
        result["bimi"] = "unknown"

    return result


def _build_provider_intelligence(
    raw_results: Dict, checks: List[Dict]
) -> Optional[Dict]:
    """Build provider intelligence data for the frontend.

    Identifies what email platform/provider the domain uses and provides
    provider-specific guidance, detection sources, and a security scorecard.

    Returns None if no providers are detected.
    """
    detected = _detect_providers(raw_results)
    if not detected:
        return None

    domain_features = _check_domain_features(raw_results, checks)

    # Separate into primary (mailbox/gateway) and sending services
    primary_providers = []
    sending_services = []

    for pid, info in detected.items():
        meta = _PROVIDER_META.get(pid)
        if not meta:
            continue

        category = meta["category"]
        sources = sorted(info["sources"])

        # Build scorecard for this provider
        scorecard = []
        caps = meta.get("capabilities", {})
        for feat_id, feat_label in _FEATURE_LABELS.items():
            provider_supports = caps.get(feat_id, False)
            domain_status = domain_features.get(feat_id, "unknown")

            scorecard.append({
                "feature": feat_label,
                "provider_supports": provider_supports,
                "domain_status": domain_status,
            })

        provider_data = {
            "id": pid,
            "name": meta["name"],
            "category": category,
            "category_label": _CATEGORY_LABELS.get(category, category),
            "badge_class": meta.get("badge_class", ""),
            "detected_via": sources,
            "guidance": meta.get("guidance", []),
            "scorecard": scorecard,
        }

        if category in ("mailbox", "gateway"):
            primary_providers.append(provider_data)
        else:
            sending_services.append(provider_data)

    if not primary_providers and not sending_services:
        return None

    # Detect gateway + upstream pattern (e.g., Proofpoint + Google Workspace)
    gateway_upstream = None
    gateways = [p for p in primary_providers if p["category"] == "gateway"]
    mailboxes = [p for p in primary_providers if p["category"] == "mailbox"]
    if gateways and mailboxes:
        gateway_upstream = {
            "gateway": gateways[0]["name"],
            "upstream": mailboxes[0]["name"],
            "note": (
                f"{gateways[0]['name']} is routing mail to {mailboxes[0]['name']}. "
                f"DKIM signing and SPF alignment must be configured at both layers."
            ),
        }

    return {
        "primary_providers": primary_providers,
        "sending_services": sending_services,
        "gateway_upstream": gateway_upstream,
    }
