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
from spf_intelligence import smart_dkim_check, detect_vendors_from_spf
from advanced_fingerprinting import AdvancedVendorFingerprinter
from security_scoring import EmailSecurityScorer
from dkim_formatter import analyze_dkim_key_strength
from dkim_key_age import DKIMKeyAgeAnalyzer
from dkim_tag_analyzer import DKIMTagAnalyzer

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
    """Check DMARC record and parse all tags."""
    result = {
        "check": "DMARC",
        "domain": domain,
        "record": None,
        "policy": None,
        "pct": None,
        "rua": None,
        "ruf": None,
        "sp": None,
        "status": "ok",
        "issues": [],
        "recommendations": [],
    }

    dmarc_recs = _lookup_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in dmarc_recs if r.strip().lower().startswith("v=dmarc1")]

    if not dmarc_records:
        result["status"] = "error"
        result["issues"].append({
            "severity": "error",
            "issue": "No DMARC record found",
            "plain_english": (
                f"No DMARC record exists at '_dmarc.{domain}'. Without DMARC, "
                "anyone can send emails pretending to be from your domain."
            ),
            "fix": (
                f"Add a TXT record at _dmarc.{domain} with: "
                f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; fo=1"
            ),
        })
        return result

    if len(dmarc_records) > 1:
        result["issues"].append({
            "severity": "error",
            "issue": f"Multiple DMARC records found ({len(dmarc_records)})",
            "plain_english": "There should be exactly one DMARC record.",
            "fix": "Remove duplicate DMARC records.",
        })

    record = dmarc_records[0]
    result["record"] = record

    # Parse tags
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()

    result["policy"] = tags.get("p", "").lower()
    result["sp"] = tags.get("sp", "").lower() or None
    result["rua"] = tags.get("rua")
    result["ruf"] = tags.get("ruf")
    try:
        result["pct"] = int(tags.get("pct", 100))
    except (ValueError, TypeError):
        result["pct"] = 100

    # Status based on policy
    policy = result["policy"]
    if policy == "none":
        result["status"] = "warning"
        result["issues"].append({
            "severity": "warning",
            "issue": "DMARC policy is none (monitoring only)",
            "plain_english": "Failed emails are still delivered. No spoofing protection.",
            "fix": "Upgrade to p=quarantine then p=reject after reviewing reports.",
        })
    elif policy == "quarantine":
        pct = result["pct"]
        if pct and pct < 100:
            result["status"] = "warning"
            result["issues"].append({
                "severity": "warning",
                "issue": f"DMARC pct={pct}% (partial enforcement)",
                "plain_english": f"Only {pct}% of failures get quarantined.",
                "fix": "Increase pct to 100.",
            })
    elif policy == "reject":
        pass  # Best state
    elif policy:
        result["status"] = "error"
        result["issues"].append({
            "severity": "error",
            "issue": f"Unknown DMARC policy: {policy}",
            "plain_english": f"Policy '{policy}' is not valid.",
            "fix": "Use p=none, p=quarantine, or p=reject.",
        })

    if not result["rua"]:
        result["issues"].append({
            "severity": "warning",
            "issue": "No aggregate reporting (rua)",
            "plain_english": "You have no visibility into authentication results.",
            "fix": f"Add rua=mailto:dmarc-reports@{domain}",
        })

    # Final status
    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    return result


def _raw_check_spf(domain: str) -> Dict[str, Any]:
    """Check SPF record with lookup counting and mechanism analysis."""
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
        "recommendations": [],
    }

    all_txt = _lookup_txt(domain)
    spf_records = [r for r in all_txt if r.strip().lower().startswith("v=spf1")]

    if not spf_records:
        result["status"] = "error"
        result["issues"].append({
            "severity": "error",
            "issue": "No SPF record found",
            "plain_english": "No SPF record tells receivers which servers can send your email.",
            "fix": f"Add TXT record at {domain}: v=spf1 include:YOUR_PROVIDER -all",
        })
        return result

    if len(spf_records) > 1:
        result["status"] = "error"
        result["issues"].append({
            "severity": "error",
            "issue": f"Multiple SPF records ({len(spf_records)})",
            "plain_english": "RFC 7208 requires exactly one SPF record. Multiple records cause SPF to fail.",
            "fix": "Merge into a single SPF record.",
        })

    record = spf_records[0]
    result["record"] = record

    # Parse mechanisms
    parts = record.split()
    lookup_mechanisms = {"include", "a", "mx", "ptr", "exists", "redirect"}
    lookup_count = 0
    include_count = 0
    ip4_count = 0
    ip6_count = 0
    all_mech = None

    for part in parts:
        part_lower = part.lower()
        if part_lower.startswith("v=spf1"):
            continue

        # Extract mechanism type
        # Strip qualifier (+, -, ~, ?)
        clean = part_lower.lstrip("+-~?")

        if clean.startswith("include:"):
            lookup_count += 1
            include_count += 1
        elif clean.startswith(("a:", "a/")):
            lookup_count += 1
        elif clean == "a":
            lookup_count += 1
        elif clean.startswith(("mx:", "mx/")):
            lookup_count += 1
        elif clean == "mx":
            lookup_count += 1
        elif clean.startswith("ptr"):
            lookup_count += 1
        elif clean.startswith("exists:"):
            lookup_count += 1
        elif clean.startswith("redirect="):
            lookup_count += 1
        elif clean.startswith("ip4:"):
            ip4_count += 1
        elif clean.startswith("ip6:"):
            ip6_count += 1
        elif clean in ("-all", "~all", "?all", "+all", "all"):
            all_mech = part_lower.lstrip("+-~?")
            # Reconstruct with qualifier
            qualifier = part_lower[0] if part_lower[0] in "+-~?" else "+"
            all_mech = qualifier + "all"

    result["lookup_count"] = lookup_count
    result["include_count"] = include_count
    result["ip4_count"] = ip4_count
    result["ip6_count"] = ip6_count
    result["all_mechanism"] = all_mech

    # Issues
    if lookup_count > 10:
        result["status"] = "error"
        result["issues"].append({
            "severity": "error",
            "issue": f"SPF exceeds 10-lookup limit ({lookup_count} lookups)",
            "plain_english": "RFC 7208 limits SPF to 10 DNS lookups. Exceeding this causes SPF to fail entirely.",
            "fix": "Reduce lookups by flattening includes to IP addresses or removing unused services.",
        })
    elif lookup_count == 10:
        result["issues"].append({
            "severity": "warning",
            "issue": "SPF is at the 10-lookup limit",
            "plain_english": "Adding any more includes will break SPF entirely.",
            "fix": "Consider SPF flattening to free up lookup slots.",
        })

    if all_mech == "+all":
        result["status"] = "error"
        result["issues"].append({
            "severity": "error",
            "issue": "SPF uses +all (authorizes everyone)",
            "plain_english": "This authorizes the entire internet to send as your domain.",
            "fix": "Change +all to -all (hard fail) or ~all (soft fail).",
        })
    elif all_mech == "?all":
        result["status"] = "warning"
        result["issues"].append({
            "severity": "warning",
            "issue": "SPF uses ?all (neutral)",
            "plain_english": "Neutral provides no protection against unauthorized senders.",
            "fix": "Change ?all to -all or ~all.",
        })
    elif not all_mech:
        result["issues"].append({
            "severity": "warning",
            "issue": "No 'all' mechanism found",
            "plain_english": "SPF record should end with -all, ~all, or ?all.",
            "fix": "Add -all to the end of the SPF record.",
        })

    # Final status
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

    # --- 3. DKIM (uses SPF intelligence) ---
    try:
        raw_dkim = smart_dkim_check(domain, spf_record)
        raw_results["dkim"] = raw_dkim
        checks.append(transform_dkim(raw_dkim, domain))
    except Exception as e:
        errors.append(f"DKIM: {str(e)}")
        checks.append(_error_card("DKIM", e))

    # --- 4. MX Records ---
    try:
        raw_mx = check_mx(domain)
        raw_results["mx"] = raw_mx
        checks.append(transform_mx(raw_mx))
    except Exception as e:
        errors.append(f"MX: {str(e)}")
        checks.append(_error_card("MX Records", e))

    # --- 5. MTA-STS ---
    try:
        raw_mta_sts = check_mta_sts(domain)
        raw_results["mta_sts"] = raw_mta_sts
        checks.append(transform_mta_sts(raw_mta_sts, domain))
    except Exception as e:
        errors.append(f"MTA-STS: {str(e)}")
        checks.append(_error_card("MTA-STS", e))

    # --- 6. TLS-RPT ---
    try:
        raw_tls_rpt = check_tls_rpt(domain)
        raw_results["tls_rpt"] = raw_tls_rpt
        checks.append(transform_tls_rpt(raw_tls_rpt, domain))
    except Exception as e:
        errors.append(f"TLS-RPT: {str(e)}")
        checks.append(_error_card("TLS-RPT", e))

    # --- 7. BIMI ---
    try:
        raw_bimi = check_bimi(domain)
        raw_results["bimi"] = raw_bimi
        checks.append(transform_bimi(raw_bimi, domain))
    except Exception as e:
        errors.append(f"BIMI: {str(e)}")
        checks.append(_error_card("BIMI", e))

    # --- 8. DNSSEC ---
    try:
        raw_dnssec = _raw_check_dnssec(domain)
        raw_results["dnssec"] = raw_dnssec
        checks.append(transform_dnssec(raw_dnssec))
    except Exception as e:
        errors.append(f"DNSSEC: {str(e)}")
        checks.append(_error_card("DNSSEC", e))

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
    Maximum 5 items, ordered by severity.
    """
    fixes = []

    # Scorer recommendations (already prioritized)
    scorer_recs = score_result.get("recommendations", [])
    for rec in scorer_recs:
        # Strip emoji prefixes for clean display
        clean = re.sub(r'^[^\w]*\s*(?:CRITICAL|HIGH|MEDIUM|LOW):\s*', '', rec)
        if clean and clean not in fixes:
            fixes.append(clean)

    # Check-level fixes (for checks the scorer might miss)
    for check in checks:
        if check.get("status") == "fail" and check.get("fix"):
            # Strip HTML for the priority list
            fix_text = re.sub(r'<[^>]+>', '', check["fix"])
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
