"""
Result Transformer
==================
Converts raw audit module outputs into uniform card format for frontend.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from dkim_formatter import analyze_dkim_key_strength
except ImportError:
    def analyze_dkim_key_strength(record):
        return {"key_size": "unknown", "is_strong": True}


# ============================================================
# Helper functions
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
# Transform functions
# ============================================================

def transform_dmarc(raw: Dict) -> Dict:
    """Transform DMARC audit result"""
    status = _map_status(raw.get("status", "error"))
    policy = raw.get("policy", "")
    record = raw.get("record")

    # Build verdict
    if not record:
        verdict = "No DMARC record found"
        pill_label = "Missing"
    elif policy == "reject":
        verdict = "Policy: reject (strongest)"
        pill_label = None
    elif policy == "quarantine":
        pct = raw.get("pct", 100)
        verdict = f"Policy: quarantine"
        if pct and pct < 100:
            verdict += f" ({pct}%)"
        pill_label = None
    elif policy == "none":
        verdict = "Policy: none (monitoring only)"
        pill_label = None
    else:
        verdict = f"Policy: {policy}" if policy else "Invalid record"
        pill_label = None

    # Details
    details = [_issue_to_detail(iss) for iss in raw.get("issues", [])]

    return {
        "name": "DMARC",
        "status": status,
        "pill_label": pill_label,
        "verdict": verdict,
        "record": record or "",
        "explanation": raw.get("explanation", ""),
        "details": details,
        "fix": _first_fix(raw.get("issues", []))
    }


def transform_spf(raw: Dict) -> Dict:
    """Transform SPF audit result"""
    status = _map_status(raw.get("status", "error"))
    record = raw.get("record", "")
    lookups = raw.get("dns_lookups", 0)

    if not record:
        verdict = "No SPF record found"
    elif lookups > 10:
        verdict = f"SPF record found ({lookups} DNS lookups - over limit!)"
    elif lookups >= 8:
        verdict = f"SPF record found ({lookups}/10 DNS lookups)"
    else:
        verdict = f"SPF record found ({lookups} DNS lookups)"

    details = [_issue_to_detail(iss) for iss in raw.get("issues", [])]

    return {
        "name": "SPF",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": raw.get("explanation", ""),
        "details": details,
        "fix": _first_fix(raw.get("issues", []))
    }


def transform_dkim(raw: Dict, domain: str) -> Dict:
    """Transform DKIM audit result"""
    status = _map_status(raw.get("status", "error"))
    selectors = raw.get("found_selectors", [])

    if not selectors:
        verdict = "No DKIM selectors found"
    elif len(selectors) == 1:
        verdict = f"1 DKIM selector found"
    else:
        verdict = f"{len(selectors)} DKIM selectors found"

    details = [_issue_to_detail(iss) for iss in raw.get("issues", [])]

    return {
        "name": "DKIM",
        "status": status,
        "verdict": verdict,
        "explanation": raw.get("explanation", ""),
        "details": details,
        "fix": _first_fix(raw.get("issues", []))
    }


def transform_mx(raw: Dict) -> Dict:
    """Transform MX audit result"""
    status = _map_status(raw.get("status", "error"))
    mx_records = raw.get("mx_records", [])

    if not mx_records:
        verdict = "No MX records found"
    elif len(mx_records) == 1:
        verdict = f"1 MX record found"
    else:
        verdict = f"{len(mx_records)} MX records found"

    details = [_issue_to_detail(iss) for iss in raw.get("issues", [])]

    return {
        "name": "MX",
        "status": status,
        "verdict": verdict,
        "explanation": raw.get("explanation", ""),
        "details": details,
        "fix": _first_fix(raw.get("issues", []))
    }


def transform_mta_sts(raw: Dict, domain: str) -> Dict:
    """Transform MTA-STS audit result"""
    status = _map_status(raw.get("status", "error"))
    has_txt = raw.get("txt_record") is not None
    has_policy = raw.get("policy") is not None

    if has_txt and has_policy:
        verdict = "MTA-STS enabled"
    elif has_txt:
        verdict = "MTA-STS TXT record found, but policy fetch failed"
    else:
        verdict = "MTA-STS not configured"

    details = [_issue_to_detail(iss) for iss in raw.get("issues", [])]

    return {
        "name": "MTA-STS",
        "status": status,
        "verdict": verdict,
        "explanation": raw.get("explanation", ""),
        "details": details,
        "fix": _first_fix(raw.get("issues", []))
    }


def transform_tls_rpt(raw: Dict, domain: str) -> Dict:
    """Transform TLS-RPT audit result"""
    status = _map_status(raw.get("status", "error"))
    record = raw.get("record", "")

    verdict = "TLS-RPT configured" if record else "No TLS-RPT record"
    details = [_issue_to_detail(iss) for iss in raw.get("issues", [])]

    return {
        "name": "TLS-RPT",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": raw.get("explanation", ""),
        "details": details,
        "fix": _first_fix(raw.get("issues", []))
    }


def transform_bimi(raw: Dict, domain: str) -> Dict:
    """Transform BIMI audit result"""
    status = _map_status(raw.get("status", "error"))
    record = raw.get("record", "")

    verdict = "BIMI record found" if record else "No BIMI record"
    details = [_issue_to_detail(iss) for iss in raw.get("issues", [])]

    return {
        "name": "BIMI",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": raw.get("explanation", ""),
        "details": details,
        "fix": _first_fix(raw.get("issues", []))
    }


def transform_dnssec(raw: Dict) -> Dict:
    """Transform DNSSEC audit result"""
    status = _map_status(raw.get("status", "error"))
    is_signed = raw.get("signed", False)

    verdict = "DNSSEC enabled" if is_signed else "DNSSEC not enabled"
    details = [_issue_to_detail(iss) for iss in raw.get("issues", [])]

    return {
        "name": "DNSSEC",
        "status": status,
        "verdict": verdict,
        "explanation": raw.get("explanation", ""),
        "details": details,
        "fix": _first_fix(raw.get("issues", []))
    }


# ============================================================
# Main transform function
# ============================================================

def transform_all(raw_results: Dict, domain: str) -> List[Dict]:
    """Transform all raw audit results into frontend card format"""
    cards = []

    if "dmarc" in raw_results:
        cards.append(transform_dmarc(raw_results["dmarc"]))

    if "spf" in raw_results:
        cards.append(transform_spf(raw_results["spf"]))

    if "dkim" in raw_results:
        cards.append(transform_dkim(raw_results["dkim"], domain))

    if "mx" in raw_results:
        cards.append(transform_mx(raw_results["mx"]))

    if "mta_sts" in raw_results:
        cards.append(transform_mta_sts(raw_results["mta_sts"], domain))

    if "tls_rpt" in raw_results:
        cards.append(transform_tls_rpt(raw_results["tls_rpt"], domain))

    if "bimi" in raw_results:
        cards.append(transform_bimi(raw_results["bimi"], domain))

    if "dnssec" in raw_results:
        cards.append(transform_dnssec(raw_results["dnssec"]))

    return cards


def calculate_security_score(cards: List[Dict]) -> tuple:
    """Calculate overall security grade and score"""
    if not cards:
        return ("F", 0)

    total = 0
    count = 0

    for card in cards:
        count += 1
        status = card.get("status", "fail")
        if status == "pass":
            total += 100
        elif status == "warn":
            total += 60
        else:  # fail
            total += 0

    avg = total / count if count > 0 else 0

    if avg >= 90:
        grade = "A"
    elif avg >= 75:
        grade = "B"
    elif avg >= 60:
        grade = "C"
    elif avg >= 40:
        grade = "D"
    else:
        grade = "F"

    return (grade, avg)
