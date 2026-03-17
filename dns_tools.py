"""
DNS Security Auditor - Core DNS Tools
======================================
Provides domain normalization, DNS lookups, and audit entry points.
Used by both cli.py and the web frontend.
"""

import dns.resolver
from datetime import datetime
from typing import Any, Dict, List, Optional

from audit_engine import run_full_audit


# ============================================================
# Helpers
# ============================================================

def normalize_domain(value: str) -> str:
    """Normalize a user-supplied string into a bare domain name."""
    if not value:
        return ""
    domain = str(value).strip().lower()
    if "@" in domain:
        domain = domain.split("@")[-1]
    domain = (
        domain.replace("http://", "")
        .replace("https://", "")
        .replace("www.", "")
    )
    return domain.split("/")[0].split("?")[0].rstrip(".")


def _get_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def _lookup_txt(name: str) -> List[str]:
    """Return all TXT record strings for *name*."""
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(name, "TXT")
        return [
            "".join(
                p.decode("utf-8") if isinstance(p, bytes) else str(p)
                for p in rdata.strings
            )
            for rdata in answers
        ]
    except Exception:
        return []


# ============================================================
# Audit scopes
# ============================================================

SCOPE_DMARC = "dmarc"
SCOPE_TRANSPORT = "transport"
SCOPE_EMAIL = "email"
SCOPE_DNS = "dns"
SCOPE_SECURITY = "security"
SCOPE_COMPLETE = "complete"

SCOPE_LABELS = {
    SCOPE_DMARC: "DMARC Check",
    SCOPE_TRANSPORT: "Transport Security",
    SCOPE_EMAIL: "Email Security (Full)",
    SCOPE_DNS: "DNS Infrastructure",
    SCOPE_SECURITY: "Security Scan",
    SCOPE_COMPLETE: "Complete Audit",
}

# Which result-transformer check names belong to each scope
SCOPE_CHECKS: Dict[str, List[str]] = {
    SCOPE_DMARC: ["DMARC"],
    SCOPE_TRANSPORT: ["MTA-STS", "TLS-RPT", "DANE"],
    SCOPE_EMAIL: ["DMARC", "SPF", "DKIM", "MX Records", "MTA-STS", "TLS-RPT", "BIMI"],
    SCOPE_DNS: ["DNSSEC", "CAA", "Nameservers", "DANE"],
    SCOPE_SECURITY: ["DMARC", "SPF", "DKIM", "MX Records", "DNSSEC", "CAA", "DANE"],
    SCOPE_COMPLETE: [],  # empty = show everything
}


# ============================================================
# Main audit entry point
# ============================================================

def audit_dns_security(
    domain: str,
    *,
    scope: str = SCOPE_COMPLETE,
    dkim_selectors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run a full audit via audit_engine, then filter by *scope*.

    Parameters
    ----------
    domain : str
        The domain to audit (will be normalized).
    scope : str
        One of the SCOPE_* constants.  Controls which check cards are
        returned in ``result["checks"]``.
    dkim_selectors : list[str] | None
        Extra DKIM selectors to test in addition to the built-in list.
        Passed through to the DKIM discovery layer (future use).
    """
    domain = normalize_domain(domain)
    if not domain:
        return {
            "domain": "",
            "error": "Empty domain after normalization",
            "checks": [],
            "priority_fixes": [],
            "score": {"total": 0, "grade": "?"},
        }

    result = run_full_audit(domain, dkim_selectors=dkim_selectors)

    # Filter checks by scope
    allowed = SCOPE_CHECKS.get(scope, [])
    if allowed:
        result["checks"] = [
            c for c in result.get("checks", [])
            if c.get("name") in allowed
        ]

    return result


# ============================================================
# Plain-text report formatter
# ============================================================

def format_report(results: Dict[str, Any], output_format: str = "full") -> str:
    """Render a plain-text report from audit results."""
    domain = results.get("domain", "unknown")
    score = results.get("score", {})
    lines = [
        "=" * 60,
        f"DNS Security Audit: {domain}",
        f"Grade: {score.get('grade', '?')}  Score: {score.get('total', 0)}/100",
        f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
        "=" * 60,
        "",
    ]

    STATUS_ICON = {"pass": "\u2705", "warn": "\u26a0\ufe0f ", "fail": "\ud83d\udd34"}

    for check in results.get("checks", []):
        icon = STATUS_ICON.get(check.get("status"), "\u2753")
        lines.append(f"{icon} {check['name']}")
        lines.append("-" * 40)

        if check.get("verdict"):
            lines.append(f"  {check['verdict']}")
        if check.get("record") and output_format == "full":
            lines.append(f"  Record: {check['record'][:120]}")

        for d in check.get("details", []):
            prefix = {"error": "  \u2717", "warning": "  \u26a0", "good": "  \u2713", "info": "  \u2139"}.get(d["type"], "  \u2022")
            lines.append(f"{prefix} {d['text']}")

        if check.get("fix") and output_format == "full":
            import re as _re
            fix_plain = _re.sub(r"<[^>]+>", "", check["fix"])
            lines.append(f"  \u2192 {fix_plain}")

        lines.append("")

    pf = results.get("priority_fixes", [])
    if pf:
        lines.append("=" * 60)
        lines.append("PRIORITY FIXES (in order):")
        lines.append("=" * 60)
        for i, fix in enumerate(pf, 1):
            lines.append(f"  {i}. {fix}")
        lines.append("")

    return "\n".join(lines)
