"""
DNS Security Auditor - Core DNS Tools
======================================
Domain normalization and audit entry point.
"""

from typing import Any, Dict, Optional

from audit_engine import run_full_audit


def normalize_domain(value: str) -> str:
    """Normalize a user-supplied string into a bare domain name."""
    if not value:
        return ""
    domain = str(value).strip().lower()
    if "@" in domain:
        domain = domain.split("@")[-1]
    domain = (
        domain.removeprefix("http://")
        .removeprefix("https://")
        .removeprefix("www.")
    )
    return domain.split("/")[0].split("?")[0].rstrip(".")


def audit_dns_security(
    domain: str,
    *,
    dkim_selector: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a full audit via audit_engine.

    Parameters
    ----------
    domain : str
        The domain to audit (will be normalized).
    dkim_selector : str | None
        A specific DKIM selector to test.
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

    return run_full_audit(domain, dkim_selector=dkim_selector)
