"""
DNS Security Auditor - Core DNS Tools
======================================
Domain normalization and audit entry point.
"""

from typing import Any, Dict, Optional

import idna

from audit_engine import run_full_audit


def normalize_domain(value: str) -> str:
    """Normalize a user-supplied string into a bare domain name.

    Handles URLs, email addresses, trailing dots, ports, and IDN domains.
    """
    if not value:
        return ""
    domain = str(value).strip().lower()
    if "@" in domain:
        domain = domain.split("@")[-1]
    domain = (
        domain.removeprefix("http://")
        .removeprefix("https://")
    )
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    # Strip port (e.g. example.com:443)
    if ":" in domain:
        domain = domain.rsplit(":", 1)[0]
    domain = domain.rstrip(".")
    # IDNA2008 (multi-label aware). Leave invalid input for downstream rejection.
    try:
        domain = idna.encode(domain).decode("ascii")
    except idna.IDNAError:
        pass
    return domain


def audit_dns_security(
    domain: str,
    *,
    dkim_selector: Optional[str] = None,
    scope: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a full audit via audit_engine.

    Parameters
    ----------
    domain : str
        The domain to audit (will be normalized).
    dkim_selector : str | None
        A specific DKIM selector to test.
    scope : str | None
        Audit scope (e.g. "email_full", "dmarc"). None = complete.
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

    return run_full_audit(domain, dkim_selector=dkim_selector, scope=scope)
