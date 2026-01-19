#!/usr/bin/env python3
"""
DNS Security Auditor - Command Line Interface
Usage: PYTHONPATH=src python3 cli.py <domain> [--scope email|dns] [--output full|summary] [--selectors s1,s2]
"""

import argparse
import json
import sys

from dns_security_auditor.dns_tools import (
    audit_email_security,
    audit_dns_security,
    format_report,
    normalize_domain,
)


def main():
    parser = argparse.ArgumentParser(
        description="DNS Security Auditor - Check email and DNS security configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  PYTHONPATH=src python3 cli.py example.com
  PYTHONPATH=src python3 cli.py example.com --scope dns
  PYTHONPATH=src python3 cli.py example.com --output summary
  PYTHONPATH=src python3 cli.py example.com --scope email --selectors google,selector1,selector2
  PYTHONPATH=src python3 cli.py example.com --json
        """,
    )

    parser.add_argument("domain", help="Domain to audit (e.g., example.com)")

    parser.add_argument(
        "--scope",
        "-s",
        choices=["email", "dns"],
        default="email",
        help="Audit scope: 'email' or 'dns' (full DNS security). Default: email",
    )

    parser.add_argument(
        "--output",
        "-o",
        choices=["full", "summary"],
        default="full",
        help="Output format: 'full' (detailed) or 'summary' (brief). Default: full",
    )

    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Output raw JSON instead of formatted report",
    )

    parser.add_argument(
        "--selectors",
        default="",
        help="Comma-separated DKIM selectors to check (e.g., google,selector1,selector2)",
    )

    args = parser.parse_args()

    # Normalize and validate domain
    domain = normalize_domain(args.domain)
    if not domain or "." not in domain:
        print(f"Error: Invalid domain '{args.domain}'", file=sys.stderr)
        sys.exit(1)

    # Parse DKIM selectors
    dkim_selectors = [s.strip() for s in (args.selectors or "").split(",") if s.strip()]

    # Run audit
    try:
        if args.scope == "dns":
            results = audit_dns_security(domain, dkim_selectors=dkim_selectors)
        else:
            results = audit_email_security(domain, dkim_selectors=dkim_selectors)
    except KeyboardInterrupt:
        print("\nAudit cancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error auditing {domain}: {e}", file=sys.stderr)
        sys.exit(1)

    # Output results
    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print(format_report(results, args.output))


if __name__ == "__main__":
    main()