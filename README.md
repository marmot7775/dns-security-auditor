# DNS Security Audit

**Built by [Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** · [GitHub](https://github.com/marmot7775)

---

A comprehensive DNS security auditing tool that analyzes domain configurations for email authentication, security policies, and DNS best practices.

**Live at [dns-audit.com](https://dns-audit.com)**

## What It Does

Enter any domain and get a detailed security audit covering:

- **DMARC** — Policy analysis with full DNS Tree Walk per the latest [DMARCbis](https://datatracker.ietf.org/doc/draft-ietf-dmarc-DMARCbis/) standard (Section 4.10), showing exactly how policy discovery traverses the DNS hierarchy
- **SPF** — Record validation, mechanism analysis, and lookup count verification
- **DKIM** — Selector discovery across major ESPs and common patterns, key analysis, and rotation age estimation
- **MX** — Mail server identification, vendor fingerprinting, and configuration checks
- **MTA-STS** — Policy file validation and mode analysis
- **TLS-RPT** — TLS reporting record verification
- **BIMI** — Brand indicator record detection and validation
- **DNSSEC** — Signature validation status

Each check produces a pass/warn/fail status with plain-English explanations, detailed findings, and actionable recommendations. Results are scored and graded A through F.

## DMARC DNS Tree Walk

One of the more interesting features is the animated DMARC DNS Tree Walk visualization. Per DMARCbis Section 4.10, DMARC policy discovery doesn't just check the exact domain — it walks up the DNS tree, stripping labels from left to right, to find an organizational or public suffix domain policy. The tool visualizes each step of this process, showing which domains were queried, what was found, and which policy ultimately applies.

## API

The tool exposes a simple REST API:

```
GET /api/audit?domain=example.com
GET /api/health
```

## Author

**[Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** — DNS, email security, and deliverability specialist

[LinkedIn](https://www.linkedin.com/in/neilanuskiewicz/) · [GitHub](https://github.com/marmot7775)
