# DNS Security Auditor

**Built by [Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** | [dns-audit.com](https://dns-audit.com)

A full-stack DNS and email security auditing platform. Enter any domain and get a detailed security assessment with a letter grade, actionable findings, copy-paste DNS fix records, and a downloadable PDF report.

Built for IT professionals, email administrators, and security consultants who need to evaluate a domain's email authentication posture and DNS security configuration quickly and accurately.

## 13 Security Checks

| Check | What It Audits |
|-------|---------------|
| **DMARC** | Policy strength, tag analysis, reporting configuration, DMARCbis compliance. Includes animated DNS Tree Walk visualization per [DMARCbis Section 4.10](https://datatracker.ietf.org/doc/draft-ietf-dmarc-DMARCbis/) showing policy inheritance across the domain hierarchy. |
| **SPF** | Record syntax, `all` mechanism qualifier, recursive lookup counting against the RFC 7208 10-lookup limit, include chain analysis. |
| **DKIM** | Intelligent selector discovery using SPF-based vendor fingerprinting and common patterns. Key strength analysis (RSA/Ed25519), rotation age estimation. |
| **MX Records** | Mail server identification, vendor fingerprinting, forward-confirmed reverse DNS (FCrDNS) validation, redundancy assessment. |
| **MTA-STS** | TXT record validation, HTTPS policy file fetch and parse, mode analysis (enforce/testing/none). |
| **TLS-RPT** | SMTP TLS Reporting record verification, report destination validation. |
| **BIMI** | Brand indicator record detection, SVG logo URL validation, VMC certificate requirements. |
| **DNSSEC** | DNSKEY presence, DS record validation against parent zone, signing verification. |
| **CAA** | Certificate Authority Authorization records, issuer restrictions, incident reporting (iodef). |
| **DANE** | TLSA record lookup for each MX host, usage/selector/matching type analysis. |
| **Nameservers** | NS count, resolution verification, IPv6 support, network diversity across /24 ranges, provider identification. |
| **Certificate Transparency** | CT log lookup via crt.sh for issued certificates. |
| **Blacklist** | MX IP reputation check against 6 DNS-based blocklists plus Spamhaus DBL domain check. |

Every check produces a pass/warn/fail status with a plain-English explanation, detailed findings, and a recommended fix. Results are weighted and scored 0-100 with a letter grade (A through F).

## Key Features

### Fix It For Me

Failing checks include copy-paste-ready DNS records. Instead of just telling you what's wrong, the tool generates the exact TXT, CAA, or TLSA record you need to add, with the correct host, value, and format for your domain.

### DMARC DNS Tree Walk

DMARC policy discovery doesn't just check the exact domain. Per the DMARCbis specification, it walks up the DNS tree, stripping labels from left to right, looking for an organizational or public suffix domain policy. The tool visualizes each step of this process with an animated timeline showing which domains were queried, what was found, and which policy ultimately applies.

Try it with a subdomain like `mail.google.com` or `support.microsoft.com` to see the full tree walk in action.

### PDF Audit Report

One-click download of a professional PDF report with an executive summary page (grade, score, priority fixes, detected vendors) followed by detailed check cards. Designed to be shared with clients, management, or IT teams.

### Scoped Audits

Six audit scopes let you run only the checks you need:
- **Complete Audit** -- all 13 checks
- **Email Security** -- DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI
- **DMARC Check** -- DMARC-only deep dive with tree walk
- **Transport Security** -- MTA-STS, TLS-RPT, DANE, MX
- **DNS Infrastructure** -- DNSSEC, CAA, DANE, Nameservers, CT
- **Security Scan** -- DMARC, SPF, DKIM, DNSSEC, DANE, CT, Blacklist

### Vendor Detection

Identifies email service providers (Google Workspace, Microsoft 365, Proofpoint, Mimecast, etc.) from MX records, SPF includes, and DKIM selectors. Confidence scores indicate detection certainty.

## Architecture

Single-page application with a FastAPI backend. No database, no user accounts, no tracking.

```
static/
  index.html          Frontend (single HTML page)
  app.js              Result rendering, tree walk visualization, scoped audits
  style.css           Design tokens, responsive layout, animations

server.py             FastAPI app, rate limiting, caching, PDF endpoint
audit_engine.py       Check orchestration, parallel execution with timeouts
result_transformer.py Raw results -> frontend cards (verdict, explanation, fix)
security_scoring.py   Weighted scoring and letter grading
pdf_report.py         FPDF2-based branded PDF generation
dmarc_tree_walk.py    DMARCbis Section 4.10 tree walk algorithm
spf_recursive.py      Recursive SPF lookup counter
checks_extra.py       MTA-STS, TLS-RPT, BIMI, DKIM checks
dns_tools.py          Low-level DNS query functions
```

### How Scoring Works

Email authentication checks carry the most weight: DMARC (30 points), SPF (25 points), DKIM (20 points). These three alone determine 75% of the score. MX, MTA-STS, and TLS-RPT make up the remaining 25 points. Infrastructure checks (DNSSEC, CAA, DANE, etc.) affect the letter grade display but not the numeric score, since many well-configured domains reasonably omit them.

## API

```
GET /api/audit?domain=example.com          Full audit (JSON)
GET /api/audit?domain=example.com&nocache=true  Bypass cache
GET /api/audit/pdf?domain=example.com      PDF report download
GET /api/health                            Health check
GET /docs                                  Interactive API docs (Swagger)
```

Rate limited to 10 requests per IP per minute. Results are cached for 5 minutes.

## Self-Hosting

Requirements: Python 3.10+, no external services or databases.

```bash
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8000
```

The application resolves DNS records directly using dnspython. No API keys or third-party DNS services required.

## Tech Stack

- **Backend**: Python, FastAPI, dnspython, FPDF2
- **Frontend**: Vanilla JavaScript, CSS custom properties, no frameworks
- **Fonts**: DM Sans (body), JetBrains Mono (DNS records)
- **Hosting**: DigitalOcean droplet, Cloudflare DNS/CDN

## Author

**[Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** -- DNS, email security, and deliverability specialist.

[LinkedIn](https://www.linkedin.com/in/neilanuskiewicz/) | [GitHub](https://github.com/marmot7775) | [dns-audit.com](https://dns-audit.com)
