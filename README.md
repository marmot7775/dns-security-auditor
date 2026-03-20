# DNS Security Auditor

**Built by [Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** | [dns-audit.com](https://dns-audit.com)

A full-stack DNS and email security auditing platform. Enter any domain and get a detailed security assessment with a letter grade, actionable findings, copy-paste DNS fix records, and a downloadable PDF report.

Built for IT professionals, email administrators, and security consultants who need to evaluate a domain's email authentication posture and DNS security configuration quickly and accurately.

## 13 Security Checks

| Check | What It Audits |
|-------|---------------|
| **DMARC** | Policy strength, tag analysis, reporting configuration, DMARCbis compliance. Includes animated DNS Tree Walk visualization per [DMARCbis Section 4.10](https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/) showing policy inheritance across the domain hierarchy. |
| **SPF** | Record syntax, `all` mechanism qualifier, recursive lookup counting against the RFC 7208 10-lookup limit, void lookup detection, include chain visualization with per-node cost breakdown. |
| **DKIM** | Intelligent selector discovery using SPF-based vendor fingerprinting and 500+ common selector patterns. Key strength analysis (RSA 1024/2048/4096, Ed25519), rotation age estimation. |
| **MX Records** | Mail server identification, vendor fingerprinting, forward-confirmed reverse DNS (FCrDNS) validation, redundancy assessment, dangling MX detection. |
| **MTA-STS** | TXT record validation, HTTPS policy file fetch and parse, mode analysis (enforce/testing/none). |
| **TLS-RPT** | SMTP TLS Reporting record verification, report destination validation. |
| **BIMI** | Brand indicator record detection, SVG Tiny PS profile validation, VMC certificate requirements. |
| **DNSSEC** | DNSKEY presence, DS record validation against parent zone, algorithm analysis, chain of trust verification. |
| **CAA** | Certificate Authority Authorization records, issuer restrictions, wildcard policy, incident reporting (iodef). |
| **DANE** | TLSA record lookup for each MX host, usage/selector/matching type analysis, DNSSEC prerequisite check. |
| **Nameservers** | NS count, resolution verification, authoritative response check, SOA serial consistency, IPv6 support, network diversity, provider identification. |
| **Certificate Transparency** | CT log lookup via crt.sh for issued certificates, issuer breakdown, CAA mismatch detection, expiring certificate alerts. |
| **Blocklist** | Domain reputation check against Spamhaus DBL and other DNS-based blocklists. |

Every check produces a pass/warn/fail status with a plain-English explanation, detailed findings, and a recommended fix with copy-paste DNS records where applicable.

## How Scoring Works

Six categories sum to 100 points with a letter grade (A through F):

| Category | Points | What It Measures |
|----------|--------|-----------------|
| DMARC | 25 | Policy strength, alignment mode, reporting |
| SPF | 20 | Record presence, mechanism analysis, lookup budget |
| DKIM | 15 | Key discovery, key type and strength |
| Best Practices | 20 | MTA-STS (8), TLS-RPT (8), DANE (4) |
| Key Security | 10 | DKIM key strength and rotation hygiene |
| Vendor Intelligence | 10 | Email service provider detection confidence |

DMARC, SPF, and DKIM together account for 60% of the score. Infrastructure checks (DNSSEC, CAA, Nameservers, Certificate Transparency, Blocklist) are reported with full detail but do not contribute to the numeric score, since many well-configured domains reasonably omit them.

Grade thresholds: A (85+), B (70-84), C (55-69), D (40-54), F (below 40).

## Key Features

### Fix It For Me

Failing checks include copy-paste-ready DNS records. Instead of just telling you what is wrong, the tool generates the exact TXT, CAA, or TLSA record you need to add, with the correct host, value, and format for your domain.

### DMARC DNS Tree Walk

DMARC policy discovery does not just check the exact domain. Per the DMARCbis specification, receivers walk up the DNS tree, stripping labels from left to right, looking for an organizational or public suffix domain policy. The tool visualizes each step of this process with an animated timeline showing which domains were queried, what was found, and which policy ultimately applies.

Try it with a subdomain like `mail.google.com` or `support.microsoft.com` to see the full tree walk in action.

### SPF Evaluation Trace

The SPF check does not just count lookups. It traces the full evaluation path through every include, redirect, and mechanism, showing the lookup cost at each node. Detected vendors are labeled inline so you can see exactly which services consume your 10-lookup budget.

### PDF Audit Report

One-click download of a professional PDF report with an executive summary page (grade, score breakdown, priority fixes, detected vendors) followed by detailed check cards. Designed to be shared with clients, management, or IT teams.

### Scoped Audits

Six audit scopes let you run only the checks you need:

| Scope | Checks |
|-------|--------|
| Complete Audit | All 13 checks |
| Email Security | DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, Blocklist |
| DMARC Check | DMARC + SPF + DKIM (authentication triad) |
| Transport Security | MTA-STS, TLS-RPT, DANE, MX |
| DNS Infrastructure | DNSSEC, CAA, DANE, Nameservers, CT |
| Security Scan | DMARC, SPF, DKIM, DNSSEC, DANE, CT, Blocklist, CAA, MTA-STS |

### Vendor Detection

Identifies email service providers (Google Workspace, Microsoft 365, Proofpoint, Mimecast, SendGrid, Mailchimp, and others) from MX records, SPF includes, DMARC reporting destinations, and DKIM selectors. Multi-signal detection with confidence scoring.

### Defensive DNS Detection

Domains configured to not send or receive email (null MX, null SPF, DMARC reject) are identified as defensive DNS configurations and scored appropriately rather than penalized for missing email infrastructure.

## Architecture

Single-page application with a FastAPI backend. No database, no user accounts, no tracking.

```
static/
  index.html          Single-page app shell
  app.js              Result rendering, tree walk visualization, scoped audits
  style.css           Design tokens, responsive layout, animations

server.py             FastAPI app, SSE streaming, rate limiting, caching, PDF endpoint
audit_engine.py       Check orchestration, parallel execution with timeouts
result_transformer.py Raw audit results to frontend card format
security_scoring.py   Weighted scoring and letter grading
pdf_report.py         FPDF2-based branded PDF generation
dmarc_tree_walk.py    DMARCbis Section 4.10 tree walk algorithm
spf_recursive.py      Recursive SPF lookup counter
spf_execution_engine.py  SPF evaluation trace with vendor labeling
checks_extra.py       MTA-STS, TLS-RPT, BIMI checks
anomaly_detector.py   Cross-check anomaly detection
remediation_planner.py  Prioritized fix roadmap generation
dkim_formatter.py     DKIM key analysis (RSA/Ed25519)
advanced_fingerprinting.py  Multi-signal vendor fingerprinting
comprehensive_selectors.py  DKIM selector list for auto-discovery
dns_tools.py          Domain normalization, audit entry point
```

## API

```
GET /api/audit?domain=example.com            Full audit (JSON)
GET /api/audit/stream?domain=example.com     SSE streaming (real-time progress)
GET /api/audit?domain=example.com&nocache=true   Bypass cache
GET /api/audit/pdf?domain=example.com        PDF report download
GET /api/health                              Health check
GET /docs                                    Interactive API docs (Swagger)
```

Optional parameters: `selector` (specific DKIM selector to test), `scope` (audit scope).

Rate limited to 10 requests per IP per minute. Results cached for 5 minutes.

## Self-Hosting

Requirements: Python 3.8+, no external services or databases.

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

## Testing

```bash
python3 -m pytest tests/ -v
```

## Author

**[Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** -- DNS, email security, and deliverability specialist with 15+ years of experience including enterprise DMARC implementations and ISP-level DNS operations.

[LinkedIn](https://www.linkedin.com/in/neilanuskiewicz/) | [GitHub](https://github.com/marmot7775) | [dns-audit.com](https://dns-audit.com)
