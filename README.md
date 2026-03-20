# DNS Audit

**Built by [Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** | **Live at [dns-audit.com](https://dns-audit.com)**

DNS and email security analysis for any domain. Enter a domain and get a scored assessment with technical findings, plain-language explanations, and copy-paste DNS fix records.

Try it with `mail.google.com` to see the DMARC Tree Walk trace inherited policy from Google's organizational domain, or with your own domain to see where you stand.

Built for engineers, email administrators, and security consultants who need to evaluate a domain's authentication posture quickly and accurately.

---

## 13 Security Checks

### Authentication

| Check | What It Does |
|-------|-------------|
| **DMARC** | Policy evaluation, tag validation, alignment modes, reporting configuration, external report authorization. Implements the DMARCbis DNS Tree Walk ([draft-ietf-dmarc-dmarcbis-41](https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/), Section 4.10) for hierarchical policy discovery with animated visualization. Detects deprecated tags (pct, ri, rf) and new DMARCbis tags (t, np, psd). |
| **SPF** | Syntax validation, mechanism analysis, recursive evaluation with full lookup chain tracing, void lookup detection, and vendor-labeled include tree visualization. Flags +all, ?all, missing all, redirect+all conflicts, deprecated ptr, overly broad CIDRs, and invalid IPs. |
| **DKIM** | Selector discovery across 1,100+ common patterns using SPF-based vendor fingerprinting. Key strength analysis for RSA (1024/2048/4096) and Ed25519. Key rotation age estimation. Direct lookup of user-supplied selectors. Wildcard DNS detection prevents false positives. |

### Mail and Transport

| Check | What It Does |
|-------|-------------|
| **MX Records** | Mail exchanger discovery, vendor fingerprinting, FCrDNS validation, redundancy analysis, dangling MX detection, null MX (RFC 7505) recognition. Major providers recognized as internally redundant. |
| **MTA-STS** | TXT record validation, HTTPS policy file retrieval and parsing, mode analysis (enforce/testing/none), MX pattern cross-referencing, max_age evaluation. |
| **TLS-RPT** | SMTP TLS reporting record validation, report destination verification (mailto and HTTPS). |
| **BIMI** | Record parsing, DMARC enforcement prerequisite check (including inherited policies), SVG logo fetch with Tiny PS profile validation, script element detection, external reference scanning, viewBox verification, file size check, VMC certificate tag analysis. |

### DNS and Cryptographic Controls

| Check | What It Does |
|-------|-------------|
| **DNSSEC** | DNSKEY presence, DS record validation at parent zone (recursive + direct parent NS query), algorithm analysis per RFC 8624, chain of trust verification via AD flag and DS-to-DNSKEY digest matching. |
| **CAA** | Certificate Authority Authorization records, issuer restrictions (issue), wildcard policy (issuewild), incident reporting (iodef). |
| **DANE** | TLSA record lookup for each MX host, usage/selector/matching type analysis, DNSSEC dependency enforcement per RFC 7672. |

### Infrastructure and Reputation

| Check | What It Does |
|-------|-------------|
| **Nameservers** | NS count, resolution and authoritative response verification, SOA serial consistency, IPv6 support, network diversity across /24 ranges, provider identification. |
| **Certificate Transparency** | CT log query via crt.sh, issuer breakdown, CAA mismatch detection, expiring certificate alerts, subdomain discovery. |
| **Blocklist** | Domain reputation check against Spamhaus DBL with return code interpretation (spam, phishing, malware, botnet C&C). |

---

## Scoring

Six categories sum to 100 points with a letter grade:

| Category | Points | What It Measures |
|----------|--------|-----------------|
| DMARC | 25 | Policy strength, alignment mode, reporting, subdomain policy |
| SPF | 20 | Record presence, all mechanism, lookup count, include complexity |
| DKIM | 15 | Key discovery, key type, cryptographic strength |
| Best Practices | 20 | MTA-STS (8 pts), TLS-RPT (8 pts), DANE (4 pts) |
| Key Security | 10 | DKIM key strength, rotation hygiene, algorithm modernity |
| Vendor Intelligence | 10 | Email service provider detection confidence |
*Note: DKIM selectors cannot be enumerated via DNS. For best results, provide your selector directly.*

DMARC, SPF, and DKIM account for 60% of the score. Infrastructure checks (DNSSEC, CAA, DANE, Nameservers, Certificate Transparency, Blocklist) are evaluated and displayed but do not contribute to the numeric score, since their absence is often intentional.

Grade thresholds: **A** 85+, **B** 70+, **C** 55+, **D** 40+, **F** below 40.

Domains where DKIM selectors could not be detected receive full DKIM credit, since selectors are private and cannot be verified from outside.

---

## Key Features

### DMARC DNS Tree Walk

When a domain has no DMARC record, the tool walks up the DNS hierarchy per DMARCbis Section 4.10, querying each ancestor for an applicable policy. The full walk is visualized as an animated timeline showing which domains were queried, where the policy was found, and which tag (p, sp, or np) applies.

### SPF Evaluation Trace

Full recursive SPF evaluation that traces the path through every include, redirect, and mechanism, showing the per-node lookup cost. Detected vendors are labeled inline so you can see exactly which services consume your 10-lookup budget.

### Defensive DNS Detection

Domains configured to not send or receive email (null MX, null SPF, DMARC reject) are identified as defensive DNS configurations and scored appropriately rather than penalized for intentionally absent email infrastructure.

### Authentication Resilience

Evaluates whether the domain can survive the failure of any single authentication mechanism. A domain with both SPF and DKIM functional has high resilience. A domain relying on SPF alone has moderate resilience because forwarded mail will fail.

### Anomaly Detection

Cross-check analysis that catches issues no single check reveals: DMARC enforcement without SPF, BIMI without DMARC enforcement, MTA-STS without TLS-RPT, mixed DKIM key strengths, parked domains with live MX records, unauthorized DMARC report destinations, broken DNSSEC chains.

### PDF Report

One-click branded PDF with executive summary (grade, score breakdown, priority fixes, detected vendors) and detailed check cards.

### Scoped Audits

| Scope | Checks |
|-------|--------|
| Complete Audit | All 13 checks |
| Email Security | DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, Blocklist |
| DMARC Check | DMARC, SPF, DKIM |
| Transport Security | MTA-STS, TLS-RPT, DANE, MX |
| DNS Infrastructure | DNSSEC, CAA, DANE, Nameservers, Certificate Transparency |
| Security Scan | DMARC, SPF, DKIM, DNSSEC, DANE, CT, Blocklist, CAA, MTA-STS |

### Vendor Detection

Identifies email service providers using multiple signals: MX hostnames, SPF includes, DMARC reporting URIs, and DKIM selectors. Multi-signal detection with confidence scoring.

---

## Architecture

Stateless single-page application with a FastAPI backend. No database, no user accounts, no tracking.

```
server.py                  FastAPI, SSE streaming, rate limiting, caching, PDF endpoint
audit_engine.py            Check orchestration, parallel execution with timeouts
result_transformer.py      Raw results to frontend card format
security_scoring.py        Weighted scoring and letter grading
pdf_report.py              FPDF2-based PDF generation
dmarc_tree_walk.py         DMARCbis Section 4.10 tree walk
spf_recursive.py           Recursive SPF lookup counter
spf_execution_engine.py    SPF evaluation trace, DMARC roadmap
checks_extra.py            MTA-STS, TLS-RPT, BIMI checks
anomaly_detector.py        Cross-check anomaly detection
remediation_planner.py     Prioritized fix roadmap
dkim_formatter.py          DKIM key analysis (RSA/Ed25519)
advanced_fingerprinting.py Multi-signal vendor fingerprinting

static/
  index.html               Single-page app shell
  app.js                   Result rendering, visualizations, scoped audits
  style.css                Design tokens, responsive layout, animations
```

## API

```
GET /api/audit?domain=example.com              JSON response
GET /api/audit/stream?domain=example.com       SSE streaming
GET /api/audit/pdf?domain=example.com          PDF download
GET /api/health                                Health check
GET /docs                                      Swagger UI
```

Optional parameters: `selector`, `scope`, `nocache=true`.

Rate limited to 10 requests per IP per minute. Results cached for 5 minutes.

## Self-Hosting

Python 3.8+. No external services or databases.

```bash
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8000
```

All DNS resolution via dnspython. No API keys needed.

## Tech Stack

- **Backend**: Python, FastAPI, dnspython, FPDF2
- **Frontend**: Vanilla JavaScript, CSS custom properties, no frameworks
- **Fonts**: DM Sans, JetBrains Mono
- **Hosting**: DigitalOcean, Cloudflare

## Author

**[Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** -- DNS, email security, and deliverability specialist.

[LinkedIn](https://www.linkedin.com/in/neilanuskiewicz/) | [GitHub](https://github.com/marmot7775) | [dns-audit.com](https://dns-audit.com)
