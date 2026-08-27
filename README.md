# dns-audit.com

**The first DMARCbis-aware DNS and email security audit tool**

**Built by [Neil Anuskiewicz](https://www.linkedin.com/in/neilanuskiewicz/)** | **Live at [dns-audit.com](https://dns-audit.com)**

DNS and email security analysis for any domain. Enter a domain and get a scored assessment with technical findings, plain-language explanations, and copy-paste DNS fix records. The first tool to validate against the upcoming DMARCbis standard, showing domain owners what changes before their records break.

Our analysis of the top 1000 internet domains found 0% adoption of DMARCbis-specific tags (`np=`, `psd=`, `t=`), 30.6% still using deprecated tags (`pct`, `rf`, `ri`), and 26% with no DMARC record at all.

Built for engineers, email administrators, and security consultants who need to evaluate a domain's authentication posture quickly and accurately.

---

## 13 Security Checks

### Authentication

| Check | What It Does |
|-------|-------------|
| **DMARC + DMARCbis** | DMARCbis-strict record validation (16 layered checks), tag-by-tag decoder with DMARCbis education notes, dangerous combination detection (21 checks across 3 severity levels), 5-state DMARCbis health verdict, personalized migration wizard, attack surface visualization (4 spoofing vectors), RFC 7489 vs DMARCbis spec mode toggle with delta view, "Why DMARCbis?" education section. Implements the DMARCbis DNS Tree Walk ([draft-ietf-dmarc-dmarcbis](https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/), Section 4.10) for hierarchical policy discovery with animated visualization. |
| **SPF** | Syntax validation, mechanism analysis, recursive evaluation with full lookup chain tracing, void lookup detection, and vendor-labeled include tree visualization. Flags `+all`, `?all`, missing `all`, `redirect`+`all` conflicts, deprecated `ptr`, overly broad CIDRs, and invalid IPs. |
| **DKIM** | Selector discovery across 1,100+ common patterns using SPF-based vendor fingerprinting. Key strength analysis for RSA (1024/2048/4096) and Ed25519. Key rotation age estimation. Direct lookup of user-supplied selectors. Wildcard DNS detection prevents false positives. |

### Mail and Transport

| Check | What It Does |
|-------|-------------|
| **MX Records** | Mail exchanger discovery, vendor fingerprinting, FCrDNS validation, redundancy analysis, dangling MX detection, null MX (RFC 7505) recognition. Major providers recognized as internally redundant. |
| **MTA-STS** | `TXT` record validation, HTTPS policy file retrieval and parsing, mode analysis (`enforce`/`testing`/`none`), MX pattern cross-referencing, `max_age` evaluation. |
| **TLS-RPT** | SMTP TLS reporting record validation, report destination verification (`mailto` and HTTPS). |
| **BIMI** | Record parsing, DMARC enforcement prerequisite check (including inherited policies), SVG logo fetch with Tiny PS profile validation, script element detection, external reference scanning, `viewBox` verification, file size check, VMC certificate tag analysis. |

### DNS and Cryptographic Controls

| Check | What It Does |
|-------|-------------|
| **DNSSEC** | `DNSKEY` presence, `DS` record validation at parent zone (recursive + direct parent NS query), algorithm analysis per RFC 8624, chain of trust verification via `AD` flag and `DS`-to-`DNSKEY` digest matching. |
| **CAA** | Certificate Authority Authorization records, issuer restrictions (`issue`), wildcard policy (`issuewild`), incident reporting (`iodef`). |
| **DANE** | `TLSA` record lookup for each MX host, usage/selector/matching type analysis, DNSSEC dependency enforcement per RFC 7672. |

### Infrastructure and Reputation

| Check | What It Does |
|-------|-------------|
| **Nameservers** | NS count, resolution and authoritative response verification, `SOA` serial consistency, IPv6 support, network diversity across /24 ranges, provider identification. |
| **Certificate Transparency** | CT log query via crt.sh, issuer breakdown, CAA mismatch detection, expiring certificate alerts, subdomain discovery. |
| **Blocklist** | Domain reputation check against Spamhaus DBL with return code interpretation (spam, phishing, malware, botnet C&C). |

---

## Scoring

Six categories sum to 100 points with a letter grade:

| Category | Points | What It Measures |
|----------|--------|-----------------|
| DMARC | 25 | Policy strength, alignment mode, reporting, subdomain policy |
| SPF | 20 | Record presence, `all` mechanism, lookup count, `include` complexity |
| DKIM | 15 | Key discovery, key type, cryptographic strength |
| Best Practices | 20 | MTA-STS, TLS-RPT, DNSSEC, DANE, CAA, nameserver diversity |
| Key Security | 10 | DKIM key strength, rotation hygiene, algorithm modernity |
| Vendor Intelligence | 10 | Email service provider detection confidence |
*Note: DKIM selectors cannot be enumerated via DNS. For best results, provide your selector directly.*

DMARC, SPF, and DKIM account for 60% of the score. Infrastructure checks (DNSSEC, CAA, DANE, Nameservers, Certificate Transparency, Blocklist) are evaluated and displayed but do not contribute to the numeric score, since their absence is often intentional.

Domains receive a letter grade (A+ through F) based on a 100-point scoring system. See the [Methodology](https://dns-audit.com/methodology) page for detailed scoring criteria and grade thresholds.

Domains where DKIM selectors could not be detected receive full DKIM credit, since selectors are private and cannot be verified from outside.

---

## Key Features

### DMARC (RFC 7489)

When evaluating an inbound message, the receiver queries DNS for a `TXT` record at `_dmarc.<domain>`, where the domain is taken from the email's RFC 5322.From (Header From). If no record is found at the exact Author Domain, the receiver determines the Organizational Domain using a Public Suffix List (PSL) and performs a single fallback lookup at that level. No intermediate subdomains are checked.

If a valid record (beginning with `v=DMARC1`) is found at either level, its policy is applied. Otherwise, DMARC does not apply to the message.

### DMARCbis DNS Tree Walk

Starting from the Author Domain (RFC 5322.From), the tool queries for a DMARC Policy Record. If none is found, it initiates a DNS Tree Walk as described in DMARCbis (draft-ietf-dmarc-dmarcbis-41, Section 4.10), walking up the DNS hierarchy one label at a time to discover both an applicable policy and the Organizational Domain used for identifier alignment. The walk is capped at eight DNS queries to prevent abuse.

Because DMARCbis is on the Standards Track and expected to be published as a Proposed Standard, these results are displayed alongside traditional RFC 7489 lookups. This lets domain owners compare how policy discovery, inheritance via `sp` and `np`, and new tags like `psd` and `t` will behave once receivers adopt the updated specification.

### Why DMARCbis Matters

DMARCbis addresses several architectural limitations in RFC 7489 that carry real security and sustainability implications for email authentication. The original spec was published in 2015 as an Informational RFC, not a formal Internet standard, and carried no conformance requirements. Receivers were free to interpret it however they chose, and they did. A decade of deployment exposed problems that could not be patched within the original framework.

The most significant change is replacing the Public Suffix List, a community-maintained external dependency, with the DNS Tree Walk, a DNS-native mechanism that lets domain owners control their own domain boundaries. RFC 7489 also only performs two lookups (the exact Author Domain and the Organizational Domain), leaving no way for intermediate subdomains to govern their own branch of the tree. For a domain like `notifications.app.services.example.com`, the only two lookups are at that exact subdomain and at `example.com`. There is no way for `services.example.com` to independently govern its own branch. The tree walk queries each level of the hierarchy, enabling decentralized policy management. DMARCbis also introduces the `np` tag to set separate policies for non-existent subdomains, closing a gap that allowed attackers to spoof fabricated subdomains like `ceo.example.com`, and replaces the widely misunderstood `pct` tag with `t`, a cleaner binary signal for testing mode.

The DMARCbis specification (draft-ietf-dmarc-dmarcbis-41) is currently in the RFC Editor Queue and is expected to be published as a Proposed Standard. This tool analyzes DMARCbis alongside RFC 7489 so that domain owners can evaluate the impact on their domains now and begin preparing their records before receivers adopt the updated specification.

### SPF Evaluation Trace

Full recursive SPF evaluation that traces the path through every `include` and `redirect`, showing the per-node lookup cost. Detected vendors are labeled inline so you can see exactly which services consume your 10-lookup budget.

### Defensive DNS Detection

Domains configured to not send or receive email (null MX, `v=spf1 -all`, `p=reject`) are identified as defensive DNS configurations and scored appropriately rather than penalized for intentionally absent email infrastructure.

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

Identifies email service providers using multiple signals: MX hostnames, SPF `include` chains, DMARC `rua` reporting URIs, and DKIM selectors. Multi-signal detection with confidence scoring.

### DMARCbis Checker

The first tool to validate DMARC records against the upcoming DMARCbis standard (draft-ietf-dmarc-dmarcbis). Features that no other tool provides:

- **Strict Record Validator**: 16 layered checks across tokenization, grammar, and semantics. Catches missing `mailto:` prefixes, duplicate tags, invalid URIs, and other issues that legacy tools silently accept.
- **Spec Mode Toggle**: Switch between RFC 7489 (legacy) and DMARCbis (strict) validation to see exactly what changes. The "See the Future" view shows domain owners which issues will break when receivers adopt DMARCbis.
- **Tag Decoder with DMARCbis Education**: Every tag explained with security consequences and a DMARCbis note explaining what changed from RFC 7489 and why.
- **Dangerous Combination Detection**: 21 checks for dangerous tag interactions (`sp=none` + `p=reject` policy gaps, contradictory policies, test mode weakening enforcement).
- **Health Verdict**: 5-state classification (DMARCbis Ready, Compatible, Monitoring, Needs Attention, Misconfigured) with specific findings.
- **Migration Wizard**: Personalized step-by-step path from current state to DMARCbis Ready, with before/after DNS records at every step and a copy-to-clipboard target record.
- **Attack Surface View**: 4-vector spoofing risk map (direct domain, subdomain, non-existent subdomain, reporting leakage) with concrete attack scenarios.
- **Email Security Roadmap**: Cross-protocol prioritized action plan synthesizing findings across all 13 checks.

### Email Security Roadmap

Synthesizes findings across all protocols into one prioritized action plan with four tiers (critical, high, medium, low). Shows the most impactful action first with business impact context for each recommendation.

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
GET /api/health                                Health check (verifies DNS resolution)
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
