# DNS Security Auditor

A comprehensive DNS and email security auditing tool that checks for misconfigurations, vulnerabilities, and provides actionable recommendations with copy-ready DNS records.

## Features

### Email Security
- **DMARC** — Policy analysis with RFC 7489 validation, syntax checking
- **SPF** — DNS lookup counting with RFC 7208 limit enforcement, syntax validation
- **DKIM** — Common selector discovery across major ESPs
- **MTA-STS** — TXT record + HTTPS policy file validation
- **TLS-RPT** — TLS reporting configuration
- **MX** — Mail exchange records with provider detection

### DNS Security
- **DNSSEC** — Signing and chain of trust validation
- **CAA** — Certificate Authority Authorization
- **NS** — Nameserver redundancy and network diversity
- **Zone Transfer** — AXFR vulnerability detection
- **Subdomain Takeover** — Dangling CNAME detection

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dns-security-auditor.git
cd dns-security-auditor

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Web Interface (Recommended)

```bash
streamlit run app.py
```

Open **http://localhost:8501** in your browser.

The web interface provides:
- Visual pass/fail/warning status for each check
- Expandable details with educational context
- Copy-ready DNS records for fixes
- Export to text report or JSON

### Command Line

```bash
# Email security audit (default)
python cli.py example.com

# Full DNS security audit  
python cli.py example.com --scope dns

# Summary output only
python cli.py example.com --output summary

# JSON output for scripting
python cli.py example.com --json
```

### Python API

```python
from dns_tools import audit_email_security, audit_dns_security

# Run audit
results = audit_email_security("example.com")

# Access results
for name, check in results["checks"].items():
    print(f"{check['check']}: {check['status']}")
    for issue in check.get("issues", []):
        print(f"  - {issue}")
```

## Example Output

```
============================================================
DNS Security Audit: example.com
Scope: Email Security
============================================================

Summary: ✅ 2 OK | ⚠️  2 Warning | 🔴 2 Error

🔴 DMARC
----------------------------------------
  🔴 NO DMARC RECORD at _dmarc.example.com. Without DMARC, anyone can 
     spoof emails from your domain. Receivers have no policy guidance 
     for handling unauthenticated mail.
  → Add a TXT record at _dmarc.example.com to start monitoring:
    v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com; fo=1

✅ SPF
----------------------------------------
  Record: v=spf1 include:_spf.google.com ~all
  ℹ️  SPF PASSES: 4/10 DNS lookups per RFC 7208.
  ℹ️  Using '~all' (softfail) — unauthorized senders will softfail SPF.

✅ DKIM
----------------------------------------
  DKIM Selectors Found:
    google._domainkey.example.com
      → RSA key
  ℹ️  DKIM FOUND: 1 selector(s) discovered: google

⚠️  MTA-STS
----------------------------------------
  🔴 NO MTA-STS: No TXT record found at _mta-sts.example.com. Without 
     MTA-STS, SMTP connections can be downgraded to unencrypted.
  → To enable MTA-STS, add:
    1. TXT record at _mta-sts.example.com: v=STSv1; id=20240101
    2. Policy file at https://mta-sts.example.com/.well-known/mta-sts.txt

============================================================
PRIORITY FIXES (in order):
============================================================
  1. [DMARC] Add TXT record at _dmarc.example.com
  2. [MTA_STS] Add TXT record at _mta-sts.example.com
```

## Checks Reference

| Check | What It Does | Risk If Missing |
|-------|--------------|-----------------|
| DMARC | Tells receivers how to handle failed auth | Email spoofing, phishing |
| SPF | Lists authorized sending IPs | Unauthorized senders |
| DKIM | Cryptographic email signatures | Tampering, failed auth |
| MTA-STS | Enforces TLS for mail delivery | Email interception |
| TLS-RPT | Reports on TLS delivery failures | Blind to attacks |
| DNSSEC | Signs DNS records cryptographically | DNS spoofing |
| CAA | Restricts certificate issuance | Rogue certificates |
| NS | Nameserver configuration | Single point of failure |
| Zone Transfer | Tests AXFR restrictions | Full zone disclosure |
| Subdomain Takeover | Finds dangling CNAMEs | Subdomain hijacking |

## Requirements

- Python 3.8+
- dnspython
- requests
- streamlit (for web interface)

## Author

Neil — Email & DNS Security Consultant

## License

MIT
