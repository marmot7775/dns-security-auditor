"""
DNS Security Auditor - Configuration
Centralizes all configurable data: selectors, check metadata, educational content
Easy to maintain - add/remove items without touching core logic
"""

# DKIM Selectors - Common selectors used by major email providers
# Add new selectors here as you discover them
DKIM_SELECTORS = [
    # Google Workspace / Gmail
    'google',
    'googlemail',
    
    # Microsoft 365
    'selector1',
    'selector2',
    
    # Major ESPs
    'default',
    'k1',
    'k2',
    'k3',
    'dkim',
    'mail',
    'email',
    's1',
    's2',
    
    # Mailchimp
    'k1._domainkey',
    
    # SendGrid
    'em',
    's1',
    's2',
    
    # Amazon SES
    'amazonses',
    
    # Proofpoint
    'proofpoint',
    'pp',
    
    # Custom/Other
    'big-email',
    'mandrill',
    'sparkpost',
    'mailgun',
]

# Check metadata - defines all available security checks
CHECK_DEFINITIONS = {
    'dmarc': {
        'name': 'DMARC',
        'full_name': 'Domain-based Message Authentication, Reporting, and Conformance',
        'category': 'email',
        'severity': 'critical',
        'description': 'Tells email receivers how to handle messages that fail authentication',
        'risk': 'Email spoofing, phishing attacks using your domain',
        'rfc': 'RFC 7489'
    },
    'spf': {
        'name': 'SPF',
        'full_name': 'Sender Policy Framework',
        'category': 'email',
        'severity': 'critical',
        'description': 'Lists which mail servers are authorized to send email for your domain',
        'risk': 'Unauthorized senders, email deliverability issues',
        'rfc': 'RFC 7208'
    },
    'dkim': {
        'name': 'DKIM',
        'full_name': 'DomainKeys Identified Mail',
        'category': 'email',
        'severity': 'high',
        'description': 'Cryptographic signatures prove emails haven\'t been tampered with',
        'risk': 'Email tampering, failed authentication',
        'rfc': 'RFC 6376'
    },
    'mta_sts': {
        'name': 'MTA-STS',
        'full_name': 'SMTP MTA Strict Transport Security',
        'category': 'email',
        'severity': 'medium',
        'description': 'Enforces TLS encryption for mail delivery to prevent downgrade attacks',
        'risk': 'Email interception, man-in-the-middle attacks',
        'rfc': 'RFC 8461'
    },
    'tls_rpt': {
        'name': 'TLS-RPT',
        'full_name': 'TLS Reporting',
        'category': 'email',
        'severity': 'low',
        'description': 'Sends reports about TLS connection failures',
        'risk': 'Blind to delivery issues and potential attacks',
        'rfc': 'RFC 8460'
    },
    'mx': {
        'name': 'MX',
        'full_name': 'Mail Exchange Records',
        'category': 'email',
        'severity': 'critical',
        'description': 'Specifies mail servers that receive email for your domain',
        'risk': 'Cannot receive email',
        'rfc': 'RFC 1035'
    },
    'dnssec': {
        'name': 'DNSSEC',
        'full_name': 'DNS Security Extensions',
        'category': 'dns',
        'severity': 'high',
        'description': 'Cryptographically signs DNS records to prevent tampering',
        'risk': 'DNS spoofing, cache poisoning attacks',
        'rfc': 'RFC 4033, 4034, 4035'
    },
    'caa': {
        'name': 'CAA',
        'full_name': 'Certification Authority Authorization',
        'category': 'dns',
        'severity': 'medium',
        'description': 'Specifies which CAs can issue SSL/TLS certificates for your domain',
        'risk': 'Rogue certificate issuance',
        'rfc': 'RFC 8659'
    },
    'ns': {
        'name': 'Nameservers',
        'full_name': 'Nameserver Configuration',
        'category': 'dns',
        'severity': 'high',
        'description': 'Checks nameserver redundancy and network diversity',
        'risk': 'Single point of failure, complete DNS outage',
        'rfc': 'RFC 1034'
    },
    'zone_transfer': {
        'name': 'Zone Transfer',
        'full_name': 'AXFR Vulnerability Check',
        'category': 'dns',
        'severity': 'critical',
        'description': 'Tests if unauthorized zone transfers are allowed',
        'risk': 'Complete zone disclosure, reconnaissance for attacks',
        'rfc': 'RFC 5936'
    },
    'subdomain_takeover': {
        'name': 'Subdomain Takeover',
        'full_name': 'Dangling CNAME Detection',
        'category': 'dns',
        'severity': 'high',
        'description': 'Finds CNAMEs pointing to non-existent resources',
        'risk': 'Subdomain hijacking, phishing, malware distribution',
        'rfc': 'N/A'
    }
}

# Email provider detection patterns for MX records
EMAIL_PROVIDERS = {
    'google.com': 'Google Workspace',
    'googlemail.com': 'Gmail',
    'outlook.com': 'Microsoft 365',
    'office365.com': 'Microsoft 365',
    'protection.outlook.com': 'Microsoft 365 (Exchange Online Protection)',
    'pphosted.com': 'Proofpoint',
    'mimecast.com': 'Mimecast',
    'messagelabs.com': 'Symantec Email Security',
    'spamh.com': 'Barracuda',
    'mailgun.org': 'Mailgun',
    'sendgrid.net': 'SendGrid',
}

# Grading thresholds
GRADING = {
    'A': {'min': 90, 'color': '#10b981', 'label': 'Excellent'},
    'B': {'min': 75, 'color': '#3b82f6', 'label': 'Good'},
    'C': {'min': 60, 'color': '#f59e0b', 'label': 'Fair'},
    'D': {'min': 40, 'color': '#f97316', 'label': 'Poor'},
    'F': {'min': 0, 'color': '#ef4444', 'label': 'Critical'},
}

# Educational content for each check (displayed when issues found)
EDUCATIONAL_CONTENT = {
    'DMARC': """
**Why DMARC Matters:**
DMARC tells email receivers (Gmail, Outlook, etc.) what to do when an email fails SPF or DKIM authentication. 
Without DMARC, attackers can easily spoof your domain to send phishing emails that appear to come from you.

**Common Policies:**
- `p=none` - Monitor only (good for initial deployment)
- `p=quarantine` - Send suspicious email to spam
- `p=reject` - Block unauthenticated email entirely (strongest protection)

**Implementation Steps:**
1. Start with `p=none` to collect reports without blocking email
2. Set up `rua` (aggregate reports) to monitor authentication
3. After validating all legitimate senders pass SPF/DKIM, move to `p=quarantine`
4. Finally move to `p=reject` for maximum protection
""",
    
    'SPF': """
**Why SPF Matters:**
SPF prevents spammers from forging your domain in the "envelope from" address. It lists which IP addresses 
and mail servers are authorized to send email on behalf of your domain.

**The 10 Lookup Limit:**
RFC 7208 limits SPF to 10 DNS lookups to prevent performance issues. Each `include:` mechanism triggers 
a lookup. If you exceed 10 lookups, your SPF record may be ignored entirely.

**Solutions for Exceeding Limits:**
- Use `ip4:` and `ip6:` mechanisms instead of `include:` where possible
- Implement SPF flattening (convert includes to direct IP listings)
- Remove services you no longer use
- Consider DKIM as your primary authentication method
""",
    
    'DKIM': """
**Why DKIM Matters:**
DKIM adds a cryptographic signature to your emails using public key cryptography. This proves the email 
content hasn't been modified in transit and verifies the sending domain.

**How It Works:**
1. Your mail server signs outgoing emails with a private key
2. You publish the public key as a TXT record at `selector._domainkey.yourdomain.com`
3. Receiving servers verify the signature using your public key

**Best Practices:**
- Use at least 1024-bit keys (2048-bit recommended)
- Rotate keys periodically for security
- Enable DKIM for all sending services (ESP, marketing platforms, etc.)
- Each service typically uses a different selector
""",

    'MTA-STS': """
**Why MTA-STS Matters:**
MTA-STS forces sending mail servers to use encrypted TLS connections when delivering email to you. 
This prevents downgrade attacks where attackers force unencrypted connections to intercept email.

**Implementation:**
1. Add TXT record at `_mta-sts.yourdomain.com`: `v=STSv1; id=20240101`
2. Host policy file at `https://mta-sts.yourdomain.com/.well-known/mta-sts.txt`
3. Policy file specifies which MX hosts support TLS and enforcement mode

**Enforcement Modes:**
- `testing` - Report but don't enforce (good for initial deployment)
- `enforce` - Require TLS or fail delivery (strongest protection)
""",

    'DNSSEC': """
**Why DNSSEC Matters:**
DNSSEC cryptographically signs your DNS records, creating a chain of trust from the root DNS servers 
down to your domain. This prevents DNS cache poisoning and other attacks that redirect users to 
malicious sites.

**Implementation Complexity:**
DNSSEC requires coordination between your domain registrar and DNS hosting provider. Both must 
support DNSSEC, and you need to properly configure DS records at your registrar.

**Trade-offs:**
- **Pros:** Strong protection against DNS-based attacks
- **Cons:** Complex setup, can cause complete domain failure if misconfigured
- **Note:** Not all registrars and hosting providers support DNSSEC
"""
}

# Common subdomains to check for takeover vulnerabilities
COMMON_SUBDOMAINS = [
    'www',
    'mail',
    'ftp',
    'admin',
    'blog',
    'shop',
    'store',
    'dev',
    'staging',
    'test',
    'api',
    'cdn',
    'status',
    'support',
    'help',
    'docs',
]
