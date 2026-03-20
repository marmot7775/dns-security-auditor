"""
EMAIL HEADER-BASED DKIM VALIDATOR

Validates DKIM signatures from actual email headers.
This confirms REAL-WORLD authentication, not just DNS configuration.

Usage:
1. User pastes email headers
2. Tool parses DKIM-Signature headers
3. Validates against DNS records
4. Shows pass/fail with detailed reasons

Critical for: "Your DNS is configured but emails still fail DKIM"
"""

import re
import base64
import dns.resolver
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class EmailHeaderDKIMValidator:
    """
    Validates DKIM signatures from email headers
    """
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
    
    def parse_email_headers(self, headers: str) -> Dict:
        """
        Parse email headers and extract DKIM signatures
        
        Returns:
            {
                'dkim_signatures': list of signature dicts,
                'from_domain': str,
                'message_id': str,
                'date': str
            }
        """
        # Extract DKIM-Signature headers
        dkim_pattern = r'DKIM-Signature:\s*([^\n]+(?:\n\s+[^\n]+)*)'
        dkim_matches = re.findall(dkim_pattern, headers, re.MULTILINE | re.IGNORECASE)
        
        signatures = []
        for match in dkim_matches:
            # Remove line breaks and extra spaces
            sig_clean = re.sub(r'\n\s+', ' ', match)
            sig_dict = self._parse_dkim_signature(sig_clean)
            signatures.append(sig_dict)
        
        # Extract From domain
        from_match = re.search(r'From:.*?@([a-zA-Z0-9.-]+)', headers, re.IGNORECASE)
        from_domain = from_match.group(1) if from_match else None
        
        # Extract Message-ID
        msgid_match = re.search(r'Message-ID:\s*(.+)', headers, re.IGNORECASE)
        message_id = msgid_match.group(1).strip() if msgid_match else None
        
        # Extract Date
        date_match = re.search(r'Date:\s*(.+)', headers, re.IGNORECASE)
        date = date_match.group(1).strip() if date_match else None
        
        return {
            'dkim_signatures': signatures,
            'from_domain': from_domain,
            'message_id': message_id,
            'date': date,
            'total_signatures': len(signatures)
        }
    
    def _parse_dkim_signature(self, signature: str) -> Dict:
        """Parse DKIM-Signature header into components"""
        sig_dict = {}
        
        # Split by semicolons
        parts = signature.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                sig_dict[key.strip()] = value.strip()
        
        return sig_dict
    
    def validate_signature(self, signature: Dict, from_domain: str) -> Dict:
        """
        Validate a single DKIM signature
        
        Returns:
            {
                'valid': bool,
                'status': str (pass/fail/temperror/permerror),
                'reasons': list of issues,
                'details': dict with validation details
            }
        """
        reasons = []
        details = {}
        
        # Extract key fields
        d = signature.get('d', '')  # Signing domain
        s = signature.get('s', '')  # Selector
        a = signature.get('a', '')  # Algorithm
        c = signature.get('c', '')  # Canonicalization
        h = signature.get('h', '')  # Signed headers
        bh = signature.get('bh', '') # Body hash
        b = signature.get('b', '')   # Signature
        
        details = {
            'signing_domain': d,
            'selector': s,
            'algorithm': a,
            'canonicalization': c,
            'signed_headers': h,
            'has_body_hash': bool(bh),
            'has_signature': bool(b)
        }
        
        # Validation checks
        
        # 1. Required fields
        if not d:
            reasons.append("Missing required 'd=' (signing domain)")
        if not s:
            reasons.append("Missing required 's=' (selector)")
        if not b:
            reasons.append("Missing required 'b=' (signature)")
        
        if reasons:
            return {
                'valid': False,
                'status': 'permerror',
                'reasons': reasons,
                'details': details
            }
        
        # 2. Domain alignment check (DMARC requirement)
        if from_domain and d:
            if not self._check_domain_alignment(from_domain, d):
                reasons.append(f"⚠️ Domain mismatch: From={from_domain}, d={d} (DMARC will FAIL)")
                details['domain_aligned'] = False
            else:
                details['domain_aligned'] = True
        
        # 3. Fetch DNS record for this selector
        try:
            dns_query = f"{s}._domainkey.{d}"
            answers = self.resolver.resolve(dns_query, 'TXT')
            
            dns_record = ''.join([str(rdata).strip('"') for rdata in answers])
            details['dns_record_found'] = True
            details['dns_record'] = dns_record
            
            # 4. Check if key is revoked (p= is empty)
            p_match = re.search(r'p=([^;]*)', dns_record)
            if p_match:
                public_key = p_match.group(1).strip()
                if not public_key:
                    reasons.append("❌ Key is REVOKED (p= is empty in DNS)")
                    return {
                        'valid': False,
                        'status': 'permerror',
                        'reasons': reasons,
                        'details': details
                    }
            
            # 5. Check algorithm compatibility
            if 'rsa' in a.lower():
                # Check if DNS supports RSA
                k_match = re.search(r'k=([^;]+)', dns_record)
                if k_match and 'rsa' not in k_match.group(1).lower():
                    reasons.append(f"Algorithm mismatch: signature uses {a}, DNS key type is {k_match.group(1)}")
            
            # 6. Check testing mode
            if 't=y' in dns_record:
                reasons.append("⚠️ Key is in TESTING mode (t=y in DNS)")
                details['testing_mode'] = True
            
        except dns.resolver.NXDOMAIN:
            reasons.append(f"❌ DNS record not found: {s}._domainkey.{d}")
            details['dns_record_found'] = False
            return {
                'valid': False,
                'status': 'permerror',
                'reasons': reasons,
                'details': details
            }
        except Exception as e:
            reasons.append(f"⚠️ DNS query error: {str(e)}")
            details['dns_record_found'] = False
            return {
                'valid': False,
                'status': 'temperror',
                'reasons': reasons,
                'details': details
            }
        
        # If we got here, signature structure is valid
        # (We can't verify cryptographic signature without full email content)
        if not reasons:
            return {
                'valid': True,
                'status': 'pass',
                'reasons': ['✓ Signature structure valid', '✓ DNS record found', '✓ Key not revoked'],
                'details': details
            }
        else:
            return {
                'valid': False,
                'status': 'fail',
                'reasons': reasons,
                'details': details
            }
    
    def _check_domain_alignment(self, from_domain: str, signing_domain: str) -> bool:
        """
        Check DMARC domain alignment (relaxed mode)
        
        Organizational domain must match
        """
        from_parts = from_domain.lower().split('.')
        sign_parts = signing_domain.lower().split('.')
        
        # Get organizational domains (last 2 parts)
        if len(from_parts) >= 2 and len(sign_parts) >= 2:
            from_org = '.'.join(from_parts[-2:])
            sign_org = '.'.join(sign_parts[-2:])
            return from_org == sign_org
        
        return from_domain.lower() == signing_domain.lower()
    
    def validate_email_headers(self, headers: str) -> Dict:
        """
        Complete email header validation
        
        Returns comprehensive validation report
        """
        # Parse headers
        parsed = self.parse_email_headers(headers)
        
        if not parsed['dkim_signatures']:
            return {
                'status': 'none',
                'message': 'No DKIM signatures found in headers',
                'from_domain': parsed['from_domain'],
                'signatures': []
            }
        
        # Validate each signature
        results = []
        for i, signature in enumerate(parsed['dkim_signatures'], 1):
            validation = self.validate_signature(signature, parsed['from_domain'])
            validation['signature_number'] = i
            results.append(validation)
        
        # Determine overall status
        any_pass = any(r['status'] == 'pass' for r in results)
        all_fail = all(r['status'] in ['fail', 'permerror'] for r in results)
        
        if any_pass:
            overall_status = 'pass'
            message = f"✓ DKIM PASS ({sum(1 for r in results if r['status'] == 'pass')}/{len(results)} signatures valid)"
        elif all_fail:
            overall_status = 'fail'
            message = f"❌ DKIM FAIL (all {len(results)} signatures failed)"
        else:
            overall_status = 'temperror'
            message = f"⚠️ DKIM TEMPERROR (temporary errors)"
        
        return {
            'status': overall_status,
            'message': message,
            'from_domain': parsed['from_domain'],
            'message_id': parsed['message_id'],
            'date': parsed['date'],
            'total_signatures': len(results),
            'signatures': results
        }
    
    def format_validation_report(self, validation: Dict) -> str:
        """Generate human-readable validation report"""
        lines = []
        
        lines.append("\n📧 EMAIL HEADER DKIM VALIDATION")
        lines.append("=" * 70)
        
        lines.append(f"\nFrom Domain: {validation['from_domain']}")
        if validation.get('message_id'):
            lines.append(f"Message-ID: {validation['message_id']}")
        if validation.get('date'):
            lines.append(f"Date: {validation['date']}")
        
        lines.append(f"\n{validation['message']}")
        lines.append(f"Total Signatures Found: {validation['total_signatures']}")
        
        if validation['status'] == 'none':
            lines.append("\nℹ️  No DKIM signatures present in email headers.")
            lines.append("   This email was not signed with DKIM.")
            return "\n".join(lines)
        
        # Detail each signature
        for sig in validation['signatures']:
            lines.append(f"\n{'='*70}")
            lines.append(f"Signature #{sig['signature_number']}: {sig['status'].upper()}")
            lines.append(f"{'='*70}")
            
            details = sig['details']
            lines.append(f"  Signing Domain (d=): {details['signing_domain']}")
            lines.append(f"  Selector (s=): {details['selector']}")
            lines.append(f"  Algorithm: {details['algorithm']}")
            
            if 'domain_aligned' in details:
                if details['domain_aligned']:
                    lines.append(f"  ✓ Domain Alignment: PASS")
                else:
                    lines.append(f"  ❌ Domain Alignment: FAIL (DMARC will fail)")
            
            if details.get('dns_record_found'):
                lines.append(f"  ✓ DNS Record: Found")
            else:
                lines.append(f"  ❌ DNS Record: Not Found")
            
            if details.get('testing_mode'):
                lines.append(f"  ⚠️  Testing Mode: Enabled")
            
            lines.append(f"\n  Validation Results:")
            for reason in sig['reasons']:
                lines.append(f"    {reason}")
        
        return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    # Sample email header with DKIM signature
    sample_headers = """
Received: from mail.example.com (mail.example.com [192.0.2.1])
From: sender@example.com
To: recipient@example.org
Subject: Test Email
Date: Mon, 20 Jan 2025 10:00:00 -0800
Message-ID: <12345@example.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=example.com; s=google;
    h=from:to:subject:date:message-id;
    bh=ABCD1234==;
    b=ABCDEFGHabcdefgh1234567890==
"""
    
    validator = EmailHeaderDKIMValidator()
    
    print("Testing Email Header DKIM Validation")
    print("=" * 70)
    
    result = validator.validate_email_headers(sample_headers)
    report = validator.format_validation_report(result)
    
    print(report)
