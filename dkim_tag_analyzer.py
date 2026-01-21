"""
COMPREHENSIVE DKIM TAG ANALYZER

Analyzes all DKIM record tags and flags issues:
- Required tags (v=, p=)
- Optional tags (k=, h=, t=, s=, n=, g=)
- Deprecated tags
- Security issues
- Best practice violations

Shows deep DKIM expertise beyond basic validation.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class DKIMTag:
    """DKIM tag definition"""
    name: str
    full_name: str
    required: bool
    deprecated: bool
    description: str
    valid_values: Optional[List[str]]
    security_sensitive: bool
    best_practice: Optional[str]

# Complete DKIM tag specifications (RFC 6376)
DKIM_TAG_SPECS = {
    'v': DKIMTag(
        name='v',
        full_name='Version',
        required=True,
        deprecated=False,
        description='DKIM version (must be DKIM1)',
        valid_values=['DKIM1'],
        security_sensitive=True,
        best_practice='Must be first tag and must be DKIM1'
    ),
    'p': DKIMTag(
        name='p',
        full_name='Public Key',
        required=True,
        deprecated=False,
        description='Base64-encoded public key data',
        valid_values=None,
        security_sensitive=True,
        best_practice='Use 2048-bit or 4096-bit RSA keys'
    ),
    'k': DKIMTag(
        name='k',
        full_name='Key Type',
        required=False,
        deprecated=False,
        description='Key type algorithm',
        valid_values=['rsa', 'ed25519'],
        security_sensitive=True,
        best_practice='RSA is default and most compatible. Ed25519 is modern but less supported.'
    ),
    'h': DKIMTag(
        name='h',
        full_name='Hash Algorithm',
        required=False,
        deprecated=False,
        description='Acceptable hash algorithms',
        valid_values=['sha1', 'sha256', 'sha1:sha256'],
        security_sensitive=True,
        best_practice='Use sha256 only. SHA-1 is deprecated for security.'
    ),
    't': DKIMTag(
        name='t',
        full_name='Flags',
        required=False,
        deprecated=False,
        description='Flags: y=testing mode, s=strict subdomain matching',
        valid_values=['y', 's', 'y:s', 's:y'],
        security_sensitive=True,
        best_practice='Remove t=y in production. Only use for testing.'
    ),
    's': DKIMTag(
        name='s',
        full_name='Service Type',
        required=False,
        deprecated=False,
        description='Service types allowed to use this key',
        valid_values=['email', '*'],
        security_sensitive=False,
        best_practice='Usually omitted (defaults to *). Use "email" to restrict to email only.'
    ),
    'n': DKIMTag(
        name='n',
        full_name='Notes',
        required=False,
        deprecated=False,
        description='Notes for administrators',
        valid_values=None,
        security_sensitive=False,
        best_practice='Optional. Can include key rotation date or contact info.'
    ),
    'g': DKIMTag(
        name='g',
        full_name='Granularity',
        required=False,
        deprecated=True,  # Deprecated in RFC 8301
        description='DEPRECATED - Local-part granularity',
        valid_values=None,
        security_sensitive=False,
        best_practice='REMOVE - This tag is deprecated and should not be used.'
    )
}

class DKIMTagAnalyzer:
    """
    Comprehensive DKIM record tag analyzer
    """
    
    def __init__(self, dkim_record: str):
        self.record = dkim_record
        self.tags = self._parse_tags()
        self.issues = []
        self.warnings = []
        self.recommendations = []
    
    def _parse_tags(self) -> Dict[str, str]:
        """Parse DKIM record into tags"""
        tags = {}
        
        # Split by semicolons
        parts = self.record.split(';')
        
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                tags[key.strip()] = value.strip()
        
        return tags
    
    def analyze(self) -> Dict:
        """
        Perform comprehensive tag analysis
        
        Returns detailed analysis with issues, warnings, and recommendations
        """
        # Check required tags
        self._check_required_tags()
        
        # Analyze each tag present
        for tag_name, tag_value in self.tags.items():
            if tag_name in DKIM_TAG_SPECS:
                self._analyze_tag(tag_name, tag_value)
            else:
                self.warnings.append({
                    'tag': tag_name,
                    'severity': 'low',
                    'message': f'Unknown tag "{tag_name}" - will be ignored by validators'
                })
        
        # Check tag ordering (v= should be first)
        self._check_tag_order()
        
        # Generate summary
        return self._generate_report()
    
    def _check_required_tags(self):
        """Check for required DKIM tags"""
        for tag_name, spec in DKIM_TAG_SPECS.items():
            if spec.required and tag_name not in self.tags:
                self.issues.append({
                    'tag': tag_name,
                    'severity': 'critical',
                    'message': f'Missing required tag "{tag_name}" ({spec.full_name})',
                    'impact': 'DKIM signature validation will FAIL'
                })
    
    def _analyze_tag(self, tag_name: str, tag_value: str):
        """Analyze individual tag"""
        spec = DKIM_TAG_SPECS[tag_name]
        
        # Check if deprecated
        if spec.deprecated:
            self.issues.append({
                'tag': tag_name,
                'severity': 'high',
                'message': f'Tag "{tag_name}" is DEPRECATED (RFC 8301)',
                'impact': 'Remove this tag - it serves no purpose',
                'recommendation': spec.best_practice
            })
            return
        
        # Validate tag value
        if spec.valid_values:
            # Check if value is in valid list
            value_parts = tag_value.replace(':', ' ').split()
            invalid_values = [v for v in value_parts if v not in spec.valid_values]
            
            if invalid_values:
                self.issues.append({
                    'tag': tag_name,
                    'severity': 'high',
                    'message': f'Invalid value for "{tag_name}": {tag_value}',
                    'impact': f'Valid values: {", ".join(spec.valid_values)}',
                    'recommendation': f'Use one of: {", ".join(spec.valid_values)}'
                })
        
        # Specific tag analysis
        self._analyze_specific_tag(tag_name, tag_value, spec)
    
    def _analyze_specific_tag(self, tag_name: str, tag_value: str, spec: DKIMTag):
        """Tag-specific analysis"""
        
        if tag_name == 'v':
            # Version check
            if tag_value != 'DKIM1':
                self.issues.append({
                    'tag': 'v',
                    'severity': 'critical',
                    'message': f'Invalid DKIM version: {tag_value}',
                    'impact': 'Must be DKIM1',
                    'recommendation': 'Change to v=DKIM1'
                })
        
        elif tag_name == 'p':
            # Public key check
            if not tag_value or tag_value.strip() == '':
                self.issues.append({
                    'tag': 'p',
                    'severity': 'critical',
                    'message': 'Empty public key (revoked key)',
                    'impact': 'All DKIM signatures will FAIL',
                    'recommendation': 'This indicates key revocation. Add new key if needed.'
                })
            else:
                # Estimate key size from base64 length
                key_len = len(tag_value)
                if key_len < 200:
                    self.warnings.append({
                        'tag': 'p',
                        'severity': 'high',
                        'message': '⚠️ Weak 1024-bit RSA key detected',
                        'impact': '1024-bit keys are deprecated for security',
                        'recommendation': 'Rotate to 2048-bit or 4096-bit key'
                    })
                elif key_len < 500:
                    self.recommendations.append({
                        'tag': 'p',
                        'severity': 'info',
                        'message': '✓ 2048-bit RSA key (good)',
                        'impact': 'Secure key size',
                        'recommendation': None
                    })
                else:
                    self.recommendations.append({
                        'tag': 'p',
                        'severity': 'info',
                        'message': '✓ 4096-bit RSA key (excellent)',
                        'impact': 'Very secure key size',
                        'recommendation': None
                    })
        
        elif tag_name == 'k':
            # Key type check
            if tag_value == 'rsa':
                self.recommendations.append({
                    'tag': 'k',
                    'severity': 'info',
                    'message': 'RSA key type (widely supported)',
                    'recommendation': None
                })
            elif tag_value == 'ed25519':
                self.warnings.append({
                    'tag': 'k',
                    'severity': 'medium',
                    'message': 'Ed25519 key type (modern but limited support)',
                    'impact': 'Some older validators may not support Ed25519',
                    'recommendation': 'Ensure your recipients support Ed25519'
                })
        
        elif tag_name == 'h':
            # Hash algorithm check
            if 'sha1' in tag_value.lower() and 'sha256' not in tag_value.lower():
                self.issues.append({
                    'tag': 'h',
                    'severity': 'high',
                    'message': '⚠️ SHA-1 only (deprecated for security)',
                    'impact': 'SHA-1 is cryptographically weak',
                    'recommendation': 'Use h=sha256 instead'
                })
            elif 'sha256' in tag_value.lower():
                self.recommendations.append({
                    'tag': 'h',
                    'severity': 'info',
                    'message': '✓ SHA-256 hash algorithm (secure)',
                    'recommendation': None
                })
        
        elif tag_name == 't':
            # Flags check
            if 'y' in tag_value:
                self.warnings.append({
                    'tag': 't',
                    'severity': 'high',
                    'message': '⚠️ TESTING MODE enabled (t=y)',
                    'impact': 'Key is marked as testing - not for production',
                    'recommendation': 'Remove t=y flag for production use'
                })
            if 's' in tag_value:
                self.recommendations.append({
                    'tag': 't',
                    'severity': 'info',
                    'message': 'Strict subdomain matching enabled (t=s)',
                    'impact': 'DKIM d= must exactly match From domain',
                    'recommendation': None
                })
        
        elif tag_name == 's':
            # Service type
            if tag_value == 'email':
                self.recommendations.append({
                    'tag': 's',
                    'severity': 'info',
                    'message': 'Restricted to email service only',
                    'recommendation': None
                })
            elif tag_value == '*':
                self.recommendations.append({
                    'tag': 's',
                    'severity': 'info',
                    'message': 'Allows all service types',
                    'recommendation': None
                })
        
        elif tag_name == 'n':
            # Notes - informational only
            self.recommendations.append({
                'tag': 'n',
                'severity': 'info',
                'message': f'Administrator notes: {tag_value}',
                'recommendation': None
            })
    
    def _check_tag_order(self):
        """Check if v= is the first tag (RFC recommendation)"""
        if self.tags:
            first_tag = list(self.tags.keys())[0]
            if first_tag != 'v':
                self.warnings.append({
                    'tag': 'ordering',
                    'severity': 'low',
                    'message': 'RFC recommends v= as first tag',
                    'impact': 'Not critical but best practice',
                    'recommendation': 'Move v=DKIM1 to beginning of record'
                })
    
    def _generate_report(self) -> Dict:
        """Generate comprehensive analysis report"""
        
        # Count present tags by category
        required_tags = [t for t in self.tags if DKIM_TAG_SPECS.get(t, DKIMTag('', '', False, False, '', None, False, None)).required]
        optional_tags = [t for t in self.tags if not DKIM_TAG_SPECS.get(t, DKIMTag('', '', False, False, '', None, False, None)).required and t in DKIM_TAG_SPECS]
        deprecated_tags = [t for t in self.tags if DKIM_TAG_SPECS.get(t, DKIMTag('', '', False, False, '', None, False, None)).deprecated]
        unknown_tags = [t for t in self.tags if t not in DKIM_TAG_SPECS]
        
        # Overall status
        if self.issues:
            status = 'FAIL' if any(i['severity'] == 'critical' for i in self.issues) else 'WARNING'
            status_icon = '❌' if status == 'FAIL' else '⚠️'
        else:
            status = 'PASS'
            status_icon = '✓'
        
        return {
            'status': status,
            'status_icon': status_icon,
            'tags': self.tags,
            'tag_counts': {
                'required': len(required_tags),
                'optional': len(optional_tags),
                'deprecated': len(deprecated_tags),
                'unknown': len(unknown_tags)
            },
            'issues': self.issues,
            'warnings': self.warnings,
            'recommendations': self.recommendations,
            'summary': self._generate_summary(status)
        }
    
    def _generate_summary(self, status: str) -> str:
        """Generate human-readable summary"""
        lines = []
        lines.append(f"\n🔍 DKIM TAG ANALYSIS")
        lines.append("=" * 60)
        
        # Tags present
        lines.append(f"\n📋 Tags Present:")
        for tag_name, tag_value in self.tags.items():
            spec = DKIM_TAG_SPECS.get(tag_name)
            if spec:
                req_indicator = " (required)" if spec.required else ""
                dep_indicator = " [DEPRECATED]" if spec.deprecated else ""
                lines.append(f"  • {tag_name}= — {spec.full_name}{req_indicator}{dep_indicator}")
            else:
                lines.append(f"  • {tag_name}= — Unknown tag")
        
        # Issues
        if self.issues:
            lines.append(f"\n❌ ISSUES ({len(self.issues)}):")
            for issue in self.issues:
                lines.append(f"  • [{issue['severity'].upper()}] {issue['message']}")
                if 'recommendation' in issue and issue['recommendation']:
                    lines.append(f"    → {issue['recommendation']}")
        
        # Warnings
        if self.warnings:
            lines.append(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                lines.append(f"  • {warning['message']}")
                if 'recommendation' in warning and warning['recommendation']:
                    lines.append(f"    → {warning['recommendation']}")
        
        # Recommendations
        good_practices = [r for r in self.recommendations if r.get('message', '').startswith('✓')]
        if good_practices:
            lines.append(f"\n✓ GOOD PRACTICES:")
            for rec in good_practices:
                lines.append(f"  • {rec['message']}")
        
        return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    # Test various DKIM records
    
    test_records = [
        # Good record
        ("Good Record", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"),
        
        # Record with deprecated tags
        ("Deprecated Tag", "v=DKIM1; k=rsa; g=*; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
        
        # Testing mode
        ("Testing Mode", "v=DKIM1; k=rsa; t=y; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
        
        # Weak key
        ("Weak Key", "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNA"),
        
        # SHA-1 only
        ("SHA-1 Hash", "v=DKIM1; k=rsa; h=sha1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
    ]
    
    for name, record in test_records:
        print(f"\n{'='*70}")
        print(f"Testing: {name}")
        print('=' * 70)
        
        analyzer = DKIMTagAnalyzer(record)
        results = analyzer.analyze()
        
        print(results['summary'])
        print(f"\nOverall Status: {results['status_icon']} {results['status']}")
