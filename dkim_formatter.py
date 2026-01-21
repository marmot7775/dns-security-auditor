"""
Clean DKIM Output Formatter
Produces actionable, security-focused DKIM summaries

Shows:
- Found selectors with key strength
- Security warnings (weak keys, missing signatures)
- Actionable recommendations
"""

from typing import List, Dict, Optional
import re

def analyze_dkim_key_strength(dkim_record: str) -> Dict:
    """
    Analyze DKIM key strength and return security assessment.
    
    Returns:
        dict with key_type, key_bits, status, warning
    """
    result = {
        'key_type': 'Unknown',
        'key_bits': 0,
        'status': 'unknown',
        'warning': None
    }
    
    # Extract public key
    key_match = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_record)
    if not key_match:
        result['status'] = 'invalid'
        result['warning'] = 'No public key found'
        return result
    
    key_data = key_match.group(1)
    
    # Determine key type (RSA is most common)
    if 'k=rsa' in dkim_record or 'p=' in dkim_record:
        result['key_type'] = 'RSA'
        
        # Estimate key size from base64 length
        # RSA 1024-bit ≈ 172 base64 chars
        # RSA 2048-bit ≈ 344 base64 chars
        # RSA 4096-bit ≈ 684 base64 chars
        key_len = len(key_data)
        
        if key_len < 200:
            result['key_bits'] = 1024
            result['status'] = 'weak'
            result['warning'] = '⚠️  Weak - 1024-bit keys deprecated'
        elif key_len < 500:
            result['key_bits'] = 2048
            result['status'] = 'strong'
        else:
            result['key_bits'] = 4096
            result['status'] = 'strong'
    elif 'k=ed25519' in dkim_record:
        result['key_type'] = 'Ed25519'
        result['key_bits'] = 256  # Ed25519 is always 256-bit
        result['status'] = 'strong'
    
    return result

def format_dkim_summary(domain: str, dkim_results: Dict, show_intelligence: bool = True) -> str:
    """
    Format DKIM results in clean, actionable summary style.
    
    Args:
        domain: Domain being checked
        dkim_results: Results from smart_dkim_check()
        show_intelligence: Whether to show SPF-based vendor detection
        
    Returns:
        Formatted summary string
    """
    output = []
    
    # Header
    output.append(f"DKIM Summary for {domain}")
    output.append("─" * (len(f"DKIM Summary for {domain}")))
    
    # Show SPF intelligence if available
    if show_intelligence and dkim_results.get('intelligence_report'):
        output.append("")
        output.append(dkim_results['intelligence_report'].strip())
    
    output.append("")
    
    # Found selectors
    found = dkim_results.get('found_selectors', [])
    
    if found:
        for selector_info in found:
            selector = selector_info['selector']
            record = selector_info.get('record', '')
            
            # Analyze key strength
            key_analysis = analyze_dkim_key_strength(record)
            
            # Format output line
            if key_analysis['status'] == 'strong':
                status_icon = "✓"
                key_desc = f"Valid ({key_analysis['key_bits']}-bit {key_analysis['key_type']} key)"
            elif key_analysis['status'] == 'weak':
                status_icon = "✓"
                key_desc = f"Valid ({key_analysis['key_bits']}-bit {key_analysis['key_type']} key) {key_analysis['warning']}"
            else:
                status_icon = "⚠️"
                key_desc = f"Found but {key_analysis['warning']}"
            
            # Show FQDN if available
            fqdn = selector_info.get('fqdn', f"{selector}._domainkey.{domain}")
            fqdn_display = f" ({fqdn})" if fqdn else ""
            
            # Show vendor if detected
            vendor_note = ""
            if selector_info.get('vendor'):
                vendor_note = f" [{selector_info['vendor']}]"
            
            output.append(f"{status_icon} Selector: **{selector}**{fqdn_display} — {key_desc}{vendor_note}")
            output.append("")  # Add blank line between selectors for readability
    
    # Show tested but not found (only high-priority ones)
    tested_count = dkim_results.get('tested_count', 0)
    if tested_count > len(found):
        # Don't list all missing selectors - just note how many were tested
        missing_count = tested_count - len(found)
        if missing_count <= 5:
            # If only a few missing, could show them
            output.append(f"ℹ️  Tested {missing_count} additional selector(s) - not found")
    
    output.append("")
    
    # Generate recommendations
    recommendations = generate_dkim_recommendations(dkim_results, domain)
    if recommendations:
        output.append("Top Recommendations:")
        for rec in recommendations:
            output.append(f"→ {rec}")
    
    # Summary stats
    output.append("")
    output.append(f"Tested {tested_count} selectors, found {len(found)}")
    if dkim_results.get('discovery_method') == 'spf_intelligent':
        output.append("✨ Used SPF intelligence for faster discovery")
    
    return "\n".join(output)

def generate_dkim_recommendations(dkim_results: Dict, domain: str) -> List[str]:
    """Generate actionable DKIM recommendations"""
    recommendations = []
    found = dkim_results.get('found_selectors', [])
    
    if not found:
        recommendations.append(f"Enable DKIM signing for {domain}")
        recommendations.append("Contact your email provider for DKIM setup instructions")
        return recommendations
    
    # Check for weak keys
    weak_selectors = []
    for selector_info in found:
        key_analysis = analyze_dkim_key_strength(selector_info.get('record', ''))
        if key_analysis['status'] == 'weak':
            weak_selectors.append(selector_info['selector'])
    
    if weak_selectors:
        for selector in weak_selectors:
            recommendations.append(f"Rotate '{selector}' to use 2048-bit or stronger key")
    
    # Check DMARC alignment
    recommendations.append("Verify DKIM domain (d=) aligns with From domain for DMARC to pass")
    
    # Vendor-specific recommendations
    vendors = dkim_results.get('vendors_detected', [])
    if vendors:
        for vendor in vendors:
            # Check if we found selectors for this vendor
            vendor_name = vendor['vendor']
            expected_selectors = vendor['dkim_selectors']
            found_selectors = [s['selector'] for s in found]
            
            missing = [s for s in expected_selectors if s not in found_selectors]
            if missing and len(missing) <= 2:  # Don't spam if many missing
                recommendations.append(f"Check if {vendor_name} has additional selectors: {', '.join(missing[:2])}")
    
    # Generic best practice
    if len(found) == 1:
        recommendations.append("Consider implementing DKIM key rotation strategy")
    
    return recommendations[:3]  # Top 3 recommendations

def format_dkim_detailed(domain: str, dkim_results: Dict) -> str:
    """
    Detailed DKIM output showing full records (for technical users)
    """
    output = []
    
    output.append(f"Detailed DKIM Analysis for {domain}")
    output.append("=" * 60)
    output.append("")
    
    found = dkim_results.get('found_selectors', [])
    
    for i, selector_info in enumerate(found, 1):
        output.append(f"Selector #{i}: {selector_info['selector']}")
        output.append(f"FQDN: {selector_info['fqdn']}")
        
        # Key analysis
        key_analysis = analyze_dkim_key_strength(selector_info.get('record', ''))
        output.append(f"Key Type: {key_analysis['key_type']} {key_analysis['key_bits']}-bit")
        output.append(f"Status: {key_analysis['status'].upper()}")
        
        if key_analysis['warning']:
            output.append(f"Warning: {key_analysis['warning']}")
        
        if selector_info.get('vendor'):
            output.append(f"Vendor: {selector_info['vendor']}")
        
        # Full record
        output.append(f"Record: {selector_info.get('record', '')[:200]}...")
        output.append("")
    
    return "\n".join(output)

# Example usage
if __name__ == "__main__":
    # Simulate results from smart_dkim_check
    sample_results = {
        'domain': 'example.com',
        'vendors_detected': [
            {
                'vendor': 'Google Workspace',
                'dkim_selectors': ['google', 'googlemail'],
                'spf_include': '_spf.google.com'
            },
            {
                'vendor': 'Microsoft 365',
                'dkim_selectors': ['selector1', 'selector2'],
                'spf_include': 'spf.protection.outlook.com'
            }
        ],
        'found_selectors': [
            {
                'selector': 'google',
                'fqdn': 'google._domainkey.example.com',
                'record': 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                'vendor': 'Google Workspace',
                'key_type': 'RSA 2048-bit'
            },
            {
                'selector': 'selector1',
                'fqdn': 'selector1._domainkey.example.com',
                'record': 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1234567890abcdefghijklmnopqrstuvwxyz',
                'vendor': 'Microsoft 365',
                'key_type': 'RSA 1024-bit'
            },
        ],
        'tested_count': 8,
        'discovery_method': 'spf_intelligent',
        'intelligence_report': '''🔍 INTELLIGENT DISCOVERY (from SPF analysis):

📧 Email Provider:
  • Google Workspace
    SPF: include:_spf.google.com
    Testing selectors: google, googlemail

  • Microsoft 365
    SPF: include:spf.protection.outlook.com
    Testing selectors: selector1, selector2'''
    }
    
    # Print clean summary
    print(format_dkim_summary('example.com', sample_results, show_intelligence=True))
    print("\n" + "=" * 70 + "\n")
    
    # Print detailed view
    print(format_dkim_detailed('example.com', sample_results))
