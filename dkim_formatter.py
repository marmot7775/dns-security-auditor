"""
DKIM key strength analysis.

analyze_dkim_key_strength() is the only public function; audit_engine,
result_transformer and spf_intelligence use it to grade a selector's key.
"""

from typing import Dict
import re

from dkim_tag_analyzer import _decode_rsa_key_bits

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
    
    # Extract public key data first (may be empty). Per RFC 6376 §3.6.1, an
    # empty p= means the key is REVOKED -- this must be checked before the
    # Ed25519 shortcut below, which otherwise returns 'strong' without ever
    # looking at whether the key was revoked.
    key_match = re.search(r'p=([A-Za-z0-9+/=]*)', dkim_record)
    if not key_match:
        result['status'] = 'invalid'
        result['warning'] = 'No public key found'
        return result

    key_data = key_match.group(1)

    if not key_data:
        result['status'] = 'invalid'
        result['warning'] = 'Empty public key (p=): this key is revoked'
        return result

    # Check Ed25519 (all records have a non-empty p= at this point)
    if 'k=ed25519' in dkim_record.lower():
        result['key_type'] = 'Ed25519'
        result['key_bits'] = 256
        result['status'] = 'strong'
        return result

    # RSA (default key type per RFC 6376)
    result['key_type'] = 'RSA'

    # Decode the DER SubjectPublicKeyInfo to get the real modulus bit
    # length. Guessing from base64 string length is unreliable: a real
    # 1024-bit key's SPKI is 216 base64 chars, not ~172.
    key_bits = _decode_rsa_key_bits(key_data)
    if key_bits is None:
        result['status'] = 'invalid'
        result['warning'] = 'Could not decode RSA public key'
        return result

    result['key_bits'] = key_bits
    if key_bits < 2048:
        result['status'] = 'weak'
        result['warning'] = f'{key_bits}-bit RSA key, upgrade to 2048-bit'
    else:
        result['status'] = 'strong'

    return result
