"""
DER decoding for DKIM RSA public keys.

Only what the live audit path uses. ``dkim_formatter.analyze_dkim_key_strength``
is the single public entry point for DKIM key grading, and it imports
``_decode_rsa_key_bits`` from here; nothing else in the application imported
anything else from this module.

What was removed: a second, parallel DKIM validator (``DKIMValidator``,
``DKIMTagAnalyzer``, ``validate_dkim``, ~660 lines) that nothing in the audit
called. It was reachable only from its own tests, which kept it green and made
it look covered while it drifted away from the path that actually ships. It had
also accumulated three wrong citations that would have become user-facing the
moment anyone wired it in: it attributed a "NOT RECOMMENDED" verdict on
1024-bit keys to RFC 8301, which instead says signers "MUST use RSA keys of at
least 1024 bits" and "SHOULD use RSA keys of at least 2048 bits"; it reported
SHA-1 as "NOT RECOMMENDED" by RFC 8301, which actually says "rsa-sha1 MUST NOT
be used for signing or verifying"; and it credited RFC 8301 with deprecating
the g= tag, which that RFC never mentions (g= was defined in RFC 4871 and is
absent from RFC 6376).
"""

import base64
from typing import Optional, Tuple


def _decode_rsa_key_bits(b64_data: str) -> Optional[int]:
    """Decode an RSA SubjectPublicKeyInfo DER blob and return the modulus bit length.

    Every declared ASN.1 length is checked against the bytes actually
    present. A DER length header is a claim, not a guarantee: a TXT value
    truncated by a DNS provider still carries the original header, so
    trusting mod_len alone reports a 60-character fragment of a 2048-bit key
    as a healthy 2048-bit key while every signature it made fails.
    """
    try:
        raw = base64.b64decode(b64_data)
    except Exception:
        return None

    try:
        if raw[0] != 0x30:
            return None
        idx = 1
        idx, _ = _asn1_length(raw, idx)

        # Skip algorithm identifier SEQUENCE
        if raw[idx] != 0x30:
            return None
        idx += 1
        idx, algo_len = _asn1_length(raw, idx)
        if idx + algo_len > len(raw):
            return None
        idx += algo_len

        # BIT STRING
        if raw[idx] != 0x03:
            return None
        idx += 1
        idx, bs_len = _asn1_length(raw, idx)
        if idx + bs_len > len(raw):
            return None
        idx += 1  # skip unused-bits byte

        # Inner SEQUENCE
        if raw[idx] != 0x30:
            return None
        idx += 1
        idx, seq_len = _asn1_length(raw, idx)
        if idx + seq_len > len(raw):
            return None

        # First INTEGER = modulus
        if raw[idx] != 0x02:
            return None
        idx += 1
        idx, mod_len = _asn1_length(raw, idx)
        if idx + mod_len > len(raw):
            return None

        # Leading zero byte for positive integers
        if raw[idx] == 0x00:
            mod_len -= 1

        if mod_len <= 0:
            return None

        return mod_len * 8
    except (IndexError, ValueError):
        return None


def _asn1_length(data: bytes, idx: int) -> Tuple[int, int]:
    if idx >= len(data):
        raise ValueError("Truncated ASN.1 data")
    b = data[idx]
    if b < 0x80:
        return idx + 1, b
    num_bytes = b & 0x7F
    if idx + 1 + num_bytes > len(data):
        raise ValueError("Truncated ASN.1 length")
    length = int.from_bytes(data[idx + 1: idx + 1 + num_bytes], "big")
    return idx + 1 + num_bytes, length
