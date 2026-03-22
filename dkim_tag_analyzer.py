"""
COMPREHENSIVE DKIM RECORD VALIDATOR

Validates every aspect of a DKIM TXT record:
  - DNS-level issues (multiple TXT records, wildcards, CNAMEs)
  - Record syntax (semicolons, duplicate tags, ordering)
  - Tag validity per RFC 6376 / RFC 8301 / RFC 8463
  - Key integrity (base64, DER/ASN.1 decode, actual bit length)
  - Security posture (algorithm, key size, flags)
  - Deprecated / unknown tags

Every issue carries a priority tier:
  P0  CRITICAL  - DKIM validation WILL fail (broken record, revoked key, missing p=)
  P1  HIGH      - Significant security risk (weak key, SHA-1 only, invalid value)
  P2  MEDIUM    - Operational concern (test mode in production, ed25519 compat)
  P3  LOW       - Best-practice deviation (tag ordering, missing v=, notes)
  P4  INFO      - Informational observation (key size, service type)
"""

import base64
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver


# ----------------------------------------------------------------
# Priority tiers
# ----------------------------------------------------------------

class Priority(IntEnum):
    P0_CRITICAL = 0
    P1_HIGH = 1
    P2_MEDIUM = 2
    P3_LOW = 3
    P4_INFO = 4


PRIORITY_LABELS = {
    Priority.P0_CRITICAL: ("P0", "CRITICAL", "error"),
    Priority.P1_HIGH:     ("P1", "HIGH",     "error"),
    Priority.P2_MEDIUM:   ("P2", "MEDIUM",   "warning"),
    Priority.P3_LOW:      ("P3", "LOW",      "warning"),
    Priority.P4_INFO:     ("P4", "INFO",     "info"),
}


@dataclass
class DKIMIssue:
    priority: Priority
    tag: str            # which tag or "dns" / "syntax" / "record"
    title: str          # short label
    detail: str         # plain-English explanation
    fix: Optional[str] = None
    impact: Optional[str] = None

    @property
    def level_code(self) -> str:
        return PRIORITY_LABELS[self.priority][0]

    @property
    def level_name(self) -> str:
        return PRIORITY_LABELS[self.priority][1]

    @property
    def ui_type(self) -> str:
        return PRIORITY_LABELS[self.priority][2]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "priority": self.priority.value,
            "level": self.level_code,
            "severity": self.level_name.lower(),
            "tag": self.tag,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
            "impact": self.impact,
            "ui_type": self.ui_type,
        }


# ----------------------------------------------------------------
# Tag specifications - RFC 6376 + RFC 8301 + RFC 8463
# ----------------------------------------------------------------

@dataclass
class TagSpec:
    name: str
    full_name: str
    required: bool
    deprecated: bool
    valid_values: Optional[List[str]]
    security_sensitive: bool
    default: Optional[str]
    description: str


TAG_SPECS: Dict[str, TagSpec] = {
    "v": TagSpec("v", "Version", True, False, ["DKIM1"], True, "DKIM1",
                 "DKIM key record version. Must be DKIM1."),
    "p": TagSpec("p", "Public Key", True, False, None, True, None,
                 "Base64-encoded public key data. Empty = revoked."),
    "k": TagSpec("k", "Key Type", False, False, ["rsa", "ed25519"], True, "rsa",
                 "Cryptographic algorithm for the key."),
    "h": TagSpec("h", "Hash Algorithms", False, False, ["sha1", "sha256"], True, "* (allow all)",
                 "Acceptable hash algorithms (colon-separated)."),
    "t": TagSpec("t", "Flags", False, False, ["y", "s"], True, "(no flags)",
                 "y = testing mode, s = strict domain match."),
    "s": TagSpec("s", "Service Type", False, False, ["email", "*"], False, "* (allow all)",
                 "Which services may use this key."),
    "n": TagSpec("n", "Notes", False, False, None, False, "(empty)",
                 "Human-readable notes."),
    "g": TagSpec("g", "Granularity", False, True, None, False, "* (match all)",
                 "DEPRECATED in RFC 8301. Remove this tag."),
}


# ----------------------------------------------------------------
# Key size decoder - parse DER, don't guess
# ----------------------------------------------------------------

def _decode_rsa_key_bits(b64_data: str) -> Optional[int]:
    """Decode an RSA SubjectPublicKeyInfo DER blob and return the modulus bit length."""
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
        idx += algo_len

        # BIT STRING
        if raw[idx] != 0x03:
            return None
        idx += 1
        idx, bs_len = _asn1_length(raw, idx)
        idx += 1  # skip unused-bits byte

        # Inner SEQUENCE
        if raw[idx] != 0x30:
            return None
        idx += 1
        idx, _ = _asn1_length(raw, idx)

        # First INTEGER = modulus
        if raw[idx] != 0x02:
            return None
        idx += 1
        idx, mod_len = _asn1_length(raw, idx)

        # Leading zero byte for positive integers
        if raw[idx] == 0x00:
            mod_len -= 1

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


def _estimate_key_bits_fallback(b64_data: str) -> int:
    n = len(b64_data)
    if n < 200:
        return 1024
    elif n < 500:
        return 2048
    elif n < 900:
        return 4096
    return 8192


# ----------------------------------------------------------------
# DNS-level checks
# ----------------------------------------------------------------

def _dns_lookup_dkim(domain: str, selector: str, timeout: int = 5) -> Dict[str, Any]:
    fqdn = f"{selector}._domainkey.{domain}"
    result: Dict[str, Any] = {
        "fqdn": fqdn,
        "txt_records": [],
        "cname_target": None,
        "error": None,
        "nxdomain": False,
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        cname_answers = resolver.resolve(fqdn, "CNAME")
        result["cname_target"] = str(list(cname_answers)[0].target).rstrip(".")
    except Exception:
        pass

    try:
        answers = resolver.resolve(fqdn, "TXT")
        for rdata in answers:
            txt = "".join(
                p.decode("utf-8", errors="replace") if isinstance(p, bytes) else str(p)
                for p in rdata.strings
            )
            result["txt_records"].append(txt)
    except dns.resolver.NXDOMAIN:
        result["nxdomain"] = True
        result["error"] = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result["error"] = "NoAnswer"
    except dns.resolver.NoNameservers:
        result["error"] = "SERVFAIL"
    except Exception as exc:
        result["error"] = str(exc)

    return result


# ----------------------------------------------------------------
# Main validator
# ----------------------------------------------------------------

class DKIMValidator:
    """
    Comprehensive DKIM record validator.

    Usage:
        v = DKIMValidator(domain="example.com", selector="google")
        report = v.validate()
    """

    def __init__(self, domain: str, selector: str, *,
                 record: Optional[str] = None,
                 dns_result: Optional[Dict] = None):
        self.domain = domain
        self.selector = selector
        self._record = record
        self._dns_result = dns_result
        self.issues: List[DKIMIssue] = []
        self.tags: Dict[str, str] = {}
        self.key_bits: Optional[int] = None
        self.key_type: str = "rsa"

    def validate(self) -> Dict[str, Any]:
        dns_info = self._dns_result or _dns_lookup_dkim(self.domain, self.selector)
        self._check_dns(dns_info)

        dkim_records = [
            r for r in dns_info["txt_records"]
            if "p=" in r and not r.strip().lower().startswith("v=spf1")
        ]

        if not dkim_records:
            if not dns_info["error"]:
                self.issues.append(DKIMIssue(
                    Priority.P0_CRITICAL, "dns",
                    "No DKIM record at this selector",
                    f"No TXT record containing a DKIM public key was found at "
                    f"{self.selector}._domainkey.{self.domain}.",
                    fix="Publish a DKIM TXT record at this selector, or verify the selector name.",
                    impact="DKIM signature verification will fail for all messages signed with this selector.",
                ))
            return self._build_report(dns_info, None)

        record = self._record if self._record else dkim_records[0]
        self._check_syntax(record)
        self.tags = self._parse_tags(record)
        self._check_tags()
        self._check_key()
        return self._build_report(dns_info, record)

    # -- DNS checks ---

    def _check_dns(self, dns_info: Dict):
        fqdn = dns_info["fqdn"]

        if dns_info["nxdomain"]:
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "dns",
                "Selector does not exist (NXDOMAIN)",
                f"The DNS name {fqdn} does not exist.",
                fix="Check the selector name. Common selectors: google, selector1, selector2, k1, default.",
                impact="DKIM verification fails.",
            ))
            return

        if dns_info["error"] == "SERVFAIL":
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "dns",
                "DNS resolution failed (SERVFAIL)",
                f"DNS query for {fqdn} returned SERVFAIL. This may indicate a DNSSEC validation "
                "failure or unreachable nameservers.",
                fix="Check DNSSEC chain and nameserver health.",
                impact="DKIM verification fails.",
            ))
            return

        if dns_info["error"] == "NoAnswer":
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "dns",
                "No TXT records at selector",
                f"The DNS name {fqdn} exists but has no TXT records.",
                fix="Publish a TXT record containing the DKIM public key.",
                impact="DKIM verification fails.",
            ))
            return

        txt_records = dns_info["txt_records"]
        dkim_records = [r for r in txt_records if "p=" in r and not r.strip().lower().startswith("v=spf1")]

        if len(dkim_records) > 1:
            self.issues.append(DKIMIssue(
                Priority.P1_HIGH, "dns",
                "Multiple DKIM TXT records at same selector",
                f"Found {len(dkim_records)} DKIM records at {fqdn}. RFC 6376 specifies exactly one.",
                fix="Remove duplicate DKIM TXT records so only one remains.",
                impact="Unpredictable DKIM validation.",
            ))

        non_dkim = [r for r in txt_records if "p=" not in r]
        if non_dkim and dkim_records:
            for r in non_dkim:
                if r.strip().lower().startswith("v=spf1") or "google-site-verification" in r.lower():
                    self.issues.append(DKIMIssue(
                        Priority.P1_HIGH, "dns",
                        "Possible wildcard TXT record",
                        f"Non-DKIM TXT records appeared at {fqdn}. This suggests a DNS wildcard "
                        "is matching the DKIM query.",
                        fix="Remove the wildcard TXT record or add an explicit record at this selector.",
                        impact="DKIM verification may use a wrong key.",
                    ))
                    break

        if dns_info.get("cname_target"):
            self.issues.append(DKIMIssue(
                Priority.P4_INFO, "dns",
                f"CNAME to {dns_info['cname_target']}",
                f"Selector is a CNAME pointing to {dns_info['cname_target']}. "
                "Common for hosted DKIM (Google, Microsoft).",
            ))

    # -- Syntax checks ---

    def _check_syntax(self, record: str):
        if ";;" in record:
            self.issues.append(DKIMIssue(
                Priority.P3_LOW, "syntax",
                "Double semicolons in record",
                "The record contains ';;' which creates an empty tag.",
                fix="Remove the extra semicolon.",
            ))

        parts = record.split(";")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                self.issues.append(DKIMIssue(
                    Priority.P1_HIGH, "syntax",
                    f"Malformed tag segment: '{part[:40]}'",
                    f"Each tag must be 'name=value' format. '{part[:60]}' has no '='.",
                    fix="Fix the record syntax.",
                    impact="Validators may reject the entire record.",
                ))

            if "=" in part:
                tag_name = part.split("=", 1)[0].strip()
                if " " in tag_name or "\t" in tag_name:
                    self.issues.append(DKIMIssue(
                        Priority.P1_HIGH, "syntax",
                        f"Whitespace in tag name: '{tag_name}'",
                        "Tag names must not contain spaces. Missing semicolon?",
                        fix="Add a semicolon to separate the tags.",
                    ))

    # -- Tag parsing ---

    def _parse_tags(self, record: str) -> Dict[str, str]:
        tags: Dict[str, str] = {}
        seen: Dict[str, int] = {}

        for part in record.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            key, _, value = part.partition("=")
            key = key.strip()
            value = value.strip()

            if key in seen:
                seen[key] += 1
                self.issues.append(DKIMIssue(
                    Priority.P1_HIGH, key,
                    f"Duplicate tag: {key}=",
                    f"Tag '{key}' appears {seen[key] + 1} times. RFC 6376 says tags MUST NOT "
                    "be duplicated. Validators use the first occurrence.",
                    fix=f"Remove the duplicate '{key}=' tag.",
                    impact="Second value is silently ignored.",
                ))
            else:
                seen[key] = 0
                tags[key] = value

        return tags

    # -- Tag-level checks ---

    def _check_tags(self):
        # Required: p=
        if "p" not in self.tags:
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "p",
                "Missing required tag: p= (public key)",
                "The 'p' tag is the only REQUIRED tag. Without it, DKIM verification cannot happen.",
                fix="Add p=<base64-encoded-public-key> to the record.",
                impact="ALL DKIM signatures using this selector will fail.",
            ))

        # Recommended: v=
        if "v" not in self.tags:
            self.issues.append(DKIMIssue(
                Priority.P3_LOW, "v",
                "Missing recommended tag: v=DKIM1",
                "RFC 6376 recommends v=DKIM1 as the first tag. Some ISPs may mark DKIM as neutral.",
                fix="Add v=DKIM1 as the first tag.",
                impact="Minor - some validators may treat the check as neutral.",
            ))
        elif self.tags.get("v") != "DKIM1":
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "v",
                f"Invalid version: v={self.tags['v']}",
                "Version must be exactly 'DKIM1'.",
                fix="Change to v=DKIM1",
                impact="DKIM verification will fail.",
            ))

        # Tag ordering
        if self.tags and list(self.tags.keys())[0] != "v" and "v" in self.tags:
            self.issues.append(DKIMIssue(
                Priority.P3_LOW, "v",
                "v= tag is not the first tag",
                "RFC 6376 says v= MUST be first if present.",
                fix="Move v=DKIM1 to the beginning of the record.",
            ))

        # Key type
        k_val = self.tags.get("k", "rsa").lower()
        self.key_type = k_val
        if k_val not in ("rsa", "ed25519"):
            self.issues.append(DKIMIssue(
                Priority.P1_HIGH, "k",
                f"Unknown key type: k={k_val}",
                f"'{k_val}' is not recognized. Valid: rsa, ed25519.",
                fix="Use k=rsa or k=ed25519.",
                impact="Validators MUST ignore records with unknown key types.",
            ))

        if k_val == "ed25519":
            self.issues.append(DKIMIssue(
                Priority.P2_MEDIUM, "k",
                "Ed25519 key type - limited receiver support",
                "Ed25519 is modern and secure but not universally supported. "
                "Consider dual-signing with RSA.",
                fix="Add an RSA key as backup if needed.",
                impact="May fail at receivers that don't support Ed25519.",
            ))

        # Hash algorithms
        h_val = self.tags.get("h", "")
        if h_val:
            algos = [a.strip().lower() for a in h_val.split(":")]
            if "sha1" in algos and "sha256" not in algos:
                self.issues.append(DKIMIssue(
                    Priority.P1_HIGH, "h",
                    "SHA-1 only - cryptographically weak",
                    "SHA-1 has known collision vulnerabilities. RFC 8301 says NOT RECOMMENDED.",
                    fix="Change to h=sha256.",
                    impact="Some receivers may reject. Security is degraded.",
                ))
            elif "sha1" in algos and "sha256" in algos:
                self.issues.append(DKIMIssue(
                    Priority.P2_MEDIUM, "h",
                    "SHA-1 still permitted alongside SHA-256",
                    "Allowing SHA-1 is unnecessary.",
                    fix="Change to h=sha256 (remove sha1).",
                ))
            for algo in algos:
                if algo not in ("sha1", "sha256"):
                    self.issues.append(DKIMIssue(
                        Priority.P1_HIGH, "h",
                        f"Unknown hash algorithm: {algo}",
                        f"'{algo}' is not a recognized DKIM hash algorithm.",
                        fix="Use sha256.",
                    ))

        # Flags
        t_val = self.tags.get("t", "")
        if t_val:
            flags = [f.strip().lower() for f in t_val.split(":")]
            if "y" in flags:
                self.issues.append(DKIMIssue(
                    Priority.P2_MEDIUM, "t",
                    "Testing mode enabled (t=y)",
                    "Receivers treat t=y signatures as unverified. This DKIM selector cannot contribute to DMARC alignment.",
                    fix="Remove t=y when DKIM signing is confirmed working.",
                    impact="DKIM from this selector does not count toward DMARC pass.",
                ))
            if "s" in flags:
                self.issues.append(DKIMIssue(
                    Priority.P4_INFO, "t",
                    "Strict subdomain matching (t=s)",
                    "The i= domain must exactly match d=. Subdomains rejected.",
                ))
            for f in flags:
                if f not in ("y", "s"):
                    self.issues.append(DKIMIssue(
                        Priority.P3_LOW, "t",
                        f"Unknown flag: {f}",
                        f"'{f}' is not recognized. Validators will ignore it.",
                    ))

        # Service type
        s_val = self.tags.get("s", "")
        if s_val and s_val not in ("*", "email"):
            self.issues.append(DKIMIssue(
                Priority.P2_MEDIUM, "s",
                f"Non-standard service type: s={s_val}",
                f"'{s_val}' is not recognized. Valid: * or email.",
                fix="Use s=email or remove the tag.",
            ))

        # Deprecated: g=
        if "g" in self.tags:
            self.issues.append(DKIMIssue(
                Priority.P2_MEDIUM, "g",
                "Deprecated tag: g= (granularity)",
                "Deprecated in RFC 8301. Ignored by modern validators.",
                fix="Remove the g= tag.",
            ))

        # Unknown tags
        for tag_name in self.tags:
            if tag_name not in TAG_SPECS:
                self.issues.append(DKIMIssue(
                    Priority.P3_LOW, tag_name,
                    f"Unknown tag: {tag_name}=",
                    f"'{tag_name}' is not defined in RFC 6376. Validators will ignore it.",
                    fix=f"Remove the '{tag_name}=' tag.",
                ))

    # -- Key integrity checks ---

    def _check_key(self):
        p_val = self.tags.get("p")
        if p_val is None:
            return

        # Revoked key
        if p_val.strip() == "":
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "p",
                "Key has been REVOKED (p= is empty)",
                "An empty p= means this key was intentionally revoked. "
                "All DKIM signatures using this selector will fail.",
                fix="Republish the key or rotate to a new selector.",
                impact="ALL messages signed with this selector fail DKIM.",
            ))
            return

        clean_b64 = re.sub(r"\s+", "", p_val)

        # Base64 validity
        try:
            raw_bytes = base64.b64decode(clean_b64, validate=True)
        except Exception:
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "p",
                "Invalid base64 in public key",
                "The p= value cannot be decoded as base64. Copy-paste error?",
                fix="Regenerate the DKIM key pair and publish the correct public key.",
                impact="DKIM verification will fail.",
            ))
            return

        if len(raw_bytes) < 10:
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "p",
                "Public key data too short",
                f"Decoded key is only {len(raw_bytes)} bytes - far too short.",
                fix="Regenerate the key pair.",
                impact="DKIM verification will fail.",
            ))
            return

        # Ed25519
        if self.key_type == "ed25519":
            if len(raw_bytes) not in (32, 44):
                self.issues.append(DKIMIssue(
                    Priority.P1_HIGH, "p",
                    f"Unusual Ed25519 key size ({len(raw_bytes)} bytes)",
                    "Ed25519 keys should be 32 bytes (raw) or 44 bytes (SPKI).",
                    fix="Regenerate the Ed25519 key pair.",
                ))
            else:
                self.key_bits = 256
                self.issues.append(DKIMIssue(
                    Priority.P4_INFO, "p",
                    "Ed25519 key - 256-bit (strong)",
                    "Equivalent to ~RSA 3072-bit security.",
                ))
            return

        # RSA - try DER decode first, fallback to estimation
        actual_bits = _decode_rsa_key_bits(clean_b64)
        self.key_bits = actual_bits if actual_bits else _estimate_key_bits_fallback(clean_b64)

        if self.key_bits < 1024:
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "p",
                f"RSA key dangerously short: {self.key_bits} bits",
                "Can be factored with modest resources. No security.",
                fix="Immediately rotate to 2048-bit RSA.",
                impact="Attackers can forge DKIM signatures for your domain.",
            ))
        elif self.key_bits == 1024:
            self.issues.append(DKIMIssue(
                Priority.P1_HIGH, "p",
                "1024-bit RSA key - deprecated",
                "RFC 8301 says NOT RECOMMENDED. Within reach of well-funded attackers.",
                fix="Rotate to 2048-bit RSA.",
                impact="Reduced security. Some receivers downgrade trust.",
            ))
        elif self.key_bits == 2048:
            self.issues.append(DKIMIssue(
                Priority.P4_INFO, "p",
                f"RSA key: {self.key_bits} bits (good)",
                "Current standard recommendation.",
            ))
        elif self.key_bits >= 4096:
            self.issues.append(DKIMIssue(
                Priority.P4_INFO, "p",
                f"RSA key: {self.key_bits} bits (excellent)",
                "Very strong. Note: keys over 4096 bits may need TXT record concatenation.",
            ))
        else:
            self.issues.append(DKIMIssue(
                Priority.P4_INFO, "p",
                f"RSA key: ~{self.key_bits} bits",
                "Key size is within acceptable range.",
            ))

        # Algorithm/key mismatch
        if self.key_type == "ed25519" and self.key_bits and self.key_bits > 256:
            self.issues.append(DKIMIssue(
                Priority.P0_CRITICAL, "k",
                "Key type / key data mismatch",
                "Record says k=ed25519 but key data is RSA-sized.",
                fix="Change k=rsa or regenerate as Ed25519.",
                impact="DKIM verification fails.",
            ))

    # -- Report builder ---

    def _build_report(self, dns_info: Dict, record: Optional[str]) -> Dict[str, Any]:
        self.issues.sort(key=lambda i: i.priority)

        if any(i.priority == Priority.P0_CRITICAL for i in self.issues):
            status = "FAIL"
        elif any(i.priority <= Priority.P1_HIGH for i in self.issues):
            status = "WARNING"
        elif any(i.priority <= Priority.P2_MEDIUM for i in self.issues):
            status = "CAUTION"
        else:
            status = "PASS"

        tag_table = []
        for tag_key in ["v", "h", "k", "n", "p", "s", "t", "g"]:
            if tag_key in self.tags:
                spec = TAG_SPECS.get(tag_key)
                val = self.tags[tag_key]
                display_val = (val[:50] + "...") if len(val) > 50 else val
                tag_table.append({
                    "tag": tag_key,
                    "name": spec.full_name if spec else tag_key,
                    "value": display_val,
                    "default": spec.default if spec else "",
                    "deprecated": spec.deprecated if spec else False,
                })

        priority_counts = {p.name: 0 for p in Priority}
        for issue in self.issues:
            priority_counts[issue.priority.name] += 1

        return {
            "status": status,
            "domain": self.domain,
            "selector": self.selector,
            "fqdn": dns_info["fqdn"],
            "record": record,
            "tags": self.tags,
            "tag_table": tag_table,
            "key_bits": self.key_bits,
            "key_type": self.key_type,
            "cname_target": dns_info.get("cname_target"),
            "issues": [i.to_dict() for i in self.issues],
            "issue_count": len(self.issues),
            "priority_counts": priority_counts,
            "summary": {
                "critical": priority_counts.get("P0_CRITICAL", 0),
                "high": priority_counts.get("P1_HIGH", 0),
                "medium": priority_counts.get("P2_MEDIUM", 0),
                "low": priority_counts.get("P3_LOW", 0),
                "info": priority_counts.get("P4_INFO", 0),
            },
        }


# ----------------------------------------------------------------
# Convenience function
# ----------------------------------------------------------------

def validate_dkim(domain: str, selector: str, record: Optional[str] = None) -> Dict[str, Any]:
    """One-shot DKIM validation. Returns structured report."""
    return DKIMValidator(domain, selector, record=record).validate()


# ----------------------------------------------------------------
# Backward-compatible DKIMTagAnalyzer wrapper
# ----------------------------------------------------------------

class DKIMTagAnalyzer:
    """
    Backward-compatible wrapper. Existing code using
    DKIMTagAnalyzer(record).analyze() still works.
    """

    def __init__(self, dkim_record: str):
        self.record = dkim_record
        self._v = DKIMValidator(domain="unknown", selector="unknown", record=dkim_record)

    def analyze(self) -> Dict:
        self._v.tags = self._v._parse_tags(self.record)
        self._v._check_syntax(self.record)
        self._v._check_tags()
        self._v._check_key()

        issues = [i for i in self._v.issues if i.priority <= Priority.P1_HIGH]
        warnings = [i for i in self._v.issues if i.priority == Priority.P2_MEDIUM]
        recommendations = [i for i in self._v.issues if i.priority >= Priority.P3_LOW]

        self._v.issues.sort(key=lambda i: i.priority)

        if any(i.priority == Priority.P0_CRITICAL for i in self._v.issues):
            status, status_icon = "FAIL", "X"
        elif any(i.priority <= Priority.P1_HIGH for i in self._v.issues):
            status, status_icon = "WARNING", "!"
        else:
            status, status_icon = "PASS", "ok"

        def _to_legacy(i):
            return {"tag": i.tag, "severity": i.level_name.lower(), "message": i.title,
                    "impact": i.impact, "recommendation": i.fix}

        return {
            "status": status,
            "status_icon": status_icon,
            "tags": self._v.tags,
            "issues": [_to_legacy(i) for i in issues],
            "warnings": [_to_legacy(i) for i in warnings],
            "recommendations": [_to_legacy(i) for i in recommendations],
            "summary": self._gen_summary(),
        }

    def _gen_summary(self) -> str:
        lines = ["\n DKIM TAG ANALYSIS", "=" * 60, "\nTags Present:"]
        for tag_name, tag_value in self._v.tags.items():
            spec = TAG_SPECS.get(tag_name)
            if spec:
                req = " (required)" if spec.required else ""
                dep = " [DEPRECATED]" if spec.deprecated else ""
                lines.append(f"  {tag_name}= -- {spec.full_name}{req}{dep}")
            else:
                lines.append(f"  {tag_name}= -- Unknown tag")

        for issue in self._v.issues:
            lines.append(f"  [{issue.level_code}] {issue.title}")
            if issue.fix:
                lines.append(f"    -> {issue.fix}")

        return "\n".join(lines)
