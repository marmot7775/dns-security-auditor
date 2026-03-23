"""
Recursive SPF Lookup Counter
=============================
Follows every include:, redirect=, a, mx, exists, and ptr mechanism
through the full SPF chain to return the TRUE DNS lookup count.

RFC 7208 Section 4.6.4: SPF implementations MUST limit the number
of mechanisms and modifiers that cause DNS lookups to at most 10.

Usage:
    from spf_recursive import count_spf_lookups
    result = count_spf_lookups("example.com")
    print(result["total_lookups"])  # e.g. 13
    print(result["over_limit"])     # True
    print(result["chain"])          # full lookup tree
"""

import dns.resolver
import dns.exception
import re
from typing import Any, Dict, List, Optional, Set, Tuple


def repair_spf_missing_spaces(record: str) -> Tuple[str, bool]:
    """Detect and fix missing spaces between SPF mechanisms.

    Some domains (e.g. GitHub) store each SPF mechanism as a separate
    TXT string without embedded boundary spaces.  After RFC-correct
    concatenation (no separator), mechanisms are jammed together like
    ``v=spf1ip4:1.2.3.0/22include:example.com~all``.

    This function inserts spaces before known mechanism/modifier
    prefixes when they appear immediately after other text, then
    returns (repaired_record, was_malformed).

    It intentionally does NOT touch arbitrary tokens like bare ``a``,
    ``mx``, or ``ptr`` because those are too short and would cause
    false splits inside domain names.
    """
    # Longer prefixes first to avoid partial matches.
    SPLIT_BEFORE = [
        r'redirect=',
        r'include:',
        r'exists:',
        r'ip4:',
        r'ip6:',
        r'exp=',
        # Qualified all (e.g. ~all, -all, ?all, +all) jammed onto prior text
        r'[~?+\-]all(?=\s|$)',
    ]

    pattern = r'(?<=\S)(' + '|'.join(SPLIT_BEFORE) + ')'
    repaired = re.sub(pattern, r' \1', record, flags=re.IGNORECASE)

    # Handle v=spf1 not followed by a space (e.g. "v=spf1ip4:...")
    repaired = re.sub(r'(v=spf1)(?=\S)', r'\1 ', repaired, flags=re.IGNORECASE)

    is_malformed = repaired != record
    return repaired, is_malformed


def _get_resolver(timeout: float = 5.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def _get_spf_record(domain: str) -> Optional[str]:
    """Fetch SPF TXT record for a domain."""
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.strip().lower().startswith("v=spf1"):
                repaired, _ = repair_spf_missing_spaces(txt.strip())
                return repaired
    except Exception:
        pass
    return None


# Mechanisms that consume a DNS lookup per RFC 7208
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def _parse_spf_mechanisms(spf_record: str) -> List[Dict[str, str]]:
    """Parse an SPF record into its mechanisms with types and values."""
    mechanisms = []
    parts = spf_record.split()

    for part in parts:
        if part.lower().startswith("v=spf1"):
            continue

        clean = part.lstrip("+-~?")

        if clean.lower().startswith("redirect="):
            value = clean.split("=", 1)[1]
            mechanisms.append({"type": "redirect", "value": value, "raw": part})
            continue

        if clean.lower().startswith("include:"):
            value = clean.split(":", 1)[1]
            mechanisms.append({"type": "include", "value": value, "raw": part})
            continue

        if clean.lower() == "a" or clean.lower().startswith("a:") or clean.lower().startswith("a/"):
            value = clean.split(":", 1)[1] if ":" in clean else ""
            mechanisms.append({"type": "a", "value": value, "raw": part})
            continue

        if clean.lower() == "mx" or clean.lower().startswith("mx:") or clean.lower().startswith("mx/"):
            value = clean.split(":", 1)[1] if ":" in clean else ""
            mechanisms.append({"type": "mx", "value": value, "raw": part})
            continue

        if clean.lower() == "ptr" or clean.lower().startswith("ptr:"):
            value = clean.split(":", 1)[1] if ":" in clean else ""
            mechanisms.append({"type": "ptr", "value": value, "raw": part})
            continue

        if clean.lower().startswith("exists:"):
            value = clean.split(":", 1)[1]
            mechanisms.append({"type": "exists", "value": value, "raw": part})
            continue

        if clean.lower().startswith(("ip4:", "ip6:", "all")):
            mechanisms.append({"type": "no_lookup", "value": clean, "raw": part})
            continue

        mechanisms.append({"type": "unknown", "value": clean, "raw": part})

    return mechanisms


def _count_recursive(domain: str, visited: Set[str], depth: int = 0,
                     max_depth: int = 10) -> Dict[str, Any]:
    """
    Recursively count DNS lookups in an SPF record chain.
    """
    node = {
        "domain": domain,
        "record": None,
        "lookups_here": 0,
        "mechanisms": [],
        "children": [],
        "total": 0,
        "error": None,
        "depth": depth,
    }

    domain_lower = domain.lower().rstrip(".")
    if domain_lower in visited:
        node["error"] = f"Circular reference: {domain} already visited"
        return node
    visited.add(domain_lower)

    if depth > max_depth:
        node["error"] = f"Max recursion depth ({max_depth}) exceeded"
        return node

    spf_record = _get_spf_record(domain)
    if not spf_record:
        node["error"] = f"No SPF record found for {domain}"
        return node

    node["record"] = spf_record
    mechanisms = _parse_spf_mechanisms(spf_record)
    node["mechanisms"] = mechanisms

    local_lookups = 0

    for mech in mechanisms:
        mtype = mech["type"]

        if mtype in ("a", "mx", "ptr", "exists"):
            local_lookups += 1

        elif mtype == "include":
            local_lookups += 1
            child = _count_recursive(mech["value"], set(visited), depth + 1, max_depth)
            node["children"].append(child)

        elif mtype == "redirect":
            local_lookups += 1
            child = _count_recursive(mech["value"], set(visited), depth + 1, max_depth)
            node["children"].append(child)

    node["lookups_here"] = local_lookups
    child_total = sum(c["total"] for c in node["children"])
    node["total"] = local_lookups + child_total

    return node


def _flatten_chain(node: Dict, chain: List[Dict] = None, indent: int = 0) -> List[Dict]:
    """Flatten the recursive tree into a readable chain."""
    if chain is None:
        chain = []

    entry = {
        "domain": node["domain"],
        "record": node["record"],
        "lookups": node["lookups_here"],
        "depth": indent,
        "error": node.get("error"),
    }

    lookup_details = []
    for mech in node.get("mechanisms", []):
        if mech["type"] in LOOKUP_MECHANISMS:
            lookup_details.append(mech["raw"])
    entry["lookup_mechanisms"] = lookup_details

    chain.append(entry)

    for child in node.get("children", []):
        _flatten_chain(child, chain, indent + 1)

    return chain


def count_spf_lookups(domain: str) -> Dict[str, Any]:
    """
    Main entry point. Returns complete recursive SPF lookup analysis.

    Returns:
        {
            "domain": "example.com",
            "total_lookups": 13,
            "limit": 10,
            "over_limit": True,
            "over_by": 3,
            "status": "fail" | "warn" | "pass",
            "record": "v=spf1 ...",
            "chain": [ ... ],
            "tree": { ... },
            "summary": "13 DNS lookups found (limit: 10). Over by 3.",
            "issues": [ ... ]
        }
    """
    visited = set()
    tree = _count_recursive(domain, visited)
    chain = _flatten_chain(tree)
    total = tree["total"]
    limit = 10

    result = {
        "domain": domain,
        "total_lookups": total,
        "limit": limit,
        "over_limit": total > limit,
        "over_by": max(0, total - limit),
        "status": "pass",
        "record": tree.get("record"),
        "chain": chain,
        "tree": tree,
        "summary": "",
        "issues": [],
    }

    if total > limit:
        result["status"] = "fail"
        result["summary"] = (
            f"{total} DNS lookups found (limit: 10). "
            f"Over by {total - limit}. "
            f"SPF record may be completely ignored by receivers."
        )
        result["issues"].append({
            "severity": "error",
            "issue": f"SPF exceeds 10-lookup limit ({total} lookups)",
            "plain_english": (
                f"Your SPF record requires {total} DNS lookups when fully resolved. "
                f"RFC 7208 limits this to 10. Receivers that enforce this limit "
                f"will return a PermError, treating your SPF as if it doesn't exist."
            ),
            "impact": "Email authentication fails entirely for strict receivers.",
            "fix": (
                f"Reduce lookups by {total - limit}. Audit your includes: "
                "remove services you no longer use and consolidate senders where possible."
            ),
        })
    elif total == limit:
        result["status"] = "warn"
        result["summary"] = (
            f"{total} DNS lookups (exactly at the 10-lookup limit). "
            f"Any additions will break SPF."
        )
        result["issues"].append({
            "severity": "warning",
            "issue": "SPF at exactly 10-lookup limit",
            "plain_english": (
                "You are using exactly 10 DNS lookups. Adding any new email "
                "service will push you over the limit and break SPF entirely."
            ),
            "impact": "No room for new services. Any addition will break SPF.",
            "fix": "Audit your includes and remove any services you no longer use to free up lookup slots.",
        })
    elif total >= 8:
        result["status"] = "warn"
        result["summary"] = (
            f"{total} DNS lookups (approaching the 10-lookup limit)."
        )
        result["issues"].append({
            "severity": "warning",
            "issue": f"SPF approaching lookup limit ({total}/10)",
            "plain_english": (
                f"You are using {total} of 10 allowed DNS lookups. "
                f"Only {10 - total} slots remain."
            ),
            "impact": "Limited room for adding new email services.",
            "fix": "Monitor lookup count when adding new services.",
        })
    else:
        result["status"] = "pass"
        result["summary"] = (
            f"{total} DNS lookups (well within the 10-lookup limit)."
        )

    # Check for void lookups (broken includes)
    for entry in chain:
        if entry.get("error") and "No SPF record" in entry["error"]:
            result["issues"].append({
                "severity": "warning",
                "issue": f"Broken include: {entry['domain']} has no SPF record",
                "plain_english": (
                    f"Your SPF chain includes {entry['domain']} but that domain "
                    f"has no SPF record. This is a 'void lookup' and "
                    f"RFC 7208 limits void lookups to 2. A third may trigger a PermError."
                ),
                "impact": "Wasted lookup slot and potential PermError.",
                "fix": f"Remove the include for {entry['domain']} if no longer used.",
            })

    # Check for deprecated ptr mechanism
    for entry in chain:
        for mech in entry.get("lookup_mechanisms", []):
            if "ptr" in mech.lower():
                result["issues"].append({
                    "severity": "warning",
                    "issue": "Deprecated 'ptr' mechanism found",
                    "plain_english": (
                        "The ptr mechanism is discouraged by RFC 7208 because it is slow and "
                        "places a burden on reverse DNS infrastructure."
                    ),
                    "impact": "Slow SPF evaluation, unreliable in practice.",
                    "fix": "Replace ptr with explicit ip4/ip6 or a mechanisms.",
                })
                break

    return result


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "netflix.com"
    result = count_spf_lookups(domain)

    print(f"\n{'='*60}")
    print(f"SPF Recursive Lookup Analysis: {domain}")
    print(f"{'='*60}")
    print(f"\nRecord: {result['record']}")
    print(f"\nTotal lookups: {result['total_lookups']} / {result['limit']}")
    print(f"Status: {result['status'].upper()}")
    print(f"Summary: {result['summary']}")

    print(f"\nLookup Chain:")
    for entry in result["chain"]:
        indent = "  " * entry["depth"]
        domain_str = entry["domain"]
        lookups = entry["lookups"]
        mechs = ", ".join(entry.get("lookup_mechanisms", []))
        error = f" [ERROR: {entry['error']}]" if entry.get("error") else ""
        print(f"{indent}{domain_str}: {lookups} lookups ({mechs}){error}")

    if result["issues"]:
        print(f"\nIssues:")
        for issue in result["issues"]:
            print(f"  [{issue['severity'].upper()}] {issue['issue']}")
            print(f"    Fix: {issue['fix']}")
