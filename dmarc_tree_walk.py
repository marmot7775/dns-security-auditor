"""
DMARC DNS Tree Walk (per draft-ietf-dmarc-dmarcbis-41, Section 4.10)
=====================================================================
Walks the DNS hierarchy to discover which DMARC policy record applies
to a given domain. Returns every step of the walk so the frontend can
visualize it.

Reference: https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/
"""

import dns.resolver
import dns.name
from typing import List, Dict, Any, Optional


def _query_dmarc(domain: str) -> Optional[str]:
    """Query for a DMARC TXT record at _dmarc.<domain>. Returns the record or None."""
    target = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(target, "TXT")
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if txt.strip().lower().startswith("v=dmarc1"):
                return txt.strip()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
        pass
    return None


def _parse_dmarc_tags(record: str) -> Dict[str, str]:
    """Parse a DMARC record into a dict of tag -> value."""
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, val = part.partition("=")
            tags[key.strip().lower()] = val.strip()
    return tags


def dmarc_tree_walk(domain: str) -> Dict[str, Any]:
    """
    Perform the DMARC DNS Tree Walk per dmarcbis Section 4.10.

    Returns a dict with:
      - domain: the input domain
      - steps: list of each query made, with domain, record found (or None), and whether it was the match
      - policy_source: the domain where the effective policy was found (or None)
      - effective_policy: the policy value (none/quarantine/reject) or None
      - effective_record: the full DMARC record that applies, or None
      - is_subdomain: whether the policy was inherited from a parent
      - applied_tag: which tag applies (p, sp, or np)
      - org_domain: the determined Organizational Domain
    """
    steps = []
    labels = domain.rstrip(".").split(".")

    # Step 1: Query the Author Domain directly
    record = _query_dmarc(domain)
    steps.append({
        "domain": domain,
        "query": f"_dmarc.{domain}",
        "record": record,
        "found": record is not None,
        "level": "author_domain",
        "label": "Author Domain",
    })

    if record:
        tags = _parse_dmarc_tags(record)
        psd = tags.get("psd", "").lower()
        policy = tags.get("p", "none")
        return {
            "domain": domain,
            "steps": steps,
            "policy_source": domain,
            "effective_policy": policy,
            "effective_record": record,
            "is_subdomain": False,
            "applied_tag": "p",
            "org_domain": domain,
            "psd_flag": psd,
        }

    # Step 2: Walk up the tree
    # Per dmarcbis: if < 8 labels, start at immediate parent.
    # If >= 8, shorten to 7 labels first.
    num_labels = len(labels)

    if num_labels < 2:
        # Single label domain (e.g., "localhost") -- no parent to walk
        return _no_policy_result(domain, steps)

    if num_labels >= 8:
        # Shorten to 7 labels
        start_labels = labels[-(7):]
    else:
        # Start at immediate parent
        start_labels = labels[1:]

    # Walk up from starting point
    current_labels = start_labels
    while len(current_labels) >= 2:
        parent = ".".join(current_labels)
        record = _query_dmarc(parent)

        # Determine the level label
        if len(current_labels) == len(labels) - 1:
            level_label = "Parent Domain"
        elif len(current_labels) <= 2:
            level_label = "Organizational Domain"
        else:
            level_label = "Ancestor Domain"

        steps.append({
            "domain": parent,
            "query": f"_dmarc.{parent}",
            "record": record,
            "found": record is not None,
            "level": "tree_walk",
            "label": level_label,
        })

        if record:
            tags = _parse_dmarc_tags(record)
            psd = tags.get("psd", "").lower()

            # Determine which policy tag applies
            # If the Author Domain is a subdomain, use sp (subdomain policy) if present
            sp = tags.get("sp")
            np_tag = tags.get("np")  # non-existent subdomain policy (dmarcbis)
            p = tags.get("p", "none")

            # Check if author domain actually exists in DNS
            author_exists = _domain_exists(domain)

            if not author_exists and np_tag:
                applied_tag = "np"
                effective_policy = np_tag
            elif sp:
                applied_tag = "sp"
                effective_policy = sp
            else:
                applied_tag = "p"
                effective_policy = p

            # If psd=n or psd=y, this is the stopping point
            return {
                "domain": domain,
                "steps": steps,
                "policy_source": parent,
                "effective_policy": effective_policy,
                "effective_record": record,
                "is_subdomain": True,
                "applied_tag": applied_tag,
                "org_domain": parent,
                "psd_flag": psd,
            }

        # Move up: remove left-most label
        current_labels = current_labels[1:]

    return _no_policy_result(domain, steps)


def _domain_exists(domain: str) -> bool:
    """Check if a domain exists in DNS (has any records)."""
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except Exception:
        pass
    try:
        dns.resolver.resolve(domain, "AAAA")
        return True
    except Exception:
        pass
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except Exception:
        pass
    return False


def _no_policy_result(domain: str, steps: list) -> Dict[str, Any]:
    """Return a result when no DMARC policy was found anywhere."""
    return {
        "domain": domain,
        "steps": steps,
        "policy_source": None,
        "effective_policy": None,
        "effective_record": None,
        "is_subdomain": False,
        "applied_tag": None,
        "org_domain": None,
        "psd_flag": None,
    }
