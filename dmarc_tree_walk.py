"""
DMARC DNS Tree Walk (per draft-ietf-dmarc-dmarcbis-41, Section 4.10)
=====================================================================
Walks the DNS hierarchy to discover which DMARC policy record applies
to a given domain. Returns every step of the walk so the frontend can
visualize it.

Reference: https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/

Key spec rules implemented:
  - Author Domain queried first (outside the walk proper)
  - Multiple DMARC records at same target → all discarded (spec Step 2)
  - Walk Step 2 (first query): stops ONLY on psd=n
  - Walk Step 7 (subsequent): stops on psd=n OR psd=y
  - Records without psd tag are collected for Org Domain determination
  - 8-query limit applies to the walk only (Author Domain query is separate)
  - Domains with >=8 labels shortened to 7 before walk starts
  - Policy tag selection: np (if author NXDOMAIN), sp, then p
"""

import dns.resolver
import dns.name
from typing import Dict, Any, Optional, List

# Maximum DNS queries for the tree walk itself (Author Domain query is separate)
MAX_TREE_WALK_QUERIES = 8


def _query_dmarc(domain: str) -> Optional[str]:
    """
    Query for a DMARC TXT record at _dmarc.<domain>.

    Per dmarcbis Step 2: "Records that do not start with a 'v=' tag that
    identifies the current version of DMARC are discarded. If multiple
    DMARC Policy Records are returned for a single target, they are all
    discarded."

    Returns the single valid record, or None if zero or >1 found.
    """
    target = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(target, "TXT")
        dmarc_records = []
        for rdata in answers:
            txt = "".join(
                s.decode() if isinstance(s, bytes) else s for s in rdata.strings
            )
            if txt.strip().lower().startswith("v=dmarc1"):
                dmarc_records.append(txt.strip())
        # Spec: multiple records → discard all
        if len(dmarc_records) == 1:
            return dmarc_records[0]
        return None
    except Exception:
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


def _domain_exists(domain: str) -> bool:
    """
    Check if a domain exists in DNS (is not NXDOMAIN).
    Uses a single SOA query -- more efficient than A+AAAA+MX.
    Only NXDOMAIN means it does not exist.
    """
    try:
        dns.resolver.resolve(domain, "SOA")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        # Domain exists but has no SOA -- still exists in DNS
        return True
    except Exception:
        # Network errors, SERVFAIL -- assume exists to avoid false np application
        return True


def dmarc_tree_walk(domain: str) -> Dict[str, Any]:
    """
    Perform the DMARC DNS Tree Walk per dmarcbis-41 Section 4.10.

    Returns a dict with:
      - domain: the input domain
      - steps: list of each query made
      - policy_source: the domain where the effective policy was found (or None)
      - effective_policy: the policy value (none/quarantine/reject) or None
      - effective_record: the full DMARC record that applies, or None
      - is_subdomain: whether the policy was inherited from a parent
      - applied_tag: which tag applies (p, sp, or np)
      - org_domain: the determined Organizational Domain
      - psd_flag: the psd tag value from the matched record
      - query_count: total DNS queries made (walk only, excludes Author Domain)
      - collected_records: all records found during walk (for debugging/display)
    """
    steps = []
    labels = domain.rstrip(".").split(".")

    # ------------------------------------------------------------------
    # Step 1: Query the Author Domain directly (OUTSIDE the tree walk)
    # Per 4.10.1: "Policy discovery starts first with a query for a valid
    # DMARC Policy Record at the Author Domain."
    # This query does NOT count toward the 8-query walk limit.
    # ------------------------------------------------------------------
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
            "query_count": 0,
            "collected_records": [],
        }

    # ------------------------------------------------------------------
    # Step 2+: Tree Walk -- walk up the hierarchy
    # The 8-query limit applies from HERE (not including Author Domain).
    #
    # Per dmarcbis:
    #   - If >=8 labels, shorten to 7 before starting
    #   - Step 2 (FIRST walk query): stop only on psd=n
    #     (psd=y at starting point does NOT stop — it's a PSO using
    #      its base domain as identifier; see IETF discussion)
    #   - Step 7 (SUBSEQUENT queries): stop on psd=n OR psd=y
    #   - Records without psd tag: collected, walk continues
    # ------------------------------------------------------------------
    num_labels = len(labels)

    if num_labels < 2:
        return _no_policy_result(domain, steps, 0)

    if num_labels >= 8:
        start_labels = labels[-(7):]
    else:
        start_labels = labels[1:]

    current_labels = list(start_labels)
    collected_records: List[Dict[str, Any]] = []
    stop_record: Optional[Dict[str, Any]] = None
    walk_query_count = 0
    is_first_walk_query = True

    while len(current_labels) >= 2 and walk_query_count < MAX_TREE_WALK_QUERIES:
        parent = ".".join(current_labels)
        record = _query_dmarc(parent)
        walk_query_count += 1

        # Determine the level label for display
        if len(current_labels) == len(labels) - 1:
            level_label = "Parent Domain"
        elif len(current_labels) <= 2:
            level_label = "Organizational Domain"
        else:
            level_label = "Ancestor Domain"

        step_entry = {
            "domain": parent,
            "query": f"_dmarc.{parent}",
            "record": record,
            "found": record is not None,
            "level": "tree_walk",
            "label": level_label,
        }
        steps.append(step_entry)

        if record:
            tags = _parse_dmarc_tags(record)
            psd = tags.get("psd", "").lower()

            record_info = {
                "domain": parent,
                "record": record,
                "tags": tags,
                "psd": psd,
                "labels": list(current_labels),
            }

            # Determine stop condition per spec:
            #   Step 2 (first walk query): stop ONLY on psd=n
            #   Step 7 (subsequent):       stop on psd=n OR psd=y
            should_stop = False
            if psd == "n":
                should_stop = True
            elif psd == "y" and not is_first_walk_query:
                should_stop = True

            if should_stop:
                stop_record = record_info
                step_entry["stop_reason"] = f"psd={psd}"
                break
            else:
                # No stop — collect for Org Domain determination, walk continues
                collected_records.append(record_info)
                step_entry["collected"] = True
                if psd == "y":
                    step_entry["note"] = "psd=y at walk start — continuing per spec"

        # Move up: remove left-most label
        current_labels = current_labels[1:]
        is_first_walk_query = False

    # Check if we hit query limit
    if walk_query_count >= MAX_TREE_WALK_QUERIES and stop_record is None and len(current_labels) >= 2:
        if steps:
            steps[-1]["stop_reason"] = "query_limit"

    # ------------------------------------------------------------------
    # Step 3: Determine the effective policy from walk results
    #
    # Per Section 4.10.2, Org Domain determination:
    #   1. Domain with psd=n → that domain is the Org Domain
    #   2. Domain one level below psd=y → that's the Org Domain
    #   3. If no psd tags: domain with fewest labels (highest in hierarchy)
    # ------------------------------------------------------------------
    policy_record = None
    org_domain = None
    psd_flag = ""

    if stop_record:
        psd = stop_record["psd"]
        if psd == "n":
            # psd=n → this domain IS the Organizational Domain
            org_domain = stop_record["domain"]
            policy_record = stop_record
            psd_flag = "n"
        elif psd == "y":
            # psd=y → Org Domain is one level BELOW this PSD
            psd_labels = stop_record["labels"]

            # Check collected records for the domain just below the PSD
            org_candidate = None
            for rec in collected_records:
                if len(rec["labels"]) == len(psd_labels) + 1:
                    org_candidate = rec
                    break

            if org_candidate:
                org_domain = org_candidate["domain"]
                policy_record = org_candidate
            else:
                # No record at the org domain level — PSD policy applies
                org_domain_labels = labels[-(len(psd_labels) + 1):]
                org_domain = ".".join(org_domain_labels)
                policy_record = stop_record
            psd_flag = "y"
    elif collected_records:
        # No explicit psd tags found anywhere
        # Per spec: Org Domain = domain with fewest labels (highest in hierarchy)
        policy_record = min(collected_records, key=lambda r: len(r["labels"]))
        org_domain = policy_record["domain"]
        psd_flag = ""
    else:
        # Nothing found at all
        return _no_policy_result(domain, steps, walk_query_count)

    # ------------------------------------------------------------------
    # Step 4: Determine which policy tag applies
    # Per dmarcbis:
    #   - If Author Domain is NXDOMAIN and np tag exists → use np
    #   - Else if sp tag exists → use sp
    #   - Else → fall back to p
    # ------------------------------------------------------------------
    tags = policy_record.get("tags", {})
    sp = tags.get("sp")
    np_tag = tags.get("np")
    p = tags.get("p", "none")

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

    return {
        "domain": domain,
        "steps": steps,
        "policy_source": policy_record["domain"],
        "effective_policy": effective_policy,
        "effective_record": policy_record["record"],
        "is_subdomain": True,
        "applied_tag": applied_tag,
        "org_domain": org_domain,
        "psd_flag": psd_flag,
        "query_count": walk_query_count,
        "collected_records": [
            {"domain": r["domain"], "psd": r["psd"]} for r in collected_records
        ],
    }


def _no_policy_result(domain: str, steps: list, query_count: int) -> Dict[str, Any]:
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
        "query_count": query_count,
        "collected_records": [],
    }
