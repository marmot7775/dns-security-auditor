"""
DMARC DNS Tree Walk
====================
Implements draft-ietf-dmarc-dmarcbis-41 §4.10 (read 2026-04-25).

Walks the DNS hierarchy to find the DMARC Policy Record that applies to
a given domain, and computes the Organizational Domain. The full step
list returned lets the frontend visualize each query.

Reference: https://datatracker.ietf.org/doc/html/draft-ietf-dmarc-dmarcbis-41

Spec rules implemented (per §4.10 numbered steps and §4.10.1 / §4.10.2):

  1. §4.10.1: Policy discovery starts with a query at the Author Domain.
     If a valid record is found there, that record's "p" tag is the
     applied policy and discovery stops.
  2. §4.10 step 2 / step 6: Records that do not start with a "v" tag for
     the current DMARC version are discarded. Multiple valid records at
     a single target are all discarded. A single remaining record with
     "psd=n" or "psd=y" stops the walk. (First walk query and subsequent
     walk queries share these stop conditions per spec.)
  3. §4.10 step 4: For Author Domains with x >= 8 labels, the walk
     starts at the name produced by removing left-most labels until 7
     remain. For x < 8, it starts at the immediate parent.
  4. §4.10 step 7: Walk continues, removing the left-most label each
     iteration, until the walk stops or no labels remain (i.e., walk
     down to the TLD inclusive).
  5. §4.10-5: Total query budget is 8 (Author Domain query included).
     With shortening + the natural label progression, this caps walk
     queries at 7 after the Author Domain query.
  6. §4.10.2 rule 1: A record with "psd=n" identifies the Organizational
     Domain directly.
  7. §4.10.2 rule 2: A record with "psd=y" at a domain other than the
     starting walk target makes the Organizational Domain the domain
     one label below the PSD.
  8. §4.10.2 rule 3 (fallback): The Organizational Domain is the record
     with the fewest labels. Used when no psd tag was found, and also
     when "psd=y" is at the starting walk target (rule 2 excludes that
     case, leaving rule 3 with a single record).
  9. §4.10.1-7: The applied policy tag cascade for walk-found records
     is: "np" if the Author Domain does not exist, else "sp" if the
     Author Domain exists, else "p" as the fallback. The "sp" tag does
     NOT apply when the Author Domain is NXDOMAIN.
"""

import dns.resolver
import dns.name
from typing import Dict, Any, Optional, List

# dmarcbis-41 §4.10-5: total query cap is 8, including the Author Domain
# query. The walk loop therefore allows at most 7 queries (1 already
# consumed by the Author Domain lookup).
MAX_TREE_WALK_QUERIES = 7


def _query_dmarc(domain: str) -> Optional[str]:
    """
    Query for a DMARC TXT record at _dmarc.<domain>.

    dmarcbis-41 §4.10 steps 2 and 6: records that do not start with a
    "v" tag identifying the current version of DMARC are discarded; if
    multiple DMARC Policy Records are returned for a single target,
    they are all discarded.

    Returns the single valid record, or None if zero or more than one
    valid record was found.
    """
    target = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(target, "TXT")
        dmarc_records = []
        for rdata in answers:
            txt = "".join(
                s.decode() if isinstance(s, bytes) else s for s in rdata.strings
            )
            if txt.strip().startswith("v=DMARC1"):
                dmarc_records.append(txt.strip())
        # §4.10 steps 2 and 6: multiple valid records at one target -> discard all.
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
    # dmarcbis-41 §4.10.1: "Policy discovery starts first with a query
    # for a valid DMARC Policy Record at the name created by prepending
    # the label '_dmarc' to the Author Domain". This query is one of
    # the 8 in the §4.10-5 total budget; the walk loop below allows
    # at most 7 more.
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
        # §4.10.1-6: when the policy record IS that of the Author Domain,
        # the "p" tag of the record provides the Domain Owner Assessment
        # Policy directly. The sp/np cascade does not apply here.
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
    # No record at the Author Domain: perform the §4.10 Tree Walk.
    #
    #   §4.10.1-5: starting point is the immediate parent for x < 8
    #     labels; for x >= 8, shorten until 7 labels remain.
    #   §4.10 step 4: shortening removes left-most labels until 7 remain.
    #   §4.10 steps 2 and 6: a single record with psd=n or psd=y at any
    #     query (first or subsequent) stops the walk.
    #   §4.10 step 7: the walk descends one label at a time and runs
    #     until it stops or no labels remain.
    # ------------------------------------------------------------------
    num_labels = len(labels)

    if num_labels < 2:
        # Single-label name has no parent to walk to; nothing to find.
        return _no_policy_result(domain, steps, 0)

    if num_labels >= 8:
        # §4.10 step 4: shorten by removing left-most labels until 7 remain.
        start_labels = labels[-7:]
    else:
        # §4.10.1-5: x < 8 -> start at immediate parent.
        start_labels = labels[1:]

    current_labels = list(start_labels)
    collected_records: List[Dict[str, Any]] = []
    stop_record: Optional[Dict[str, Any]] = None
    stop_at_first_walk = False
    walk_query_count = 0
    is_first_walk_query = True

    # §4.10 step 7: "Repeat ... until the process stops or there are no
    # more labels remaining." Walk down to 1 label inclusive (TLD); the
    # loop exits when current has 0 labels.
    while len(current_labels) >= 1 and walk_query_count < MAX_TREE_WALK_QUERIES:
        parent = ".".join(current_labels)
        record = _query_dmarc(parent)
        walk_query_count += 1

        # Display label heuristic for the frontend tree visualization.
        # The true Org Domain depends on psd tags, not label count, but
        # this gives a reasonable hint when the walk is in progress.
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

            # §4.10 steps 2 and 6: stop on psd=n or psd=y at any walk
            # query, including the first one. The "psd=y at starting
            # walk target" case is handled by §4.10.2 rule 2 (which
            # excludes that domain), causing rule 3 fewest-labels with
            # one record to apply -- that domain becomes the Org Domain.
            if psd == "n" or psd == "y":
                stop_record = record_info
                stop_at_first_walk = is_first_walk_query
                step_entry["stop_reason"] = f"psd={psd}"
                break

            # Records without an applicable psd tag are collected so the
            # §4.10.2 selection rules can choose the Org Domain after
            # the walk finishes.
            collected_records.append(record_info)
            step_entry["collected"] = True

        # §4.10 step 7: drop the left-most label and continue.
        current_labels = current_labels[1:]
        is_first_walk_query = False

    # Annotate the step where the §4.10-5 query budget was exhausted, if
    # the walk ran out of queries before stopping naturally.
    if walk_query_count >= MAX_TREE_WALK_QUERIES and stop_record is None and current_labels:
        if steps:
            steps[-1]["stop_reason"] = "query_limit"

    # ------------------------------------------------------------------
    # §4.10.2 Org Domain selection (after the walk finishes):
    #   Rule 1: psd=n  -> that record's domain is the Org Domain.
    #   Rule 2: psd=y at a domain other than the starting walk target
    #           -> Org Domain is the domain one label below it.
    #   Rule 3: otherwise, the record with the fewest labels.
    # ------------------------------------------------------------------
    policy_record = None
    org_domain = None
    psd_flag = ""

    if stop_record:
        psd = stop_record["psd"]
        if psd == "n":
            # §4.10.2 rule 1: psd=n marks the Organizational Domain.
            org_domain = stop_record["domain"]
            policy_record = stop_record
            psd_flag = "n"
        elif psd == "y" and stop_at_first_walk:
            # §4.10.2 rule 2 explicitly excludes the starting walk
            # target from the "one level below" treatment. With a
            # single record collected (the stop_record itself), rule 3
            # selects fewest labels -> the starting walk domain IS
            # the Organizational Domain.
            org_domain = stop_record["domain"]
            policy_record = stop_record
            psd_flag = "y"
        elif psd == "y":
            # §4.10.2 rule 2: psd=y at a non-starting target -> Org
            # Domain is the name one label below the PSD.
            psd_labels = stop_record["labels"]
            org_candidate = None
            for rec in collected_records:
                if len(rec["labels"]) == len(psd_labels) + 1:
                    org_candidate = rec
                    break

            if org_candidate:
                org_domain = org_candidate["domain"]
                policy_record = org_candidate
            else:
                # No collected record at the level immediately below
                # the PSD: synthesize the name from the Author Domain's
                # labels. The PSD's policy still applies.
                org_domain_labels = labels[-(len(psd_labels) + 1):]
                org_domain = ".".join(org_domain_labels)
                policy_record = stop_record
            psd_flag = "y"
    elif collected_records:
        # §4.10.2 rule 3: no psd tag was found at any walked record,
        # so the Org Domain is the record with the fewest labels
        # (highest in the DNS hierarchy among those with records).
        policy_record = min(collected_records, key=lambda r: len(r["labels"]))
        org_domain = policy_record["domain"]
        psd_flag = ""
    else:
        # §4.10.1-10: walk produced no DMARC Policy Record. Caller
        # treats this as "DMARC does not apply".
        return _no_policy_result(domain, steps, walk_query_count)

    # ------------------------------------------------------------------
    # §4.10.1-7 tag cascade for a walk-discovered policy record:
    #   - If the Author Domain exists, "sp" applies (else fall back to p).
    #   - If the Author Domain does NOT exist, "np" applies (else p).
    #   - "sp" never applies when the Author Domain is NXDOMAIN.
    # _domain_exists() approximates receive-time existence by querying
    # SOA at audit time; non-NXDOMAIN responses (including SERVFAIL or
    # timeout) treat the domain as existing, which keeps np from being
    # applied to merely-unreachable domains.
    # ------------------------------------------------------------------
    tags = policy_record.get("tags", {})
    sp = tags.get("sp")
    np_tag = tags.get("np")
    p = tags.get("p", "none")

    author_exists = _domain_exists(domain)

    if not author_exists:
        if np_tag:
            applied_tag = "np"
            effective_policy = np_tag
        else:
            applied_tag = "p"
            effective_policy = p
    else:
        if sp:
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
