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
     applied policy. §4.10.1 ¶3: finding a record at the Author Domain
     "does not necessarily mean that the Author Domain is the
     Organizational Domain". Whether it is is decided by the psd tag
     and §4.10.2 selection (see "org_domain_method" in the result):
       - psd=n at Author -> Author IS Org Domain (rule 1).
       - psd=y at Author -> rule 2 excludes the starting target; rule 3
         with one record makes Author the Org Domain.
       - psd absent or "u" at Author -> walk continues to apply §4.10.2
         (Author Domain record participates in rule 3 fewest-labels).
       - 2-label Author Domain -> fast path: already at the minimum,
         no walk performed.
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

import os

try:
    import tldextract
    # ProtectHome=read-only on the prod systemd unit makes tldextract's
    # default ~/.cache path unwritable. Pin the cache under the working
    # directory (in ReadWritePaths) to keep the suffix-list refresh able
    # to complete.
    _tldextract_cache_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".tldextract_cache"
    )
    _tld_extract = tldextract.TLDExtract(cache_dir=_tldextract_cache_dir)
except ImportError:
    tldextract = None
    _tld_extract = None

# dmarcbis-41 §4.10-5: total query cap is 8, including the Author Domain
# query. The walk loop therefore allows at most 7 queries (1 already
# consumed by the Author Domain lookup).
MAX_TREE_WALK_QUERIES = 7

# Public suffixes with two labels (e.g. "co.uk"). Mirrors the fallback
# table in audit_engine._get_org_domain so dmarc_tree_walk's PSL hint
# does not require tldextract.
_TWO_PART_PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "web.za",
    "com.br", "net.br", "org.br",
    "co.in", "net.in", "org.in", "gen.in",
    "com.mx", "org.mx", "gob.mx",
    "co.kr", "or.kr", "ne.kr",
    "com.cn", "net.cn", "org.cn",
    "com.tw", "org.tw", "net.tw",
    "co.il", "org.il", "net.il",
    "com.sg", "org.sg", "net.sg",
    "com.hk", "org.hk", "net.hk",
    "co.id", "or.id", "web.id",
    "com.ar", "org.ar", "net.ar",
    "com.tr", "org.tr", "net.tr",
    "co.th", "or.th", "in.th",
    "com.ph", "org.ph", "net.ph",
    "co.ke", "or.ke",
}


def _psl_org_domain(domain: str) -> Optional[str]:
    """Best-effort PSL Organizational Domain.

    Used when the §4.10.2 selection collected only the Author Domain's
    own record (so rule 3 trivially returns the Author Domain), but the
    audited domain has more labels than its public suffix would suggest.
    Returning the PSL Org Domain in that case matches RFC 7489 receiver
    behavior and avoids false-external-rua flags for sub-domain audits
    whose parents do not publish DMARC records.
    """
    if tldextract is not None:
        ext = _tld_extract(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return None

    labels = domain.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return None
    last_two = ".".join(labels[-2:])
    if last_two in _TWO_PART_PUBLIC_SUFFIXES:
        if len(labels) < 3:
            return None
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


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
      - org_domain_method: how org_domain was decided. One of
        "psd_n_at_author" | "psd_y_at_author" | "label_minimum" |
        "walked" | "psl_fallback" | None (no record).
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

    num_labels = len(labels)

    if record:
        tags = _parse_dmarc_tags(record)
        psd = tags.get("psd", "").lower()
        policy = tags.get("p", "none")

        # ------------------------------------------------------------------
        # §4.10.1 ¶3: finding a record at the Author Domain "does not
        # necessarily mean that the Author Domain is the Organizational
        # Domain". Whether it is depends on the psd tag and the §4.10.2
        # selection rules. Decide the Org Domain, but always keep the
        # Author Domain record as the policy source: §4.10.1 says when
        # the applied policy record IS that of the Author Domain, the
        # "p" tag of the record provides the Domain Owner Assessment
        # Policy directly (no sp/np cascade).
        # ------------------------------------------------------------------

        # §4.10.2 rule 1: psd=n at any record IS the Org Domain.
        # §4.10 step 2 also says a single record with psd=n stops the walk.
        if psd == "n":
            return _author_hit_result(
                domain, steps, record, policy, psd,
                org_domain=domain,
                org_domain_method="psd_n_at_author",
            )

        # §4.10.2 rule 2 explicitly excludes the starting target. With
        # the Author Domain as the only collected record, rule 3
        # fewest-labels picks it: Author IS Org Domain. §4.10 step 2
        # also stops the walk on psd=y, so no further queries.
        if psd == "y":
            return _author_hit_result(
                domain, steps, record, policy, psd,
                org_domain=domain,
                org_domain_method="psd_y_at_author",
            )

        # psd absent or psd="u": §4.10.1 ¶3 says we cannot assume the
        # Author Domain is the Org Domain. Decide via §4.10.2.
        #
        # Fast path: 2-label Author Domain is already at the minimum
        # below the TLD; the walk would query at most the TLD itself,
        # which in practice never publishes DMARC. Skip to save a query.
        if num_labels == 2:
            return _author_hit_result(
                domain, steps, record, policy, psd,
                org_domain=domain,
                org_domain_method="label_minimum",
            )

        # Continue the walk with the Author Domain pre-collected for
        # the §4.10.2 rule 3 fewest-labels comparison.
        author_record_info = {
            "domain": domain,
            "record": record,
            "tags": tags,
            "psd": psd,
            "labels": list(labels),
        }
        return _walk_after_author_hit(
            domain, labels, steps, author_record_info, record, policy, psd,
        )

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
    walk_query_count = 0

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
            # query, including the first one.
            if psd == "n" or psd == "y":
                stop_record = record_info
                step_entry["stop_reason"] = f"psd={psd}"
                break

            # Records without an applicable psd tag are collected so the
            # §4.10.2 selection rules can choose the Org Domain after
            # the walk finishes.
            collected_records.append(record_info)
            step_entry["collected"] = True

        # §4.10 step 7: drop the left-most label and continue.
        current_labels = current_labels[1:]

    # Annotate the step where the §4.10-5 query budget was exhausted, if
    # the walk ran out of queries before stopping naturally.
    if walk_query_count >= MAX_TREE_WALK_QUERIES and stop_record is None and current_labels:
        if steps:
            steps[-1]["stop_reason"] = "query_limit"

    # ------------------------------------------------------------------
    # §4.10.2 Org Domain selection (after the walk finishes):
    #   Rule 1: psd=n  -> that record's domain is the Org Domain.
    #   Rule 2: psd=y at a domain other than the one where the Tree
    #           Walk started -> Org Domain is the domain one label
    #           below it.
    #   Rule 3: otherwise, the record with the fewest labels.
    #
    # "The domain where the Tree Walk started" (rule 2's exclusion) is
    # the Author Domain itself, per RFC 9989 §4.10.2's own worked
    # example: "if in the course of a Tree Walk a DMARC Policy Record
    # is queried for at first '_dmarc.mail.example.com' and then
    # '_dmarc.example.com', and a valid DMARC Policy Record containing
    # the 'psd' tag set to 'y' is found at '_dmarc.example.com', then
    # 'mail.example.com' is the domain one label below 'example.com'
    # ... and is thus the Organizational Domain." The excluded domain
    # is the original Author Domain, not whichever domain the technical
    # walk phase happens to query first (which per §4.10.1 paragraph 5
    # is already the immediate parent for <8-label Author Domains).
    # This whole branch only runs when the Author Domain had no record
    # of its own, so it is never a candidate here -- rule 2's exclusion
    # never applies in this branch. _walk_after_author_hit's psd=y
    # handling reads the exclusion the same way.
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
        elif psd == "y":
            # §4.10.2 rule 2: psd=y (never the Author Domain in this
            # branch) -> Org Domain is the name one label below the PSD.
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
        "org_domain_method": "walked",
        "psd_flag": psd_flag,
        "query_count": walk_query_count,
        "collected_records": [
            {"domain": r["domain"], "psd": r["psd"]} for r in collected_records
        ],
    }


def _author_hit_result(
    domain: str,
    steps: list,
    record: str,
    policy: str,
    psd: str,
    org_domain: str,
    org_domain_method: str,
    walk_query_count: int = 0,
    collected_records: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Return value for the Author-Domain-hit branch of §4.10.1.

    Policy always comes from the Author Domain's own record (§4.10.1-6:
    when the applied policy record IS that of the Author Domain, the
    "p" tag provides the Domain Owner Assessment Policy directly; the
    sp/np cascade does not apply). Org Domain is decided by the caller
    per §4.10.1 ¶3 / §4.10.2 and surfaced via org_domain_method.
    """
    return {
        "domain": domain,
        "steps": steps,
        "policy_source": domain,
        "effective_policy": policy,
        "effective_record": record,
        "is_subdomain": False,
        "applied_tag": "p",
        "org_domain": org_domain,
        "org_domain_method": org_domain_method,
        "psd_flag": psd,
        "query_count": walk_query_count,
        "collected_records": [
            {"domain": r["domain"], "psd": r["psd"]}
            for r in (collected_records or [])
        ],
    }


def _walk_after_author_hit(
    domain: str,
    labels: List[str],
    steps: list,
    author_record_info: Dict[str, Any],
    author_record: str,
    author_policy: str,
    author_psd: str,
) -> Dict[str, Any]:
    """Walk after an Author-Domain hit when the Author record has no psd.

    §4.10.1 ¶3: a record at the Author Domain "does not necessarily
    mean that the Author Domain is the Organizational Domain". When
    psd is absent or "u", §4.10.2 still has to run to identify the Org
    Domain. The Author Domain record is included in the §4.10.2 rule 3
    fewest-labels comparison.

    Policy stays anchored to the Author Domain record. The walk only
    affects the Org Domain decision. If the walk turns up no other
    DMARC records, fall back to the PSL Org Domain so subdomains whose
    parents do not publish DMARC do not get treated as their own org
    (matches RFC 7489 receiver behavior and avoids false-external-rua
    flags on rua= addresses at the parent).
    """
    num_labels = len(labels)

    if num_labels >= 8:
        start_labels = labels[-7:]
    else:
        start_labels = labels[1:]

    current_labels = list(start_labels)
    walked_records: List[Dict[str, Any]] = []
    stop_record: Optional[Dict[str, Any]] = None
    walk_query_count = 0

    while len(current_labels) >= 1 and walk_query_count < MAX_TREE_WALK_QUERIES:
        parent = ".".join(current_labels)
        record = _query_dmarc(parent)
        walk_query_count += 1

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

            if psd == "n" or psd == "y":
                stop_record = record_info
                step_entry["stop_reason"] = f"psd={psd}"
                break

            walked_records.append(record_info)
            step_entry["collected"] = True

        current_labels = current_labels[1:]

    if walk_query_count >= MAX_TREE_WALK_QUERIES and stop_record is None and current_labels:
        if steps:
            steps[-1]["stop_reason"] = "query_limit"

    # §4.10.2 selection. The Author Domain itself counts as the
    # "domain where the tree walk started" (§4.10.2 paragraph: walks
    # for Identifier Alignment may start at the Author Domain), so
    # rule 2 does NOT exclude walked psd=y records.
    org_domain: Optional[str] = None
    org_domain_method = "walked"
    psd_flag = author_psd

    if stop_record:
        psd = stop_record["psd"]
        psd_flag = psd
        if psd == "n":
            org_domain = stop_record["domain"]
        elif psd == "y":
            # §4.10.2 rule 2: Org Domain is one label below the PSD.
            psd_labels = stop_record["labels"]
            org_candidate = None
            for rec in [author_record_info] + walked_records:
                if len(rec["labels"]) == len(psd_labels) + 1:
                    org_candidate = rec
                    break
            if org_candidate:
                org_domain = org_candidate["domain"]
            else:
                org_domain_labels = labels[-(len(psd_labels) + 1):]
                org_domain = ".".join(org_domain_labels)
    else:
        # §4.10.2 rule 3: fewest labels among collected. Author Domain
        # is included.
        candidates = [author_record_info] + walked_records
        chosen = min(candidates, key=lambda r: len(r["labels"]))
        org_domain = chosen["domain"]

        # Walk found no records other than the Author Domain itself:
        # spec rule 3 trivially returns the Author Domain. Fall back to
        # the PSL Org Domain so that subdomain audits with rua=mailto:
        # at the parent do not get false-external flags when the parent
        # does not publish DMARC.
        if not walked_records and num_labels > 2:
            psl_org = _psl_org_domain(domain)
            if psl_org and psl_org != domain:
                org_domain = psl_org
                org_domain_method = "psl_fallback"

    return {
        "domain": domain,
        "steps": steps,
        "policy_source": domain,
        "effective_policy": author_policy,
        "effective_record": author_record,
        "is_subdomain": False,
        "applied_tag": "p",
        "org_domain": org_domain,
        "org_domain_method": org_domain_method,
        "psd_flag": psd_flag,
        "query_count": walk_query_count,
        "collected_records": [
            {"domain": r["domain"], "psd": r["psd"]}
            for r in walked_records
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
        "org_domain_method": None,
        "psd_flag": None,
        "query_count": query_count,
        "collected_records": [],
    }
