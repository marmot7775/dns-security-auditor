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

from dns_tools import get_resolver


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
        # Qualified all (e.g. ~all, ?all, +all) jammed onto prior text.
        # None of those three qualifiers can appear inside a domain name or
        # an IP address, so finding one mid token is unambiguous.
        r'[~?+]all(?=\s|$)',
        # '-all' is the ambiguous case: '-' is a legal hostname character, so
        # "include:mail-all" is an ordinary target and not a jammed record.
        # Only split when the character before the qualifier could not be the
        # end of a label, which is what makes it a real token boundary.
        r'(?<![A-Za-z0-9])-all(?=\s|$)',
    ]

    pattern = r'(?<=\S)(' + '|'.join(SPLIT_BEFORE) + ')'
    repaired = re.sub(pattern, r' \1', record, flags=re.IGNORECASE)

    # Handle v=spf1 not followed by a space (e.g. "v=spf1ip4:...")
    repaired = re.sub(r'(v=spf1)(?=\S)', r'\1 ', repaired, flags=re.IGNORECASE)

    is_malformed = repaired != record
    return repaired, is_malformed


def _get_resolver(timeout: float = 5.0):
    # Shared factory: every resolver in the process draws from one TTL-honoring
    # answer cache, so the repeated lookups a single audit makes hit memory
    # instead of the network.
    return get_resolver(timeout)


# Outcome of a single SPF TXT lookup.
SPF_FOUND = "found"
# The name resolves but publishes no SPF record. RFC 7208 section 5.2: a
# recursive check_host() that returns "none" makes the include a permerror.
SPF_NO_RECORD = "no_record"
# The name does not exist. RFC 7208 section 4.6.4 counts this as a void lookup.
SPF_NXDOMAIN = "nxdomain"
# SERVFAIL, timeout, no reachable nameserver. We do not know what is
# published, so we must neither advise on it nor call the record clean.
SPF_INDETERMINATE = "indeterminate"
# More than one v=spf1 record is published at the name. RFC 7208 section 4.5
# makes that a PermError for the whole evaluation, not just for that name.
SPF_MULTIPLE = "multiple"


def _lookup_spf(domain: str) -> Dict[str, Any]:
    """Fetch a domain's SPF TXT record and classify the DNS outcome.

    Returns {"record": Optional[str], "status": SPF_*, "error": Optional[str]}.

    A transient failure is not the same answer as "no record": collapsing the
    two makes the tool advise removing a live include on the strength of one
    SERVFAIL, and silently drops that subtree's lookups from the count.
    """
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(domain, "TXT")
    except dns.resolver.NXDOMAIN:
        return {"record": None, "status": SPF_NXDOMAIN,
                "error": f"{domain} does not exist (NXDOMAIN)"}
    except dns.resolver.NoAnswer:
        return {"record": None, "status": SPF_NO_RECORD, "error": None}
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        return {"record": None, "status": SPF_INDETERMINATE,
                "error": (f"DNS lookup for {domain} did not complete "
                          f"({type(e).__name__})")}
    except Exception as e:
        return {"record": None, "status": SPF_INDETERMINATE,
                "error": (f"DNS lookup for {domain} did not complete "
                          f"({type(e).__name__})")}

    # Every v=spf1 record at the name, not just the first. RFC 7208 section
    # 4.5: if more than one is published, check_host() returns permerror, so
    # stopping at the first one hides a record that fails at every receiver.
    records = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if txt.strip().lower().startswith("v=spf1"):
            repaired, _ = repair_spf_missing_spaces(txt.strip())
            records.append(repaired)

    if len(records) > 1:
        return {"record": None, "status": SPF_MULTIPLE,
                "error": (f"{domain} publishes {len(records)} SPF records "
                          f"(RFC 7208 section 4.5 requires exactly one)")}
    if records:
        return {"record": records[0], "status": SPF_FOUND, "error": None}

    return {"record": None, "status": SPF_NO_RECORD, "error": None}


def _get_spf_record(domain: str) -> Optional[str]:
    """Fetch SPF TXT record for a domain (record only)."""
    return _lookup_spf(domain)["record"]


def _query_answer_status(domain: str, rdtype: str) -> str:
    """Resolve one name and report "ok", "void" or "error".

    RFC 7208 section 4.6.4 defines a void lookup as a query that returns
    NXDOMAIN or zero answer records.
    """
    try:
        resolver = _get_resolver()
        answers = resolver.resolve(domain, rdtype)
        return "ok" if len(answers) > 0 else "void"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "void"
    except Exception:
        return "error"


def _mechanism_target(mech: Dict[str, str], current_domain: str) -> str:
    """The name a lookup mechanism queries, with any dual-cidr suffix removed."""
    value = (mech.get("value") or "").strip()
    if value:
        value = value.split("/", 1)[0]
    return value or current_domain


def _mechanism_lookup_status(mtype: str, target: str) -> str:
    """Resolve an a:/mx:/exists: target. Returns "ok", "void" or "error"."""
    if not target or "%" in target:
        # A macro-expanded target depends on the connecting client, so it
        # cannot be evaluated from the record alone.
        return "ok"
    if mtype == "mx":
        return _query_answer_status(target, "MX")
    if mtype == "exists":
        # RFC 7208 section 5.7: exists: always issues an A query.
        return _query_answer_status(target, "A")
    # "a": an AAAA-only host is not a void lookup, so check both.
    status = _query_answer_status(target, "A")
    if status == "void":
        status6 = _query_answer_status(target, "AAAA")
        return "ok" if status6 == "ok" else status6
    return status


# Mechanisms that consume a DNS lookup per RFC 7208
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def record_has_all(mechanisms: List[Dict[str, str]]) -> bool:
    """True when an 'all' mechanism appears anywhere in the record."""
    return any(
        m.get("type") == "no_lookup" and (m.get("value") or "").lower() == "all"
        for m in mechanisms
    )


def mechanism_is_all(mech: Dict[str, str]) -> bool:
    """True for the 'all' mechanism, whatever qualifier it carries."""
    return (mech.get("type") == "no_lookup"
            and (mech.get("value") or "").lower() == "all")


def mechanism_is_macro(mech: Dict[str, str]) -> bool:
    """True when the target is macro expanded at evaluation time.

    A macro expanded target depends on the connecting client, so it cannot be
    resolved from the record alone.
    """
    return "%" in (mech.get("value") or "")


def mechanism_recurses(mech: Dict[str, str], has_all: bool) -> bool:
    """True when this mechanism causes the counter to fetch a target's SPF.

    The trace and the tree visualization pair child nodes to mechanisms, so
    they have to agree with the counter on which mechanisms produced one.
    """
    mtype = mech.get("type")
    if mtype == "redirect" and has_all:
        # RFC 7208 section 6.1: redirect is ignored when 'all' is present.
        return False
    if mtype not in ("include", "redirect"):
        return False
    return not mechanism_is_macro(mech)


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
        "lookup_status": None,
        "void_lookups": 0,
        "indeterminate": False,
        "macro_targets": [],
    }

    domain_lower = domain.lower().rstrip(".")
    if domain_lower in visited:
        node["error"] = f"Circular reference: {domain} already visited"
        return node
    visited.add(domain_lower)

    if depth > max_depth:
        node["error"] = f"Max recursion depth ({max_depth}) exceeded"
        return node

    lookup = _lookup_spf(domain)
    spf_record = lookup.get("record")
    node["lookup_status"] = lookup.get("status") or (
        SPF_FOUND if spf_record else SPF_NO_RECORD
    )
    if not spf_record:
        if node["lookup_status"] == SPF_INDETERMINATE:
            node["indeterminate"] = True
            node["error"] = lookup.get("error") or (
                f"DNS lookup for {domain} did not complete"
            )
        elif node["lookup_status"] == SPF_NXDOMAIN:
            node["error"] = f"{domain} does not exist (NXDOMAIN)"
        elif node["lookup_status"] == SPF_MULTIPLE:
            node["error"] = lookup.get("error") or (
                f"{domain} publishes more than one SPF record"
            )
        else:
            node["error"] = f"No SPF record found for {domain}"
        return node

    node["record"] = spf_record
    mechanisms = _parse_spf_mechanisms(spf_record)
    node["mechanisms"] = mechanisms

    # RFC 7208 §6.1: a redirect modifier MUST be ignored if an 'all'
    # mechanism appears anywhere in the record, since 'all' always
    # matches and redirect is only reached when nothing else matched.
    has_all = record_has_all(mechanisms)

    local_lookups = 0
    local_voids = 0
    local_macros = []

    for mech in mechanisms:
        mtype = mech["type"]

        # RFC 7208 §5.1: terms after 'all' are never evaluated.
        if mechanism_is_all(mech):
            break

        if mtype in ("a", "mx", "ptr", "exists"):
            local_lookups += 1
            # RFC 7208 section 4.6.4: a void lookup is a query that returns
            # NXDOMAIN or an empty answer, so the target has to actually be
            # resolved. Counting the mechanism without querying it reports a
            # record full of dead a:/mx:/exists: targets as clean while
            # enforcing receivers return a PermError.
            #
            # ptr: is deliberately excluded: its query is a PTR of the
            # connecting client's IP, which cannot be evaluated from the
            # record alone.
            if mtype != "ptr":
                mech_status = _mechanism_lookup_status(
                    mtype, _mechanism_target(mech, domain)
                )
                if mech_status == "void":
                    local_voids += 1
                    mech["void"] = True
                elif mech_status == "error":
                    node["indeterminate"] = True

        elif mtype in ("include", "redirect"):
            # RFC 7208 §6.1: a redirect with 'all' present is never reached,
            # so it costs nothing and resolves nothing.
            if mtype == "redirect" and has_all:
                continue

            local_lookups += 1

            # A macro expanded target is built from the connecting client's
            # address and identity, so there is no name here to resolve. The
            # lookup still happens at evaluation time and is counted, but
            # recursing into the literal text queries a name nobody publishes
            # and books the NXDOMAIN as a void lookup, which turns a working
            # macro record into a false PermError.
            if mechanism_is_macro(mech):
                mech["macro"] = True
                local_macros.append(mech.get("raw") or mech["value"])
                continue

            child = _count_recursive(mech["value"], set(visited), depth + 1, max_depth)
            node["children"].append(child)
            if child.get("lookup_status") == SPF_NXDOMAIN:
                local_voids += 1

    node["lookups_here"] = local_lookups
    node["void_lookups"] = local_voids
    node["macro_targets"] = local_macros
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
        "lookup_status": node.get("lookup_status"),
        "void_lookups": node.get("void_lookups", 0),
        "indeterminate": bool(node.get("indeterminate")),
        "macro_targets": list(node.get("macro_targets") or []),
    }

    lookup_details = []
    lookup_types = []
    for mech in node.get("mechanisms", []):
        if mech["type"] in LOOKUP_MECHANISMS:
            lookup_details.append(mech["raw"])
            lookup_types.append(mech["type"])
    entry["lookup_mechanisms"] = lookup_details
    entry["lookup_mechanism_types"] = lookup_types

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

    # RFC 7208 section 4.6.4 void lookups: NXDOMAIN or empty-answer results
    # from a:, mx:, exists: targets and from include/redirect targets that do
    # not exist. Counted where they happen, in _count_recursive.
    void_lookups = sum(e.get("void_lookups", 0) for e in chain)
    indeterminate_domains = [e["domain"] for e in chain if e.get("indeterminate")]
    # chain[0] is the audited domain itself: it having no SPF record is
    # "no SPF", not an include permerror.
    permerror_domains = [
        e["domain"] for e in chain[1:] if e.get("lookup_status") == SPF_NO_RECORD
    ]
    nxdomain_domains = [
        e["domain"] for e in chain[1:] if e.get("lookup_status") == SPF_NXDOMAIN
    ]
    # RFC 7208 section 4.5 makes more than one SPF record at a name a
    # permerror for the whole evaluation, wherever in the chain it sits, so
    # the audited domain is included here rather than skipped.
    multiple_spf_domains = [
        e["domain"] for e in chain if e.get("lookup_status") == SPF_MULTIPLE
    ]
    # (domain, term) for every include or redirect whose target is macro
    # expanded. Deduplicated, since the same term can appear more than once.
    macro_terms = []
    for entry in chain:
        for term in entry.get("macro_targets", []):
            pair = (entry["domain"], term)
            if pair not in macro_terms:
                macro_terms.append(pair)

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
        "void_lookups": void_lookups,
        "indeterminate": bool(indeterminate_domains),
        "indeterminate_domains": indeterminate_domains,
        "permerror_domains": permerror_domains,
        "multiple_spf_domains": multiple_spf_domains,
        "macro_terms": [{"domain": d, "term": t} for d, t in macro_terms],
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

    # A DNS failure we could not resolve one way or the other. Say so, and do
    # not hand out removal advice or a clean bill of health on the strength of
    # a SERVFAIL or a timeout.
    if indeterminate_domains:
        if result["status"] == "pass":
            result["status"] = "warn"
        result["summary"] += (
            " Some lookups did not complete, so this count may be incomplete."
        )
    for target in indeterminate_domains:
        result["issues"].append({
            "severity": "warning",
            "issue": f"SPF lookup for {target} did not complete",
            "plain_english": (
                f"The DNS query for {target} failed to answer (SERVFAIL, "
                f"timeout, or no reachable nameserver) rather than telling us "
                f"there is no record. This audit cannot say whether {target} "
                f"is healthy, and cannot count the lookups inside it, so the "
                f"totals above may be under-counted."
            ),
            "impact": "Lookup count and include health for this branch are unknown.",
            "fix": (
                f"Re-run the audit. If {target} keeps failing to answer, raise "
                f"it with whoever operates that domain. Do not remove the "
                f"include on the strength of a transient DNS failure."
            ),
        })

    # RFC 7208 section 5.2: when the recursive check_host() of an include
    # target returns "none" -- the name resolves and publishes no SPF record
    # -- the include produces a permerror. That is immediate and has nothing
    # to do with the two-void-lookup budget.
    for target in permerror_domains:
        result["issues"].append({
            "severity": "error",
            "issue": f"Broken include: {target} publishes no SPF record",
            "plain_english": (
                f"Your SPF chain includes {target}, but {target} resolves and "
                f"publishes no SPF record. RFC 7208 section 5.2 makes that an "
                f"immediate PermError for the including record, not a 'void "
                f"lookup' you are allowed two of. SPF fails entirely."
            ),
            "impact": "SPF returns PermError. Authentication fails for every message.",
            "fix": (
                f"Remove the include for {target}, or have {target} publish an "
                f"SPF record."
            ),
        })

    for target in nxdomain_domains:
        result["issues"].append({
            "severity": "warning",
            "issue": f"Broken include: {target} does not exist",
            "plain_english": (
                f"Your SPF chain includes {target}, but that name does not "
                f"exist (NXDOMAIN). RFC 7208 section 4.6.4 counts this as a "
                f"void lookup and allows only two."
            ),
            "impact": "Wasted lookup slot and potential PermError.",
            "fix": f"Remove the include for {target}.",
        })

    # RFC 7208 section 4.5: exactly one SPF record per name. Two of them at
    # any name in the chain is a permerror for the whole evaluation, so an
    # include target with duplicates breaks the including domain too.
    for target in multiple_spf_domains:
        result["issues"].append({
            "severity": "error",
            "issue": f"Multiple SPF records at {target}",
            "plain_english": (
                f"{target} publishes more than one v=spf1 record. RFC 7208 "
                f"section 4.5 requires exactly one, and receivers return a "
                f"PermError for the entire evaluation when they find two. "
                f"That failure applies to this whole SPF chain, not only to "
                f"mail sent from {target}."
            ),
            "impact": "SPF returns PermError. Authentication fails for every message.",
            "fix": (
                f"Merge the SPF records at {target} into a single v=spf1 "
                f"record. If {target} is not yours, raise it with whoever "
                f"operates it."
            ),
        })

    # Macro expanded include and redirect targets. Reported so the lookup they
    # cost is explained, not so the operator removes a working mechanism.
    for owner, term in macro_terms:
        result["issues"].append({
            "severity": "info",
            "issue": f"Macro expanded target not evaluated: {term}",
            "plain_english": (
                f"The term {term} in the SPF record for {owner} builds its "
                f"target from macros at evaluation time, using the connecting "
                f"client's address and identity. The target cannot be "
                f"resolved from the record alone, so this audit counts the "
                f"DNS lookup it costs and makes no claim about what the "
                f"target publishes."
            ),
            "impact": "One lookup counted. This branch is not checked further.",
            "fix": (
                "No change needed if the macro is intentional. Confirm the "
                "expansion with whoever operates the macro zone if you are "
                "not sure it still resolves."
            ),
        })

    # Check for deprecated ptr mechanism
    for entry in chain:
        # Match the parsed mechanism type, not the raw text: a substring test
        # flags include:spf.mailptr.com as a ptr mechanism.
        for mech_type in entry.get("lookup_mechanism_types", []):
            if mech_type == "ptr":
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

    print("\nLookup Chain:")
    for entry in result["chain"]:
        indent = "  " * entry["depth"]
        domain_str = entry["domain"]
        lookups = entry["lookups"]
        mechs = ", ".join(entry.get("lookup_mechanisms", []))
        error = f" [ERROR: {entry['error']}]" if entry.get("error") else ""
        print(f"{indent}{domain_str}: {lookups} lookups ({mechs}){error}")

    if result["issues"]:
        print("\nIssues:")
        for issue in result["issues"]:
            print(f"  [{issue['severity'].upper()}] {issue['issue']}")
            print(f"    Fix: {issue['fix']}")
