"""
SPF Execution Engine & DMARC Evaluation Summary
=================================================
Post-processes existing audit data to produce:
  1. SPF evaluation trace -- step-by-step mechanism walk
  2. DMARC evaluation summary -- alignment + disposition logic

Zero extra DNS queries. Transforms data already computed by the audit.
"""

from typing import Any, Dict, List, Optional
from spf_intelligence import SPF_VENDOR_MAP


# ============================================================
# Vendor matching
# ============================================================

def _match_vendor(domain: str) -> tuple:
    """Match a domain against SPF_VENDOR_MAP. Returns (vendor, category) or (None, None)."""
    domain_lower = domain.lower().rstrip(".")
    for pattern, info in SPF_VENDOR_MAP.items():
        if pattern in domain_lower:
            return info["vendor"], info["category"]
    return None, None


# ============================================================
# SPF Execution Trace
# ============================================================

def _walk_tree(node: Dict, flat_steps: List[Dict], running_total: int,
               depth: int, limit: int, exceeded_flagged: List[bool]) -> int:
    """
    Depth-first, left-to-right walk of the SPF recursive tree.
    Mirrors RFC 7208 evaluation order.

    Args:
        node: A node from count_spf_lookups() tree
        flat_steps: Accumulator for the flat timeline
        running_total: DNS lookups consumed so far
        depth: Current nesting depth (0 = root)
        limit: SPF lookup limit (10)
        exceeded_flagged: Single-element list used as mutable flag

    Returns:
        Updated running_total after processing this node
    """
    mechanisms = node.get("mechanisms", [])
    children = node.get("children", [])
    child_idx = 0

    for mech in mechanisms:
        mtype = mech["type"]
        raw = mech.get("raw", "")
        qualifier = "+"
        if raw and raw[0] in "+-~?":
            qualifier = raw[0]

        if mtype in ("include", "redirect"):
            # This mechanism costs 1 lookup itself, plus its children
            running_total += 1
            mechanism_start = running_total

            # Get the child subtree for this include/redirect
            child_node = children[child_idx] if child_idx < len(children) else None
            child_idx += 1

            # Count child lookups
            child_lookups = child_node["total"] - child_node.get("lookups_here", 0) if child_node else 0
            child_local = child_node.get("lookups_here", 0) if child_node else 0
            subtree_cost = 1 + (child_node["total"] if child_node else 0) - 1  # -1 because the include itself is already counted
            # Actually: include costs 1 lookup + child's total
            total_cost = 1 + (child_node["total"] if child_node else 0)
            mechanism_end = mechanism_start - 1 + (child_node["total"] if child_node else 0)

            # Only match vendor on top-level includes (depth 0)
            vendor, vendor_category = (None, None)
            if depth == 0:
                value = mech.get("value", "")
                vendor, vendor_category = _match_vendor(value)

            status = "ok"
            if not exceeded_flagged[0] and running_total + (child_node["total"] if child_node else 0) > limit:
                # Check if this mechanism pushes us over
                pass

            # Process children recursively to get accurate running_total
            old_total = running_total
            if child_node:
                running_total = _walk_tree(child_node, [], running_total, depth + 1, limit, exceeded_flagged)

            lookup_range = str(mechanism_start) if running_total == mechanism_start else f"{mechanism_start}-{running_total}"

            if not exceeded_flagged[0] and running_total > limit:
                status = "exceeded"
                exceeded_flagged[0] = True
            elif exceeded_flagged[0]:
                status = "exceeded"

            flat_steps.append({
                "mechanism": raw or f"{mtype}:{mech.get('value', '')}",
                "type": mtype,
                "qualifier": qualifier,
                "vendor": vendor,
                "vendor_category": vendor_category,
                "lookup_cost": running_total - old_total + 1,
                "lookup_range": lookup_range,
                "running_total": running_total,
                "status": status,
                "depth": depth,
            })

        elif mtype in ("a", "mx", "ptr", "exists"):
            running_total += 1
            status = "ok"
            if not exceeded_flagged[0] and running_total > limit:
                status = "exceeded"
                exceeded_flagged[0] = True
            elif exceeded_flagged[0]:
                status = "exceeded"

            flat_steps.append({
                "mechanism": raw or mtype,
                "type": mtype,
                "qualifier": qualifier,
                "vendor": None,
                "vendor_category": None,
                "lookup_cost": 1,
                "lookup_range": str(running_total),
                "running_total": running_total,
                "status": status,
                "depth": depth,
            })

        elif mtype == "no_lookup":
            # ip4, ip6, all -- no DNS lookup cost
            flat_steps.append({
                "mechanism": raw,
                "type": mtype,
                "qualifier": qualifier,
                "vendor": None,
                "vendor_category": None,
                "lookup_cost": 0,
                "lookup_range": None,
                "running_total": running_total,
                "status": "ok",
                "depth": depth,
            })

    return running_total


def build_spf_execution_trace(spf_recursive_result: Dict, spf_record: Optional[str]) -> Optional[Dict]:
    """
    Build a step-by-step SPF evaluation trace from existing recursive lookup data.

    Args:
        spf_recursive_result: The full result from count_spf_lookups()
        spf_record: The raw SPF record string

    Returns:
        Trace dict with steps[] and flat_steps[], or None on error
    """
    if not spf_recursive_result:
        return None

    tree = spf_recursive_result.get("tree")
    if not tree:
        return None

    total_lookups = spf_recursive_result.get("total_lookups", 0)
    limit = 10
    flat_steps = []
    exceeded_flagged = [False]

    _walk_tree(tree, flat_steps, 0, 0, limit, exceeded_flagged)

    return {
        "domain": spf_recursive_result.get("domain", ""),
        "record": spf_record or spf_recursive_result.get("record"),
        "total_lookups": total_lookups,
        "limit": limit,
        "over_limit": total_lookups > limit,
        "flat_steps": flat_steps,
    }


# ============================================================
# DMARC Evaluation Summary
# ============================================================

def build_dmarc_evaluation(raw_dmarc: Dict, raw_spf: Dict,
                           raw_dkim: Dict, tree_walk: Optional[Dict]) -> Optional[Dict]:
    """
    Build a DMARC evaluation summary showing how receivers would process
    legitimate mail from this domain's authorized servers.

    This is educational -- it shows the *best case* for properly configured mail,
    not a live message evaluation.

    Args:
        raw_dmarc: Raw DMARC check result
        raw_spf: Raw SPF check result
        raw_dkim: Raw DKIM check result
        tree_walk: Tree walk result (for inherited policies)

    Returns:
        Evaluation dict, or None if insufficient data
    """
    if not raw_dmarc:
        return None

    # Need at least SPF or DKIM data to produce a meaningful evaluation.
    # Without them (e.g. dmarc-only scope), the eval would be misleading.
    has_spf_data = bool(raw_spf and raw_spf.get("record"))
    has_dkim_data = bool(raw_dkim and raw_dkim.get("found_selectors"))
    if not has_spf_data and not has_dkim_data:
        return None

    # --- SPF result ---
    spf_record = raw_spf.get("record") if raw_spf else None
    spf_status = raw_spf.get("status", "error") if raw_spf else "error"
    spf_lookup_count = raw_spf.get("lookup_count", 0) if raw_spf else 0

    if not spf_record:
        spf_result = "none"
    elif spf_status == "error" or spf_lookup_count > 10:
        spf_result = "permerror"
    else:
        spf_result = "pass"

    # --- DKIM result ---
    found_selectors = raw_dkim.get("found_selectors", []) if raw_dkim else []
    dkim_result = "pass" if found_selectors else "none"

    # --- DMARC record and alignment modes ---
    dmarc_record = raw_dmarc.get("record")
    if not dmarc_record and not (tree_walk and tree_walk.get("policy_source")):
        return None  # No DMARC at all, nothing to evaluate

    aspf = raw_dmarc.get("aspf") or "r"  # default relaxed
    adkim = raw_dmarc.get("adkim") or "r"  # default relaxed

    spf_alignment_mode = "strict" if aspf == "s" else "relaxed"
    dkim_alignment_mode = "strict" if adkim == "s" else "relaxed"

    # For this educational display, we assume alignment passes for
    # properly configured mail (same organizational domain)
    spf_aligned = spf_result == "pass"
    dkim_aligned = dkim_result == "pass"

    # --- DMARC result ---
    # DMARC passes if EITHER (SPF pass + aligned) OR (DKIM pass + aligned)
    dmarc_pass = (spf_result == "pass" and spf_aligned) or (dkim_result == "pass" and dkim_aligned)
    dmarc_result = "pass" if dmarc_pass else "fail"

    # --- Policy ---
    policy = raw_dmarc.get("policy") or ""
    if not policy and tree_walk and tree_walk.get("effective_policy"):
        policy = tree_walk["effective_policy"]
    policy = policy.lower() if policy else "none"

    # Disposition: what happens to the message
    if dmarc_pass:
        disposition = "none"  # passes, delivered normally
    else:
        disposition = policy  # apply the domain's policy

    # --- Explanation ---
    if dmarc_pass:
        passing_methods = []
        if spf_result == "pass" and spf_aligned:
            passing_methods.append("SPF")
        if dkim_result == "pass" and dkim_aligned:
            passing_methods.append("DKIM")
        methods_str = " and ".join(passing_methods)
        explanation = (
            f"DMARC passes because {methods_str} "
            f"{'both pass' if len(passing_methods) > 1 else 'passes'} "
            f"with {spf_alignment_mode} alignment. "
            f"Legitimate mail from authorized servers will be delivered."
        )
    else:
        explanation = (
            "DMARC fails because neither SPF nor DKIM passes with alignment. "
            f"The domain's policy ({policy}) determines how receivers handle the message."
        )

    return {
        "spf_result": spf_result,
        "spf_aligned": spf_aligned,
        "spf_alignment_mode": spf_alignment_mode,
        "dkim_result": dkim_result,
        "dkim_aligned": dkim_aligned,
        "dkim_alignment_mode": dkim_alignment_mode,
        "dmarc_result": dmarc_result,
        "policy": policy,
        "disposition": disposition,
        "explanation": explanation,
    }
