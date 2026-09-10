"""
Result Transformer
==================
Converts raw audit module outputs into the uniform card format
expected by the frontend.

Each card looks like:
{
    "name": "DMARC",
    "status": "pass" | "warn" | "fail",
    "pill_label": optional override for the status pill text,
    "verdict": "one-line summary for the collapsed card header",
    "record": "the raw DNS record string (shown in monospace block)",
    "configured": True | False,  # this protocol has something published, decided
        # from the check result rather than from pill_label text
        # (see build_executive_summary's Protocol Coverage metric)
    "explanation": "HTML-safe plain-English explanation",
    "details": [
        {"type": "error|warning|info|good", "text": "..."}
    ],
    "fix": "HTML-safe recommended action (shown in blue fix block)"
}
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from html import escape as _e

from dkim_formatter import analyze_dkim_key_strength


# ============================================================
# Status mapping helpers
# ============================================================

def _map_status(raw_status: str) -> str:
    """Map module statuses to frontend's pass/warn/fail."""
    mapping = {
        "ok": "pass",
        "pass": "pass",
        "good": "pass",
        "info": "pass",
        "warning": "warn",
        "warn": "warn",
        "error": "fail",
        "fail": "fail",
        "critical": "fail",
    }
    return mapping.get(raw_status.lower(), "warn")


def _lookup_unavailable_card(name: str, raw: Dict, subject: str, pill_label: str = "Not checked") -> Dict:
    """Card for a check whose DNS query never completed.

    NXDOMAIN and NoAnswer mean the record is absent and are reported as
    such. SERVFAIL, REFUSED and timeout mean nothing was learned, and the
    difference matters more here than anywhere else in the report: "you have
    no SPF record" and "we could not ask" lead to opposite actions, and the
    first one hands the operator a fix for a problem they may not have.

    Neither a pass nor a finding, so it drops out of the pass/warn/fail
    tallies on the PDF cover and the executive summary rather than padding
    one of them.
    """
    target = raw.get("lookup_target") or raw.get("domain") or ""
    where = f" at <strong>{_e(target)}</strong>" if target else ""
    return {
        "name": name,
        "status": "unavailable",
        "pill_label": pill_label,
        "verdict": "Not checked by this audit",
        "record": None,
        "configured": False,
        "explanation": (
            f"The DNS query for this domain's {subject}{where} did not complete. "
            "The nameserver returned a failure or stopped responding, so this "
            "audit did not learn whether the record exists. This is not a "
            "finding about the domain, and it does not mean the record is "
            "missing. Nothing about the domain was assessed here."
        ),
        "details": [
            {"type": "info", "text": f"The {name} lookup did not complete, so it was not assessed"},
        ],
        "fix": None,
        "fix_records": None,
        # Two different things produce status "unavailable" and they need
        # different prose above the card: a lookup that never completed, and a
        # lookup that completed but cannot settle the question (DKIM selector
        # probing). Readers branch on this rather than on the pill text.
        #
        # Deliberately not "unavailable_reason": raw results already use that
        # key with an unrelated vocabulary ("dns_lookup_failed", "timeout",
        # "response_too_large"), and one name over two vocabularies means a
        # reader holding either dict cannot tell which it has.
        "unavailable_kind": "lookup_failed",
    }


def _issue_to_detail(issue: Dict) -> Dict[str, str]:
    """Convert a module issue dict to a frontend detail item."""
    severity = issue.get("severity", "info").lower()
    type_map = {
        "error": "error",
        "critical": "error",
        "warning": "warning",
        "warn": "warning",
        "info": "info",
        "good": "good",
        "ok": "good",
    }
    detail = {
        "type": type_map.get(severity, "info"),
        "text": issue.get("plain_english") or issue.get("issue", ""),
    }
    risk = issue.get("business_risk")
    if risk:
        detail["business_risk"] = risk
    return detail


def _first_fix(issues: List[Dict]) -> Optional[str]:
    """Extract the first actionable fix from issues list."""
    for issue in issues:
        fix = issue.get("fix")
        if fix:
            return fix
    return None


# ============================================================
# Executive Summary (Prompt 16)
# ============================================================

def _join_names(names: List[str]) -> str:
    """Join names for prose: "SPF", "DMARC and SPF", "DMARC, SPF and DKIM"."""
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " and " + names[-1]


def _spoofing_detail(vectors: List[Dict]) -> str:
    """Say which spoofing vectors are not protected, in severity order."""
    if not vectors:
        return "No DMARC policy to assess"
    exposed = [v["name"] for v in vectors if v.get("status") == "exposed"]
    partial = [v["name"] for v in vectors if v.get("status") == "partial"]
    # "All" rather than listing every one: at p=none all three are exposed and
    # naming them fills the tile with a list the panel below already shows.
    if len(exposed) == len(vectors):
        return "Every spoofing vector exposed"
    if exposed:
        return f"{_join_names(exposed)} exposed"
    if len(partial) == len(vectors):
        return "Every spoofing vector only partly protected"
    if partial:
        return f"{_join_names(partial)} only partly protected"
    return "Every spoofing vector protected"


def build_executive_summary(checks: List[Dict], roadmap: Dict) -> Dict:
    """Build the executive summary card shown at the very top of results.

    Returns a dict with: verdict, spoofing_protection, dmarcbis_readiness,
    protocol_coverage, biggest_risk, and has_record_builder.
    """
    check_map = {c.get("name", ""): c for c in checks}
    dmarc = check_map.get("DMARC", {})

    # A check whose DNS query never completed carries status "unavailable"
    # and an empty record. Every gate below tests for "fail", so without
    # this guard an unavailable check reads as "nothing wrong here" and the
    # summary issues an explicit all clear about records it never read.
    # remediation_planner.py already models this correctly; same guard here.
    #
    # DKIM has a second way to arrive at "unavailable": the probe completed and
    # still could not settle the question, because selectors are not
    # enumerable from DNS. That is not a lookup that failed, and every sentence
    # below keyed off `unread` says the lookups did not complete, so it is kept
    # out of that list and carried separately.
    def _unavailable(name):
        card = check_map.get(name, {})
        return (card.get("status") == "unavailable"
                and card.get("unavailable_kind") != "not_enumerable")

    def _scoped_out(name):
        """This run's scope never queried this check at all.

        scope=dns_infra and scope=transport never run DMARC/SPF/DKIM, so
        those checks are absent from check_map entirely rather than marked
        "unavailable". Falling through to the else branch below asserted
        "Your domain has email authentication configured" from checks that
        never queried DNS.
        """
        return name not in check_map

    def _unconfirmed(name):
        return check_map.get(name, {}).get("unavailable_kind") == "not_enumerable"

    dmarc_unavailable = _unavailable("DMARC")
    spf_unavailable = _unavailable("SPF")
    dkim_unavailable = _unavailable("DKIM")
    dkim_unconfirmed = _unconfirmed("DKIM")
    unread = [n for n, u in (("DMARC", dmarc_unavailable),
                             ("SPF", spf_unavailable),
                             ("DKIM", dkim_unavailable)) if u]
    auth_unavailable = bool(unread)
    unread_names = _join_names(unread)
    unread_verb = "lookups did" if len(unread) > 1 else "lookup did"

    # Unavailable (a lookup ran and failed) and scoped out (this run never
    # queried it) are different facts, but the same one for a verdict: the
    # audit did not read the record and cannot make a claim about it. Used
    # for the verdict and the two metrics computed from the DMARC record.
    # Kept separate from unread/auth_unavailable above, which the
    # deliverability summary and the biggest-risk section below use with
    # their original, narrower meaning: deliverability already names a
    # scoped-out check with its own "outside the scope of this run"
    # sentence, and conflating the two here made this block's generic
    # "lookup did not complete" caveat overwrite that sentence.
    dmarc_unassessed = dmarc_unavailable or _scoped_out("DMARC")
    spf_unassessed = spf_unavailable or _scoped_out("SPF")
    dkim_unassessed = dkim_unavailable or _scoped_out("DKIM")
    unassessed = [n for n, u in (("DMARC", dmarc_unassessed),
                                 ("SPF", spf_unassessed),
                                 ("DKIM", dkim_unassessed)) if u]
    auth_unassessed = bool(unassessed)
    unassessed_names = _join_names(unassessed)
    unassessed_verb = "lookups did" if len(unassessed) > 1 else "lookup did"

    # ── Part 1: One-sentence verdict ─────────────────────────
    attack_surface = dmarc.get("attack_surface")
    health = (dmarc.get("tag_breakdown") or {}).get("health", {})
    health_status = health.get("status", "")
    dmarc_status = dmarc.get("status", "")
    spf_check = check_map.get("SPF", {})
    spf_status = spf_check.get("status", "")

    # Count protected vectors.
    #
    # "Reporting Intelligence" is one of the four vectors and it is not a
    # spoofing vector: it describes whether you can see what your policy is
    # doing, not whether an attacker can send as you. Counting it in a metric
    # labelled Spoofing Protection meant a missing rua cost a domain a
    # spoofing point, so a domain rejecting every failing message scored 2 of 4
    # and one quarantining every failing message scored 0 of 4. rua is OPTIONAL
    # in RFC 7489 section 6.3 and in RFC 9989. It stays in the panel, where it
    # belongs; it is out of this count.
    _all_vectors = (attack_surface or {}).get("vectors", [])
    vectors = [v for v in _all_vectors if v.get("name") != "Reporting Intelligence"]
    _vector_total = len(vectors)
    protected_count = sum(1 for v in vectors if v.get("status") == "protected")
    exposed_count = sum(1 for v in vectors if v.get("status") == "exposed")
    partial_count = sum(1 for v in vectors if v.get("status") == "partial")

    # Ahead of every other branch: if a lookup never completed, this report
    # cannot say the domain is healthy or that a record is absent. Saying
    # either would be a claim the audit did not establish.
    if auth_unassessed:
        verdict = (
            "Parts of this domain's DNS did not answer, so its email authentication "
            f"was not assessed. The {unassessed_names} {unassessed_verb} not complete, and this "
            "report cannot say whether those records exist."
        )
    elif dmarc_status == "fail" and dmarc.get("pill_label") == "Missing":
        if spf_check.get("pill_label") == "Missing":
            verdict = (
                "Your domain publishes neither an SPF record nor a DMARC record. "
                "Receivers have no way to tell your mail from mail that only claims "
                "to be yours, and no policy to apply when it fails."
            )
        else:
            verdict = "Your domain has no DMARC record. SPF alone cannot prevent email spoofing."
    elif health_status == "monitoring":
        verdict = "Your domain is monitoring email authentication but not yet enforcing it. This requests no action from receivers, who each decide independently what to do with mail that fails."
    elif _vector_total and protected_count == _vector_total:
        if health_status == "ready":
            verdict = "Your domain is well-protected against email spoofing across all attack vectors."
        else:
            verdict = "Your domain blocks spoofed email across all vectors, with minor improvements available."
    elif protected_count >= 3 and exposed_count == 0:
        verdict = "Your domain has strong email authentication with most attack vectors covered."
    elif exposed_count >= 2:
        verdict = "Your domain has significant gaps in email spoofing protection across multiple attack vectors."
    elif exposed_count == 1:
        weakest = [v for v in vectors if v.get("status") == "exposed"]
        vec_name = weakest[0]["name"].lower() if weakest else "one vector"
        verdict = f"Your domain has email authentication but attackers can still exploit {vec_name}."
    elif partial_count > 0:
        verdict = "Your domain partially blocks spoofed email but enforcement could be stronger."
    else:
        verdict = "Your domain has email authentication configured."

    # Check if enforcement exists but no reporting. Skipped when something
    # went unread, so this cannot overwrite the verdict set above.
    if not auth_unassessed and health_status in ("ready", "compatible", "attention"):
        tb = dmarc.get("tag_breakdown") or {}
        cw = tb.get("config_warnings", [])
        has_no_rua = any(w.get("title") == "No aggregate reporting" for w in cw)
        if has_no_rua:
            verdict = "Your domain blocks spoofed email but has no visibility into what is being blocked."

    # ── Part 2: Three key metrics ────────────────────────────

    # Metric 1: Spoofing Protection
    if dmarc_unassessed:
        spoof_label, spoof_color = "Not assessed", "neutral"
    elif _vector_total and protected_count == _vector_total:
        spoof_label, spoof_color = "Full", "green"
    elif protected_count == _vector_total - 1 and _vector_total > 1:
        spoof_label, spoof_color = "Strong", "green"
    elif protected_count >= 1 and partial_count:
        spoof_label, spoof_color = "Partial", "amber"
    elif protected_count >= 1:
        spoof_label, spoof_color = "Weak", "red"
    elif partial_count:
        spoof_label, spoof_color = "Partial", "amber"
    else:
        spoof_label, spoof_color = "None", "red"

    # No attack surface means no DMARC record, unless the DMARC lookup is the
    # thing that failed, in which case zero vectors is not a finding.
    if not attack_surface and not dmarc_unassessed:
        spoof_label, spoof_color = "None", "red"
        protected_count = 0
        _vector_total = 0

    spoofing_protection = {
        "label": spoof_label,
        "color": spoof_color,
        # Names what is not protected instead of counting what is.
        #
        # "2/3 spoofing vectors protected" hides the difference between a
        # vector that is partial and one that is exposed, which are very
        # different domains with the same fraction, and the denominator moves
        # whenever the vector list changes. The composite grade was removed
        # from this tool in April 2026 for the same reason: a number flattens
        # a report whose value is in the specifics. The per-dimension label
        # survived that removal deliberately and is kept; only the arithmetic
        # beside it is replaced with the thing it was standing in for.
        "detail": ("DMARC lookup did not complete" if dmarc_unassessed
                   else _spoofing_detail(vectors)),
    }

    # Metric 2: RFC 9989 Readiness
    readiness_map = {
        "ready": ("Ready", "green"),
        "compatible": ("Compatible", "blue"),
        "monitoring": ("In Progress", "amber"),
        "attention": ("In Progress", "amber"),
        "misconfigured": ("Action Needed", "red"),
    }
    if dmarc_unassessed:
        # "Action Needed" would be advice drawn from a record never read.
        rd_label, rd_color = "Not assessed", "neutral"
    elif health_status and health_status in readiness_map:
        rd_label, rd_color = readiness_map[health_status]
    else:
        rd_label, rd_color = "Action Needed", "red"

    dmarcbis_readiness = {
        "label": rd_label,
        "color": rd_color,
    }

    # Metric 3: Protocol Coverage
    protocol_names = ["DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "DNSSEC", "BIMI", "CAA"]
    configured = 0
    assessed = 0
    for pname in protocol_names:
        # A protocol this run never checked is not evidence either way. A scoped
        # audit produces no card at all, and check_map.get returned an empty
        # dict whose "" status and "" pill scored as assessed-and-not-configured,
        # so a dmarc-scope run with one perfect record reported "1/9" and the
        # About page then said the cover scored nine of a list holding one name.
        if pname not in check_map:
            continue
        c = check_map[pname]
        st = c.get("status", "")
        # A lookup that never completed is not evidence either way either, so it
        # leaves the denominator instead of scoring as "not configured".
        # Otherwise a protocol nobody could read is indistinguishable from
        # one the domain genuinely does not publish.
        if st == "unavailable":
            continue
        assessed += 1
        # "configured" is set by the transform layer from the check result
        # itself (a record was found), not guessed here from pill_label text.
        # Testing pill_label against a hardcoded allowlist missed every label
        # meaning "nothing published" that wasn't in the allowlist ("Not
        # found", "Not enabled", "No mail", "None", "N/A"), and separately let
        # a pass-status card with no record (BIMI, DANE "N/A"/"Not configured")
        # count as configured without looking at the pill at all.
        if c.get("configured"):
            configured += 1

    total_protocols = assessed
    # Thresholds stay proportional so they mean the same thing when the
    # denominator shrinks. At the full nine these are the original 7 and 4.
    ratio = (configured / total_protocols) if total_protocols else 0.0
    if not total_protocols:
        cov_color = "neutral"
    elif ratio >= 7 / 9:
        cov_color = "green"
    elif ratio >= 4 / 9:
        cov_color = "amber"
    else:
        cov_color = "red"

    protocol_coverage = {
        "configured": configured,
        "total": total_protocols,
        "color": cov_color,
    }

    # ── Part 3: Biggest risk ─────────────────────────────────
    roadmap_items = roadmap.get("items", [])
    _urgent = any(i.get("priority") in ("critical", "high") for i in roadmap_items)
    if auth_unavailable and not _urgent:
        # The roadmap gates on "fail", so an unread record contributes no item
        # and some minor nicety floats to the top. Presenting that as the
        # biggest risk implies the real ones were weighed, and they were not.
        biggest_risk = (
            "This audit could not read part of this domain's DNS, so it cannot name the "
            f"biggest risk. The {unread_names} {unread_verb} not complete. Re-run the audit "
            "once the nameservers are answering."
        )
    else:
        # A low-priority item (an optional nicety like an explicit np= tag)
        # floating to the top of an otherwise-empty roadmap is the same
        # failure mode as the auth_unavailable case above: presenting it as
        # "the biggest risk" implies real risks were weighed and lost, when
        # none were found at all.
        risk_candidates = [i for i in roadmap_items if i.get("priority") != "low"]
        if risk_candidates:
            top = risk_candidates[0]
            biggest_risk = top.get("impact", top.get("action", ""))
        else:
            biggest_risk = "No urgent risks found. The roadmap below lists smaller improvements."

    # ── Part 4: has_record_builder flag ──────────────────────
    has_record_builder = dmarc.get("record_builder") is not None

    # ── Part 5: Deliverability summary ────────────────────────
    deliverability_issues = []
    if dmarc_status == "fail" and dmarc.get("pill_label") == "Missing":
        deliverability_issues.append("no DMARC record")
    elif health_status == "monitoring":
        deliverability_issues.append("DMARC is in monitoring mode (p=none)")

    if spf_status == "fail" and spf_check.get("pill_label") == "Missing":
        deliverability_issues.append("no SPF record")

    spf_lookups = None
    for d in spf_check.get("details", []):
        text = d.get("text", "")
        if "DNS lookups" in text and ("near" in text or "at" in text or "invalid" in text.lower()):
            deliverability_issues.append("SPF lookup count is at or near the limit")
            break

    # DKIM that could not be confirmed by probing is not an issue to list: the
    # domain may well sign under a selector this audit never guessed. It is
    # also not something to pass over in silence, because the all-clear below
    # would otherwise read as covering it. It gets a caveat, not a finding.

    if deliverability_issues:
        top_issue = deliverability_issues[0]
        if "no DMARC" in top_issue:
            deliverability_summary = (
                "Without DMARC, receivers have no instruction for mail that fails "
                "authentication, and you get no reports about who is sending as you. "
                "Google and Yahoo require DMARC of bulk senders (Google's threshold "
                "is 5,000 messages a day to Gmail); below that it is optional but "
                "still the only way to see what is being sent in your name."
            )
        elif "p=none" in top_issue:
            deliverability_summary = "Your DMARC policy is monitoring only (p=none), which requests no action from receivers. It provides visibility, not protection, until you move to p=quarantine or p=reject."
        elif "no SPF" in top_issue:
            deliverability_summary = "Without SPF, receivers cannot verify your sending servers. This is a common cause of emails going to spam."
        elif "SPF lookup" in top_issue:
            deliverability_summary = "Your SPF record is near the 10-lookup limit. Adding one more email service could break SPF for all your email."
        else:
            deliverability_summary = f"Your configuration has {len(deliverability_issues)} issue{'s' if len(deliverability_issues) != 1 else ''} that may affect inbox placement."
    else:
        # Only name the protocols this run actually assessed. The all-clear used
        # to state that SPF, DKIM and DMARC were properly set up on a scoped
        # audit that never queried two of them. auth_unavailable below covers the
        # read-and-failed case; this covers the never-ran case.
        _assessed_auth = [n for n in ("SPF", "DKIM", "DMARC")
                          if check_map.get(n, {}).get("status") not in (None, "unavailable")]
        # DKIM that ran and could not be confirmed is not out of scope, and the
        # caveat appended below already says what happened to it. Naming it here
        # as well would tell the reader it was never checked.
        _out_of_scope = [n for n in ("SPF", "DKIM", "DMARC")
                         if n not in _assessed_auth and not _unconfirmed(n)]
        if len(_assessed_auth) == 3:
            deliverability_summary = "Your configuration looks solid. SPF, DKIM, and DMARC are properly set up, giving you the best chance of reaching inboxes."
        elif _assessed_auth:
            deliverability_summary = (
                f"No inbox placement issues found in what this audit checked. "
                f"{_join_names(sorted(_assessed_auth))} "
                f"{'were' if len(_assessed_auth) > 1 else 'was'} assessed"
            ) + (
                "; the rest of the email authentication stack was outside the "
                "scope of this run." if _out_of_scope else "."
            )
        else:
            deliverability_summary = (
                "This audit did not assess email authentication, so it cannot speak to "
                "inbox placement."
            )

    # A lookup that never completed is not a clean bill of health. Without
    # this, the branch above names SPF, DKIM and DMARC as properly set up on
    # a run that never read them. Real findings are kept and annotated rather
    # than replaced, since a real finding still matters here.
    if auth_unavailable:
        caveat = (f"The {unread_names} {unread_verb} not complete, so that part of the "
                  "configuration was not assessed.")
        if deliverability_issues:
            deliverability_summary = f"{deliverability_summary} {caveat}"
        else:
            deliverability_summary = (
                f"The {unread_names} {unread_verb} not complete, so inbox placement "
                "could not be assessed. Nothing here says the configuration is good "
                "or bad, only that it was not read."
            )

    # Said last so it survives whichever branch above ran. Without it the
    # all-clear reads as covering DKIM, which this audit did not establish
    # either way.
    if dkim_unconfirmed:
        deliverability_summary += (
            " DKIM could not be confirmed by probing, since a selector cannot be "
            "enumerated from DNS. Enter your selector above, or read the s= value "
            "from a message this domain sent, to settle it."
        )

    # Whether biggest_risk actually names a risk. The PDF frames it in fail red
    # unconditionally, which put a red "YOUR BIGGEST RISK RIGHT NOW" box around
    # "No urgent risks found" and around the neutral could-not-read message.
    if auth_unavailable and not _urgent:
        biggest_risk_severity = "unknown"
    elif risk_candidates:
        biggest_risk_severity = top.get("priority", "medium")
    else:
        biggest_risk_severity = "none"

    return {
        "verdict": verdict,
        "spoofing_protection": spoofing_protection,
        "dmarcbis_readiness": dmarcbis_readiness,
        "protocol_coverage": protocol_coverage,
        "biggest_risk": biggest_risk,
        "biggest_risk_severity": biggest_risk_severity,
        "has_record_builder": has_record_builder,
        "deliverability_summary": deliverability_summary,
    }


# ============================================================
# Email Security Roadmap (Prompt 11)
# ============================================================

def build_security_roadmap(checks: List[Dict], is_no_mail: bool = False) -> Dict:
    """Synthesize all check results into a prioritized action plan.

    Takes the transformed checks list and returns a roadmap with
    4 priority tiers: critical, high, medium, low.
    """
    items: List[Dict] = []
    check_map = {c.get("name", ""): c for c in checks}

    dmarc = check_map.get("DMARC", {})
    spf = check_map.get("SPF", {})
    dkim = check_map.get("DKIM", {})
    mta_sts = check_map.get("MTA-STS", {})
    tls_rpt = check_map.get("TLS-RPT", {})
    dane = check_map.get("DANE", {})

    # ── Critical ────────────────────────────────────────────
    if dmarc.get("status") == "fail" and dmarc.get("pill_label") == "Missing":
        items.append({"priority": "critical", "protocol": "DMARC",
                      "action": "Publish a DMARC record",
                      "impact": "Your domain has no DMARC protection. Anyone can send email as your domain."})

    if spf.get("status") == "fail" and spf.get("pill_label") == "Missing":
        items.append({"priority": "critical", "protocol": "SPF",
                      "action": "Publish an SPF record",
                      "impact": "No SPF record means receivers cannot verify your authorized mail servers."})

    # More than one v=spf1 record is a PermError for every message, so it belongs
    # at the same tier as having none. It reaches the roadmap under its own pill
    # rather than "Missing", which is why it used to contribute nothing here.
    if spf.get("pill_label") == "Multiple records":
        items.append({"priority": "critical", "protocol": "SPF",
                      "action": "Merge the duplicate SPF records into one",
                      "impact": "Receivers return PermError and evaluate neither record. SPF fails for every message."})

    # +all in SPF
    if spf.get("record") and "+all" in (spf.get("record") or ""):
        items.append({"priority": "critical", "protocol": "SPF",
                      "action": "Remove +all from your SPF record",
                      "impact": "+all authorizes every server on the internet to send as your domain."})

    # No rua at any policy.
    #
    # Not critical. rua is OPTIONAL in RFC 7489 section 6.3 and in RFC 9989, so
    # a record without it is compliant, and at an enforcing policy the domain
    # is doing the thing that stops spoofing. Ranking it critical put "Add
    # aggregate reporting" in the biggest-risk slot of a domain rejecting every
    # failing message, ahead of anything about the spoofing the report is
    # supposed to be about. It is a real gap and it stays on the roadmap; it is
    # a high, and it does not outrank a policy that is not enforcing.
    tb = dmarc.get("tag_breakdown", {})
    if tb:
        cw = tb.get("config_warnings", [])
        for w in cw:
            if w.get("level") == "critical" and w.get("title") == "No aggregate reporting":
                items.append({"priority": "high", "protocol": "DMARC",
                              "action": "Add aggregate reporting (rua=)",
                              "impact": "You cannot see who is sending as your domain or "
                                        "whether their mail is passing authentication, so a "
                                        "legitimate sender that starts failing goes unnoticed."})
                break

    # ── High ────────────────────────────────────────────────
    # Missing p= with rua: interop hazard between RFC 7489 and RFC 9989
    if tb:
        for w in cw:
            if w.get("title") == "Missing p= tag (interop hazard)":
                items.append({"priority": "high", "protocol": "DMARC",
                              "action": "Add explicit p= tag to the DMARC record",
                              "impact": "RFC 7489 receivers ignore this record entirely; RFC 9989 receivers treat as p=none. Receiver behavior is split."})
                break

    # p=none with rua (monitoring)
    health = tb.get("health", {}) if tb else {}
    if health.get("status") == "monitoring":
        items.append({"priority": "high", "protocol": "DMARC",
                      "action": "Progress from p=none to enforcement",
                      "impact": "Domain is in monitoring mode, requesting no action from receivers, who each decide independently what to do with failing mail."})

    # DKIM weak keys
    dkim_deep = dkim.get("dkim_deep", {})
    # A key that does not parse is broken now, not weak. has_weak stayed False
    # for it, so the roadmap said nothing at all about a key failing every
    # signature it makes.
    if dkim_deep and dkim_deep.get("has_invalid"):
        items.append({"priority": "critical", "protocol": "DKIM",
                      "action": "Republish the unparseable DKIM key",
                      "impact": "The published key does not parse, so every message signed with that selector fails DKIM."})
    if dkim_deep and dkim_deep.get("has_weak"):
        items.append({"priority": "high", "protocol": "DKIM",
                      "action": "Rotate weak DKIM keys to 2048-bit",
                      "impact": "These keys are below current recommendations and should be rotated."})

    # SPF near limit
    spf_deep = spf.get("spf_deep", {})
    if spf_deep and spf_deep.get("lookup_count", 0) >= 8:
        items.append({"priority": "high", "protocol": "SPF",
                      "action": f"Reduce SPF lookups ({spf_deep['lookup_count']}/10)",
                      "impact": "Exceeding 10 lookups causes SPF to fail entirely."})

    # ── Medium ──────────────────────────────────────────────
    # Every gate below reads a pill_label or a count, and an absent card returns
    # the default for both. A scoped audit that never ran MTA-STS, TLS-RPT, DANE
    # or BIMI therefore produced "configure this" advice about checks it did not
    # perform. A check whose lookup failed is excluded for the same reason.
    def _assessed(card):
        return bool(card) and card.get("status") != "unavailable"

    if _assessed(mta_sts) and mta_sts.get("pill_label") == "Not configured":
        items.append({"priority": "medium", "protocol": "MTA-STS",
                      "action": "Configure MTA-STS for TLS enforcement",
                      "impact": "Without MTA-STS, email encryption can be silently stripped."})

    if _assessed(tls_rpt) and (tls_rpt.get("status") == "fail"
                               or tls_rpt.get("pill_label") == "Not configured"):
        items.append({"priority": "medium", "protocol": "TLS-RPT",
                      "action": "Configure TLS-RPT for failure visibility",
                      "impact": "TLS downgrade attacks go undetected."})

    if _assessed(dane) and dane.get("pill_label") == "Not configured":
        items.append({"priority": "medium", "protocol": "DANE",
                      "action": "Consider DANE TLSA records",
                      "impact": "Inbound mail TLS relies solely on the CA system, with no DNS-pinned backstop if a CA is compromised or coerced."})

    # RFC 9989 readiness gaps
    if health.get("status") in ("compatible", "attention"):
        for reason in health.get("reasons", []):
            items.append({"priority": "medium", "protocol": "DMARC",
                          "action": f"Address: {reason}",
                          "impact": "Record is not fully RFC 9989-ready."})

    # ── Low ─────────────────────────────────────────────────
    bimi = check_map.get("BIMI", {})
    if not _assessed(bimi):
        pass  # BIMI was not part of this run, so it gets no recommendation.
    elif bimi.get("records_found", 0) == 0:
        # No item. BIMI is optional branding, so "you have not adopted an
        # optional feature" is not a security recommendation, and it competed
        # for roadmap space with findings the domain can act on.
        pass
    elif bimi.get("status") != "pass":
        action = bimi.get("fix") or "Review your BIMI configuration"
        items.append({"priority": "low", "protocol": "BIMI",
                      "action": action,
                      "impact": "An issue with your existing BIMI setup may prevent your logo from displaying."})

    # np= at an enforcing policy. Not a gap: an absent np inherits from p=,
    # so subdomains are already covered. Worth a low-priority note only
    # because an explicit np= is one less thing for a reader of the record
    # to infer, not because anything is unprotected without it.
    if _assessed(dmarc) and dmarc.get("record"):
        _dmarc_tags = _parse_record_tags(dmarc["record"])
        if _dmarc_tags.get("p", "").lower() in ("reject", "quarantine") and "np" not in _dmarc_tags:
            items.append({"priority": "low", "protocol": "DMARC",
                          "action": "Consider adding an explicit np= tag",
                          "impact": "Purely optional. Subdomains already inherit your enforcing policy without it."})

    # Count by tier
    tiers = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        tiers[item["priority"]] = tiers.get(item["priority"], 0) + 1

    # A roadmap with no items is only an all-clear when every protocol was
    # actually examined. Two things produce an empty list that is not good news:
    # a check whose lookup never completed carries status "unavailable" and
    # passes through every gate above untouched, and a scoped audit never
    # produces the card at all. Saying "meets all current best practices across
    # all protocols" on either is a claim about protocols this run did not read.
    #
    # A third case sits between them: DKIM probing completes and still cannot
    # settle the question, because selectors are not enumerable from DNS. That
    # is not a lookup that failed, so it does not belong in `unread`, and
    # saying "the DKIM lookup did not complete" about it would be untrue.
    _ROADMAP_PROTOCOLS = ("DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "DANE", "BIMI")
    unread = [n for n in _ROADMAP_PROTOCOLS
              if check_map.get(n, {}).get("status") == "unavailable"
              and check_map.get(n, {}).get("unavailable_kind") != "not_enumerable"]
    unconfirmed = [n for n in _ROADMAP_PROTOCOLS
                   if check_map.get(n, {}).get("unavailable_kind") == "not_enumerable"]
    not_run = [n for n in _ROADMAP_PROTOCOLS if n not in check_map]

    _unconfirmed_note = (
        f" {_join_names(unconfirmed)} could not be confirmed by probing, since a "
        "selector cannot be enumerated from DNS, so nothing here says whether it "
        "is configured."
    ) if unconfirmed else ""

    total = len(items)
    if total == 0 and unread:
        summary = (
            f"No action items, but the {_join_names(unread)} "
            f"{'lookups' if len(unread) > 1 else 'lookup'} did not complete, so "
            f"{'those protocols were' if len(unread) > 1 else 'that protocol was'} "
            "not assessed. This is not an all-clear."
        ) + _unconfirmed_note
    elif total == 0 and not_run:
        summary = (
            "No action items across the protocols this audit covered. "
            f"{_join_names(not_run)} "
            f"{'were' if len(not_run) > 1 else 'was'} outside the scope of this "
            "run and not checked."
        ) + _unconfirmed_note
    elif total == 0 and unconfirmed:
        summary = (
            "No action items across the protocols this audit could assess."
            + _unconfirmed_note
            + " This is not an all-clear."
        )
    elif total == 0:
        summary = "Your email security meets all current best practices across all protocols."
    else:
        summary = f"{total} recommendation{'s' if total != 1 else ''} across {sum(1 for v in tiers.values() if v > 0)} priority tier{'s' if sum(1 for v in tiers.values() if v > 0) != 1 else ''}." + _unconfirmed_note

    return {
        "items": items,
        "tiers": tiers,
        "total": total,
        "summary": summary,
        "unread_protocols": unread,
        "unscoped_protocols": not_run,
    }


# ============================================================
# TTL Freshness Helpers (Prompt 18, Part 2)
# ============================================================


def format_ttl(ttl: Optional[int]) -> Optional[Dict]:
    """Convert a TTL value into a human-readable freshness indicator."""
    if ttl is None:
        return None

    if ttl < 300:
        category = "very_short"
        label = "Very short TTL"
        detail = "This record changes frequently or was recently modified. Changes propagate in under 5 minutes."
    elif ttl <= 3600:
        minutes = ttl // 60
        category = "short"
        label = "Short TTL"
        detail = f"Changes propagate within {minutes} minute{'s' if minutes != 1 else ''}."
    elif ttl <= 86400:
        hours = ttl // 3600
        category = "standard"
        label = "Standard TTL"
        detail = f"Changes propagate within {hours} hour{'s' if hours != 1 else ''}."
    else:
        hours = ttl // 3600
        days = ttl // 86400
        category = "long"
        label = "Long TTL"
        if days >= 1:
            detail = f"Changes take over {days} day{'s' if days != 1 else ''} to propagate."
        else:
            detail = f"Changes take over {hours} hours to propagate."

    return {
        "ttl": ttl,
        "category": category,
        "label": label,
        "detail": detail,
        "human": _humanize_seconds(ttl),
    }


def _humanize_seconds(seconds: int) -> str:
    """Convert seconds to a human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        m = seconds // 60
        return f"{m}m"
    if seconds < 86400:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h{m}m" if m else f"{h}h"
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    return f"{d}d{h}h" if h else f"{d}d"


# ============================================================
# Change Detection (Prompt 18, Part 1)
# ============================================================


_RECORD_TYPE_LABELS = {
    "dmarc": "DMARC",
    "spf": "SPF",
    "mx": "MX Records",
    "mta-sts": "MTA-STS",
    "tls-rpt": "TLS-RPT",
    "dnssec": "DNSSEC",
    "caa": "CAA",
    "nameservers": "Nameservers",
}


def _classify_change(record_type: str, old_value: str, new_value: str) -> Dict:
    """Analyze what specifically changed between two record values and whether
    the change is an improvement or regression."""
    change = {
        "description": f"{_RECORD_TYPE_LABELS.get(record_type, record_type)} record changed",
        "is_improvement": None,  # True = green, False = red, None = neutral
    }

    if record_type == "dmarc":
        old_tags = _parse_record_tags(old_value)
        new_tags = _parse_record_tags(new_value)

        # Check policy change
        old_p = old_tags.get("p", "")
        new_p = new_tags.get("p", "")
        policy_rank = {"none": 0, "quarantine": 1, "reject": 2}
        if old_p != new_p:
            old_rank = policy_rank.get(old_p.lower(), -1)
            new_rank = policy_rank.get(new_p.lower(), -1)
            if new_rank > old_rank:
                change["description"] = f"Policy upgraded from p={old_p} to p={new_p}"
                change["is_improvement"] = True
            elif new_rank < old_rank:
                change["description"] = f"Policy downgraded from p={old_p} to p={new_p}"
                change["is_improvement"] = False
            else:
                change["description"] = f"Policy changed from p={old_p} to p={new_p}"

        # A policy-rank verdict (upgrade/downgrade) is the dominant signal
        # for DMARC posture. Once set, the checks below must not overwrite
        # it -- e.g. adding rua= alongside a p=reject -> p=none downgrade
        # is still a regression, not an improvement.
        policy_decided = change["is_improvement"] is not None

        # Check sp change
        old_sp = old_tags.get("sp", "")
        new_sp = new_tags.get("sp", "")
        if not policy_decided and old_sp != new_sp and old_p == new_p:
            change["description"] = f"Subdomain policy changed from sp={old_sp or '(absent)'} to sp={new_sp or '(absent)'}"
            sp_old_rank = policy_rank.get(old_sp.lower(), -1) if old_sp else -1
            sp_new_rank = policy_rank.get(new_sp.lower(), -1) if new_sp else -1
            change["is_improvement"] = sp_new_rank > sp_old_rank

        # Check np added
        if not policy_decided and "np" not in old_tags and "np" in new_tags:
            change["description"] = f"Added np={new_tags['np']} (RFC 9989 tag)"
            change["is_improvement"] = True

        # Check rua added/removed
        if not policy_decided:
            if "rua" not in old_tags and "rua" in new_tags:
                change["description"] = "Added aggregate reporting (rua=)"
                change["is_improvement"] = True
            elif "rua" in old_tags and "rua" not in new_tags:
                change["description"] = "Removed aggregate reporting (rua=)"
                change["is_improvement"] = False

    elif record_type == "spf":
        # Check for all-mechanism changes
        old_all = _extract_spf_all(old_value)
        new_all = _extract_spf_all(new_value)
        all_rank = {"+all": 0, "?all": 1, "~all": 2, "-all": 3}
        if old_all != new_all:
            old_rank = all_rank.get(old_all, -1)
            new_rank = all_rank.get(new_all, -1)
            if new_rank > old_rank:
                change["description"] = f"SPF hardened: {old_all} to {new_all}"
                change["is_improvement"] = True
            elif new_rank < old_rank:
                change["description"] = f"SPF weakened: {old_all} to {new_all}"
                change["is_improvement"] = False

    return change


def _parse_record_tags(record: str) -> Dict[str, str]:
    """Parse tag=value pairs from a DMARC-style record."""
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    return tags


def _extract_spf_all(record: str) -> str:
    """Extract the all mechanism from an SPF record."""
    parts = record.strip().split()
    for p in reversed(parts):
        p_lower = p.lower()
        if p_lower in ("+all", "-all", "~all", "?all", "all"):
            return p_lower
    return ""


def _normalize_record_for_comparison(value: str) -> str:
    """Normalize a DNS record string so whitespace-only differences are ignored.

    Strips extra spaces, standardizes semicolon/space patterns (e.g. both
    ``p=quarantine;sp=reject`` and ``p=quarantine; sp=reject`` become the same
    canonical form), and lowercases for comparison purposes.
    """
    import re
    if not value:
        return ""
    # Collapse all runs of whitespace to a single space
    s = re.sub(r'\s+', ' ', value.strip())
    # Standardize semicolons: ensure exactly "; " (semicolon + one space)
    s = re.sub(r'\s*;\s*', '; ', s)
    return s


def build_change_detection(
    raw_results: Dict,
    history: Dict[str, list],
    first_seen: Optional[str],
) -> Optional[Dict]:
    """Build the change detection section from snapshot history.

    Args:
        raw_results: Current raw audit results keyed by check name
        history: Dict of record_type -> list of historical snapshots (newest first)
        first_seen: Timestamp of earliest snapshot for this domain
    """
    if not history:
        return {
            "status": "first_audit",
            "message": "We are now tracking this domain. Run another audit later to detect changes.",
            "changes": [],
            "first_seen": None,
        }

    changes = []

    # Map raw_results keys to snapshot record types
    record_map = {
        "dmarc": ("dmarc", lambda r: r.get("record")),
        "spf": ("spf", lambda r: r.get("record")),
        "mx": ("mx", lambda r: "; ".join(sorted(r.get("records") or []))),
        "mta_sts": ("mta-sts", lambda r: r.get("txt_record")),
        "tls_rpt": ("tls-rpt", lambda r: r.get("record")),
        "dnssec": ("dnssec", lambda r: r.get("dnskey_record")),
        "caa": ("caa", lambda r: "; ".join(sorted(c["raw"] if isinstance(c, dict) else str(c) for c in (r.get("records") or [])))),
        "nameservers": ("nameservers", lambda r: "; ".join(sorted(n["hostname"] if isinstance(n, dict) else str(n) for n in (r.get("nameservers") or [])))),
    }

    for check_key, (record_type, extract_fn) in record_map.items():
        raw = raw_results.get(check_key, {})
        current_value = extract_fn(raw)
        snapshots = history.get(record_type, [])

        if not snapshots:
            continue

        if len(snapshots) >= 2:
            # We have at least two snapshots, meaning at least one change happened
            for i in range(len(snapshots) - 1):
                newer = snapshots[i]
                older = snapshots[i + 1]
                # Compare normalized versions to ignore whitespace-only differences
                # (e.g. semicolon spacing from record normalization across runs)
                norm_newer = _normalize_record_for_comparison(newer["record_value"])
                norm_older = _normalize_record_for_comparison(older["record_value"])
                if norm_newer == norm_older:
                    continue  # Whitespace-only difference, not a real change
                if newer["record_hash"] != older["record_hash"]:
                    classification = _classify_change(
                        record_type, older["record_value"], newer["record_value"]
                    )
                    changes.append({
                        "record_type": record_type,
                        "record_label": _RECORD_TYPE_LABELS.get(record_type, record_type),
                        "timestamp": newer["timestamp"],
                        "old_value": older["record_value"],
                        "new_value": newer["record_value"],
                        "description": classification["description"],
                        "is_improvement": classification["is_improvement"],
                    })

    # Also check DKIM selectors
    for rt, snapshots in history.items():
        if rt.startswith("dkim:") and len(snapshots) >= 2:
            selector = rt.split(":", 1)[1]
            for i in range(len(snapshots) - 1):
                newer = snapshots[i]
                older = snapshots[i + 1]
                # Skip whitespace-only differences
                if _normalize_record_for_comparison(newer["record_value"]) == _normalize_record_for_comparison(older["record_value"]):
                    continue
                if newer["record_hash"] != older["record_hash"]:
                    changes.append({
                        "record_type": rt,
                        "record_label": f"DKIM ({selector})",
                        "timestamp": newer["timestamp"],
                        "old_value": older["record_value"],
                        "new_value": newer["record_value"],
                        "description": f"DKIM key for selector '{selector}' changed (possible rotation)",
                        "is_improvement": True,
                    })

    # Sort changes by timestamp (newest first)
    changes.sort(key=lambda c: c.get("timestamp", ""), reverse=True)

    if not changes:
        # We have snapshots but no changes detected
        latest_ts = first_seen
        for snapshots in history.values():
            if snapshots:
                ts = snapshots[0].get("timestamp", "")
                if ts > (latest_ts or ""):
                    latest_ts = ts

        return {
            "status": "no_changes",
            "message": f"No changes detected since {latest_ts or 'first audit'}",
            "changes": [],
            "first_seen": first_seen,
        }

    return {
        "status": "changes_found",
        "message": f"{len(changes)} record change{'s' if len(changes) != 1 else ''} detected",
        "changes": changes,
        "first_seen": first_seen,
    }


# ============================================================
# Consistency Findings (Prompt 18, Part 4)
# ============================================================


def build_consistency_findings(
    raw_results: Dict,
    checks: List[Dict],
) -> Optional[List[Dict]]:
    """Check for cross-record inconsistencies that suggest partial updates
    or configuration drift.

    Returns a list of finding dicts, or None if no findings.
    """
    findings = []
    check_map = {c.get("name", ""): c for c in checks}

    # 1. SPF includes that resolve to empty/error
    spf_deep = check_map.get("SPF", {}).get("spf_deep")
    if spf_deep:
        for mech in spf_deep.get("mechanisms", []):
            if mech.get("type") == "include" and mech.get("provider") is None:
                # Could be decommissioned service, but only flag if we also don't know the provider
                pass  # Covered by SPF deep analysis already

    # 2. MTA-STS MX mismatch
    mta_sts_raw = raw_results.get("mta_sts", {})
    mx_raw = raw_results.get("mx", {})
    mta_sts_mx = mta_sts_raw.get("policy_mx") or []
    actual_mx = []
    for detail in mx_raw.get("mx_details", []):
        host = detail.get("hostname", "").rstrip(".")
        if host:
            actual_mx.append(host.lower())
    if mta_sts_mx and actual_mx:
        mta_set = {m.lower().lstrip("*.") for m in mta_sts_mx}
        mx_set = set(actual_mx)
        # Check if any actual MX is not covered by MTA-STS
        uncovered = []
        for mx_host in mx_set:
            covered = False
            for pattern in mta_set:
                if mx_host == pattern or mx_host.endswith("." + pattern):
                    covered = True
                    break
            if not covered:
                uncovered.append(mx_host)
        if uncovered:
            findings.append({
                "protocol": "MTA-STS",
                "badge": "Configuration Drift",
                "title": "MTA-STS policy does not cover all MX hosts",
                "detail": (
                    f"Your MTA-STS policy does not list {', '.join(uncovered)}. "
                    f"Senders enforcing MTA-STS may refuse to deliver to "
                    f"{'this host' if len(uncovered) == 1 else 'these hosts'}."
                ),
                "severity": "warning",
            })

    # 3. DKIM selectors that resolve to NXDOMAIN
    dkim_raw = raw_results.get("dkim", {})
    for sel in dkim_raw.get("found_selectors", []):
        if sel.get("status") == "nxdomain" or (not sel.get("record") and sel.get("selector")):
            pass  # Already handled by DKIM check

    # 4. Removed: an external rua destination was flagged for not appearing in
    # the SPF record. SPF does not authorize DMARC report destinations, the
    # <domain>._report._dmarc.<destination> record does, and the anomaly
    # detector already checks that one against parsed report_destinations.

    # 5. CAA vs MTA-STS certificate providers
    caa_raw = raw_results.get("caa", {})
    caa_cas = [ca.lower() for ca in caa_raw.get("authorized_cas", [])]
    if caa_cas and mta_sts_raw.get("policy_mode") == "enforce":
        findings.append({
            "protocol": "CAA",
            "badge": "Informational",
            "title": "CAA records may affect MTA-STS certificate renewal",
            "detail": (
                f"Your CAA records restrict certificate issuance to: {', '.join(caa_raw.get('authorized_cas', []))}. "
                f"Ensure your MTA-STS mail server certificates are issued by one of these authorized CAs, "
                f"or renewal failures could break MTA-STS enforcement."
            ),
            "severity": "info",
        })

    return findings if findings else None


# ============================================================
# Subdomain Discovery & Audit (Prompt 17)
# ============================================================


def build_subdomain_audit(
    raw: Dict,
    policy: Optional[str] = None,
    sp: Optional[str] = None,
    np: Optional[str] = None,
    has_record: bool = False,
) -> Optional[Dict]:
    """Transform raw subdomain probe results into a structured audit section.

    Classifies each discovered subdomain as active mail sender, exists but no
    mail config, or does not exist, and determines the effective DMARC policy.

    Args:
        raw: Output from _audit_subdomains() with "probes" list
        policy: Root domain DMARC p= value (e.g. "reject", "none")
        sp: Root domain sp= value (or None if absent)
        np: Root domain np= value (or None if absent)
        has_record: Whether root domain has a DMARC record at all
    """
    probes = raw.get("probes", [])
    if not probes:
        return None

    # Effective subdomain policy: sp= if set, otherwise falls back to p=
    effective_sp = sp if sp else policy
    # Effective non-existent subdomain policy: np= if set, otherwise sp= then p=
    effective_np = np if np else (sp if sp else policy)

    subdomains = []
    for probe in probes:
        sub = probe.get("subdomain", "")
        exists = probe.get("exists", False)
        has_mx = probe.get("has_mx", False)
        has_spf = probe.get("has_spf", False)
        has_dmarc = probe.get("has_dmarc", False)
        dmarc_record = probe.get("dmarc_record")

        sends_mail = has_mx or has_spf
        mail_reason = []
        if has_mx:
            mail_reason.append("MX")
        if has_spf:
            mail_reason.append("SPF")

        # Determine effective policy
        if has_dmarc and dmarc_record:
            # Parse the subdomain's own DMARC record for its policy
            own_policy = None
            for part in dmarc_record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    own_policy = part[2:].strip().lower()
                    break
            eff_policy = own_policy or "none"
            policy_source = "own"
            policy_display = f"p={eff_policy}"
        elif exists:
            eff_policy = effective_sp or "none"
            policy_source = "inherited_sp"
            if sp:
                policy_display = f"Inherits sp={sp}"
            elif policy:
                policy_display = f"Inherits p={policy}"
            else:
                policy_display = "No DMARC (none)"
        else:
            eff_policy = effective_np or "none"
            policy_source = "inherited_np"
            if np:
                policy_display = f"np={np}"
            elif sp:
                policy_display = f"No np=, fallback sp={sp}"
            elif policy:
                policy_display = f"No np=, fallback p={policy}"
            else:
                policy_display = "No np=, fallback none"

        # Classify
        if exists and sends_mail:
            category = "active_mail"
            category_label = "Active mail sender"
        elif exists:
            category = "exists_no_mail"
            category_label = "Exists, no mail config"
        else:
            category = "nonexistent"
            category_label = "Does not exist"

        # Status: protected / partial / exposed
        if eff_policy == "reject":
            status = "protected"
            status_label = "Protected"
            color = "green"
        elif eff_policy == "quarantine":
            status = "partial"
            status_label = "Quarantine"
            color = "amber"
        else:
            status = "exposed"
            status_label = "Exposed"
            color = "red"

        # If no DMARC record on root at all, everything is exposed
        if not has_record and not has_dmarc:
            status = "exposed"
            status_label = "Exposed"
            color = "red"
            policy_display = "No DMARC record"

        subdomains.append({
            "subdomain": sub,
            "exists": exists,
            "sends_mail": sends_mail,
            "mail_signals": ", ".join(mail_reason) if mail_reason else None,
            "has_own_dmarc": has_dmarc,
            "dmarc_record": dmarc_record,
            "effective_policy": eff_policy,
            "policy_source": policy_source,
            "policy_display": policy_display,
            "category": category,
            "category_label": category_label,
            "status": status,
            "status_label": status_label,
            "color": color,
        })

    # Sort: exposed first, then partial, then protected
    sort_order = {"exposed": 0, "partial": 1, "protected": 2}
    subdomains.sort(key=lambda s: (sort_order.get(s["status"], 3), s["subdomain"]))

    # Summary stats
    total_discovered = sum(1 for s in subdomains if s["exists"])
    total_mail = sum(1 for s in subdomains if s["sends_mail"])
    total_exposed = sum(1 for s in subdomains if s["status"] == "exposed")
    exposed_mail = sum(1 for s in subdomains if s["status"] == "exposed" and s["sends_mail"])
    exposed_exist = sum(1 for s in subdomains if s["status"] == "exposed" and s["exists"] and not s["sends_mail"])
    exposed_nx = sum(1 for s in subdomains if s["status"] == "exposed" and not s["exists"])

    # Build summary lines
    summary_lines = [
        f"{total_discovered} subdomain{'s' if total_discovered != 1 else ''} discovered, "
        f"{total_mail} with mail configuration",
    ]
    if total_exposed > 0:
        summary_lines.append(
            f"{total_exposed} subdomain{'s' if total_exposed != 1 else ''} "
            f"exposed due to policy gaps"
        )

    # Build the "killer insight" callout
    callout = None
    if (policy and policy.lower() in ("reject", "quarantine")
            and (not sp or sp.lower() == "none")
            and exposed_mail > 0):
        callout = (
            f"We found {exposed_mail} active subdomain{'s' if exposed_mail != 1 else ''} "
            f"that inherit{'s' if exposed_mail == 1 else ''} your sp={sp or 'none'} policy. "
            f"{'This subdomain' if exposed_mail == 1 else 'These subdomains'} can be spoofed "
            f"despite your root domain being at p={policy}. "
            f"This is not a theoretical risk: "
            f"{'this is a real subdomain' if exposed_mail == 1 else 'these are real subdomains'} "
            f"with real mail infrastructure."
        )
    elif not has_record and total_discovered > 0:
        callout = (
            f"Your domain has no DMARC record. All {total_discovered} discovered "
            f"subdomain{'s' if total_discovered != 1 else ''} can be freely spoofed."
        )
    elif sp and sp.lower() == "none" and total_discovered > 0 and total_exposed > 0:
        callout = (
            f"Your subdomain policy gap (sp=none) affects "
            f"{total_exposed} real subdomain{'s' if total_exposed != 1 else ''}, "
            f"not just theoretical ones."
        )

    return {
        "subdomains": subdomains,
        "summary_lines": summary_lines,
        "callout": callout,
        "total_probed": len(subdomains),
        "total_discovered": total_discovered,
        "total_mail": total_mail,
        "total_exposed": total_exposed,
        "exposed_mail": exposed_mail,
        "exposed_exist": exposed_exist,
        "exposed_nx": exposed_nx,
    }


# ============================================================
# DMARC
# ============================================================


def _build_dmarcbis_card_data(readiness: Optional[Dict], record: Optional[str]) -> Optional[Dict]:
    """Transform the raw _assess_dmarcbis_readiness output into the
    checklist + suggested-record format consumed by the frontend card.

    Returns None when there is no record (nothing to assess).
    """
    if not readiness or not record:
        return None

    # Parse tags from the record for building suggestions
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    deprecated = readiness.get("deprecated_tags", [])
    new_tags = readiness.get("new_tags", {})

    checklist = []

    # 1. Valid DMARC record
    record_valid = readiness.get("record_valid", True)
    checklist.append({
        "label": "Valid DMARC record found",
        "status": "pass" if record_valid else "fail",
        "detail": None if record_valid else (
            "The DMARC record has syntax errors; RFC 9989 readiness cannot "
            "be assessed until those are fixed."
        ),
    })

    # 2. No deprecated tags (pct, rf, ri). Each entry passes through its
    # source / spec_reference so the frontend can render spec-required
    # findings differently from editorial suggestions.
    dep_names = [d["tag"] for d in deprecated]
    if dep_names:
        dep_details = [
            {
                "tag": d["tag"],
                "reason": d.get("recommendation", ""),
                "source": d.get("source", "editorial"),
                "spec_reference": d.get("spec_reference"),
            }
            for d in deprecated
        ]
        # Worst-case status across deprecated entries: spec_required
        # is rendered as "warn" (a real issue), editorial as "info".
        checklist_status = "warn" if any(d.get("source") == "spec_required" for d in deprecated) else "info"
        checklist.append({
            "label": "No deprecated tags (pct, rf, ri)",
            "status": checklist_status,
            "detail": ", ".join(dep_names),
            "deprecated_details": dep_details,
        })
    else:
        checklist.append({
            "label": "No deprecated tags (pct, rf, ri)",
            "status": "pass",
            "detail": None,
        })

    # 3. NP policy defined + precedence chain
    np_info = new_tags.get("np", {})
    p_val = tags.get("p", "none")
    sp_val = tags.get("sp")
    np_val = np_info.get("value")

    # Build the fallback chain: np → sp → p
    np_chain = []
    if np_val:
        np_chain.append({"tag": "np", "value": np_val, "active": True})
    else:
        np_chain.append({"tag": "np", "value": None, "active": False})
    if sp_val:
        np_chain.append({"tag": "sp", "value": sp_val, "active": not np_val})
    np_chain.append({"tag": "p", "value": p_val, "active": not np_val and not sp_val})

    if np_info.get("present"):
        checklist.append({
            "label": "NP policy defined (non-existent domains)",
            "status": "pass",
            "detail": f"np={np_info['value']}",
            "np_chain": np_chain,
        })
    else:
        fallback_tag = "sp" if sp_val else "p"
        fallback_val = sp_val if sp_val else p_val
        checklist.append({
            "label": "NP policy defined (non-existent domains)",
            # np absence is editorial: RFC 9989 §4.7 does not require
            # an explicit np tag. Render as info so the user sees this
            # as advice rather than a spec violation.
            "status": "info",
            "detail": "missing",
            "suggestion": f"np={fallback_val}",
            "np_chain": np_chain,
            "np_fallback_note": f"Non-existent subdomains currently fall back to {fallback_tag}={fallback_val}",
            "source": np_info.get("source", "editorial"),
            "spec_reference": np_info.get("spec_reference"),
            "recommendation": np_info.get("recommendation"),
        })

    # 4. PSD indicator declared
    psd_info = new_tags.get("psd", {})
    if psd_info.get("present") and psd_info.get("value") in ("y", "n"):
        checklist.append({
            "label": "PSD indicator declared",
            "status": "pass",
            "detail": f"psd={psd_info['value']}",
        })
    else:
        psd_val = psd_info.get("value")
        checklist.append({
            "label": "PSD indicator declared",
            "status": "info",
            "detail": f"psd={psd_val}" if psd_val else "u (default)",
            "note": ("Optional. RFC 9989 4.7 defaults psd= to 'u'. Publish it "
                     "only if this domain is a public suffix."),
        })

    # Overall status
    raw_status = readiness.get("status", "compatible")
    status_map = {"ready": "compliant", "needs_update": "non_compliant", "invalid": "non_compliant"}
    status = status_map.get(raw_status, "compatible")

    # Build suggested record + changes list
    changes = []
    new_record_tags = dict(tags)

    for dep in deprecated:
        tag_name = dep["tag"]
        if tag_name in new_record_tags:
            val = new_record_tags.pop(tag_name)
            source = dep.get("source", "editorial")
            spec_ref = dep.get("spec_reference")
            if tag_name == "pct":
                if val == "100":
                    reason = "Removed pct (RFC 9989 §C.5.2 / §A.6); value was already 100 (default)."
                else:
                    reason = f"Removed pct (RFC 9989 §C.5.2 / §A.6); was {val}%. Use t=y for testing instead."
            elif tag_name == "rf":
                reason = "Removed rf (RFC 9989 §C.5.2); only afrf was ever defined and RFC 9989 receivers will ignore the tag."
            elif tag_name == "ri":
                reason = "Removed ri (RFC 9989 §C.5.2); receivers send aggregate reports on their own schedule and RFC 9989 receivers will ignore the tag."
            else:
                reason = f"Removed {tag_name}."
            changes.append({
                "type": "removed",
                "tag": tag_name,
                "reason": reason,
                "source": source,
                "spec_reference": spec_ref,
            })

    if not np_info.get("present"):
        np_src_tag = "sp" if "sp" in new_record_tags else "p"
        np_value = new_record_tags.get(np_src_tag, "none")
        new_record_tags["np"] = np_value
        changes.append({
            "type": "added",
            "tag": "np",
            "reason": (
                f"Editorial suggestion (not spec-required): added np from "
                f"{np_src_tag} value to make non-existent subdomain policy "
                f"explicit. RFC 9989 §4.7 does not require this."
            ),
            "source": np_info.get("source", "editorial"),
            "spec_reference": np_info.get("spec_reference"),
        })

    # Reconstruct in standard tag order
    tag_order = ["v", "p", "sp", "np", "adkim", "aspf", "psd", "t", "fo", "rua", "ruf"]
    parts = []
    for t in tag_order:
        if t in new_record_tags:
            parts.append(f"{t}={new_record_tags[t]}")
    for t, v in new_record_tags.items():
        if t not in tag_order:
            parts.append(f"{t}={v}")

    suggested_record = "; ".join(parts) if changes else None

    pass_count = sum(1 for c in checklist if c["status"] == "pass")

    return {
        "status": status,
        "checklist": checklist,
        "pass_count": pass_count,
        "total_count": len(checklist),
        "suggested_record": suggested_record,
        "changes": changes,
        "recommendations": readiness.get("recommendations", []),
    }


def transform_dmarc(raw: Dict, tree_walk: Optional[Dict] = None, is_no_mail: bool = False) -> Dict:
    # The tree walk is optional and comes back None whenever dmarc_tree_walk
    # times out or raises, while _enrich_dmarc_inheritance still sets
    # inherited_policy from its PSL fallback. The inherited branches below
    # must keep working on that path or the whole DMARC card is lost to a
    # transient DNS failure.
    tw = tree_walk or {}

    # The _dmarc lookup never completed, or the subdomain has no record of
    # its own and the org domain lookup that would have found the inherited
    # policy never completed either. Either way this audit does not know
    # what policy applies, and "No DMARC policy published" would be a claim
    # it cannot support.
    if raw.get("status") == "unavailable":
        return _lookup_unavailable_card("DMARC", raw, "DMARC record")

    # A record is published at _dmarc but its version tag does not conform,
    # so every receiver discards it. Neither of the branches below fits: "no
    # record found" contradicts what the operator can see in their zone, and
    # the has-record branch narrates a policy that is not in force.
    if raw.get("malformed_record"):
        return _malformed_version_tag_card(
            "DMARC", raw, raw["malformed_record"],
            "Receivers ignore it and treat the domain as having no DMARC "
            "protection, so the anti-spoofing coverage DMARC exists to "
            "provide is not in place.",
            f"Republish the TXT record at <strong>_dmarc.{_e(raw.get('domain', ''))}</strong> "
            f"starting with exactly <strong>v=DMARC1;</strong>.",
        )

    if not raw.get("record") and raw.get("inheritance_lookup_failed"):
        return _lookup_unavailable_card(
            "DMARC",
            {"lookup_target": raw.get("inheritance_lookup_target")},
            "inherited DMARC policy",
        )

    # On no-mail domains, missing rua is not a visibility gap because there is
    # no legitimate mail to monitor. Drop the issue so it stops driving the
    # status, details, fix, and downstream summaries.
    if is_no_mail and raw.get("issues"):
        raw["issues"] = [
            i for i in raw["issues"]
            if i.get("issue") != "No aggregate reporting (rua) configured"
        ]

    status = _map_status(raw.get("status", "error"))
    policy = raw.get("policy", "")
    record = raw.get("record")
    pill_label = None

    # Check if this domain inherits policy (raw_dmarc fields set by
    # _enrich_dmarc_inheritance using tree walk first, PSL fallback)
    inherited = not record and raw.get("is_subdomain") and raw.get("inherited_policy")
    inherited_policy = raw.get("inherited_policy") if inherited else None
    inherited_source = raw.get("inherited_from") if inherited else None

    # Build verdict and override status based on policy
    if inherited:
        verdict = f"Inherited: {inherited_policy} (from {inherited_source})"
        if inherited_policy == "reject":
            status = "pass"
        elif inherited_policy == "quarantine":
            status = "pass"
        elif inherited_policy == "none":
            status = "warn"
        pill_label = "Inherited"
    elif not record:
        verdict = "No DMARC policy published"
        status = "fail"
        pill_label = "Missing"
    elif policy in ("reject", "quarantine"):
        pct = raw.get("pct", 100)
        if pct is None:
            pct = 100
        # pct=0 is not a flat "enforcement is off". RFC 9989 section C.5.2
        # removed the pct tag, and the same report warns that RFC 9989 receivers
        # ignore it, so an unqualified claim contradicts the tool's own tag
        # breakdown and the RFC 9989 Readiness metric on the cover. The split
        # between receiver populations is the fact; state it.
        #
        # What the unselected fraction gets differs by policy, and reading it as
        # "nothing" for both was wrong for reject. RFC 7489 section 6.6.4: "If
        # the email is not subject to the 'reject' policy (due to the 'pct'
        # tag), the Mail Receiver SHOULD treat the email as though the
        # 'quarantine' policy applies." So p=reject with pct=0 is not zero
        # enforcement, it is full quarantine on RFC 7489 receivers and full
        # reject on RFC 9989 ones. Only quarantine degrades to nothing, where
        # the same section sends the unselected fraction to "local message
        # classification as normal".
        # The verdict leads with what happens to failing mail and states the
        # weaker of the two receiver populations, because that is the coverage
        # the operator can actually count on. The RFC 7489 against RFC 9989
        # split is the reason for the number, not the verdict, so it goes to a
        # detail row where there is room to say it. The old verdict carried the
        # whole split inline and ran to 132 characters against roughly 45 for
        # every other verdict on this card.
        _pct_raw = raw.get("pct")
        if policy == "reject":
            verdict = "p=reject (authentication failures are rejected)"
            _disabled = (
                f"p=reject with pct={_pct_raw} (failing mail is quarantined, "
                "not rejected)"
            )
            _partial = (
                f"p=reject with pct={pct} ({pct}% of failing mail is rejected, "
                "the rest quarantined)"
            )
        else:
            verdict = "p=quarantine (failures sent to spam)"
            _disabled = (
                f"p=quarantine with pct={_pct_raw} (failing mail is not "
                "quarantined)"
            )
            _partial = (
                f"p=quarantine with pct={pct} ({pct}% of failing mail is "
                "quarantined, the rest is not)"
            )
        # An enforcing policy is only a pass when it applies to all failing
        # mail. pct is what receivers act on, so it decides the status here
        # and is not merely appended to the sentence. A missing rua still
        # does not downgrade a policy that really is enforcing.
        #
        # p=reject with pct=0 is a warn, not a fail: every receiver population
        # acts on every failing message, one quarantining where the other
        # rejects. Grading that a failure put a red card on a domain whose
        # failing mail is universally enforced against.
        #
        # p=quarantine with pct=0 grades the way p=none does, warn with rua
        # and fail without, because it is never less protective than p=none.
        # RFC 7489 receivers do nothing for either. RFC 9989 receivers ignore
        # pct and quarantine everything, so it is better there. This branch
        # used to grade it fail unconditionally, which put a redder card on
        # the strictly stronger of the two records and never looked at rua.
        # The colour is a protection grade on every other row of this card,
        # and the pct detail row now says exactly what each receiver does, so
        # the colour does not have to carry "you think you are enforcing" on
        # its own.
        if pct <= 0:
            verdict = _disabled
            if policy == "reject" or raw.get("rua"):
                status = "warn"
            else:
                status = "fail"
        elif pct < 100:
            verdict = _partial
            status = "warn"
        elif not raw.get("rua"):
            # Amber, not green and not red. The policy is enforcing and the
            # record is compliant, since rua is OPTIONAL in RFC 7489 section
            # 6.3 and RFC 9989, so this is not a failure. But the owner cannot
            # see what their own policy is doing, and a green card would say
            # there is nothing to look at.
            status = "warn"
        else:
            status = "pass"
    elif policy == "none":
        verdict = "p=none (monitoring only, no enforcement)"
        # p=none with no rua is a critical failure: no enforcement AND no visibility
        if not raw.get("rua"):
            status = "fail"
        else:
            status = "warn"
    else:
        verdict = f"Policy: {policy}" if policy else "Invalid record"
        status = "fail"

    # Syntax errors or engine-level errors override to fail
    if record and not inherited:
        has_syntax_errors = bool(raw.get("syntax_errors"))
        has_engine_errors = any(
            i.get("severity") == "error" for i in raw.get("issues", [])
        )
        if has_syntax_errors or has_engine_errors:
            status = "fail"

    # RFC 9989 §4.10.1 policy recovery: invalid p/sp/np with valid
    # rua= is treated as p=none by RFC 9989 receivers but may be
    # ignored by RFC 7489 receivers. Surface this distinctly so the
    # user sees it as a spec-recovery state, not as a clean p=none.
    if record and not inherited and raw.get("policy_recovery_applied"):
        pill_label = "Recovery"
        verdict = (
            "Spec recovery applied (RFC 9989 §4.10.1): invalid value "
            "masked by rua fallback, treated as p=none."
        )
        if status != "fail":
            status = "warn"

    # Build explanation
    if inherited:
        applied_tag = raw.get("applied_tag", "p")
        tag_label = {"sp": "subdomain policy (sp=)", "np": "non-existent subdomain policy (np=)", "p": "domain policy (p=)"}.get(applied_tag, f"{applied_tag}=")
        _method = raw.get("inheritance_method", "psl")
        if _method == "tree_walk":
            _method_note = (
                " Policy was discovered via the "
                "<a href=\"https://www.rfc-editor.org/rfc/rfc9989.html\" target=\"_blank\" rel=\"noopener\">RFC 9989</a> "
                "DNS tree walk."
            )
        else:
            _method_note = (
                " Policy was discovered via the organizational domain fallback defined in "
                "<a href=\"https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.3\" target=\"_blank\" rel=\"noopener\">RFC 7489 Section 6.6.3</a> "
                "using the Public Suffix List."
            )
        _best_practice = (
            ""
        )
        if inherited_policy == "reject":
            explanation = (
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{_e(raw.get('domain', ''))}</strong>, but inherits "
                f"<strong>p=reject</strong> from the organizational domain "
                f"<strong>{_e(inherited_source)}</strong> via the {tag_label} tag. "
                f"Messages that fail both SPF and DKIM alignment will be rejected."
                + _method_note + _best_practice
            )
        elif inherited_policy == "quarantine":
            explanation = (
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{_e(raw.get('domain', ''))}</strong>, but inherits "
                f"<strong>p=quarantine</strong> from the organizational domain "
                f"<strong>{_e(inherited_source)}</strong> via the {tag_label} tag. "
                f"Messages that fail authentication will be routed to the spam folder."
                + _method_note + _best_practice
            )
        elif inherited_policy == "none":
            explanation = (
                f"This subdomain has no DMARC record at "
                f"<strong>_dmarc.{_e(raw.get('domain', ''))}</strong>, but inherits "
                f"<strong>p=none</strong> from the organizational domain "
                f"<strong>{_e(inherited_source)}</strong> via the {tag_label} tag. "
                f"This is monitoring only; receivers take no enforcement action, but aggregate reports "
                f"provide visibility into authentication results."
                + _method_note + _best_practice
            )
        else:
            explanation = (
                f"This subdomain inherits DMARC policy <strong>{_e(inherited_policy)}</strong> "
                f"from the organizational domain <strong>{_e(inherited_source)}</strong>."
                + _method_note + _best_practice
            )
    elif not record:
        explanation = (
            f"No DMARC record was found at <strong>_dmarc.{_e(raw.get('domain', ''))}</strong>. "
            f"Without DMARC, there is no policy telling receivers how to handle messages that fail authentication. "
            f"Google and Yahoo require bulk senders to publish a "
            f"<a href=\"https://datatracker.ietf.org/doc/html/rfc7489\" target=\"_blank\" rel=\"noopener\">DMARC</a> "
            f"record, and messages without one are more likely to be throttled or sent to spam."
        )
    elif policy == "none":
        explanation = (
            "Your DMARC policy is set to <strong>p=none</strong> (monitoring mode). "
            "Your record is technically valid, but it provides no active protection: it "
            "requests no action from receivers when authentication fails, and each receiver "
            "decides independently what to do with the message. "
            "p=none is a necessary starting point for collecting aggregate report data. "
            "To protect deliverability and prevent spoofing, move toward an enforcement policy "
            "(<strong>p=quarantine</strong> or <strong>p=reject</strong>) once your legitimate "
            "mail streams are aligned."
        )
    elif policy == "quarantine":
        explanation = (
            "The enforcing DMARC policy <strong>p=quarantine</strong> requests that mail receivers "
            "send messages to spam when neither SPF nor DKIM passes with an aligned domain. "
            "Only one of SPF or DKIM needs to pass with alignment for the message to be delivered normally. "
            "DKIM is the more resilient mechanism because it survives mail forwarding."
        )
    elif policy == "reject":
        explanation = (
            "The enforcing DMARC policy <strong>p=reject</strong> requests that mail receivers "
            "reject messages outright when neither SPF nor DKIM passes with an aligned domain. "
            "Only one of SPF or DKIM needs to pass with alignment for the message to be delivered. "
            "DKIM is the more resilient mechanism because it survives mail forwarding."
        )
    else:
        explanation = f"DMARC record found but the policy value is unexpected: '{policy}'."

    # Reporting note
    if record and not raw.get("rua") and not is_no_mail:
        if policy in ("quarantine", "reject"):
            explanation += (
                " <strong>Warning:</strong> No aggregate reporting (rua) is configured. "
                "You are enforcing a policy without seeing who is being affected. "
                "If a legitimate sender (like a payroll system or CRM) fails authentication, "
                "you will not know until users report missing email."
            )
        else:
            explanation += (
                " <strong>Note:</strong> No aggregate reporting (rua) is configured. "
                "Without rua, you have no visibility into who is sending as your domain "
                "or whether authentication is passing."
            )
    elif record and is_no_mail and policy in ("quarantine", "reject"):
        explanation += (
            " This domain is configured to not send or receive email "
            "(null MX, null SPF). Aggregate reporting (rua) is optional "
            "because there is no legitimate mail to monitor."
        )

    # Details
    details = []
    if inherited:
        applied_tag = tw.get("applied_tag", "p")
        if inherited_policy == "reject":
            details.append({"type": "good", "text": f"Effective policy: reject (inherited from {inherited_source})"})
        elif inherited_policy == "quarantine":
            details.append({"type": "good", "text": f"Effective policy: quarantine (inherited from {inherited_source})"})
        elif inherited_policy == "none":
            details.append({"type": "warning", "text": f"Effective policy: none (inherited from {inherited_source})"})

        _detail_method = "DNS tree walk" if raw.get("inheritance_method") == "tree_walk" else "organizational domain lookup"
        details.append({"type": "info", "text": f"No record at _dmarc.{raw.get('domain', '')}. Policy found via {_detail_method}"})
        details.append({"type": "info", "text": f"Applied tag: {applied_tag}= from {inherited_source}"})

        if tw.get("org_domain"):
            details.append({"type": "info", "text": f"Organizational domain: {tw['org_domain']}"})

    elif record:
        if raw.get("policy_recovery_applied"):
            details.append({
                "type": "warning",
                "text": (
                    "Spec recovery applied: invalid value masked by rua fallback. "
                    "RFC 9989 §4.10.1 receivers will treat as p=none; older "
                    "RFC 7489 receivers may ignore the record. Fix the offending tag."
                ),
            })
        elif policy == "reject":
            details.append({"type": "good", "text": "Policy p=reject: authentication failures are rejected"})
        elif policy == "quarantine":
            details.append({"type": "good", "text": "Policy p=quarantine: authentication failures are sent to spam"})
        elif policy == "none":
            details.append({"type": "warning", "text": "Policy p=none: monitoring only, no enforcement requested"})

        report_dests = raw.get("report_destinations")
        if report_dests and raw.get("rua"):
            rua_dests = [d for d in report_dests if d["type"] == "rua"]
            unauthorized = [d for d in rua_dests if d.get("authorized") is False]
            if unauthorized:
                details.append({
                    "type": "error",
                    "text": (
                        f"Aggregate reporting (rua): {len(rua_dests)} destination(s), "
                        f"{len(unauthorized)} NOT authorized (reports silently dropped)"
                    ),
                })
            else:
                details.append({
                    "type": "good",
                    "text": f"Aggregate reporting (rua): {len(rua_dests)} destination(s), all authorized",
                })
        elif raw.get("rua") and raw.get("report_auth_indeterminate"):
            details.append({
                "type": "info",
                "text": (
                    "Aggregate reporting (rua) is configured. The check of whether "
                    "each destination has authorized this domain did not finish, so "
                    "those destinations were not verified"
                ),
            })
        elif raw.get("rua"):
            details.append({"type": "good", "text": "Aggregate reporting (rua) is configured"})
        elif is_no_mail:
            details.append({"type": "info", "text": "Aggregate reporting (rua) not configured (optional for non-mail domain)"})
        else:
            details.append({"type": "warning", "text": "No aggregate reporting (rua) configured"})

        if report_dests and raw.get("ruf"):
            details.append({
                "type": "info",
                "text": "Forensic reporting (ruf) configured (note: most mailbox providers no longer send failure reports because of PII concerns)",
            })
        elif raw.get("ruf"):
            details.append({"type": "good", "text": "Forensic reporting (ruf) is configured"})

        if raw.get("sp"):
            sp_val = raw["sp"]
            # Flag sp=none when p= is enforcing as a contradiction
            if sp_val == "none" and policy in ("quarantine", "reject"):
                details.append({"type": "warning", "text": f"Subdomain policy sp=none contradicts your p={policy} enforcement. Subdomains are unprotected."})
            else:
                details.append({"type": "info", "text": f"Subdomain policy: sp={sp_val}"})

        pct = raw.get("pct")
        if pct is not None and 0 <= pct < 100:
            # This row is where the two receiver populations get named. It used
            # to read "policy applied to only N% of failing messages" for both
            # policies, which is wrong for reject: RFC 7489 section 6.6.4 sends
            # the unselected fraction to quarantine rather than to nothing.
            if policy == "reject":
                _seven = (
                    f"reject {pct}% of failing messages and quarantine the rest"
                    if pct else "quarantine all failing messages"
                )
                _nine = "ignore pct and reject all of them"
            else:
                _seven = (
                    f"apply the policy to {pct}% of failing messages and leave "
                    "the rest to local filtering"
                    if pct else "enforce on no mail at all"
                )
                _nine = "ignore pct and quarantine all of them"
            details.append({
                "type": "warning",
                "text": (
                    f"pct={pct}: RFC 7489 receivers {_seven}. RFC 9989 receivers "
                    f"{_nine}, because pct is removed in RFC 9989."
                ),
            })

        # Append all issues from the audit engine (syntax_errors already merged into issues)
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))
    else:
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))

    # Fix
    domain_name = raw.get("domain", "")
    if inherited:
        if inherited_policy == "none":
            fix = (
                f"The inherited policy from <strong>{_e(inherited_source)}</strong> is p=none (monitoring only). "
                f"This provides no enforcement against spoofing."
            )
        else:
            # quarantine or reject inherited, no fix needed
            fix = None
    elif not record:
        if is_no_mail:
            fix = (
                f"This domain is configured to not send or receive email "
                f"(null MX, null SPF, no DKIM). To protect against spoofing, "
                f"publish a DMARC record at <strong>_dmarc.{_e(domain_name)}</strong> with "
                f"<strong>p=reject</strong>. Aggregate reporting (rua) is optional "
                f"because there is no legitimate mail to monitor."
            )
        else:
            fix = (
                f"Publish a DMARC TXT record at <strong>_dmarc.{_e(domain_name)}</strong> with <strong>p=none</strong>. "
                f"Requires an <strong>rua=</strong> reporting address: either your own mailbox "
                f"(reports arrive as compressed XML) or a DMARC reporting service that provides a dashboard."
            )
    elif raw.get("syntax_errors") or any(i.get("severity") == "error" for i in raw.get("issues", [])):
        # Prioritize syntax/error fixes over generic policy advice
        fix = _first_fix(raw.get("syntax_errors", [])) or _first_fix(raw.get("issues", []))
    elif policy == "none":
        if is_no_mail:
            fix = (
                "This domain does not send email. A monitoring policy (p=none) provides "
                "no protection against spoofing. Upgrade to <strong>p=reject</strong> to "
                "reject all mail that fails authentication. Reporting is optional because "
                "there is no legitimate mail to monitor."
            )
        else:
            fix = (
                "Review your DMARC aggregate reports to identify all legitimate senders and confirm "
                "they pass SPF or DKIM with aligned domains. Once you are confident in your sender "
                "inventory, move to an enforcement policy (<strong>p=quarantine</strong> or <strong>p=reject</strong>)."
            )
    else:
        fix = _first_fix(raw.get("issues", []))

    # For inherited policy, show the parent's record
    display_record = record
    if inherited and not display_record:
        # Pull record from tree walk steps
        for step in (tw.get("steps") or []):
            if step.get("found") and step.get("record"):
                display_record = step["record"]
                break

    # No copy-paste fix_records for DMARC -- requires choosing a reporting
    # address and understanding the enforcement path.
    fix_records = None

    # Build tag-by-tag breakdown + combo warnings + health verdict
    breakdown_record = display_record or record
    tag_breakdown = None
    if breakdown_record:
        tags_list = _build_dmarc_tag_breakdown(breakdown_record, raw)
        # Parse tags for combo detection
        _parsed = {}
        for part in breakdown_record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                _parsed[k.strip().lower()] = v.strip()
        _pol = _parsed.get("p", "").lower()
        config_warnings = _detect_dangerous_combinations(
            _parsed, _pol, is_no_mail=is_no_mail, domain=raw.get("domain", ""))
        health = _calculate_dmarcbis_health(_parsed, _pol, config_warnings)
        _domain = raw.get("domain", "")
        migration = _build_migration_path(_parsed, _pol, health["status"], domain=_domain)
        why_dmarcbis = _build_why_dmarcbis(_parsed, _pol, health["status"], domain=_domain)
        record_builder = _build_record_builder(
            _parsed, _pol, health["status"], breakdown_record,
            config_warnings, domain=_domain,
        )
        tag_breakdown = {
            "health": health,
            "tags": tags_list,
            "config_warnings": config_warnings,
            "migration": migration,
            "record_builder": record_builder,
            "why_dmarcbis": why_dmarcbis,
        }

    # Record builder for "no record" case (tag_breakdown is None)
    _domain = raw.get("domain", "")
    if not tag_breakdown:
        no_record_builder = _build_record_builder({}, "", "", None, [], domain=_domain)
    else:
        no_record_builder = None

    # Deliverability context
    if not record and not inherited:
        _deliverability = (
            "Without DMARC, Gmail, Yahoo, and Outlook increasingly penalize your domain. "
            "Since February 2024, Google and Yahoo require DMARC for bulk senders. Even non-bulk "
            "senders benefit because DMARC tells receivers you take your email reputation seriously. "
            "If you send marketing emails, sales outreach, or business communications, this gap "
            "is likely hurting your inbox placement right now."
        )
    elif inherited and inherited_policy == "none":
        _deliverability = (
            "Your inherited p=none policy means receivers make their own judgment about suspicious "
            "email from your domain. Gmail and Yahoo may filter or delay messages that fail "
            "authentication. Moving toward enforcement protects your sending reputation."
        )
    elif policy == "none":
        _deliverability = (
            "With p=none, Gmail, Yahoo, and Microsoft decide on their own how to handle "
            "emails that fail authentication from your domain. They often treat unaligned "
            "mail with suspicion. Since February 2024, Google and Yahoo require DMARC for "
            "bulk senders. Moving to p=quarantine or p=reject signals that you control your "
            "email and generally improves inbox placement."
        )
    elif policy == "quarantine":
        _deliverability = (
            "Good for deliverability. Receivers know to quarantine spoofed emails, which "
            "protects your domain's sending reputation. Spoofed emails will not drag down "
            "your legitimate mail's reputation."
        )
    elif policy == "reject":
        _deliverability = (
            "Excellent for deliverability. This is the strongest signal to receivers that "
            "you control your email. Domains with p=reject generally see better inbox placement "
            "because receivers trust them more."
        )
    else:
        _deliverability = None

    return {
        "name": "DMARC",
        "status": status,
        "pill_label": pill_label,
        "verdict": verdict,
        "record": display_record,
        "configured": bool(record) or bool(inherited),
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": fix_records,
        "strict_validation": _build_strict_validation(raw.get("strict_validation")),
        "legacy_validation": _build_strict_validation(raw.get("legacy_validation")),
        "spec_comparison": _build_spec_comparison(
            raw.get("strict_validation"), raw.get("legacy_validation")
        ),
        "attack_surface": _build_attack_surface(raw, display_record or record, is_no_mail=is_no_mail),
        "tag_breakdown": tag_breakdown,
        "record_builder": no_record_builder,
        "dmarcbis_readiness": _build_dmarcbis_card_data(
            raw.get("dmarcbis_readiness"), raw.get("record")
        ),
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": _deliverability,
    }


# ============================================================
# RFC 9989 Strict Validation
# ============================================================

_SV_CATEGORY_LABELS = {
    "record_structure": "Record Structure",
    "uri_validation": "URI Validation",
    "external_auth": "External Authorization",
    "tag_values": "Tag Values",
    "dns_integrity": "DNS Integrity",
}

# Display order for categories
_SV_CATEGORY_ORDER = ["record_structure", "uri_validation", "external_auth", "tag_values", "dns_integrity"]


def _build_strict_validation(sv: Optional[Dict]) -> Optional[Dict]:
    """Transform strict validation results for the frontend."""
    if not sv:
        return None

    # Group checks by category
    categories: Dict[str, List[Dict]] = {}
    for check in sv.get("checks", []):
        cat = check["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(check)

    grouped = []
    for cat_key in _SV_CATEGORY_ORDER:
        if cat_key in categories:
            grouped.append({
                "key": cat_key,
                "label": _SV_CATEGORY_LABELS.get(cat_key, cat_key),
                "checks": categories[cat_key],
            })
    # Any categories not in the display order
    for cat_key, checks in categories.items():
        if cat_key not in _SV_CATEGORY_ORDER:
            grouped.append({
                "key": cat_key,
                "label": _SV_CATEGORY_LABELS.get(cat_key, cat_key),
                "checks": checks,
            })

    return {
        "categories": grouped,
        "pass_count": sv["pass_count"],
        "fail_count": sv["fail_count"],
        "warn_count": sv["warn_count"],
        "total_count": sv["total_count"],
        "summary": sv["summary"],
        "has_structural_errors": sv["has_structural_errors"],
    }


def _build_spec_comparison(strict: Optional[Dict], legacy: Optional[Dict]) -> Optional[Dict]:
    """Compare strict (RFC 9989) and legacy (RFC 7489) validation results.

    Returns the delta: which issues are RFC 9989-only, which are in both,
    and summary stats for the toggle UI.
    """
    if not strict or not legacy:
        return None

    strict_checks = strict.get("checks", [])
    legacy_checks = legacy.get("checks", [])

    # Build sets of failure/warn codes for comparison
    strict_fails = {c["code"] + ":" + c["message"][:60] for c in strict_checks if c["status"] == "fail"}
    legacy_fails = {c["code"] + ":" + c["message"][:60] for c in legacy_checks if c["status"] == "fail"}
    strict_warns = {c["code"] + ":" + c["message"][:60] for c in strict_checks if c["status"] == "warn"}
    legacy_warns = {c["code"] + ":" + c["message"][:60] for c in legacy_checks if c["status"] == "warn"}

    strict_issues = strict_fails | strict_warns
    legacy_issues = legacy_fails | legacy_warns

    dmarcbis_only = strict_issues - legacy_issues
    both = strict_issues & legacy_issues

    # Build human-readable list of RFC 9989-only findings
    dmarcbis_only_items = []
    for c in strict_checks:
        key = c["code"] + ":" + c["message"][:60]
        if key in dmarcbis_only and c["status"] in ("fail", "warn"):
            dmarcbis_only_items.append({
                "code": c["code"],
                "message": c["message"],
                "status": c["status"],
            })

    # Determine if legacy passes but strict fails
    legacy_passes = legacy.get("fail_count", 0) == 0
    strict_fails_count = strict.get("fail_count", 0)
    # Named for what it means: the record only passes because the receiver is
    # still on the obsolete RFC 7489.
    legacy_only_pass = legacy_passes and strict_fails_count > 0

    return {
        "dmarcbis_only_count": len(dmarcbis_only_items),
        "both_count": len(both),
        "dmarcbis_only_items": dmarcbis_only_items,
        "legacy_only_pass": legacy_only_pass,
        "legacy_pass_count": legacy.get("pass_count", 0),
        "legacy_fail_count": legacy.get("fail_count", 0),
        "legacy_warn_count": legacy.get("warn_count", 0),
        "legacy_total_count": legacy.get("total_count", 0),
        "legacy_summary": legacy.get("summary", ""),
        "strict_fail_count": strict_fails_count,
        "strict_summary": strict.get("summary", ""),
    }


# ============================================================
# Attack Surface View
# ============================================================

def _build_attack_surface(raw: Dict, record: Optional[str], is_no_mail: bool = False) -> Optional[Dict]:
    """Build the 4-vector email spoofing attack surface analysis."""
    if not record:
        return None

    # Parse tags
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "").lower()
    sp = tags.get("sp")
    np_val = tags.get("np")
    rua = tags.get("rua")
    domain = raw.get("domain", "yourdomain.com")

    pct_raw = tags.get("pct")
    try:
        pct = int(pct_raw) if pct_raw not in (None, "") else 100
    except ValueError:
        pct = 100

    vectors = []

    # ── Vector 1: Direct Domain Spoofing ────────────────────
    # pct= scopes what fraction of failing mail the policy is even applied
    # to (RFC 7489 §6.3), so a policy is only fully enforcing at pct=100.
    if policy == "reject" and pct >= 100:
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "protected",
            "color": "green",
            "summary": "Mail failing authentication is blocked.",
            "detail": f"An attacker attempting to send as user@{domain} would have their message rejected by receiving mail servers.",
        }
    elif policy == "reject" and pct > 0:
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": f"Only {pct}% of failing mail is rejected (pct={pct}).",
            # Not "delivered as if p=none". RFC 7489 section 6.6.4 sends the
            # unselected fraction of a reject policy to quarantine, so the
            # attacker lands in spam rather than the inbox, and the old
            # "{100-pct}% chance their spoofed message is delivered normally"
            # overstated the exposure it was describing.
            "detail": f"pct={pct} means RFC 7489 receivers apply p=reject to {pct}% of messages that fail authentication and quarantine the rest (RFC 7489 section 6.6.4), so roughly {100 - pct}% of spoofed mail reaches the spam folder instead of being rejected outright. RFC 9989 receivers ignore pct and reject all of it.",
        }
    elif policy == "reject" and pct <= 0:
        # Every receiver population acts on every failing message here: RFC 7489
        # treats mail not subject to reject as though p=quarantine applies
        # (section 6.6.4), and RFC 9989 ignores pct and rejects in full. Scoring
        # this "exposed" told the reader spoofed mail lands in the inbox, which
        # is the one outcome that cannot happen under either reading.
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": "pct=0 degrades reject to quarantine on RFC 7489 receivers.",
            "detail": f"pct=0 means RFC 7489 receivers apply p=reject to none of the failing mail and treat all of it as p=quarantine instead (RFC 7489 section 6.6.4), so spoofed mail sent as user@{domain} reaches the spam folder rather than being rejected. RFC 9989 receivers ignore pct and reject all of it. Removing pct closes the gap.",
        }
    elif policy == "quarantine" and pct >= 100:
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": "Spoofed mail goes to spam but still reaches recipients.",
            "detail": "Spoofed messages land in spam/junk folders. Recipients may still see and interact with them.",
        }
    elif policy == "quarantine" and pct > 0:
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": f"Only {pct}% of failing mail is quarantined (pct={pct}).",
            "detail": f"pct={pct} means receivers apply p=quarantine to only {pct}% of messages that fail authentication; the rest are delivered normally.",
        }
    else:
        exposure_note = ""
        if policy in ("reject", "quarantine") and pct <= 0:
            exposure_note = f" pct=0 means the p={policy} policy is applied to none of the failing messages."
        v1 = {
            "name": "Direct Domain Spoofing",
            "status": "exposed",
            "color": "red",
            "summary": f"Spoofed mail is delivered normally (p={policy or 'none'}).{exposure_note}",
            "detail": f"An attacker could send an email appearing to be from ceo@{domain} to your employees requesting a wire transfer. Without enforcement, this email is delivered to their inbox with no warning.",
        }
    vectors.append(v1)

    # ── Vector 2: Subdomain Spoofing ────────────────────────
    effective_sp = sp if sp else policy
    if effective_sp == "reject":
        v2 = {
            "name": "Subdomain Spoofing",
            "status": "protected",
            "color": "green",
            "summary": f"Subdomains {'use' if sp else 'inherit'} reject policy.",
            "detail": f"Spoofed mail from subdomains like mail.{domain} is blocked.",
        }
    elif effective_sp == "quarantine":
        v2 = {
            "name": "Subdomain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": "Subdomain spoofed mail goes to spam.",
            "detail": f"An attacker sending from support@helpdesk.{domain} would land in spam.",
        }
    else:
        gap_note = ""
        if sp == "none" and policy in ("reject", "quarantine"):
            gap_note = (
                " Your root domain is protected but subdomains are not, so mail "
                f"claiming to be from a subdomain of {domain} is delivered as if "
                "the policy did not exist."
            )
        v2 = {
            "name": "Subdomain Spoofing",
            "status": "exposed",
            "color": "red",
            "summary": f"Subdomains have no enforcement.{gap_note}",
            "detail": f"An attacker could send from support@helpdesk.{domain} to your customers requesting password resets. The subdomain looks legitimate but has no protection.",
        }
    vectors.append(v2)

    # ── Vector 3: Non-Existent Subdomain Spoofing ───────────
    np_effective = np_val if np_val else (sp if sp else policy)
    np_fallback = np_val is None
    if np_effective == "reject":
        note = ""
        if np_fallback:
            note = " Protected by fallback, but not explicitly. RFC 9989 recommends setting np= directly."
        v3 = {
            "name": "Non-Existent Subdomain Spoofing",
            "status": "protected" if not np_fallback else "partial",
            "color": "green" if not np_fallback else "amber",
            "summary": f"Non-existent subdomains {'reject' if not np_fallback else 'inherit reject via fallback'}.{note}",
            "detail": f"Invented subdomains like secure-login.{domain} are blocked.",
        }
    elif np_effective == "quarantine":
        v3 = {
            "name": "Non-Existent Subdomain Spoofing",
            "status": "partial",
            "color": "amber",
            "summary": "Non-existent subdomain spoofed mail goes to spam.",
            "detail": f"An attacker inventing secure-portal.{domain} would land in spam.",
        }
    else:
        v3 = {
            "name": "Non-Existent Subdomain Spoofing",
            "status": "exposed",
            "color": "red",
            "summary": "Attackers can invent any subdomain.",
            "detail": f"An attacker could create secure-portal.{domain}, a domain that doesn't exist, and send password phishing emails from it. Attackers prefer non-existent subdomains because they look convincing and many organizations don't realize they need to protect domains that don't exist in DNS.",
        }
    vectors.append(v3)

    # ── Vector 4: Reporting Intelligence Leakage ────────────
    report_dests = raw.get("report_destinations", [])
    has_unauthorized = any(d.get("authorized") is False for d in report_dests)

    if not rua and is_no_mail:
        v4 = {
            "name": "Reporting Intelligence",
            "status": "protected",
            "color": "green",
            "summary": "Not applicable (non-mail domain).",
            "detail": "This domain does not send or receive email, so there is no legitimate mail to monitor. Aggregate reporting (rua) is optional.",
        }
    elif not rua:
        v4 = {
            "name": "Reporting Intelligence",
            "status": "partial",
            "color": "amber",
            "summary": "No reporting configured. No leakage risk, but zero visibility.",
            "detail": "No aggregate reporting means you have no visibility into authentication results, but also no risk of report data being sent to unauthorized parties.",
        }
    elif raw.get("report_auth_indeterminate"):
        # Not "protected". Nothing verified these destinations, and the green
        # card said "Reports go to authorized destinations" on the strength
        # of a check that never ran.
        v4 = {
            "name": "Reporting Intelligence",
            "status": "partial",
            "color": "amber",
            "summary": "Report destinations were not verified by this audit.",
            "detail": "The check of whether each rua destination has authorized this domain to send it reports did not finish, so this audit cannot say where the reports are going. Re-run the audit to complete it.",
        }
    elif has_unauthorized:
        v4 = {
            "name": "Reporting Intelligence",
            "status": "exposed",
            "color": "red",
            "summary": "Reports may be sent to an unauthorized destination.",
            "detail": "An unauthorized party could be receiving your DMARC aggregate reports, learning which servers send email for your domain, your IP ranges, and your email volumes.",
        }
    else:
        v4 = {
            "name": "Reporting Intelligence",
            "status": "protected",
            "color": "green",
            "summary": "Reports go to authorized destinations.",
            "detail": "Aggregate reports are sent to verified destinations.",
        }
    vectors.append(v4)

    # ── Overall Score ───────────────────────────────────────
    exposed = [v for v in vectors if v["status"] == "exposed"]
    partial = [v for v in vectors if v["status"] == "partial"]

    if len(exposed) >= 2:
        overall = {"level": "critical", "label": "Critical Risk", "color": "red",
                   "summary": "This domain has multiple paths for email spoofing attacks."}
    elif len(exposed) == 1:
        overall = {"level": "high", "label": "High Risk", "color": "red",
                   "summary": f"This domain can be spoofed through {exposed[0]['name'].lower()}."}
    elif partial:
        overall = {"level": "moderate", "label": "Moderate Risk", "color": "amber",
                   "summary": "Some attack vectors are exposed."}
    else:
        overall = {"level": "low", "label": "Low Risk", "color": "green",
                   "summary": "This domain has strong email spoofing defenses."}

    # Attacker perspective
    weakest = exposed[0] if exposed else (partial[0] if partial else None)
    attacker_path = ""
    if weakest:
        if weakest["name"] == "Direct Domain Spoofing":
            attacker_path = f"If an attacker wanted to spoof this domain, they would send directly as user@{domain} since the policy is p={policy} and no mail is blocked."
        elif weakest["name"] == "Subdomain Spoofing":
            attacker_path = f"If an attacker wanted to spoof this domain, they would target subdomains like mail.{domain} since subdomain policy is weaker than the root."
        elif weakest["name"] == "Non-Existent Subdomain Spoofing":
            attacker_path = f"If an attacker wanted to spoof this domain, they would target non-existent subdomains like secure-login.{domain} since there is no np= policy to prevent it."
        elif weakest["name"] == "Reporting Intelligence":
            if raw.get("report_auth_indeterminate"):
                attacker_path = "This audit did not finish verifying where aggregate reports are sent, so it cannot say whether an unauthorized party is receiving them."
            else:
                attacker_path = "An unauthorized party may be receiving aggregate reports revealing your email infrastructure."

    return {
        "overall": overall,
        "vectors": vectors,
        "attacker_path": attacker_path,
    }


# ============================================================
# DMARC Record Breakdown (tag-by-tag decoder)
# ============================================================

_TAG_ORDER = ["v", "p", "sp", "np", "adkim", "aspf", "fo", "rua", "ruf", "pct", "rf", "ri", "psd", "t"]


def _explain_policy_value(value: str) -> str:
    """Shared explanation for p=, sp=, np= policy values."""
    return {
        "reject": (
            "Strongest enforcement. Mail that fails authentication is blocked entirely. "
            "Your domain is protected against spoofing."
        ),
        "quarantine": (
            "Mail that fails authentication is sent to spam. One step below full protection. "
            "Spoofed mail still reaches recipients, just in their junk folder."
        ),
        "none": (
            "Monitoring only: no mail is blocked or quarantined. Spoofed and malicious email "
            "claiming to be from your domain is still delivered to recipients. While monitoring is "
            "the correct first step, the goal is to progress to an enforcing policy "
            "(p=quarantine then p=reject). Without enforcement, your domain can be used to send "
            "phishing or malware to your customers and partners, which can damage your domain's "
            "sending reputation and erode trust with the people you do business with."
        ),
    }.get(value, f"Unknown policy value '{value}'.")


def _build_dmarc_tag_breakdown(record: str, raw: Dict) -> Optional[List[Dict]]:
    """Parse every tag in a DMARC record and return a structured breakdown.

    Each entry:
      tag, value, is_default, is_absent, label, explanation, dmarcbis, warnings
    """
    if not record:
        return None

    # Parse present tags
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "").lower()
    breakdown: List[Dict] = []

    # Determine which tags to show
    shown_tags = list(_TAG_ORDER)
    for tag_name in tags:
        if tag_name not in shown_tags:
            shown_tags.append(tag_name)

    for tag_name in shown_tags:
        present = tag_name in tags
        value = tags.get(tag_name, "")

        entry = _build_tag_entry(tag_name, value, present, tags, policy,
                                 domain=raw.get("domain", ""))
        if entry:
            breakdown.append(entry)

    return breakdown


def _build_tag_entry(tag: str, value: str, present: bool, tags: Dict, policy: str,
                     domain: str = "") -> Optional[Dict]:
    """Build a single tag entry with explanation, warnings, and RFC 9989 notes."""
    _dom = domain or "yourdomain.com"

    # ── v= ──────────────────────────────────────────────────
    if tag == "v":
        if not present:
            return None
        return _entry(tag, value, False, False, "Version",
                      "Valid DMARC version identifier. Required as the first tag.",
                      "current",
                      dmarcbis_note=(
                          "RFC 9989 tightens parsing. This MUST be the first tag. Records that place "
                          "it elsewhere will be rejected by RFC 9989-compliant receivers, even though some "
                          "legacy receivers were lenient about tag ordering."
                      ))

    # ── p= ──────────────────────────────────────────────────
    if tag == "p":
        if not present:
            return None
        e = _entry(tag, value, False, False, "Policy",
                   _explain_policy_value(value), "current",
                   dmarcbis_note=(
                       "RFC 9989 clarifies policy semantics and removes ambiguities in how receivers "
                       "interpret these values. The biggest change is replacing pct with the binary t=y "
                       "test mode for safer policy rollout."
                   ))
        if value == "none":
            e["warnings"].append({
                "level": "warning",
                "text": "Monitoring only. No enforcement is applied to messages that fail authentication.",
            })
        return e

    # ── sp= ─────────────────────────────────────────────────
    if tag == "sp":
        note = (
            "RFC 9989 clarifies inheritance behavior. The new np= tag extends subdomain protection "
            "to cover non-existent subdomains, something RFC 7489 had no concept of."
        )
        if present:
            e = _entry(tag, value, False, False, "Subdomain Policy",
                       _explain_policy_value(value), "current", dmarcbis_note=note)
            if value == "none" and policy in ("reject", "quarantine"):
                e["warnings"].append({
                    "level": "warning",
                    "text": (
                        "Your subdomains have weaker enforcement than your root domain, so "
                        f"mail claiming to be from mail.{_dom} is delivered as if the "
                        "policy did not exist."
                    ),
                })
            return e
        else:
            p_val = tags.get("p", "none")
            return _entry(tag, None, False, True, "Subdomain Policy",
                          f"Subdomains inherit the root policy (p={p_val}). "
                          f"Setting sp= explicitly removes ambiguity.",
                          "current", dmarcbis_note=note)

    # ── np= (RFC 9989) ─────────────────────────────────────
    if tag == "np":
        note = (
            "This tag is NEW in RFC 9989. RFC 7489 had no way to set policy for subdomains that "
            "don't exist in DNS. Attackers exploit this by inventing subdomains. np= closes that gap."
        )
        if present:
            e = _entry(tag, value, False, False, "Non-Existent Subdomain Policy",
                       _explain_policy_value(value), "new", dmarcbis_note=note)
            if value == "none" and policy == "reject":
                e["warnings"].append({
                    "level": "warning",
                    "text": (
                        "Critical gap. Non-existent subdomains have no enforcement while your root "
                        "domain rejects. Attackers can invent subdomains like "
                        "secure-login.yourdomain.com and spoof mail from them."
                    ),
                })
            return e
        else:
            sp_val = tags.get("sp")
            p_val = tags.get("p", "none")
            resolved = sp_val if sp_val else p_val
            resolved_via = "sp" if sp_val else "p"
            e = _entry(tag, None, False, True, "Non-Existent Subdomain Policy",
                       f"No non-existent subdomain policy. Falls back to sp= (if set), then p=. "
                       f"Current effective policy for non-existent subdomains: {resolved_via}={resolved}.",
                       "new", dmarcbis_note=note)
            chain = [{"tag": "np", "value": None, "active": False}]
            if sp_val:
                chain.append({"tag": "sp", "value": sp_val, "active": True})
                chain.append({"tag": "p", "value": p_val, "active": False})
            else:
                chain.append({"tag": "p", "value": p_val, "active": True})
            e["fallback_chain"] = chain
            e["resolved_value"] = resolved
            if resolved != "reject":
                e["warnings"].append({
                    "level": "warning",
                    "text": (
                        f"Attackers can invent non-existent subdomains like "
                        f"secure-login.yourdomain.com. Without np=, the policy for these is "
                        f"{resolved_via}={resolved}. Consider adding np=reject."
                    ),
                })
            return e

    # ── adkim= ──────────────────────────────────────────────
    if tag == "adkim":
        note = (
            "RFC 9989 clarifies alignment edge cases, especially around subdomains and how "
            "organizational domain is determined (now via tree walk instead of PSL)."
        )
        if present:
            explanation = {
                "r": (
                    "Relaxed. Subdomains of the DKIM signing domain satisfy alignment. "
                    "mail.example.com aligns with example.com."
                ),
                "s": (
                    "Strict. The DKIM d= domain must exactly match the From domain. "
                    "More secure but rejects mail signed by a subdomain."
                ),
            }.get(value, f"Unknown DKIM alignment value '{value}'.")
            e = _entry(tag, value, False, False, "DKIM Alignment Mode",
                       explanation, "current", dmarcbis_note=note)
        else:
            e = _entry(tag, "r", True, True, "DKIM Alignment Mode",
                       "Defaults to relaxed (r). Subdomain alignment is permitted.",
                       "current", dmarcbis_note=note)
            value = "r"
        return e

    # ── aspf= ───────────────────────────────────────────────
    if tag == "aspf":
        note = (
            "RFC 9989 explicitly states that DMARC evaluates SPF against the MAIL FROM identity "
            "only, not HELO. RFC 7489 was ambiguous about this."
        )
        if present:
            explanation = {
                "r": "Relaxed. Subdomains of the SPF-authenticated domain satisfy alignment.",
                "s": "Strict. The MAIL FROM domain must exactly match the From domain.",
            }.get(value, f"Unknown SPF alignment value '{value}'.")
            e = _entry(tag, value, False, False, "SPF Alignment Mode",
                       explanation, "current", dmarcbis_note=note)
        else:
            e = _entry(tag, "r", True, True, "SPF Alignment Mode",
                       "Defaults to relaxed (r).",
                       "current", dmarcbis_note=note)
            value = "r"
        return e

    # ── fo= ─────────────────────────────────────────────────
    if tag == "fo":
        note = (
            "The fo tag is defined in RFC 9989 Section 4.7, but the reports it "
            "governs are specified in RFC 9991. Most large receivers, Google and "
            "Microsoft among them, no longer send failure reports at all."
        )
        if present:
            explanation = {
                "0": (
                    "Reports only when BOTH SPF and DKIM fail. You miss most failures. "
                    "Set fo=1 for broader visibility."
                ) if tags.get("ruf") else (
                    "Reports only when BOTH SPF and DKIM fail. This has no effect: "
                    "RFC 9989 section 4.7 requires a ruf= tag for fo to do anything, "
                    "and this record does not set one."
                ),
                "1": "Reports when either mechanism fails. Recommended.",
                "d": "Reports on DKIM failure regardless of alignment.",
                "s": "Reports on SPF failure regardless of alignment.",
            }.get(value, f"Failure reporting option: {value}.")
            return _entry(tag, value, False, False, "Failure Reporting Options",
                          explanation, "current", dmarcbis_note=note)
        else:
            return _entry(tag, "0", True, True, "Failure Reporting Options",
                          "Defaults to fo=0. Reports only on complete failure of both mechanisms.",
                          "current", dmarcbis_note=note)

    # ── rua= ────────────────────────────────────────────────
    if tag == "rua":
        note = (
            "Reporting moved into its own documents: RFC 9990 for aggregate reports, RFC 9991 for "
            "failure reports. URI validation is tighter. The mailto: "
            "prefix is now strictly required. Bare email addresses are rejected. RFC 9989 also "
            "strengthens external reporting authorization checks."
        )
        if present:
            base = (
                f"Aggregate reports are sent to {value}. These show which sources send mail "
                f"as your domain and whether they pass or fail authentication."
            )
            if policy == "reject":
                base += (
                    " These reports are the only way to know if legitimate mail is being silently rejected."
                )
            elif policy == "quarantine":
                base += (
                    " These show what's landing in spam. Check if legitimate senders are affected."
                )
            elif policy == "none":
                base += (
                    " These show every source sending as your domain. Review before moving to enforcement."
                )
            return _entry(tag, value, False, False, "Aggregate Report Recipients",
                          base, "current", dmarcbis_note=note)
        else:
            if policy == "reject":
                msg = (
                    "No reporting. You are rejecting mail with zero visibility. "
                    "Legitimate mail could be silently disappearing."
                )
            elif policy == "quarantine":
                msg = "No reporting. Failing mail goes to spam and you cannot see what's affected."
            else:
                msg = (
                    "No enforcement AND no monitoring. This record serves no purpose."
                )
            e = _entry(tag, None, False, True, "Aggregate Report Recipients",
                       msg, "current", dmarcbis_note=note)
            e["warnings"].append({"level": "warning", "text": msg})
            return e

    # ── ruf= ────────────────────────────────────────────────
    if tag == "ruf":
        note = (
            "Failure reporting is now defined in its own document, RFC 9991, reflecting "
            "that it's increasingly uncommon in practice."
        )
        if present:
            return _entry(tag, value, False, False, "Forensic Report Recipients",
                          f"Failure reports sent to {value}. Most providers including Google and "
                          f"Microsoft no longer send failure reports due to PII concerns.",
                          "current", dmarcbis_note=note)
        else:
            return _entry(tag, None, False, True, "Forensic Report Recipients",
                          "No failure reporting. Common since most providers don't send them. "
                          "Aggregate reports provide sufficient visibility.",
                          "current", dmarcbis_note=note)

    # ── pct= (deprecated) ──────────────────────────────────
    if tag == "pct":
        if present:
            e = _entry(tag, value, False, False, "Percentage",
                       f"Policy applies to {value}% of failing messages. "
                       "RFC 9989 removes the pct tag. Only values of 0 and 100 were reliably "
                       "honored. RFC 9989 replaces this with t=y/t=n for predictable testing. "
                       "Receivers that have not moved off RFC 7489 still honor pct, but RFC 9989 "
                       "receivers ignore it. To migrate: "
                       "use t=y for testing or remove pct for full enforcement.",
                       "deprecated")
            e["warnings"].append({
                "level": "info",
                "text": "Removed in RFC 9989. Use t=y for testing, or drop pct for full enforcement.",
            })
            return e
        else:
            return _entry(tag, "100", True, True, "Percentage",
                          "RFC 7489 defaulted to 100. RFC 9989 removes the pct tag.",
                          "deprecated")

    # ── rf= (deprecated) ───────────────────────────────────
    if tag == "rf":
        if present:
            e = _entry(tag, value, False, False, "Report Format",
                       "Only afrf was ever implemented. Removed in RFC 9989. Safe to remove.",
                       "deprecated")
            e["warnings"].append({"level": "info", "text": "Removed in RFC 9989. Safe to remove."})
            return e
        else:
            return _entry(tag, "afrf", True, True, "Report Format",
                          "RFC 7489 defaulted to afrf. RFC 9989 removes the rf tag.",
                          "deprecated")

    # ── ri= (deprecated) ───────────────────────────────────
    if tag == "ri":
        if present:
            suffix = f" ({int(value)//3600}h)" if value.isdigit() else ""
            e = _entry(tag, value, False, False, "Report Interval",
                       f"Requested interval: {value} seconds{suffix}. "
                       "Report intervals were rarely respected. RFC 9990 describes daily or more frequent "
                       "reports and gives the Domain Owner no way to request an interval. "
                       "Safe to remove.",
                       "deprecated")
            e["warnings"].append({"level": "info", "text": "Removed in RFC 9989. Safe to remove."})
            return e
        else:
            return _entry(tag, "86400", True, True, "Report Interval",
                          "RFC 7489 defaulted to 86400s (24h). RFC 9989 removes the ri tag.",
                          "deprecated")

    # ── psd= (RFC 9989) ────────────────────────────────────
    if tag == "psd":
        note = (
            "This tag is NEW in RFC 9989. It replaces reliance on the Public Suffix List (PSL) "
            "for determining organizational domain boundaries. The PSL was maintained manually and "
            "often outdated. psd= lets domain owners declare their own status directly in DNS."
        )
        if present:
            explanation = {
                "y": (
                    "This domain declares itself as a Public Suffix Domain (like .com or .co.uk). "
                    "The DNS tree walk stops here and subdomains are treated as separate organizational "
                    "domains that will NOT inherit this DMARC policy. If this domain is not actually a "
                    "public suffix, this is a critical misconfiguration: subdomains lose policy "
                    "inheritance entirely."
                ),
                "n": (
                    "Not a Public Suffix. Subdomains inherit policy normally. "
                    "This is the correct value for most domains."
                ),
                "u": (
                    "Undeclared, which is the RFC 9989 default and the right value for "
                    "almost every domain. Receivers fall back to the Public Suffix List. "
                    "Declare psd=y only if this domain really is a public suffix."
                ),
            }.get(value, f"Unknown psd value '{value}'.")
            e = _entry(tag, value, False, False, "Public Suffix Domain", explanation, "new",
                       dmarcbis_note=note)
            if value == "y":
                e["warnings"].append({
                    "level": "warning",
                    "text": (
                        "If this domain is not actually a public suffix, this misconfiguration "
                        "disrupts policy inheritance for all subdomains."
                    ),
                })
            return e
        else:
            return _entry(tag, "u", True, True, "Public Suffix Domain",
                          "Not declared, which is the RFC 9989 default ('u') and correct for "
                          "almost every domain. Receivers fall back to the Public Suffix List. "
                          "Publish psd= only if this domain is a public suffix.",
                          "new", dmarcbis_note=note)

    # ── t= (RFC 9989) ──────────────────────────────────────
    if tag == "t":
        note = (
            "This tag is NEW in RFC 9989, replacing the unreliable pct tag. Under RFC 7489, "
            "pct=50 meant 'apply to 50% of failing mail' but receivers implemented this "
            "inconsistently. Only pct=0 and pct=100 were reliable. RFC 9989 replaces this with a "
            "clean binary flag: t=y (testing, drop policy one level) or t=n (enforce fully). This "
            "gives domain owners a safe, predictable way to test stricter policies before committing."
        )
        if present:
            if value == "y":
                explanation = (
                    "Test mode ACTIVE. Your published policy is NOT enforced at full strength. "
                    "p=reject becomes p=quarantine. p=quarantine becomes p=none. "
                    "This also drops sp= and np= one level. Test mode is useful "
                    "during migration but should be temporary."
                )
                e = _entry(tag, value, False, False, "Testing Mode", explanation, "new",
                           dmarcbis_note=note)
                if policy == "none":
                    e["warnings"].append({
                        "level": "info",
                        "text": "t=y on p=none has no effect. p=none cannot drop further. Remove t=y.",
                    })
                return e
            else:
                return _entry(tag, value, False, False, "Testing Mode",
                              "Normal enforcement. Policies applied as published.",
                              "new", dmarcbis_note=note)
        else:
            return _entry(tag, None, False, True, "Testing Mode",
                          "Normal enforcement. Policies applied as published.",
                          "new", dmarcbis_note=note)

    # ── Unknown tag ─────────────────────────────────────────
    if present:
        e = _entry(tag, value, False, False, f"Unknown Tag ({tag})",
                   "This tag is not defined in RFC 7489 or RFC 9989. It may be ignored by receivers.",
                   "current")
        e["warnings"].append({
            "level": "warning",
            "text": f"Unrecognized tag '{tag}' may be ignored by mail receivers.",
        })
        return e

    return None


def _entry(tag: str, value, is_default: bool, is_absent: bool,
           label: str, explanation: str, dmarcbis: str,
           dmarcbis_note: str = None) -> Dict:
    """Helper to build a tag breakdown entry."""
    entry = {
        "tag": tag,
        "value": value,
        "is_default": is_default,
        "is_absent": is_absent,
        "label": label,
        "explanation": explanation,
        "dmarcbis": dmarcbis,
        "warnings": [],
    }
    if dmarcbis_note:
        entry["dmarcbis_note"] = dmarcbis_note
    return entry


# ============================================================
# Dangerous Combination Detection (Prompt 2)
# ============================================================

def _detect_dangerous_combinations(tags: Dict[str, str], policy: str, is_no_mail: bool = False,
                                   domain: str = "") -> List[Dict]:
    """Check for dangerous tag combinations. Returns a list of warnings
    with level ("critical" or "advisory"), title, and text."""
    warnings: List[Dict] = []
    _dom = domain or "yourdomain.com"
    sp = tags.get("sp")
    np_val = tags.get("np")
    np_present = "np" in tags
    t_val = tags.get("t")
    psd = tags.get("psd")
    fo = tags.get("fo", "0")
    rua = tags.get("rua")
    ruf = tags.get("ruf")
    deprecated_present = [t for t in ("pct", "rf", "ri") if t in tags]

    # Resolve np fallback
    np_resolved = np_val if np_present else (sp if sp else policy)
    np_resolved_via = "np" if np_present else ("sp" if sp else "p")

    # ── RED: Critical ───────────────────────────────────────

    # 0. Missing p= but rua= present. RFC 9989 §4.10.1 MUSTs treat-as-p=none;
    # RFC 7489 ignores the record. Same record, two behaviors.
    if not tags.get("p") and rua:
        warnings.append({
            "level": "critical",
            "title": "Missing p= tag (interop hazard)",
            "text": (
                "No explicit p= tag. RFC 9989-compliant receivers treat this as p=none; RFC 7489 "
                "receivers ignore the record entirely. Behavior depends on which spec the receiver "
                "implements. Add an explicit p=none, p=quarantine, or p=reject."
            ),
            "tags": ["p"],
        })

    # 1. Any policy + no rua (skipped on no-mail domains: no legitimate mail to monitor)
    if not rua and not is_no_mail:
        if policy == "reject":
            msg = (
                "No aggregate reporting configured. At p=reject, you are rejecting mail that "
                "fails authentication with zero visibility. Legitimate mail could be silently "
                "disappearing and you would never know. Add an rua= address immediately."
            )
        elif policy == "quarantine":
            msg = (
                "No aggregate reporting configured. At p=quarantine, failing mail goes to spam "
                "and you cannot see what is being quarantined. Add an rua= address immediately."
            )
        else:
            msg = (
                "No aggregate reporting configured. At p=none, there is no enforcement and no "
                "monitoring. This DMARC record serves no purpose. Add an rua= address immediately."
            )
        warnings.append({"level": "critical", "title": "No aggregate reporting", "text": msg, "tags": ["rua"]})

    # 2. sp=none + p=reject
    if sp == "none" and policy == "reject":
        warnings.append({
            "level": "critical",
            "title": "Subdomain policy gap",
            "text": (
                "Subdomain policy gap. Your root domain rejects spoofed mail but subdomains allow "
                f"it through, so mail claiming to be from mail.{_dom} is delivered as if the "
                "policy did not exist."
            ),
            "tags": ["sp", "p"],
        })

    # 3. np=none + p=reject
    if np_val == "none" and policy == "reject":
        warnings.append({
            "level": "critical",
            "title": "Non-existent subdomain gap",
            "text": (
                "Non-existent subdomain gap. Invented subdomains like "
                "secure-login.yourdomain.com have no enforcement while your root domain rejects."
            ),
            "tags": ["np", "p"],
        })

    # 4. np missing + sp=none + p=reject
    if not np_present and sp == "none" and policy == "reject":
        warnings.append({
            "level": "critical",
            "title": "Double policy gap",
            "text": (
                "Double policy gap. Both existing and non-existent subdomains fall back to sp=none. "
                "Your p=reject only protects the root domain."
            ),
            "tags": ["np", "sp", "p"],
        })

    # 5. psd=y
    if psd == "y":
        warnings.append({
            "level": "critical",
            "title": "Public Suffix declaration",
            "text": (
                "This domain claims to be a Public Suffix Domain. If incorrect, the DNS tree walk "
                "stops prematurely and subdomains lose policy inheritance entirely. This is likely a "
                "misconfiguration. Set psd=n if this is a regular domain."
            ),
            "tags": ["psd"],
        })

    # 6. p=none + no rua (already covered by #1 but with specific text)
    # Already handled above in the p=none branch of #1

    # 7. np=reject + p=none
    if np_val == "reject" and policy == "none":
        warnings.append({
            "level": "critical",
            "title": "Contradictory np vs p policy",
            "text": (
                "np=reject is stricter than p=none, so invented subdomains are protected "
                "while the root domain is not. The root domain is the easier target."
            ),
            "tags": ["np", "p"],
        })

    # 8. sp=reject + p=none
    if sp == "reject" and policy == "none":
        warnings.append({
            "level": "critical",
            "title": "Contradictory sp vs p policy",
            "text": (
                "Stricter policy on subdomains than the root domain. Same contradiction: "
                "the root domain is the easier target."
            ),
            "tags": ["sp", "p"],
        })

    # ── AMBER: Warnings ────────────────────────────────────

    # 9. t=y + p=reject
    if t_val == "y" and policy == "reject":
        warnings.append({
            "level": "advisory",
            "title": "Test mode weakens reject",
            "text": (
                "Test mode reduces your effective policy to p=quarantine. Spoofed mail lands in "
                "spam instead of being blocked. If testing is complete, remove t=y to enforce full rejection."
            ),
            "tags": ["t", "p"],
        })

    # 10. t=y + np=reject
    if t_val == "y" and np_val == "reject":
        warnings.append({
            "level": "advisory",
            "title": "Test mode weakens np=reject",
            "text": (
                "Test mode also drops np=reject to np=quarantine. Non-existent subdomain "
                "spoofing lands in spam instead of being blocked."
            ),
            "tags": ["t", "np"],
        })

    # 11. t=y + p=none
    if t_val == "y" and policy == "none":
        warnings.append({
            "level": "advisory",
            "title": "Test mode on p=none",
            "text": "Test mode on a policy that already permits everything. t=y has no effect here. Remove it.",
            "tags": ["t", "p"],
        })

    # 12. (removed) An absent psd= tag is not a defect. RFC 9989 section 4.7
    # makes the tag OPTIONAL with a default of "u", and psd=n published on a
    # name that is not the Organizational Domain terminates the tree walk
    # there, changing alignment scope and external rua authorization.

    # 13. fo=0 + ruf configured
    if fo == "0" and ruf:
        warnings.append({
            "level": "advisory",
            "title": "Underutilized failure reporting",
            "text": (
                "Failure reporting is configured but set to report only when both SPF and DKIM fail. "
                "You are missing most failure data. Set fo=1 to capture all failures."
            ),
            "tags": ["fo", "ruf"],
        })

    # 15. Deprecated tags present
    if deprecated_present:
        warnings.append({
            "level": "advisory",
            "title": "Deprecated tags present",
            "text": (
                f"Deprecated tags found that will be ignored by RFC 9989-compliant receivers. "
                f"Consider removing: {', '.join(deprecated_present)}."
            ),
            "tags": deprecated_present,
        })

    # 16. sp absent + p=reject
    if sp is None and policy == "reject":
        warnings.append({
            "level": "advisory",
            "title": "Implicit subdomain policy",
            "text": (
                "Subdomains inherit p=reject by default, which is correct. But setting sp=reject "
                "explicitly removes ambiguity."
            ),
            "tags": ["sp", "p"],
        })

    # 16. np absent at enforcing policy
    if not np_present and policy in ("reject", "quarantine"):
        warnings.append({
            "level": "advisory",
            "title": "No explicit np= policy",
            "text": (
                f"No explicit non-existent subdomain policy. Falls back to "
                f"{np_resolved_via}={np_resolved}. Consider adding np= to close potential gaps."
            ),
            "tags": ["np"],
        })

    # 17. p=none + rua configured
    if policy == "none" and rua:
        warnings.append({
            "level": "advisory",
            "title": "Monitoring mode",
            "text": (
                "Monitoring mode. Your domain is not protected against spoofing. Mail that fails "
                "authentication is still delivered to recipients. Your domain can be used to send "
                "phishing or malware to your customers and partners, which can damage your sending "
                "reputation and erode trust with the people you do business with. Review your aggregate "
                "reports and progress to p=quarantine then p=reject."
            ),
            "tags": ["p", "rua"],
        })

    # ── BLUE: Informational ────────────────────────────────

    # 18. SPF evaluates MAIL FROM only under RFC 9989
    warnings.append({
        "level": "info",
        "title": "SPF alignment under RFC 9989",
        "text": "Under RFC 9989, SPF alignment is evaluated against the MAIL FROM (envelope sender) identity only, not HELO.",
        "tags": [],
    })

    # 19. p=reject + mailing list risk
    if policy == "reject":
        warnings.append({
            "level": "info",
            "title": "Mailing list participation",
            "text": (
                "p=reject may cause issues with mailing lists that rewrite the From header. "
                "ARC (Authenticated Received Chain) helps, but not all receivers support it yet."
            ),
            "tags": ["p"],
        })

    # 20. RFC 9989 reporting split
    warnings.append({
        "level": "info",
        "title": "RFC 9989 reporting restructured",
        "text": "RFC 9989 splits the specification into three separate RFCs: core mechanism, aggregate reporting, and failure reporting.",
        "tags": [],
    })

    # 21. External reporting destinations
    if rua and "@" in rua:
        # Check if any rua destination is external
        rua_domains = []
        for uri in rua.split(","):
            uri = uri.strip()
            if "mailto:" in uri:
                email = uri.split("mailto:")[1].split("!")[0]
                if "@" in email:
                    rua_domains.append(email.split("@")[1])
        if rua_domains:
            warnings.append({
                "level": "info",
                "title": "External reporting destinations",
                "text": f"Aggregate reports are sent to domain(s): {', '.join(set(rua_domains))}.",
                "tags": ["rua"],
            })

    return warnings


# ============================================================
# RFC 9989 Health Verdict (Prompt 3)
# ============================================================

def _calculate_dmarcbis_health(tags: Dict[str, str], policy: str, config_warnings: List[Dict]) -> Dict:
    """Evaluate the record and return one of five verdicts with a badge color
    and one-line summary.

    Returns:
      status   - "ready", "compatible", "monitoring", "attention", "misconfigured"
      label    - display label
      color    - "green", "blue", "amber", "red"
      summary  - one-line explanation
      reasons  - specific tags/combos that determined the verdict
    """
    critical = [w for w in config_warnings if w["level"] == "critical"]
    advisory = [w for w in config_warnings if w["level"] == "advisory"]

    deprecated_present = [t for t in ("pct", "rf", "ri") if t in tags]
    # RFC 9989 section 4.7 makes psd= OPTIONAL with a default of "u", and
    # publishing psd=n on a name that is not the Organizational Domain
    # actively changes relaxed-alignment scope and external rua
    # authorization. It is not a readiness criterion. np and sp are
    # likewise both OPTIONAL and inherit from p= when absent, so neither
    # is read here; see the Ready/Compatible branches below.
    t_val = tags.get("t")
    rua = tags.get("rua")

    # ── Misconfigured (red) ─────────────────────────────────
    # Critical issues that actively undermine the record
    if critical:
        reasons = [w["title"] for w in critical]
        # Build a specific summary from the worst issue
        worst = critical[0]
        return {
            "status": "misconfigured",
            "label": "Misconfigured",
            "color": "red",
            "summary": f"This record has critical issues. {worst['text'].split('.')[0]}.",
            "reasons": reasons,
        }

    # ── Monitoring (amber) ──────────────────────────────────
    # p=none with rua configured
    if policy == "none" and rua:
        return {
            "status": "monitoring",
            "label": "Monitoring",
            "color": "amber",
            "summary": (
                "This domain is in monitoring mode. Mail that fails authentication is still "
                "delivered: your domain is not yet protected against spoofing. Review your "
                "reports and progress toward an enforcing policy."
            ),
            "reasons": ["p=none (monitoring only)"],
        }

    # ── Needs Attention (amber) ─────────────────────────────
    # Enforcing but has dangerous combinations that weaken protection
    # These are the advisory warnings that actually weaken protection:
    _attention_titles = {
        "Test mode weakens reject", "Test mode weakens np=reject",
        "Test mode on p=none",
        "Underutilized failure reporting",
    }
    attention_triggers = [w["title"] for w in advisory if w["title"] in _attention_titles]

    if attention_triggers and policy in ("reject", "quarantine"):
        issues = ", ".join(attention_triggers[:3])
        return {
            "status": "attention",
            "label": "Needs Attention",
            "color": "amber",
            "summary": f"This record has an enforcing policy but {issues} weaken its protection.",
            "reasons": attention_triggers,
        }

    # ── RFC 9989 Ready (green) ──────────────────────────────
    # Clean record, fully compliant. np and sp are unset here on purpose in
    # plenty of Ready records: both are OPTIONAL, and an absent tag inherits
    # from p= rather than leaving anything unprotected, so neither belongs
    # in a readiness gate.
    if (policy in ("reject", "quarantine")
            and not deprecated_present
            and t_val != "y"
            and rua
            and not critical):
        return {
            "status": "ready",
            "label": "RFC 9989 Ready",
            "color": "green",
            "summary": "This record is fully RFC 9989-compliant with no issues detected.",
            "reasons": [],
        }

    # ── RFC 9989 Compatible (blue) ──────────────────────────
    # Valid with minor gaps. np and sp being unset is not one of them (see
    # above), so neither appears here either.
    reasons = []
    if deprecated_present:
        reasons.append(f"Deprecated tags: {', '.join(deprecated_present)}")

    improvements = ". ".join(reasons) if reasons else "Minor improvements available"

    return {
        "status": "compatible",
        "label": "RFC 9989 Compatible",
        "color": "blue",
        "summary": f"This record works under RFC 9989 but has room for improvement. {improvements}.",
        "reasons": reasons,
    }


# ============================================================
# Migration Wizard
# ============================================================

def _build_why_dmarcbis(tags: Dict[str, str], policy: str, health_status: str, domain: str = "") -> Dict:
    """Build the 'Why RFC 9989?' education section, personalized to this domain's record."""

    sections = []

    # Section 1: What is RFC 9989 (always shown)
    sections.append({
        "title": "What is RFC 9989 (DMARCbis)?",
        "content": (
            "RFC 9989 is the DMARC standard. Published in May 2026 on the IETF Standards Track, it "
            "obsoletes RFC 7489 and RFC 9091, the documents that defined DMARC until then. It is "
            "still widely called DMARCbis, the name it carried through the working group. It "
            "addresses real-world problems "
            "discovered over a decade of DMARC deployment: inconsistent parsing across receivers, "
            "unreliable percentage-based rollout, no protection for non-existent subdomains, and "
            "dependence on the manually-maintained Public Suffix List."
        ),
    })

    # Section 2: What's new (conditional based on domain's record)
    whats_new = []

    if "pct" in tags:
        whats_new.append(
            "Your record uses the pct tag. RFC 9989 removes pct because only values of 0 "
            "and 100 were reliably enforced by receivers. It's replaced by t=y/t=n, a clean binary "
            "test mode that predictably drops your policy one level for safe rollout."
        )

    if "np" not in tags:
        whats_new.append(
            f"Your record doesn't have an np= tag. This is a new RFC 9989 tag that sets policy for "
            f"non-existent subdomains, domains like secure-login.{domain or 'yourdomain.com'} that "
            f"don't exist but can be spoofed. Under RFC 7489, there was no way to control this."
        )

    dep_in_record = [t for t in ("rf", "ri") if t in tags]
    if dep_in_record:
        tag_list = " and ".join(dep_in_record)
        whats_new.append(
            f"Your record uses {tag_list} which {'is' if len(dep_in_record) == 1 else 'are'} deprecated in RFC 9989. "
            f"rf was redundant (only afrf was ever implemented) and ri was rarely respected by receivers."
        )

    # Always-show items
    whats_new.append(
        "RFC 9989 tightens record parsing significantly. Records with missing mailto: prefixes, "
        "duplicate tags, empty values, or malformed URIs that older tools silently accepted will "
        "be rejected by RFC 9989-compliant receivers."
    )

    whats_new.append(
        "RFC 9989 replaces the DNS tree walk's dependence on the Public Suffix List with the psd= "
        "tag and an 8-query safety limit, making organizational domain resolution more reliable and DNS-native."
    )

    whats_new.append(
        "RFC 9989 splits the specification into three separate RFCs: the core mechanism, aggregate "
        "reporting, and failure reporting, reflecting that these are distinct operational concerns."
    )

    sections.append({
        "title": "What changed from RFC 7489?",
        "items": whats_new,
    })

    # Section 3: Where this record stands on the readiness scale
    verdict_scale = [
        {"status": "misconfigured", "label": "Misconfigured", "color": "red"},
        {"status": "monitoring", "label": "Monitoring", "color": "amber"},
        {"status": "attention", "label": "Needs Attention", "color": "amber"},
        {"status": "compatible", "label": "Compatible", "color": "blue"},
        {"status": "ready", "label": "RFC 9989 Ready", "color": "green"},
    ]

    sections.append({
        "title": "Where does this record stand?",
        "content": (
            "This scale reflects how completely the record matches RFC 9989, the current DMARC "
            "standard. Ready means it uses the current tags and needs no changes. Compatible means "
            "it works but leaves protection unused. Anything below that has gaps worth closing. "
            f"This record is currently rated '{health_status}'."
        ),
        "verdict_scale": verdict_scale,
        "current_verdict": health_status,
    })

    # Section 4: Why does this matter
    sections.append({
        "title": "Why does this matter?",
        "content": (
            "When your domain can be spoofed, someone else can send phishing and fraud that "
            "appears to come from you. Your customers, partners, and employees see your name "
            "on it. That costs you twice: the recipients who were fooled, and the sending "
            "reputation you need for your own mail to reach inboxes. RFC 9989 closes gaps "
            "RFC 7489 left open, particularly around non-existent subdomains and inconsistent "
            "receiver behavior."
        ),
    })

    # Section 5: What should I do
    sections.append({
        "title": "What should I do?",
        "content": "See your personalized migration path above for step-by-step instructions to reach RFC 9989 Ready status.",
    })

    return {"sections": sections}


def _build_migration_path(tags: Dict[str, str], policy: str, health_status: str, domain: str = "") -> Optional[Dict]:
    """Generate a personalized step-by-step migration path to RFC 9989 Ready.

    Returns None if already RFC 9989 Ready.
    """
    if health_status == "ready":
        return {"status": "ready", "steps": [], "message": "No migration needed. This record is RFC 9989 Ready."}

    steps = []
    step_num = 0
    rua = tags.get("rua")
    sp = tags.get("sp")
    np_val = tags.get("np")
    fo = tags.get("fo", "0")
    has_ruf = bool(tags.get("ruf"))
    deprecated = [t for t in ("pct", "rf", "ri") if t in tags]

    # Build the current record for before/after
    current_parts = []
    for part_key in ["v", "p", "sp", "np", "adkim", "aspf", "fo", "rua", "ruf", "pct", "rf", "ri", "psd", "t"]:
        if part_key in tags:
            current_parts.append(f"{part_key}={tags[part_key]}")

    rua_placeholder = rua if rua else "mailto:dmarc@yourdomain.com"

    # Step: Add reporting if missing
    if not rua:
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Add aggregate reporting",
            "why": "Without rua=, you have zero visibility into authentication results.",
            "record_after": f"v=DMARC1; p={policy or 'none'}; rua={rua_placeholder}",
            "tags_changed": ["rua"],
        })

    # Step: Review reports (for p=none)
    if policy == "none":
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Review aggregate reports for 2-4 weeks",
            "why": "Identify all legitimate senders and fix their SPF/DKIM alignment before enforcing.",
            "tags_changed": [],
        })

        # Step: Test quarantine
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Test quarantine with t=y",
            "why": "t=y drops the effective policy one level, so p=quarantine with t=y acts like p=none. Safe to test.",
            "record_after": f"v=DMARC1; p=quarantine; t=y; rua={rua_placeholder}",
            "tags_changed": ["p", "t"],
        })

        # Step: Enforce quarantine
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Enforce quarantine by removing t=y",
            "why": "Once reports show no legitimate mail failures, enforce quarantine.",
            "record_after": f"v=DMARC1; p=quarantine; rua={rua_placeholder}",
            "tags_changed": ["t"],
        })

    # Step: Test reject (for quarantine or just-promoted)
    if policy in ("none", "quarantine"):
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Test reject with t=y",
            "why": "p=reject with t=y effectively acts as p=quarantine. Monitor for issues.",
            "record_after": f"v=DMARC1; p=reject; t=y; rua={rua_placeholder}",
            "tags_changed": ["p", "t"],
        })

        # Step: Enforce reject
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Enforce reject by removing t=y",
            "why": "Full protection. Mail failing authentication is blocked.",
            "record_after": f"v=DMARC1; p=reject; rua={rua_placeholder}",
            "tags_changed": ["t"],
        })

    # Step: Fix sp=none gap if present
    if sp == "none" and policy in ("reject", "quarantine"):
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Align subdomain policy: change sp=none to sp=reject",
            "why": "Close the subdomain policy gap. Attackers target subdomains to bypass your root policy.",
            "tags_changed": ["sp"],
        })

    # Step: Set fo=1 if needed. RFC 9989 section 4.7: "This tag's content
    # MUST be ignored if a ruf tag is not also specified", so this step only
    # applies when the current record already sets ruf. Without ruf, fo has
    # no effect regardless of its value.
    if has_ruf and (fo == "0" or "fo" not in tags):
        step_num += 1
        steps.append({
            "step": step_num,
            "action": "Set fo=1 for full failure visibility",
            "why": (
                "fo=0 reports only when every mechanism fails. fo=1 reports when "
                "either SPF or DKIM fails. The tag has no effect unless ruf= is "
                "also set."
            ),
            "tags_changed": ["fo"],
        })

    # Step: Add RFC 9989 tags
    dmarcbis_needed = []
    if not np_val:
        dmarcbis_needed.append("np=reject")
    if not sp or sp == "none":
        dmarcbis_needed.append("sp=reject")

    if dmarcbis_needed:
        step_num += 1
        steps.append({
            "step": step_num,
            "action": f"Add RFC 9989 tags: {', '.join(dmarcbis_needed)}",
            "why": "These tags close gaps in the old standard and prepare for RFC 9989.",
            "tags_changed": [t.split("=")[0] for t in dmarcbis_needed],
        })

    # Step: Remove deprecated tags
    if deprecated:
        step_num += 1
        steps.append({
            "step": step_num,
            "action": f"Remove deprecated tags: {', '.join(deprecated)}",
            "why": "These tags are ignored by RFC 9989 receivers. Removing them cleans up the record.",
            "tags_changed": deprecated,
        })

    # Final target record. fo=1 is only meaningful alongside ruf= (RFC 9989
    # section 4.7); this migration path does not add ruf, so fo=1 is only
    # included when the current record already has it.
    _target_parts = ["v=DMARC1", "p=reject", "sp=reject", "np=reject"]
    if has_ruf:
        _target_parts.append("fo=1")
    _target_parts.append(f"rua={rua_placeholder}")
    target = "; ".join(_target_parts)

    return {
        "status": "migration",
        "steps": steps,
        "total_steps": len(steps),
        "target_record": target,
    }


# ============================================================
# Record Builder ("Fix It For Me")
# ============================================================

# Canonical tag order for generated records
_RECORD_TAG_ORDER = ["v", "p", "sp", "np", "adkim", "aspf", "fo", "psd", "t", "rua", "ruf"]


def _build_record_builder(
    tags: Dict[str, str],
    policy: str,
    health_status: str,
    record: Optional[str],
    config_warnings: List[Dict],
    domain: str = "",
) -> Dict:
    """Build the Record Builder payload.

    Returns a dict with current_record, recommended_record, changes list,
    deploy instructions, and edge-case flags.
    """
    has_record = bool(record and record.strip())

    # ── No existing record ─────────────────────────────────────
    if not has_record:
        safe_domain = domain or "yourdomain.com"
        # No fo=1 here: RFC 9989 section 4.7 requires a ruf= tag for fo to
        # have any effect, and this starter record does not add one.
        rec = f"v=DMARC1; p=none; rua=mailto:dmarc@{safe_domain}"
        return {
            "mode": "first_record",
            "current_record": None,
            "recommended_record": rec,
            "changes": [{
                "tag": "p", "action": "added", "value": "none",
                "reason": "Start with monitoring to review aggregate reports before enforcing.",
            }, {
                "tag": "rua", "action": "added", "value": f"mailto:dmarc@{safe_domain}",
                "reason": "Aggregate reporting address. Replace with your actual address.",
            }],
            "deploy": _deploy_instructions(domain, record),
        }

    # ── Already RFC 9989 Ready ─────────────────────────────────
    if health_status == "ready":
        suggestions = _ready_suggestions(tags)
        return {
            "mode": "ready",
            "current_record": record,
            "recommended_record": record,
            "changes": [],
            "suggestions": suggestions,
            "deploy": _deploy_instructions(domain, record),
        }

    # ── Build recommended record from current ──────────────────
    rec_tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            rec_tags[k.strip().lower()] = v.strip()

    changes: list = []

    # 1. Fix policy progression — target is p=reject for RFC 9989 Ready
    cur_p = rec_tags.get("p", "none").lower()
    if cur_p != "reject":
        rec_tags["p"] = "reject"
        if cur_p == "quarantine":
            reason = "Upgrade from quarantine to reject for full spoofing protection."
        else:
            reason = "Enforce reject to block spoofed mail. Use t=y if you need a testing period first."
        changes.append({
            "tag": "p", "action": "changed",
            "old": cur_p, "value": "reject",
            "reason": reason,
        })

    # 2. Fix sp
    cur_sp = rec_tags.get("sp", "").lower()
    target_p = rec_tags["p"]
    if cur_sp != target_p:
        old_val = cur_sp if cur_sp else "(not set)"
        rec_tags["sp"] = target_p
        changes.append({
            "tag": "sp", "action": "changed" if cur_sp else "added",
            "old": old_val, "value": target_p,
            "reason": "Closes subdomain policy gap. Matches root domain enforcement.",
        })

    # 3. Add np=
    if "np" not in rec_tags:
        rec_tags["np"] = target_p
        changes.append({
            "tag": "np", "action": "added", "value": target_p,
            "reason": "Protects non-existent subdomains from spoofing (new in RFC 9989).",
        })
    elif rec_tags.get("np", "").lower() == "none" and target_p == "reject":
        rec_tags["np"] = "reject"
        changes.append({
            "tag": "np", "action": "changed",
            "old": "none", "value": "reject",
            "reason": "Closes non-existent subdomain gap. Matches root policy.",
        })

    # 4. Fix fo. RFC 9989 section 4.7: "This tag's content MUST be ignored
    # if a ruf tag is not also specified." This builder does not add ruf,
    # so setting fo=1 only does something when the current record already
    # has ruf.
    if rec_tags.get("ruf"):
        cur_fo = rec_tags.get("fo", "")
        if cur_fo != "1":
            old_val = cur_fo if cur_fo else "(not set)"
            rec_tags["fo"] = "1"
            changes.append({
                "tag": "fo", "action": "changed" if cur_fo else "added",
                "old": old_val, "value": "1",
                "reason": "Reports when either SPF or DKIM fails, not just when both do.",
            })

    # 5. (removed) psd= is not injected. RFC 9989 section 4.7 makes it
    # OPTIONAL with a default of "u", and psd=n declares this exact name the
    # Organizational Domain: published on a subdomain it terminates the tree
    # walk there, changing relaxed-alignment scope and external rua
    # authorization.

    # 6. Remove deprecated tags
    for dep in ("pct", "rf", "ri"):
        if dep in rec_tags:
            dep_reasons = {
                "pct": "Removed in RFC 9989. Replaced by the t= tag.",
                "rf": "Deprecated in RFC 9989. Only afrf was ever implemented.",
                "ri": "Deprecated in RFC 9989. Receivers standardize on daily reports.",
            }
            changes.append({
                "tag": dep, "action": "removed",
                "old": rec_tags[dep], "value": None,
                "reason": dep_reasons[dep],
            })
            del rec_tags[dep]

    # 7. Remove t=y if present and policy is already reject
    if rec_tags.get("t") == "y" and rec_tags.get("p") == "reject":
        rec_tags.pop("t", None)
        changes.append({
            "tag": "t", "action": "removed",
            "old": "y", "value": None,
            "reason": "Test mode is no longer needed at full reject enforcement.",
        })

    # 8. (removed) The old rule rewrote every psd=y to psd=n without ever
    # testing whether the domain is a public suffix, so it told a registry
    # operator with a correct record to break it.

    # Assemble recommended record in canonical order
    rec_parts = []
    for tag_key in _RECORD_TAG_ORDER:
        if tag_key in rec_tags:
            rec_parts.append(f"{tag_key}={rec_tags[tag_key]}")
    # Include any remaining tags not in canonical order (preserve unknowns)
    for tag_key, val in rec_tags.items():
        if tag_key not in _RECORD_TAG_ORDER:
            rec_parts.append(f"{tag_key}={val}")

    recommended = "; ".join(rec_parts)

    return {
        "mode": "fix",
        "current_record": record,
        "recommended_record": recommended,
        "changes": changes,
        "deploy": _deploy_instructions(domain, record),
    }


def _ready_suggestions(tags: Dict[str, str]) -> List[Dict]:
    """Optional suggestions for already-ready records."""
    suggestions = []
    if "ruf" not in tags:
        suggestions.append({
            "tag": "ruf",
            "reason": "Consider adding failure reporting (ruf=) for per-message forensic data.",
        })
    return suggestions


def _deploy_instructions(domain: str, record: Optional[str]) -> Dict:
    """Build deployment instructions."""
    host = f"_dmarc.{domain}" if domain else "_dmarc.yourdomain.com"
    return {
        "host": host,
        "replace_existing": bool(record and record.strip()),
        "note_ttl": "Changes typically propagate within minutes, depending on your DNS provider's TTL.",
    }


# ============================================================
# SPF
# ============================================================

def _is_null_spf(record: str) -> bool:
    """Detect a null SPF record: v=spf1 -all with no senders.
    Only hardfail (-all) is an explicit declaration that the domain does not send email.
    Softfail (~all) is ambiguous and should not be treated as null SPF."""
    if not record:
        return False
    parts = record.strip().lower().split()
    if len(parts) == 2 and parts[0] == "v=spf1" and parts[1] == "-all":
        return True
    return False


def transform_spf(raw: Dict, has_mx: bool = True) -> Dict:
    # The apex TXT lookup never completed. "No SPF record published" would
    # be a claim about the domain that this audit did not establish.
    if raw.get("status") == "unavailable":
        return _lookup_unavailable_card("SPF", raw, "SPF record")

    # More than one v=spf1 record at the name. RFC 7208 section 4.5 makes that a
    # PermError for the whole evaluation. The record field is empty on this path
    # because there is no single record to show, and the branches below read an
    # empty record as absence, so this has to be handled before them.
    _multiple = raw.get("multiple_records")
    if _multiple:
        _n = len(_multiple)
        _details = [
            {"type": "error", "text": f"{_n} v=spf1 records published at this domain"},
        ]
        for _rec in _multiple:
            _details.append({"type": "info", "text": _rec})
        for _issue in raw.get("issues", []):
            _details.append(_issue_to_detail(_issue))
        return {
            "name": "SPF",
            "status": "fail",
            "pill_label": "Multiple records",
            "verdict": f"{_n} SPF records published (RFC 7208 requires exactly one)",
            "record": None,
            "configured": True,
            "explanation": (
                f"This domain publishes <strong>{_n}</strong> separate v=spf1 records. "
                "<a href=\"https://datatracker.ietf.org/doc/html/rfc7208\" target=\"_blank\" rel=\"noopener\">RFC 7208</a> "
                "section 4.5 requires exactly one, and a receiver that finds more than one "
                "returns PermError and evaluates neither. The effect is the same as having "
                "no SPF record at all, except that it is harder to spot: the records are "
                "published and look correct in isolation."
            ),
            "details": _details,
            "fix": (
                "Merge these into a single v=spf1 record. Combine every authorized IP "
                "address and include into one record, keep one <strong>all</strong> "
                "mechanism at the end, and delete the others. Watch the 10-lookup limit "
                "while merging."
            ),
            "fix_records": None,
            "deliverability": (
                "Every message from this domain currently fails SPF with a PermError, so "
                "SPF cannot contribute to DMARC alignment. Expect spam folder placement at "
                "receivers that weight SPF, until the records are merged."
            ),
        }

    status = _map_status(raw.get("status", "error"))
    record = raw.get("record")
    pill_label = None
    null_spf = _is_null_spf(record)

    # Verdict
    if null_spf:
        verdict = "Null SPF (domain does not send email)"
        pill_label = "No mail"
    elif not record and not has_mx:
        verdict = "No SPF record (no mail)"
        pill_label = "No mail"
    elif not record:
        verdict = "No SPF record published"
        pill_label = "Missing"
    else:
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)
        if all_mech == "+all":
            verdict = "Authorizes the entire internet to send as you"
        elif lookups > 10:
            verdict = f"SPF is invalid ({lookups}/10 lookups). Fails at most receivers."
        elif not all_mech and raw.get("has_redirect"):
            verdict = "SPF configured (via redirect)"
        elif not all_mech:
            verdict = "Configured but missing an all mechanism"
        else:
            verdict = "SPF record configured"

    # Explanation
    if null_spf:
        all_mech = raw.get("all_mechanism") or ""
        explanation = (
            f"This domain publishes a null SPF record (<strong>v=spf1 {_e(all_mech)}</strong>), "
            f"which explicitly declares that no servers are authorized to send email for this domain. "
            f"This is correct configuration for domains that do not send email."
        )
    elif not record and not has_mx:
        explanation = (
            "No SPF record found, but this domain also has no MX records, "
            "which means it does not send or receive email. "
            "For best practice, consider publishing a null SPF record "
            "(<strong>v=spf1 -all</strong>) to explicitly signal that this domain does not send email."
        )
    elif not record:
        explanation = (
            "No SPF record found. SPF (<a href=\"https://datatracker.ietf.org/doc/html/rfc7208\" target=\"_blank\" rel=\"noopener\">RFC 7208</a>) specifies which IP addresses are authorized "
            "to send email for your domain. Without it, receiving servers cannot use SPF to "
            "validate whether a message originated from your mail infrastructure."
        )
    else:
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)

        if all_mech == "-all":
            explanation = (
                "SPF record ends with <strong>-all</strong> (hardfail), declaring that servers "
                "not listed in this record are not authorized to send mail for your domain. "
                "SPF results feed into DMARC alignment evaluation; enforcement decisions "
                "are made at the DMARC policy layer, not by SPF alone."
            )
        elif all_mech == "~all":
            explanation = (
                "SPF record ends with <strong>~all</strong> (softfail), indicating that servers "
                "not listed in this record are not authorized but should not be outright rejected. "
                "Like -all, the SPF result feeds into DMARC alignment evaluation; "
                "enforcement decisions are made at the DMARC policy layer."
            )
        elif all_mech == "?all":
            explanation = (
                "SPF record uses <strong>?all</strong> (neutral). Per <a href=\"https://datatracker.ietf.org/doc/html/rfc7208\" target=\"_blank\" rel=\"noopener\">RFC 7208</a>, this means the domain "
                "makes no assertion about unlisted servers. A neutral result is not an SPF pass. "
                "Only an SPF pass can satisfy DMARC's SPF alignment requirement."
            )
        elif all_mech == "+all":
            explanation = (
                "<strong>WARNING:</strong> SPF record uses <strong>+all</strong>, which authorizes "
                "the entire internet to send email as your domain. This is almost certainly a misconfiguration."
            )
        elif not all_mech and raw.get("has_redirect"):
            explanation = (
                "SPF record uses a <strong>redirect</strong> modifier instead of an explicit "
                "<strong>all</strong> mechanism. The SPF evaluation is delegated to another domain's record."
            )
        elif not all_mech:
            explanation = (
                "SPF record is missing an <strong>all</strong> mechanism. Per <a href=\"https://datatracker.ietf.org/doc/html/rfc7208\" target=\"_blank\" rel=\"noopener\">RFC 7208</a> Section 4.7, "
                "if processing reaches the end of the record without a match, the result is neutral. "
                "This means unlisted servers produce no SPF pass and cannot contribute to DMARC alignment."
            )
        else:
            explanation = "SPF record found."

        if lookups and lookups > 10:
            explanation += (
                f" <strong>Critical:</strong> This SPF record has a PermError because it requires "
                f"{lookups} DNS lookups, exceeding the 10-lookup limit "
                f"(<a href=\"https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4\" target=\"_blank\" rel=\"noopener\">RFC 7208 Section 4.6.4</a>). "
                f"Receivers must return PermError once the limit is exceeded "
                f"(RFC 7208 section 4.6.4). A PermError is not a pass, so SPF cannot "
                f"satisfy DMARC alignment for any message from this domain. Audit your "
                f"includes and remove services you no longer use."
            )
        elif lookups and lookups > 8:
            explanation += (
                f" <strong>Note:</strong> SPF uses {lookups} of the allowed 10 DNS lookups "
                f"(<a href=\"https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4\" target=\"_blank\" rel=\"noopener\">RFC 7208 Section 4.6.4</a>). "
                f"{'At the limit. Any addition will cause a PermError.' if lookups == 10 else 'Approaching the limit. Plan for headroom before adding new services.'}"
            )

    # Details
    details = []
    if null_spf:
        all_mech = raw.get("all_mechanism") or ""
        details.append({"type": "good", "text": f"Null SPF record (v=spf1 {_e(all_mech)})"})
        details.append({"type": "good", "text": "Explicitly declares this domain does not send email"})
        status = "pass"
    elif not record and not has_mx:
        details.append({"type": "info", "text": "No SPF record and no MX records"})
        details.append({"type": "info", "text": "This domain does not appear to send or receive email"})
        status = "warn"
    elif not record:
        # No SPF record but domain has MX (sends/receives mail) -- critical failure
        status = "fail"
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))
    elif record:
        lookups = raw.get("lookup_count", 0)
        if lookups <= 8:
            details.append({"type": "good", "text": f"{lookups} DNS lookups (well within the 10-lookup limit)"})
        elif lookups <= 10:
            details.append({"type": "warning", "text": f"{lookups} DNS lookups ({'at' if lookups == 10 else 'near'} the 10-lookup limit)"})
        else:
            details.append({"type": "error", "text": f"{lookups} DNS lookups. SPF is invalid and will fail at most receivers (PermError)."})

        all_mech = raw.get("all_mechanism") or ""
        if all_mech == "-all":
            details.append({"type": "good", "text": "-all (hardfail): declares no other servers are authorized"})
        elif all_mech == "~all":
            details.append({"type": "good", "text": "~all (softfail): unlisted servers are not authorized"})
        elif all_mech == "?all":
            details.append({"type": "warning", "text": "Neutral (?all) provides no protection"})
        elif all_mech == "+all":
            details.append({"type": "error", "text": "+all authorizes ALL senders (misconfiguration!)"})

        includes = raw.get("include_count", 0)
        if includes:
            details.append({"type": "info", "text": f"{includes} include mechanism{'s' if includes != 1 else ''}"})

        ip4_count = raw.get("ip4_count", 0)
        ip6_count = raw.get("ip6_count", 0)
        if ip4_count or ip6_count:
            parts = []
            if ip4_count:
                parts.append(f"{ip4_count} IPv4")
            if ip6_count:
                parts.append(f"{ip6_count} IPv6")
            details.append({"type": "info", "text": f"Direct IP authorization: {', '.join(parts)}"})

        # Append all issues from the audit engine (syntax_errors already merged into issues)
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))
    else:
        for issue in raw.get("issues", []):
            details.append(_issue_to_detail(issue))

    # Override status based on critical SPF issues
    if record and not null_spf:
        all_mech = raw.get("all_mechanism") or ""
        lookups = raw.get("lookup_count", 0)
        has_engine_errors = any(
            i.get("severity") == "error" for i in raw.get("issues", [])
        )
        if all_mech == "+all":
            status = "fail"
        elif lookups and lookups > 10:
            status = "fail"
        elif has_engine_errors:
            status = "fail"
        elif raw.get("spf_indeterminate"):
            # At least one lookup in the chain never answered, so the lookup
            # count is a floor rather than a total. Do not certify the record.
            status = "warn"
        elif all_mech in ("-all", "~all") and lookups <= 10 and not has_engine_errors:
            # Lenient parser recovered a valid record with a proper all mechanism
            # and within lookup limits.  Syntax warnings (e.g. missing spaces)
            # should not downgrade the card to "warn" -- show "pass" with the
            # warning details visible in the card body.
            status = "pass"

    # Fix
    fix = None
    if null_spf:
        # Null SPF is correct, no fix needed
        pass
    elif not record and not has_mx:
        fix = (
            "Publish a null SPF record (<strong>v=spf1 -all</strong>) to explicitly declare "
            "that no IP addresses are authorized to send email for this domain."
        )
    elif not record:
        fix = (
            "Publish an SPF TXT record listing the IP addresses and services authorized to send "
            "email for your domain. Requires identifying all legitimate senders (mail server, ESP, "
            "marketing platforms) and staying within the 10 DNS lookup limit."
        )
    else:
        fix = _first_fix(raw.get("issues", []))
        if not fix and record:
            all_mech = raw.get("all_mechanism") or ""
            lookups = raw.get("lookup_count", 0)
            if all_mech in ("?all", "+all") and lookups and lookups > 10:
                fix = (
                    "Change the all mechanism to <strong>-all</strong> (hardfail) or <strong>~all</strong> (softfail). "
                    "Also reduce SPF lookups to 10 or fewer by removing includes for services you no longer use "
                    "or consolidating senders."
                )
            elif all_mech in ("?all", "+all"):
                fix = "Change the all mechanism to <strong>-all</strong> (hardfail) or <strong>~all</strong> (softfail)."
            elif lookups and lookups > 10:
                fix = (
                    "Your SPF record has a PermError and is not functional. Reduce to 10 or fewer "
                    "DNS lookups by auditing your includes: remove services you no longer use, "
                    "consolidate senders where possible, and verify each include is still needed."
                )

    # Fix records -- copy-paste DNS records for missing records only
    # SPF mechanism changes (+all -> ~all) are excluded because they require
    # verifying all legitimate senders first.
    fix_records = []
    domain_name = raw.get("domain", "")
    if null_spf:
        pass
    elif not record and not has_mx:
        fix_records.append({
            "type": "TXT",
            "host": domain_name,
            "value": "v=spf1 -all",
            "comment": "Null SPF: declares this domain does not send email",
        })
    # No copy-paste for starter SPF -- user must identify their authorized senders first

    # Deliverability context
    _deliverability = None
    if null_spf or (not record and not has_mx):
        pass  # No deliverability concern for non-mail domains
    elif not record:
        _deliverability = (
            "Without SPF, receivers cannot verify that your email server is authorized "
            "to send for your domain. This is one of the most common causes of emails "
            "landing in spam. Every major email provider checks SPF."
        )
    elif record:
        _lookups = raw.get("lookup_count", 0)
        _all = raw.get("all_mechanism", "")
        if _all == "+all":
            _deliverability = (
                "DANGER: +all authorizes the entire internet to send email as your domain. "
                "This effectively disables SPF and will severely damage your deliverability. "
                "Fix this immediately."
            )
        elif _lookups and _lookups > 10:
            _deliverability = (
                f"Your SPF record requires {_lookups} DNS lookups, exceeding the 10-lookup limit. "
                f"This means SPF fails completely for all your email, which can cause messages "
                f"to bounce or go to spam. Every email platform you add (Mailchimp, Salesforce, "
                f"HubSpot, SendGrid) consumes lookups. Audit your includes: remove "
                f"services you no longer use and consolidate senders where possible."
            )
        elif _lookups and _lookups > 8:
            _deliverability = (
                f"Your SPF record uses {_lookups} of 10 allowed DNS lookups. "
                f"{'You are at the limit. Adding one more email service will break SPF for all your email.' if _lookups == 10 else 'You are close to the limit. Plan carefully before adding new sending services like Mailchimp, HubSpot, or SendGrid.'}"
            )
        elif _all == "~all":
            _deliverability = (
                "Softfail (~all) means unauthorized servers are flagged but not blocked. "
                "This is fine during setup, but for production email, consider -all (hard fail) "
                "once you have confirmed all legitimate senders are included."
            )

    return {
        "name": "SPF",
        "status": status,
        "pill_label": pill_label if not record else None,
        "verdict": verdict,
        "record": record,
        "configured": bool(record),
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": fix_records if fix_records else None,
        "spf_deep": _build_spf_deep_analysis(raw) if record else None,
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": _deliverability,
    }


# ============================================================
# SPF Deep Analysis (Prompt 7)
# ============================================================

_SPF_PROVIDER_MAP = {
    "_spf.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "servers.mcsv.net": "Mailchimp",
    "_spf.salesforce.com": "Salesforce",
    "mail.zendesk.com": "Zendesk",
    "spf.mandrillapp.com": "Mandrill",
    "_spf.firebasemail.com": "Firebase",
    "spf.messagelabs.com": "Symantec/Broadcom",
    "_spf.intuit.com": "Intuit",
    "hubspot.com": "HubSpot",
    "aspmx.pardot.com": "Pardot/Salesforce",
    "_spf.protonmail.ch": "ProtonMail",
    "spf.constantcontact.com": "Constant Contact",
    "_netblocks.mimecast.com": "Mimecast",
    "pphosted.com": "Proofpoint",
    "_spf.mx.cloudflare.net": "Cloudflare",
    "zoho.com": "Zoho",
    "mktomail.com": "Marketo",
    "outbound.mailhop.org": "DuoCircle",
    "spf.brevo.com": "Brevo",
    "secureserver.net": "GoDaddy",
    "spf.mailkit.eu": "Omnivery/Mailkit",
    "mailkit.eu": "Omnivery/Mailkit",
    "omnivery.com": "Omnivery",
}

_ALL_EXPLANATIONS = {
    "~all": (
        "Unauthorized servers are flagged but mail is delivered. Under DMARC, the SPF result "
        "feeds into alignment evaluation. The DMARC policy determines actual enforcement."
    ),
    "-all": "Unauthorized servers are explicitly rejected. Strongest SPF enforcement.",
    "+all": (
        "This authorizes EVERY server on the internet to send as your domain. "
        "SPF provides zero protection. This is a critical misconfiguration."
    ),
    "?all": "No assertion about unauthorized servers. Provides no protection on its own.",
}


def _build_spf_deep_analysis(raw: Dict) -> Optional[Dict]:
    """Build deep SPF analysis: mechanism breakdown, provider mapping, misconfigs, optimization."""
    record = raw.get("record")
    if not record:
        return None


    parts = record.strip().split()
    mechanisms = []
    all_mechanism = None
    lookups = raw.get("lookup_count", 0)
    has_ptr = False

    for part in parts:
        if part.lower() == "v=spf1":
            continue

        # Determine type and lookup cost
        p_lower = part.lower()
        cost = 0
        mech_type = "unknown"
        provider = None
        value = part

        if p_lower.startswith("include:"):
            mech_type = "include"
            cost = 1
            domain = part.split(":", 1)[1] if ":" in part else ""
            value = domain
            # Provider lookup
            for pattern, name in _SPF_PROVIDER_MAP.items():
                if pattern in domain.lower():
                    provider = name
                    break
            if not provider:
                provider = "Unknown service"
        elif p_lower.startswith("ip4:"):
            mech_type = "ip4"
            value = part.split(":", 1)[1] if ":" in part else ""
        elif p_lower.startswith("ip6:"):
            mech_type = "ip6"
            value = part.split(":", 1)[1] if ":" in part else ""
        elif p_lower.startswith("redirect="):
            mech_type = "redirect"
            cost = 1
            value = part.split("=", 1)[1] if "=" in part else ""
        elif p_lower.startswith("exists:"):
            mech_type = "exists"
            cost = 1
            value = part.split(":", 1)[1] if ":" in part else ""
        elif p_lower in ("a", "+a") or p_lower.startswith("a:") or p_lower.startswith("a/"):
            mech_type = "a"
            cost = 1
        elif p_lower in ("mx", "+mx") or p_lower.startswith("mx:") or p_lower.startswith("mx/"):
            mech_type = "mx"
            cost = 1
        elif p_lower.startswith("ptr") or p_lower == "ptr":
            mech_type = "ptr"
            cost = 1
            has_ptr = True
        elif p_lower in ("-all", "~all", "+all", "?all"):
            all_mechanism = part
            continue
        else:
            mech_type = "other"

        mechanisms.append({
            "raw": part,
            "type": mech_type,
            "value": value,
            "cost": cost,
            "provider": provider,
        })

    # All-mechanism analysis
    all_explanation = ""
    all_severity = "info"
    if all_mechanism:
        all_explanation = _ALL_EXPLANATIONS.get(all_mechanism.lower(),
                                                 f"Unknown all mechanism: {all_mechanism}")
        if all_mechanism.lower() == "+all":
            all_severity = "critical"
    else:
        all_explanation = ("No all mechanism found. Implicit default is ?all (neutral). "
                          "SPF makes no assertion about unauthorized senders.")
        all_severity = "warning"

    # Misconfigurations
    misconfigs = []

    if has_ptr:
        misconfigs.append({
            "level": "warning",
            "title": "Deprecated ptr mechanism",
            "text": "The ptr mechanism is deprecated in RFC 7208. Slow, unreliable, stresses DNS infrastructure. Replace with explicit ip4: or ip6: mechanisms.",
        })

    if all_mechanism and all_mechanism.lower() == "+all":
        misconfigs.append({
            "level": "critical",
            "title": "Open SPF (+all)",
            "text": "This authorizes EVERY server on the internet to send as your domain. SPF provides zero protection.",
        })

    # Check for broad IP ranges
    for mech in mechanisms:
        if mech["type"] in ("ip4", "ip6") and "/" in mech["value"]:
            cidr = mech["value"].split("/")[-1]
            try:
                prefix = int(cidr)
                if mech["type"] == "ip4" and prefix < 16:
                    hosts = 2 ** (32 - prefix)
                    misconfigs.append({
                        "level": "warning",
                        "title": f"Broad IP range: {mech['value']}",
                        "text": f"This range authorizes {hosts:,} addresses. Verify this is intentional.",
                    })
                elif mech["type"] == "ip6" and prefix < 48:
                    misconfigs.append({
                        "level": "warning",
                        "title": f"Broad IPv6 range: {mech['value']}",
                        "text": "This range is very broad. Verify this is intentional.",
                    })
            except ValueError:
                pass

    # Record length
    if len(record) > 450:
        misconfigs.append({
            "level": "info",
            "title": "Long SPF record",
            "text": f"Record is {len(record)} characters. Long records may cause issues with DNS UDP packet size limits.",
        })

    # Optimization suggestions
    optimizations = []
    if lookups >= 8:
        optimizations.append(
            f"Your SPF record uses {lookups} of 10 allowed lookups. Audit your includes: "
            f"remove services you no longer use and consolidate senders where possible."
        )

    return {
        "mechanisms": mechanisms,
        "all_mechanism": all_mechanism,
        "all_explanation": all_explanation,
        "all_severity": all_severity,
        "lookup_count": lookups,
        "misconfigs": misconfigs,
        "optimizations": optimizations,
        "dmarcbis_note": (
            "Under RFC 9989, SPF alignment is evaluated against the MAIL FROM (envelope sender) "
            "identity only, not HELO. SPF pass alone does not guarantee DMARC pass. The MAIL FROM "
            "domain must also align with the From header domain."
        ),
    }


# ============================================================
# DKIM
# ============================================================

# ------------------------------------------------------------
# DKIM: three outcomes, deliberately kept apart
# ------------------------------------------------------------
#
# RFC 6376 section 3.6.1: "An empty value means that this public key has been
# revoked." That is how a key is retired, not how one breaks. The record is
# left in place on purpose so a receiver meeting a delayed or replayed message
# gets an explicit revocation rather than a missing record, and grading it as a
# failure of the domain tells an operator to fix something they did correctly.
#
# Nothing found is a separate state again. DNS offers no way to enumerate the
# names under _domainkey; a selector is chosen by the sending service and is
# learned from the s= tag of a signed message. A probe that finds no live key
# has established only that the names it guessed did not resolve, so this card
# reports what it could not confirm rather than asserting an absence.

_DKIM_NOT_ENUMERABLE = (
    "DKIM selectors cannot be enumerated from DNS: the name is chosen by the "
    "sending service, so a probe can only look up names it already guessed."
)

# The two things that actually settle it, in the order a reader can act on them.
_DKIM_HOW_TO_SETTLE = (
    {
        "type": "info",
        "text": "Enter your selector in the field above for a direct lookup",
    },
    {
        "type": "info",
        "text": (
            "The selector is the s= value in the DKIM-Signature or "
            "Authentication-Results header of any message this domain sent"
        ),
    },
)


def _split_dkim_selectors(found: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Split discovered selectors into live keys and revoked (empty p=) ones.

    Called before anything counts or grades keys, so "3 selectors found"
    cannot turn out to mean three retired ones.
    """
    live, revoked = [], []
    for sel in found or []:
        analysis = analyze_dkim_key_strength(sel.get("record", "") or "")
        (revoked if analysis.get("reason") == "revoked" else live).append(sel)
    return live, revoked


def _dkim_retired_detail(selectors: List[Dict], business_risk) -> List[Dict]:
    """One info line per retired selector, with the revocation callout once.

    Info rather than error: the callout distinguishes a revocation from an
    undecodable key, which is a different problem with different advice.
    """
    details = []
    for i, sel in enumerate(selectors):
        detail = {
            "type": "info",
            "text": (
                f"{sel.get('selector', 'unknown')}: retired key "
                f"(empty p=, revoked per RFC 6376 section 3.6.1)"
            ),
        }
        if i == 0 and business_risk:
            detail["business_risk"] = business_risk
        details.append(detail)
    return details


def transform_dkim(raw: Dict, domain: str, has_mx: bool = True, non_mail: bool = False) -> Dict:
    """Only a positive non-mail declaration (RFC 7505 null MX, or a null ``v=spf1 -all`` SPF record) waives this check. Absent MX alone does not: send-only subdomains have no MX and still send real mail.

    Grades a live key. Reports retired keys as correctly retired. Reports
    finding nothing as not confirmed rather than as absent. See the comment
    above _DKIM_NOT_ENUMERABLE for why the last two are not the same state.
    """
    # Lazy import avoids the audit_engine ↔ result_transformer cycle.
    from audit_engine import BUSINESS_RISK

    # The selector lookup never completed. "Selector 'x' not found. Verify the
    # selector name is correct." would be advice about a name the audit could
    # not read, and it sends the operator to check a setting that is fine.
    if raw.get("status") == "unavailable":
        return _lookup_unavailable_card("DKIM", raw, "DKIM public key")

    found = raw.get("found_selectors", [])
    tested = raw.get("tested_count", 0)
    # tested_count is 1 whenever the user supplied a selector, and that name
    # was the one they typed, not a "common" one this audit guessed.
    _sel_count = f"{tested} selector" + ("" if tested == 1 else "s")
    _user_supplied = bool(raw.get("selector_queried"))
    _common = "" if _user_supplied else "common "
    live, revoked = _split_dkim_selectors(found)

    if not live:
        # No live key. Only a positive non-mail declaration (null MX or null
        # SPF) makes that expected. Absent MX alone is not one.
        if non_mail:
            return {
                "name": "DKIM",
                "status": "pass",
                "pill_label": "N/A",
                "verdict": "Not applicable (non-mail domain)",
                "record": None,
                "configured": False,
                "explanation": (
                    "This domain declares that it does not send email (RFC 7505 null MX "
                    "or a null SPF record). DKIM signing is not applicable."
                ),
                "details": [
                    {"type": "info", "text": "Null MX or null SPF published - domain declares it does not handle email"},
                    {"type": "info", "text": "DKIM is only relevant for domains that send email"},
                ],
                "fix": None,
                "fix_records": None,
                "deliverability": None,
            }

        # User provided a specific selector that wasn't found. The operator
        # asserted that name, so an empty answer at it is a finding about the
        # name rather than the unconfirmed state below.
        selector_not_found = raw.get("selector_not_found")
        if selector_not_found:
            _details = [
                {
                    "type": "error",
                    "text": f"No TXT record at {_e(selector_not_found)}._domainkey.{_e(domain)}",
                    "business_risk": BUSINESS_RISK.get("DKIM_SELECTOR_NOT_FOUND"),
                },
                {"type": "info", "text": "Check your email provider's admin console for the correct selector name"},
            ]
            for issue in raw.get("issues", []):
                _details.append(_issue_to_detail(issue))
            return {
                "name": "DKIM",
                "status": "fail",
                "pill_label": "Not found",
                "verdict": f"Selector '{selector_not_found}' not found",
                "record": None,
                "configured": False,
                "explanation": (
                    f"No DKIM public key was found at "
                    f"<strong>{_e(selector_not_found)}._domainkey.{_e(domain)}</strong>. "
                    f"Verify the selector name is correct. You can find your DKIM "
                    f"selector in the DKIM-Signature header of a sent message (the s= value)."
                ),
                "details": _details,
                "fix": (
                    f"Verify that DKIM is enabled in your email provider's settings and that the public key "
                    f"TXT record is published at <strong>{_e(selector_not_found)}._domainkey.{_e(domain)}</strong>."
                ),
                "fix_records": None,
                "deliverability": None,
            }

        # The operator named a selector and it resolved, revoked. Nothing was
        # probed and nothing was guessed, so the hedging below would be false
        # in both directions: this audit did settle the question for the name
        # it was given, and the answer is that the key is gone. The record is
        # still correctly published, so this is not a fail; the finding is the
        # gap between what the operator asserted and what is live.
        _queried = raw.get("selector_queried")
        if revoked and _queried:
            _sel = revoked[0].get("selector", _queried)
            _q_details = _dkim_retired_detail(revoked, BUSINESS_RISK.get("DKIM_REVOKED_KEY"))
            _q_details.append({
                "type": "warning",
                "text": (
                    f"Any message signed with s={_sel} fails DKIM at every receiver, "
                    "because there is no key to verify it against"
                ),
            })
            _q_details.append(dict(_DKIM_HOW_TO_SETTLE[1]))
            for issue in raw.get("issues", []):
                _q_details.append(_issue_to_detail(issue))
            return {
                "name": "DKIM",
                "status": "warn",
                "pill_label": "Retired",
                "verdict": f"Selector '{_sel}' is published but retired",
                "record": None,
                "configured": True,
                "explanation": (
                    f"<strong>{_e(_sel)}._domainkey.{_e(domain)}</strong> exists and "
                    "publishes an empty <strong>p=</strong>, which per "
                    "<a href=\"https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1\" "
                    "target=\"_blank\" rel=\"noopener\">RFC 6376 section 3.6.1</a> means the "
                    "key has been revoked. Publishing the record this way is the correct "
                    "way to retire a key, so nothing is misconfigured in DNS. It does mean "
                    "this selector signs nothing. If your mail server still signs with it, "
                    "those signatures fail everywhere."
                ),
                "details": _q_details,
                "fix": (
                    f"Check which selector your mail server actually signs with, using the "
                    f"s= value in the DKIM-Signature header of a message you sent. If it is "
                    f"still <strong>{_e(_sel)}</strong>, the key was revoked and needs to be "
                    f"republished or the server pointed at the live selector. If it is a "
                    f"different name, re-run this audit with that name."
                ),
                "fix_records": None,
                "dkim_deep": _build_dkim_key_analysis(raw),
                "deliverability": None,
            }

        # Outcome B: retired keys and nothing live. Neither a pass nor a
        # finding, so it drops out of the pass/warn/fail tallies rather than
        # padding one of them with something the domain did right.
        if revoked:
            _n = len(revoked)
            _plural = "s" if _n != 1 else ""
            _names = _join_names([s.get("selector", "unknown") for s in revoked])
            _retired_details = _dkim_retired_detail(revoked, BUSINESS_RISK.get("DKIM_REVOKED_KEY"))
            _retired_details.append(
                {"type": "info", "text": f"Checked {_sel_count}, no live public key found"}
            )
            _retired_details.append({"type": "info", "text": _DKIM_NOT_ENUMERABLE})
            # Surfaced here as well as in the graded outcome. Discovery cut
            # short by its own deadline searched fewer names than it meant to,
            # and "no live key found" reads differently when the sweep did not
            # finish. The resilience section says so; this card said nothing.
            if raw.get("timeout_note"):
                _retired_details.append({"type": "warning", "text": raw["timeout_note"]})
            _retired_details.extend(dict(d) for d in _DKIM_HOW_TO_SETTLE)
            for issue in raw.get("issues", []):
                _retired_details.append(_issue_to_detail(issue))
            return {
                "name": "DKIM",
                "status": "unavailable",
                "pill_label": "Not confirmed",
                "verdict": (
                    f"{_n} retired selector{_plural} published, no live key found by probing"
                ),
                "record": None,
                "configured": True,
                "explanation": (
                    f"This domain publishes <strong>{_n}</strong> DKIM selector{_plural} "
                    f"({_e(_names)}) whose <strong>p=</strong> tag is empty. Per "
                    "<a href=\"https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1\" "
                    "target=\"_blank\" rel=\"noopener\">RFC 6376 section 3.6.1</a> an empty "
                    "p= means the key has been revoked, and this is how a retired key is "
                    "meant to look: the record stays published so a receiver meeting a "
                    "delayed or replayed message gets an explicit revocation instead of a "
                    "missing record. Nothing here is misconfigured. This audit found no "
                    "live key, but DKIM selectors cannot be enumerated from DNS, so it "
                    "cannot say whether this domain signs mail under a selector it did "
                    "not guess."
                ),
                "details": _retired_details,
                "fix": None,
                "fix_records": None,
                "unavailable_kind": "not_enumerable",
                "dkim_deep": _build_dkim_key_analysis(raw),
                "deliverability": None,
            }

        # Outcome C: nothing found. Same reasoning, without the retired keys.
        #
        # A truncated probe (the discovery deadline hit mid-sweep, usually
        # DKIM worker starvation under concurrent audits, not slow DNS) is not
        # the same as a completed sweep that found nothing: selectors the
        # probe never reached might still hold a key. The same domain audited
        # alone can find that key; audited alongside seven others it gets
        # this card instead, and the card must say why rather than reading
        # like a considered "nothing here".
        discovery_truncated = bool(raw.get("timed_out"))
        _unknown_details = [
            {
                "type": "warning" if discovery_truncated else "info",
                "text": (
                    f"Selector discovery did not finish: checked {_sel_count} "
                    "before running out of time"
                ) if discovery_truncated else (
                    f"Checked {tested} {_common}selector{'' if tested == 1 else 's'}, "
                    "no public key found"
                ),
            },
            {"type": "info", "text": _DKIM_NOT_ENUMERABLE},
        ]
        _unknown_details.extend(dict(d) for d in _DKIM_HOW_TO_SETTLE)
        for issue in raw.get("issues", []):
            _unknown_details.append(_issue_to_detail(issue))
        if discovery_truncated:
            explanation = (
                "DKIM (<a href=\"https://datatracker.ietf.org/doc/html/rfc6376\" "
                "target=\"_blank\" rel=\"noopener\">RFC 6376</a>) attaches a "
                "cryptographic signature to each outgoing message, letting receivers "
                "verify that it was not altered and came from an authorized sender. "
                f"This audit's selector probe ran out of time after checking {_sel_count}, "
                "so this is an incomplete search, not a completed one that "
                "found nothing. A re-run, especially at a quieter time, may reach a "
                "selector this one did not. Two things settle it directly: enter the "
                "selector above for a direct lookup, or read the s= value from the "
                "DKIM-Signature or Authentication-Results header of a message this "
                "domain sent."
            )
        else:
            _looked_up = (
                "This audit looked up the selector you supplied and found no public "
                "key at it. "
            ) if _user_supplied else (
                f"This audit looked up {tested} common selector "
                f"name{'' if tested == 1 else 's'} and found no public key at "
                f"{'it' if tested == 1 else 'any of them'}. "
            )
            explanation = (
                "DKIM (<a href=\"https://datatracker.ietf.org/doc/html/rfc6376\" "
                "target=\"_blank\" rel=\"noopener\">RFC 6376</a>) attaches a "
                "cryptographic signature to each outgoing message, letting receivers "
                "verify that it was not altered and came from an authorized sender. "
                + _looked_up +
                "That is not the same as this domain having "
                "no DKIM: the name is chosen by the sending service and cannot be "
                "enumerated from DNS, so nothing here says whether the domain signs "
                "its mail. Two things settle it: enter the selector above for a direct "
                "lookup, or read the s= value from the DKIM-Signature or "
                "Authentication-Results header of a message this domain sent."
            )
        return {
            "name": "DKIM",
            "status": "unavailable",
            "pill_label": "Not confirmed",
            "verdict": (
                "DKIM discovery did not finish" if discovery_truncated
                else "DKIM could not be confirmed by probing"
            ),
            "record": None,
            "configured": False,
            "explanation": explanation,
            "details": _unknown_details,
            "fix": None,
            "fix_records": None,
            "unavailable_kind": "not_enumerable",
            "deliverability": None,
        }

    # Outcome A: at least one live key. Graded on the live keys; retired ones
    # are listed for the reader and count toward nothing.
    details = []
    vendor_names = set()
    weak_keys = []
    # Every key that failed to yield a size, whatever the reason. The three
    # reasons are distinguished in the detail line and the callout below.
    invalid_keys = []
    risks_called_out = set()
    for sel in found:
        selector = sel.get("selector", "unknown")
        sel_record = sel.get("record", "")
        vendor = sel.get("vendor")
        key_type = sel.get("key_type", "")

        # Analyze key strength
        key_analysis = analyze_dkim_key_strength(sel_record)
        bits = key_analysis.get("key_bits", 0)
        strength = key_analysis.get("status", "unknown")

        vendor_str = f" ({vendor})" if vendor else ""
        if vendor:
            vendor_names.add(vendor)

        # A revoked selector alongside a live one is a key that was rotated
        # away from, which is the rotation advice working, not a defect.
        if key_analysis.get("reason") == "revoked":
            details.extend(
                _dkim_retired_detail(
                    [sel],
                    BUSINESS_RISK.get("DKIM_REVOKED_KEY")
                    if "DKIM_REVOKED_KEY" not in risks_called_out else None,
                )
            )
            risks_called_out.add("DKIM_REVOKED_KEY")
            continue

        if strength == "invalid":
            invalid_detail = {
                "type": "error",
                "text": f"{selector}: {key_analysis.get('warning') or 'invalid key'}{vendor_str}",
            }
            # "invalid" covers two remaining conditions and neither is a
            # revocation. Attaching one callout to both put "the key does not
            # parse" next to a record that publishes no key at all, and the
            # reader had no way to tell which had happened.
            risk_key = {
                "undecodable": "DKIM_UNDECODABLE_KEY",
                "no_key": "DKIM_NO_KEY",
            }.get(key_analysis.get("reason"))
            # One callout per distinct condition, not one per selector: two
            # undecodable keys do not need the same paragraph twice, but an
            # undecodable key and an empty record are different problems.
            if risk_key and risk_key not in risks_called_out:
                invalid_detail["business_risk"] = BUSINESS_RISK.get(risk_key)
                risks_called_out.add(risk_key)
            details.append(invalid_detail)
            invalid_keys.append(selector)
        elif strength == "weak":
            weak_detail = {
                "type": "warning",
                "text": f"{selector}: {bits}-bit {key_analysis.get('key_type', 'RSA')} key{vendor_str} - upgrade recommended",
            }
            # Only attach business_risk to the first weak-key detail to avoid
            # repeating the same callout once per selector.
            if not weak_keys:
                weak_detail["business_risk"] = BUSINESS_RISK.get("DKIM_WEAK_KEY")
            details.append(weak_detail)
            weak_keys.append((selector, bits))
        elif strength == "strong":
            details.append({
                "type": "good",
                "text": f"{selector}: {bits}-bit {key_analysis.get('key_type', 'RSA')} key{vendor_str}"
            })
        else:
            details.append({
                "type": "info",
                "text": f"{selector}: key found{vendor_str}"
            })

    # One joined string, not one record block per selector: the generic
    # record-block renderer (app.js's renderCheckBody) takes a single
    # string per check, and a second render path just for DKIM was more
    # than this fix needed. Each line is prefixed with its selector so the
    # copied text is still usable, since a bare TXT value does not say
    # where to publish it.
    _live_records = "\n".join(
        f"{sel.get('selector', 'unknown')}._domainkey: {sel.get('record', '')}"
        for sel in live if sel.get("record")
    )

    details.append({"type": "info", "text": f"Tested {_sel_count}"})

    if raw.get("timeout_note"):
        details.append({"type": "warning", "text": raw["timeout_note"]})

    # ARC informational note (RFC 8617)
    details.append({"type": "info", "text": "ARC (RFC 8617) extends the DKIM signing mechanism to preserve authentication across mail forwarding"})

    # Append any issues from the audit engine
    for issue in raw.get("issues", []):
        details.append(_issue_to_detail(issue))

    # Verdict. Counts live keys: a retired selector is not a published key
    # anyone can verify a signature against.
    verdict = f"{len(live)} DKIM public key{'s' if len(live) != 1 else ''} published in DNS"

    # Status
    status = "pass"
    if weak_keys:
        status = "warn"
    if invalid_keys:
        status = "fail"
    # Downgrade status if audit engine found errors or warnings
    if raw.get("syntax_errors") or any(i.get("severity") == "error" for i in raw.get("issues", [])):
        status = "fail"
    elif status == "pass" and any(i.get("severity") == "warning" for i in raw.get("issues", [])):
        status = "warn"

    # Explanation
    explanation = (
        f"Found <strong>{len(live)}</strong> live DKIM public key{'s' if len(live) != 1 else ''} "
        f"published in DNS."
    )
    if revoked:
        explanation += (
            (f" A further {len(revoked)} selectors publish an empty p=, which retires "
             "those keys correctly and is not a fault.")
            if len(revoked) != 1 else
            (" One further selector publishes an empty p=, which retires that key "
             "correctly and is not a fault.")
        )
    if vendor_names:
        explanation += f" Sending providers detected: {', '.join(sorted(vendor_names))}."
    explanation += (
        " Each key is a TXT record at <strong>selector._domainkey.{domain}</strong>. "
        "Receiving servers retrieve this key to verify the DKIM signature on incoming messages "
        "(<a href=\"https://datatracker.ietf.org/doc/html/rfc6376\" target=\"_blank\" rel=\"noopener\">RFC 6376</a>). Note: this audit confirms the public key exists in DNS; "
        "it does not test live message signatures."
    ).format(domain=_e(domain))
    if raw.get("discovery_method") == "spf_intelligent":
        explanation += " Selectors were targeted using SPF-based sender discovery."

    # Fix
    fix = None
    if raw.get("syntax_errors"):
        fix = _first_fix(raw.get("syntax_errors", []))
    elif weak_keys:
        # Name the sizes actually measured. This said "use 1024-bit keys"
        # whatever the real size was, so a card whose own detail line read
        # "1536-bit RSA key" carried fix text calling it 1024-bit.
        _sized = ", ".join(
            f"{sel} ({bits}-bit)" if bits else sel for sel, bits in weak_keys
        )
        fix = (
            f"The following selectors use RSA keys below the recommended 2048 bits: "
            f"<strong>{_e(_sized)}</strong>. "
            f"Key rotation is provider-specific. Check your email provider's documentation "
            f"for how to generate and publish a new 2048-bit or Ed25519 key pair."
        )
    elif raw.get("issues"):
        fix = _first_fix(raw.get("issues", []))

    # Deliverability context
    if weak_keys:
        _sizes = sorted({bits for _sel, bits in weak_keys if bits})
        _size_text = (
            " and ".join(f"{b}-bit" for b in _sizes) if _sizes else "under 2048-bit"
        )
        _deliverability = (
            f"Your DKIM keys work but some are {_size_text}. Google recommends 2048-bit keys. "
            "While they will not directly hurt deliverability today, upgrading signals "
            "that you maintain your email infrastructure."
        )
    else:
        _deliverability = (
            "DKIM signing is active, which helps build your domain's sending reputation. "
            "Each signed email that recipients engage with (open, reply, mark as not spam) "
            "strengthens your reputation with that receiver."
        )

    return {
        "name": "DKIM",
        "status": status,
        "verdict": verdict,
        "record": _live_records or None,
        "configured": True,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,  # DKIM keys are generated by email providers, not manually
        "dkim_deep": _build_dkim_key_analysis(raw),
        "deliverability": _deliverability,
    }


# ============================================================
# DKIM Key Strength & Rotation Advisory (Prompt 8)
# ============================================================

_DKIM_SELECTOR_PROVIDERS = {
    "google": "Google Workspace", "gapps": "Google Workspace",
    "selector1": "Microsoft 365", "selector2": "Microsoft 365",
    "k1": "Mailchimp", "k2": "Mailchimp", "k3": "Mailchimp",
    "mandrill": "Mandrill",
    "s1": "Generic (Exchange)", "s2": "Generic (Exchange)",
    "ses": "Amazon SES",
    "cm": "Campaign Monitor",
    "zendesk1": "Zendesk", "zendesk2": "Zendesk",
    "hubspot": "HubSpot", "hs1": "HubSpot", "hs2": "HubSpot",
    "sf": "Salesforce", "sf1": "Salesforce", "sf2": "Salesforce",
    "protonmail": "ProtonMail", "protonmail2": "ProtonMail", "protonmail3": "ProtonMail",
    "mg": "Mailgun",
    "dkim": "Generic",
    "default": "Generic",
    "sendgrid": "SendGrid", "smtpapi": "SendGrid", "s1._domainkey": "SendGrid",
    "fm1": "Fastmail", "fm2": "Fastmail", "fm3": "Fastmail",
    "mimecast": "Mimecast",
    "pphosted": "Proofpoint",
    "everlytickey1": "Everlytic", "everlytickey2": "Everlytic",
}


def _build_dkim_key_analysis(raw: Dict) -> Optional[Dict]:
    """Build DKIM key strength analysis, tag breakdown, provider mapping, rotation guidance."""
    found = raw.get("found_selectors", [])
    if not found:
        return None

    keys = []
    has_weak = False
    has_revoked = False
    has_invalid = False
    all_strong = True

    for sel in found:
        selector = sel.get("selector", "unknown")
        sel_record = sel.get("record", "")
        vendor = sel.get("vendor")
        key_analysis = analyze_dkim_key_strength(sel_record)
        bits = key_analysis.get("key_bits", 0)
        key_type = key_analysis.get("key_type", "RSA")
        strength = key_analysis.get("status", "unknown")

        # Key strength rating.
        #
        # "invalid" is tested first and on its own. It used to fall through the
        # Ed25519 shortcut (green, "modern elliptic curve") or land in the bits
        # == 0 else branch as amber "could not be determined", so one report
        # showed three severities for one key: a FAIL card header, an amber row
        # with a blank Bits column, and "Review key configuration" as the
        # guidance. A key that does not parse fails every signature it makes.
        if strength == "invalid":
            reason = key_analysis.get("reason")
            if reason == "revoked":
                # Neutral, not red. An empty p= is the RFC 6376 section 3.6.1
                # form for a retired key, so the row reports a fact about the
                # selector rather than a defect in it. Red here printed a FAIL
                # colour next to a record the operator published on purpose.
                rating = "neutral"
                rating_label = "Retired. p= is empty, the RFC 6376 revocation form."
            elif reason == "no_key":
                rating = "red"
                rating_label = "No p= tag. This record publishes no key."
            else:
                rating = "red"
                rating_label = (
                    key_analysis.get("warning")
                    or "Key data does not parse. Every signature from this selector fails."
                )
            # An empty p= is a revocation, which is deliberate and already has
            # its own guidance. Only a key that was meant to work and does not
            # belongs in has_invalid, or the advice tells an operator to
            # republish a key they revoked on purpose. It leaves all_strong
            # alone for the same reason: a retired key is not a key that fell
            # short of a standard.
            if reason != "revoked":
                has_invalid = True
                all_strong = False
        elif key_type.lower() == "ed25519":
            rating = "green"
            rating_label = "Modern elliptic curve. Smaller, faster, more secure."
        elif bits >= 2048:
            rating = "green"
            rating_label = "Meets current security recommendations."
            if bits >= 4096:
                rating_label = "Exceeds recommendations. Larger keys increase DNS response size."
        elif bits >= 1024:
            rating = "amber"
            rating_label = "Weak by modern standards. NIST deprecated 1024-bit RSA in 2013. Rotate to 2048-bit."
            has_weak = True
            all_strong = False
        elif bits > 0:
            rating = "red"
            rating_label = "Critical. This key can be factored and forged. Rotate immediately."
            has_weak = True
            all_strong = False
        else:
            rating = "amber"
            rating_label = "Key strength could not be determined."
            all_strong = False

        # Parse DKIM record tags
        dkim_tags = []
        key_revoked = False
        for part in sel_record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                k = k.strip().lower()
                v = v.strip()

                tag_info = {"tag": k, "value": v}
                if k == "v":
                    tag_info["label"] = "Version"
                elif k == "k":
                    tag_info["label"] = "Key type"
                elif k == "p":
                    if not v:
                        tag_info["label"] = "Public key (REVOKED)"
                        tag_info["revoked"] = True
                        has_revoked = True
                        key_revoked = True
                    else:
                        tag_info["label"] = "Public key"
                        tag_info["truncated"] = v[:40] + "..." if len(v) > 40 else v
                elif k == "t":
                    if v == "y":
                        tag_info["label"] = "Test mode"
                    elif v == "s":
                        tag_info["label"] = "Strict domain"
                    else:
                        tag_info["label"] = f"Flag: {v}"
                elif k == "h":
                    tag_info["label"] = "Hash algorithm"
                elif k == "s":
                    tag_info["label"] = "Service type"
                else:
                    tag_info["label"] = k

                dkim_tags.append(tag_info)

        # Provider from selector name
        provider = vendor or _DKIM_SELECTOR_PROVIDERS.get(selector.lower())

        # Per-key rotation status, derived from the same signals that drive
        # the shared rotation_guidance text below.
        if key_revoked:
            rotation_status = "Revoked"
        elif strength == "invalid":
            rotation_status = "Replace"
        elif rating in ("red", "amber"):
            rotation_status = "Rotate"
        else:
            rotation_status = "Current"

        keys.append({
            "selector": selector,
            "bits": bits,
            "key_type": key_type,
            "rating": rating,
            "rating_label": rating_label,
            "rotation_status": rotation_status,
            "revoked": key_revoked,
            "provider": provider,
            "tags": dkim_tags,
        })

    # Rotation guidance
    _has_live = any(not k["revoked"] for k in keys)
    if not _has_live:
        # Every selector found is retired, so there is no key to rotate and
        # nothing to fix. Advice framed as a defect here would be advice about
        # a record the operator published correctly.
        rotation = (
            "Every selector found publishes an empty p=, the RFC 6376 section 3.6.1 "
            "form for a revoked key, so these are retired rather than broken. Nothing "
            "signs with them and no action is needed. This audit found no live key, "
            "but selectors cannot be enumerated from DNS, so it cannot rule one out "
            "either."
        )
    elif all_strong and not has_revoked:
        rotation = "Keys meet standards. Best practice: rotate annually."
    elif all_strong:
        rotation = (
            "Live keys meet standards. Best practice: rotate annually. The retired "
            "selectors carry an empty p= and are correctly published."
        )
    elif has_invalid:
        _broken = [k["selector"] for k in keys if k["rotation_status"] == "Replace"]
        rotation = (
            f"Republish the key for {', '.join(_broken)}. The published p= value does "
            "not parse as a public key, so every signature made with that selector "
            "fails verification at every receiver. A DNS provider that truncates a long "
            "TXT value produces exactly this, so compare the published record against "
            "the key your mail server holds before regenerating anything."
        )
    elif has_weak:
        weak_selectors = [k["selector"] for k in keys if k["rating"] in ("red", "amber")]
        rotation = (
            f"Rotate {', '.join(weak_selectors)} to 2048-bit. Steps: "
            "1) Generate new key pair, 2) Publish new public key under new selector, "
            "3) Configure mail server to sign with new selector, 4) Revoke old key by emptying p=."
        )
    else:
        rotation = "Review key configuration."

    return {
        "keys": keys,
        "rotation_guidance": rotation,
        "has_weak": has_weak,
        "has_invalid": has_invalid,
    }


# ============================================================
# MX
# ============================================================

def transform_mx(raw: Dict) -> Dict:
    # The MX query never completed. "No MX records exist for this domain" is a
    # claim about the domain, and every other check in this report already
    # distinguishes a failed lookup from an absent record. MX did not, and it
    # is the check the most others are derived from.
    if raw.get("status") == "unavailable":
        return _lookup_unavailable_card("MX Records", raw, "MX records")

    status = _map_status(raw.get("status", "error"))
    records = raw.get("records", [])
    providers = raw.get("providers", [])
    count = raw.get("record_count", 0)

    # Null MX (RFC 7505): "0 ." means domain explicitly does not accept email.
    # mx_check strips the trailing dot off the hostname, so the record string
    # is "0 " and never matched a literal comparison here. Read the producer's
    # own boolean instead and render the record as valid zone-file syntax.
    is_null_mx = bool(raw.get("has_null_mx"))
    if is_null_mx:
        return {
            "name": "MX Records",
            "status": "pass",
            "pill_label": "Null MX",
            "verdict": "Domain does not accept email (RFC 7505)",
            "record": "0 .",
            "explanation": (
                "This domain publishes a null MX record (<strong>0 .</strong>) per RFC 7505, "
                "which explicitly declares that it does not accept inbound email. "
                "Sending servers will get a clean rejection rather than attempting delivery."
            ),
            "details": [
                {"type": "good", "text": "Null MX record correctly configured"},
                *[_issue_to_detail(i) for i in raw.get("issues", [])],
            ],
            "fix": None,
            "fix_records": None,
        }

    if not records:
        return {
            "name": "MX Records",
            "status": "warn",
            "pill_label": "None",
            "verdict": "No MX records found",
            "record": None,
            "explanation": (
                "No MX records exist for this domain. If this domain is not intended to "
                "receive email, this is expected and no action is needed. If the domain "
                "should receive email, MX records tell other mail servers where to deliver "
                "messages addressed to it."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": (
                "If this domain should receive email, add an MX record pointing to your "
                "mail server. If it is not meant to receive email, publish a null MX record "
                "(RFC 7505) to explicitly declare that."
            ),
            "fix_records": [{
                "type": "MX",
                "host": raw.get("domain", ""),
                "value": "0 .",
                "comment": "Null MX (RFC 7505): declares this domain does not accept email",
            }],
        }

    # Verdict: meaningful at a glance
    provider_str = ", ".join(providers) if providers else ""
    if count == 1:
        verdict = f"Single MX host{' (' + provider_str + ')' if provider_str else ''}"
    elif provider_str:
        verdict = provider_str
    else:
        verdict = f"{count} MX hosts configured"

    # Record display (all MX records)
    record = "\n".join(records)

    # A recognised provider is one mx_check's MX_PROVIDERS table matched. It
    # was a second, shorter hardcoded list here, so a domain on Zoho or
    # Fastmail was told its single MX was a single point of failure while a
    # domain on Google was not, for no reason either card explained. Any
    # provider that hands you one hostname is fanning out behind it.
    _is_major_provider = bool(providers)

    # Explanation
    if count >= 2:
        explanation = f"MX records are configured with <strong>{count} hosts</strong> for redundancy."
    elif _is_major_provider:
        explanation = (
            f"One MX record is configured, hosted by <strong>{_e(providers[0])}</strong>. "
            f"Major providers like {_e(providers[0])} handle redundancy internally across their infrastructure, "
            f"so a single MX hostname does not indicate a single point of failure."
        )
    else:
        explanation = (
            "Only one MX record is configured. If this host becomes unavailable, inbound email "
            "delivery will fail until it recovers."
        )
    if providers:
        explanation += f" Provider: {', '.join(providers)}."

    # Details
    details = []
    for mx_detail in raw.get("mx_details", []):
        hostname = mx_detail.get("hostname", "")
        priority = mx_detail.get("priority", 0)
        provider = mx_detail.get("provider", "")
        resolved = mx_detail.get("resolved", False)

        provider_note = f" [{provider}]" if provider else ""
        if resolved:
            details.append({"type": "good", "text": f"Priority {priority}: {hostname}{provider_note} (resolves)"})
        else:
            details.append({"type": "error", "text": f"Priority {priority}: {hostname} does not resolve (dangling MX)"})

    if count >= 2:
        details.append({"type": "good", "text": "Multiple MX hosts provide failover redundancy"})
    elif count == 1 and _is_major_provider:
        details.append({"type": "info", "text": f"Single MX hostname, but {providers[0]} handles redundancy internally"})
    # No hardcoded line for the self-hosted single MX. mx_check raises the
    # redundancy issue for exactly that case and it flows through the loop
    # below, so stating it here too printed the same finding twice in slightly
    # different words.

    # Add any issues not already covered
    for issue in raw.get("issues", []):
        severity = issue.get("severity", "info")
        text = issue.get("plain_english") or issue.get("issue", "")
        if "dangling" not in text.lower() and "single" not in text.lower():
            details.append(_issue_to_detail(issue))

    fix = _first_fix(raw.get("issues", []))

    # Deliverability context
    _deliverability = None
    if count == 1 and not _is_major_provider:
        _deliverability = (
            "You have only one mail server. If it goes down, incoming emails will queue at "
            "the sender's server for hours or days, and some senders give up after a few retries. "
            "A second MX host provides failover for incoming mail."
        )
    if providers:
        _prov_lower = providers[0].lower() if providers else ""
        if "google" in _prov_lower:
            _deliverability = (_deliverability or "") + (
                " You are using Google Workspace. Check your Postmaster Tools dashboard "
                "(postmaster.google.com) for reputation data and delivery error details."
            )
        elif "microsoft" in _prov_lower or "outlook" in _prov_lower:
            _deliverability = (_deliverability or "") + (
                " You are using Microsoft 365. Verify DKIM is enabled in the Exchange admin "
                "center, as it is not always turned on by default."
            )
    if _deliverability:
        _deliverability = _deliverability.strip()

    return {
        "name": "MX Records",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": _deliverability,
    }


# ============================================================
# MTA-STS
# ============================================================

def _malformed_version_tag_card(name: str, raw: Dict, record: str,
                                consequence: str, fix: str) -> Dict:
    """Card for a record whose version tag misses, so receivers ignore it.

    Reported as a failure rather than an absence. The operator published
    something and can see it in their zone, so "no record found" reads as a
    tool that cannot see their DNS, and they go looking for the wrong problem.
    Naming the record and the exact reason is the whole value here.
    """
    return {
        "name": name,
        "status": "fail",
        "pill_label": "Malformed",
        "verdict": f"{name} record published but ignored by receivers",
        "record": record,
        "configured": True,
        "explanation": (
            f"A TXT record is published, but its version tag does not match "
            f"what the specification requires, so it is discarded before "
            f"anything else in it is read. {consequence}"
        ),
        "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
        "fix": fix,
        "fix_records": None,
    }


def transform_mta_sts(raw: Dict, domain: str, has_mx: bool = True, non_mail: bool = False) -> Dict:
    """Only a positive non-mail declaration (RFC 7505 null MX, or a null ``v=spf1 -all`` SPF record) waives this check. Absent MX alone does not: send-only subdomains have no MX and still send real mail."""
    # The lookup never completed, so "not configured" would be a claim about
    # the domain that this audit did not establish.
    if raw.get("status") == "unavailable":
        return _lookup_unavailable_card("MTA-STS", raw, "MTA-STS policy record")

    # A record is published at _mta-sts but its version tag does not conform,
    # so every sender discards it. Neither of the branches below fits: "no
    # record found" contradicts what the operator can see in their zone, and
    # the has-record branch narrates a policy that is not in force.
    if raw.get("malformed_record"):
        return _malformed_version_tag_card(
            "MTA-STS", raw, raw["malformed_record"],
            "Senders ignore it and deliver without the policy, so the "
            "downgrade protection MTA-STS exists to provide is not in place.",
            f"Republish the TXT record at <strong>_mta-sts.{_e(domain)}</strong> "
            f"starting with exactly <strong>v=STSv1;</strong>, keeping the "
            f"<strong>id=</strong> tag.",
        )

    raw_status = raw.get("status", "warning")
    status = _map_status(raw_status)
    txt_record = raw.get("txt_record")
    policy_mode = raw.get("policy_mode")

    if not txt_record:
        # MTA-STS protects inbound delivery. Waive it only on a positive
        # non-mail declaration (null MX or null SPF), never on absent MX alone.
        if non_mail:
            return {
                "name": "MTA-STS",
                "status": "pass",
                "pill_label": "N/A",
                "verdict": "Not applicable (non-mail domain)",
                "record": None,
                "configured": False,
                "explanation": (
                    "MTA-STS protects inbound email delivery by requiring TLS encryption. "
                    "This domain declares that it does not handle email (RFC 7505 null MX "
                    "or a null SPF record), so MTA-STS is not applicable."
                ),
                "details": [
                    {"type": "info", "text": "Null MX or null SPF published - domain declares it does not handle email"},
                    {"type": "info", "text": "MTA-STS is only relevant for domains with MX records"},
                ],
                "fix": None,
                "fix_records": None,
                "deliverability": None,
            }

        sts_id = datetime.now(timezone.utc).strftime('%Y%m%d')
        return {
            "name": "MTA-STS",
            "status": "warn",
            "pill_label": "Not configured",
            "verdict": "No MTA-STS record found",
            "record": None,
            "configured": False,
            "explanation": (
                "While DMARC protects the <em>identity</em> of the sender, "
                "MTA-STS (<a href=\"https://datatracker.ietf.org/doc/html/rfc8461\" target=\"_blank\" rel=\"noopener\">RFC 8461</a>) "
                "protects the <em>connection</em>. It prevents downgrade attacks where a network attacker "
                "forces email to be delivered without encryption. Without MTA-STS, SMTP's opportunistic "
                "TLS (STARTTLS) can be silently stripped, allowing email content to be intercepted in transit."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": (
                f"MTA-STS requires a DNS TXT record at <strong>_mta-sts.{_e(domain)}</strong> and a "
                f"policy file hosted at <strong>https://mta-sts.{_e(domain)}/.well-known/mta-sts.txt</strong>. "
                f"The policy file specifies your MX hosts and the TLS enforcement mode."
            ),
            "fix_records": None,
            "deliverability": (
                "Without MTA-STS, the TLS encryption between mail servers can be silently stripped. "
                "While this does not directly affect spam filtering, some enterprise recipients flag "
                "inbound email that was not delivered over verified TLS."
            ),
        }

    # Has record
    if policy_mode == "enforce":
        verdict = "Inbound email must use encryption"
    elif policy_mode == "testing":
        verdict = "Monitoring TLS, not yet enforcing"
    elif policy_mode == "none":
        verdict = "Configured but disabled"
    else:
        verdict = f"Mode: {policy_mode}" if policy_mode else "Record found"

    explanation = ""
    if policy_mode == "enforce":
        explanation = (
            "MTA-STS is in <strong>enforce</strong> mode (<a href=\"https://datatracker.ietf.org/doc/html/rfc8461\" target=\"_blank\" rel=\"noopener\">RFC 8461</a>). Sending servers that "
            "support MTA-STS are required to use authenticated TLS when delivering to your domain. "
            "If TLS cannot be established, delivery fails rather than falling back to plaintext."
        )
    elif policy_mode == "testing":
        explanation = (
            "MTA-STS is in <strong>testing</strong> mode. Senders attempt TLS but will not "
            "refuse delivery if TLS fails. TLS-RPT reports will capture any failures. "
            "Move to <strong>enforce</strong> mode once you've confirmed reliable TLS delivery."
        )
    elif policy_mode == "none":
        explanation = (
            "MTA-STS is configured but the policy mode is set to <strong>none</strong>, "
            "which disables enforcement. The record has no protective effect in this state."
        )

    details = [_issue_to_detail(i) for i in raw.get("issues", [])]
    fix = _first_fix(raw.get("issues", []))
    if not fix and policy_mode == "testing":
        fix = "Move to mode=enforce once TLS-RPT reports confirm reliable TLS delivery."

    # Enforce mode is only a pass once there is nothing left to fix. An MX
    # pattern that doesn't cover an actual MX host is a real gap the matcher
    # correctly caught, not a false positive to override.
    if policy_mode == "enforce" and raw_status != "error" and not fix:
        status = "pass"

    return {
        "name": "MTA-STS",
        "status": status,
        "verdict": verdict,
        "record": txt_record,
        "configured": bool(txt_record),
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
        "mta_sts_deep": _build_mta_sts_deep(raw, domain) if txt_record else None,
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": None,
    }


def _build_mta_sts_deep(raw: Dict, domain: str) -> Optional[Dict]:
    """MTA-STS deep analysis: mode breakdown, max age, setup guidance."""
    mode = raw.get("policy_mode")
    # check_mta_sts publishes the parsed policy fields under the policy_
    # prefix (checks_extra.py). There is no bare "max_age" key, and nothing
    # anywhere produces "policy_file_content".
    max_age = raw.get("policy_max_age")

    mode_explanations = {
        "testing": (
            "Senders attempt TLS but deliver even if it fails. Correct starting point. "
            "Monitor TLS-RPT for failures before enforcing."
        ),
        "enforce": (
            "Senders MUST establish TLS. If TLS fails, mail is NOT delivered. "
            "Strongest downgrade protection. Ensure certificates stay valid."
        ),
        "none": (
            "Explicitly disabled. Signals MTA-STS was previously configured but is now inactive."
        ),
    }

    result: Dict = {
        "mode": mode,
        "mode_explanation": mode_explanations.get(mode, f"Unknown mode: {mode}") if mode else None,
    }

    # Max age analysis
    if max_age is not None:
        try:
            age_secs = int(max_age)
            if age_secs < 86400:
                result["max_age_note"] = f"{age_secs}s ({age_secs//3600}h). Very short cache. DNS outage quickly removes protection."
                result["max_age_level"] = "warning"
            elif age_secs > 2592000:
                result["max_age_note"] = f"{age_secs}s ({age_secs//86400}d). Long cache. Policy changes propagate slowly."
                result["max_age_level"] = "info"
            else:
                result["max_age_note"] = f"{age_secs}s ({age_secs//86400}d). Good range."
                result["max_age_level"] = "pass"
        except (ValueError, TypeError):
            pass

    return result


# ============================================================
# TLS-RPT
# ============================================================

def transform_tls_rpt(raw: Dict, domain: str, has_mx: bool = True, non_mail: bool = False) -> Dict:
    """Only a positive non-mail declaration (RFC 7505 null MX, or a null ``v=spf1 -all`` SPF record) waives this check. Absent MX alone does not: send-only subdomains have no MX and still send real mail."""
    # The lookup never completed, so "not configured" would be a claim about
    # the domain that this audit did not establish.
    if raw.get("status") == "unavailable":
        return _lookup_unavailable_card("TLS-RPT", raw, "TLS-RPT record")

    # See the same branch in transform_mta_sts. A near miss is neither an
    # absence nor a working record, and saying it is either one is a false
    # statement about the domain.
    if raw.get("malformed_record"):
        return _malformed_version_tag_card(
            "TLS-RPT", raw, raw["malformed_record"],
            "No aggregate reports are sent, and reports that never arrive "
            "look exactly like having nothing to report.",
            f"Republish the TXT record at <strong>_smtp._tls.{_e(domain)}</strong> "
            f"starting with exactly <strong>v=TLSRPTv1;</strong>, keeping the "
            f"<strong>rua=</strong> tag.",
        )

    status = _map_status(raw.get("status", "warning"))
    record = raw.get("record")

    if not record:
        # TLS-RPT reports on inbound TLS delivery issues. Waive it only on a
        # positive non-mail declaration (null MX or null SPF), never on
        # absent MX alone.
        if non_mail:
            return {
                "name": "TLS-RPT",
                "status": "pass",
                "pill_label": "N/A",
                "verdict": "Not applicable (non-mail domain)",
                "record": None,
                "configured": False,
                "explanation": (
                    "TLS-RPT reports on TLS encryption failures during inbound email delivery. "
                    "This domain declares that it does not handle email (RFC 7505 null MX "
                    "or a null SPF record), so TLS-RPT is not applicable."
                ),
                "details": [
                    {"type": "info", "text": "Null MX or null SPF published - domain declares it does not handle email"},
                    {"type": "info", "text": "TLS-RPT is only relevant for domains with MX records"},
                ],
                "fix": None,
                "fix_records": None,
            }

        return {
            "name": "TLS-RPT",
            "status": "warn",
            "pill_label": "Not configured",
            "verdict": "No TLS-RPT record found",
            "record": None,
            "configured": False,
            "explanation": (
                "Without TLS-RPT (<a href=\"https://datatracker.ietf.org/doc/html/rfc8460\" target=\"_blank\" rel=\"noopener\">RFC 8460</a>), "
                "you have no visibility into encryption failures on inbound email delivery. "
                "If a sending server cannot establish a secure connection with your mail server, "
                "it may fall back to plaintext delivery or fail silently. TLS-RPT provides daily reports "
                "on these failures, allowing you to identify certificate issues or misconfigurations "
                "before they affect delivery."
            ),
            "details": [_issue_to_detail(i) for i in raw.get("issues", [])],
            "fix": (
                f"Publish a TLS-RPT TXT record at <strong>_smtp._tls.{_e(domain)}</strong>. "
                f"Requires a reporting address (<strong>rua=</strong>) that can receive JSON-formatted "
                f"TLS failure reports: either your own mailbox or a reporting service."
            ),
            "fix_records": None,
        }

    destinations = raw.get("report_destinations", [])
    verdict = f"Reports to {len(destinations)} destination{'s' if len(destinations) != 1 else ''}"

    explanation = (
        "TLS-RPT (<a href=\"https://datatracker.ietf.org/doc/html/rfc8460\" target=\"_blank\" rel=\"noopener\">RFC 8460</a>) is configured. Sending mail servers that support the protocol "
        "will report SMTP TLS failures to your specified destinations, giving you visibility "
        "into encryption issues on inbound delivery. This is particularly useful alongside "
        "MTA-STS or DANE to detect delivery problems caused by TLS policy enforcement."
    )
    if destinations:
        explanation += f" Reports are sent to: {', '.join(destinations[:3])}."

    details = [_issue_to_detail(i) for i in raw.get("issues", [])]
    if destinations:
        details.insert(0, {"type": "good", "text": f"Report delivery configured ({len(destinations)} destination{'s' if len(destinations) != 1 else ''})"})

    fix = _first_fix(raw.get("issues", []))

    return {
        "name": "TLS-RPT",
        "status": status,
        "verdict": verdict,
        "record": record,
        "configured": bool(record),
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
        "tls_rpt_deep": _build_tls_rpt_deep(raw) if record else None,
        "ttl_info": format_ttl(raw.get("ttl")),
    }


def _build_tls_rpt_deep(raw: Dict) -> Optional[Dict]:
    """TLS-RPT deep analysis: destinations, cross-protocol relationships."""
    # The check emits "report_destinations", which transform_tls_rpt four
    # lines above already reads correctly.
    destinations = raw.get("report_destinations", [])

    dest_types = []
    for d in destinations:
        if isinstance(d, str):
            if d.startswith("mailto:"):
                dest_types.append({"type": "mailto", "value": d})
            elif d.startswith("https:"):
                dest_types.append({"type": "https", "value": d})
            else:
                dest_types.append({"type": "unknown", "value": d})

    return {
        "destinations": dest_types,
        "cross_protocol_note": (
            "Without TLS-RPT, a man-in-the-middle stripping encryption from your inbound email "
            "would go undetected."
        ),
    }


# ============================================================
# BIMI
# ============================================================

def transform_bimi(raw: Dict, domain: str, has_mx: bool = True, non_mail: bool = False) -> Dict:
    """Only a positive non-mail declaration (RFC 7505 null MX, or a null ``v=spf1 -all`` SPF record) waives this check. Absent MX alone does not: send-only subdomains have no MX and still send real mail."""
    # The lookup never completed, so "not configured" would be a claim about
    # the domain that this audit did not establish.
    if raw.get("status") == "unavailable":
        return _lookup_unavailable_card("BIMI", raw, "BIMI record")
    status = _map_status(raw.get("status", "info"))
    record = raw.get("record")
    records_found = raw.get("records_found", 0)

    if not record and records_found == 0:
        # BIMI is an email branding feature. Waive it only on a positive
        # non-mail declaration (null MX or null SPF), never on absent MX alone.
        if non_mail:
            return {
                "name": "BIMI",
                "status": "pass",
                "pill_label": "N/A",
                "verdict": "Not applicable (non-mail domain)",
                "record": None,
                "records_found": 0,
                "configured": False,
                "explanation": (
                    "BIMI displays a brand logo next to emails in supporting mail clients. "
                    "This domain declares that it does not handle email (RFC 7505 null MX "
                    "or a null SPF record), so BIMI is not applicable."
                ),
                "details": [
                    {"type": "info", "text": "Null MX or null SPF published - domain declares it does not handle email"},
                    {"type": "info", "text": "BIMI is only relevant for domains that send email"},
                ],
                "fix": None,
                "fix_records": None,
                "deliverability": None,
            }

        # BIMI is optional, so "not found" is a soft warning, not a failure.
        #
        # The verdict names the selector actually queried. This audit looks up
        # default._bimi and nothing else, and a domain may publish under any
        # selector: the BIMI specification lets a message name one in a
        # BIMI-Selector header field, and receivers then query
        # <selector>._bimi.<domain> instead. "No BIMI record found" therefore
        # asserted more than the query established, and the fix text told an
        # operator using a custom selector to publish a record they already
        # have. This is GitHub issue 26.
        #
        # Verified against draft-brand-indicators-for-message-identification-14
        # (the current Internet-Draft, May 2026; BIMI is not an RFC): the
        # default selector is "default", and a Domain Owner "may override the
        # use of the default selector and specify the use of an alternative
        # using the [RFC5322]-compliant header 'BIMI-Selector'".
        return {
            "name": "BIMI",
            # BIMI is optional brand display, not a security control, and a
            # domain that has not adopted it has done nothing wrong. A warning
            # is a thing the owner should act on; this is a thing they may
            # choose to. Kept out of the warnings tally with the same
            # pass-with-a-pill idiom used elsewhere for "nothing to answer for
            # here", rather than a fifth status the front end and the PDF would
            # both have to learn. The wording is unchanged from 08e6ac3.
            "status": "pass",
            "pill_label": "Not configured",
            "verdict": "No BIMI record at the default selector",
            "record": None,
            "records_found": 0,
            "configured": False,
            "explanation": (
                "BIMI (Brand Indicators for Message Identification) is not a security protocol. "
                "It is a brand recognition feature that displays your logo next to emails in "
                "supporting clients (Gmail, Apple Mail, Yahoo Mail). "
                "BIMI is currently a draft standard, not a published RFC. "
                "It requires DMARC at p=quarantine or p=reject as a prerequisite. "
                f"This audit queried <strong>default._bimi.{_e(domain)}</strong> and found no "
                "record there. That is the name receivers use unless a message names another "
                "one, so if this domain publishes under a custom selector, mail carrying a "
                "BIMI-Selector header may still display a logo."
            ),
            "details": [
                {"type": "info", "text": "BIMI is about brand recognition, not security"},
                {"type": "info", "text": f"Queried default._bimi.{_e(domain)}, the selector receivers use by default"},
                {"type": "info", "text": "A custom selector cannot be discovered from DNS. It is named by the BIMI-Selector header on a sent message, and receivers query <selector>._bimi instead"},
                {"type": "info", "text": "Requires DMARC policy of p=quarantine or p=reject"},
                {"type": "info", "text": "Gmail accepts a VMC (Verified Mark Certificate) or CMC (Common Mark Certificate). Apple Mail does not require either."},
            ],
            "fix": (
                f"If this domain already publishes BIMI under a custom selector, no change is "
                f"needed: check the s= value of the BIMI-Selector header on a message it sent. "
                f"To publish at the default selector, BIMI requires DMARC at p=quarantine or "
                f"p=reject, an SVG logo in Tiny P/S format hosted at a public URL, and a BIMI "
                f"TXT record at <strong>default._bimi.{_e(domain)}</strong>. "
                f"Gmail requires a VMC (registered trademark) or CMC (domain-validated) certificate."
            ),
            "fix_records": None,
            "deliverability": (
                "BIMI displays your brand logo next to emails in Gmail, Apple Mail, and Yahoo Mail. "
                "It does not directly affect whether email reaches the inbox, but branded emails "
                "see higher open rates. BIMI requires DMARC at p=quarantine or p=reject first."
            ),
        }

    logo_url = raw.get("logo_url")
    vmc_url = raw.get("vmc_url")
    if vmc_url:
        verdict = "Certificate referenced (VMC or CMC)"
    elif logo_url:
        verdict = "Logo configured"
    else:
        verdict = "Record found"

    explanation = "BIMI record is published. BIMI is a brand recognition feature, not a security protocol."
    if logo_url:
        explanation += " Your brand logo URL is configured."
    if vmc_url:
        explanation += " A certificate (VMC or CMC) is referenced in the <strong>a=</strong> tag."
    elif not vmc_url:
        explanation += (
            " <strong>Note:</strong> No certificate is referenced in the <strong>a=</strong> tag. "
            "Gmail requires either a VMC (registered trademark required) or CMC (domain validation only) "
            "for logo display. Other clients like Apple Mail do not require a certificate."
        )

    details = [_issue_to_detail(i) for i in raw.get("issues", [])]

    # Add SVG validation summary to details
    svg_validated = raw.get("svg_validated")
    svg_profile = raw.get("svg_profile")
    if svg_validated is True:
        if svg_profile == "tiny-ps":
            details.append({"type": "good", "text": f"SVG validated (profile: {svg_profile})"})
        elif svg_profile == "tiny":
            details.append({"type": "warning", "text": "SVG profile is 'tiny' but BIMI requires 'tiny-ps'. Gmail and other clients will reject this."})
        elif svg_profile:
            details.append({"type": "warning", "text": f"SVG parsed but profile is '{svg_profile}' (expected tiny-ps)"})
        else:
            details.append({"type": "warning", "text": "SVG parsed but baseProfile not declared (expected tiny-ps)"})
    elif svg_validated is False:
        details.append({"type": "error", "text": "SVG validation failed"})
        status = "fail"

    fix = _first_fix(raw.get("issues", []))

    return {
        "name": "BIMI",
        "status": status,
        "verdict": verdict,
        "record": record,
        "records_found": records_found,
        "configured": bool(record),
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
        "deliverability": None,
    }


# ============================================================
# DNSSEC
# ============================================================

def transform_dnssec(raw: Dict, domain: str = "") -> Dict:
    # The DNSKEY query never completed (SERVFAIL, NoNameservers, or a
    # timeout on both attempts), so has_dnssec=False here is not a real
    # negative answer. Reporting it as "not configured" told a signed and
    # anchored domain it had no DNSSEC, off the back of one failed query.
    if raw.get("lookup_failed"):
        return _lookup_unavailable_card("DNSSEC", raw, "DNSSEC records", pill_label="Not confirmed")

    has_dnssec = raw.get("has_dnssec", False)
    dnssec_state = raw.get("dnssec_state", "insecure")
    algorithms = raw.get("algorithms", [])
    key_count = raw.get("key_count", 0)
    has_ds = raw.get("has_ds", False)
    validated_by_resolver = raw.get("validated_by_resolver", False)
    issues = raw.get("issues", [])
    status = _map_status(raw.get("status", "ok"))

    # Bogus state: DNSSEC is configured but signatures fail validation.
    # This is an availability issue, not just a security one — render it
    # with a fail status and a clear, actionable fix.
    if dnssec_state == "bogus":
        details = []
        for issue in issues:
            details.append(_issue_to_detail(issue))
        bogus_fix = (
            f"Run 'delv {_e(domain)}' locally for a chain analysis, or open "
            f"<a href=\"https://dnsviz.net/d/{_e(domain)}/dnssec/\" target=\"_blank\" rel=\"noopener\">"
            f"https://dnsviz.net/d/{_e(domain)}/dnssec/</a> in a browser. "
            f"If a key rollover is in progress, coordinate with your registrar "
            f"to update the DS record at the parent zone."
        )
        return {
            "name": "DNSSEC",
            "status": "fail",
            "pill_label": "Bogus",
            "verdict": "DNSSEC validation failure (zone is bogus)",
            "record": None,
            "configured": True,
            "explanation": (
                "DNSSEC is configured but its signatures fail to validate. "
                "Validating resolvers (Cloudflare 1.1.1.1, Quad9 9.9.9.9, "
                "Google 8.8.8.8 in DNSSEC mode) return SERVFAIL for this "
                "domain, so users behind those resolvers cannot reach it. "
                "Common causes: expired RRSIGs, an orphaned DS record at the "
                "parent after a key rollover, or a KSK/ZSK mismatch."
            ),
            "details": details,
            "fix": bogus_fix,
            "fix_records": None,
            "ttl_info": format_ttl(raw.get("ttl")),
        }

    if not has_dnssec:
        details = [
            {"type": "warning", "text": "No DNSKEY records found"},
            {"type": "info", "text": "DNSSEC requires support from both your registrar and DNS hosting provider"},
        ]
        for issue in issues:
            details.append(_issue_to_detail(issue))

        return {
            "name": "DNSSEC",
            "status": "warn",
            "pill_label": "Not enabled",
            "verdict": "DNSSEC not configured",
            "record": None,
            "configured": False,
            "explanation": (
                "DNSSEC (<a href=\"https://datatracker.ietf.org/doc/html/rfc4033\" target=\"_blank\" rel=\"noopener\">RFC 4033</a>/4034/4035) cryptographically signs DNS records so that "
                "resolvers can verify responses have not been tampered with, preventing cache "
                "poisoning and DNS spoofing. It is also a prerequisite for DANE. "
                "Enabling DNSSEC requires coordination between your registrar (for the DS record) "
                "and your DNS hosting provider (for DNSKEY records and zone signing)."
            ),
            "details": details,
            "fix": (
                "Enable DNSSEC through your DNS hosting provider, then publish the DS record "
                "at your domain registrar to complete the chain of trust. "
                "Many registrars and DNS hosts support this through their control panels."
            ),
            "fix_records": None,  # DNSSEC requires registrar/DNS provider activation, not manual DNS records
            "ttl_info": format_ttl(raw.get("ttl")),
        }

    # Has DNSSEC
    details = []
    details.append({"type": "good", "text": f"DNSKEY records found ({key_count} key{'s' if key_count != 1 else ''})"})

    chain_valid = raw.get("chain_valid")
    chain_details = raw.get("chain_details", [])

    if has_ds:
        details.append({"type": "good", "text": "DS record present at parent (chain of trust anchored)"})
        # Chain verification result
        if chain_valid is True:
            details.append({"type": "good", "text": "DS digest matches DNSKEY (chain of trust verified)"})
        elif chain_valid is False:
            details.append({"type": "error", "text": "DS digest does NOT match any DNSKEY (chain of trust not valid; validating resolvers will return SERVFAIL)"})
    elif not validated_by_resolver:
        # No direct DS evidence and no AD-bit corroboration: real warning.
        # When AD is set the audit engine emits an info-level annotation
        # which is rendered below by the issues loop.
        details.append({"type": "warning", "text": "No DS record at parent zone (chain may not validate)"})

    # Show algorithms
    for algo in algorithms:
        if algo.get("deprecated"):
            details.append({"type": "error", "text": f"Algorithm {algo['number']}: {algo['name']}"})
        elif algo.get("legacy"):
            details.append({"type": "warning", "text": f"Algorithm {algo['number']}: {algo['name']}"})
        else:
            details.append({"type": "good", "text": f"Algorithm {algo['number']}: {algo['name']}"})

    # Append issues from audit engine (skip algorithm issues already shown above)
    for issue in issues:
        text = (issue.get("issue") or "").lower()
        if "algorithm" not in text:
            details.append(_issue_to_detail(issue))

    # Verdict
    if algorithms:
        algo_names = [a["name"].split(" (")[0] for a in algorithms]
        verdict = f"DNS records cryptographically signed ({', '.join(algo_names)})"
    else:
        verdict = "DNS records cryptographically signed"

    # signed_unanchored: DNSKEY published but no DS at parent. Effectively
    # insecure for end users behind validating resolvers, so render with
    # warn status and a distinct pill — never green.
    if dnssec_state == "signed_unanchored":
        verdict = "DNSKEY published but unanchored (no DS at parent)"

    # Downgrade status if issues exist. AD-bit corroboration keeps the
    # DNSSEC card at "pass" even when DS isn't directly observable.
    if any(a.get("deprecated") for a in algorithms):
        status = "fail"
    elif chain_valid is False:
        status = "fail"
    elif dnssec_state == "signed_unanchored":
        status = "warn"
    elif not has_ds and not validated_by_resolver:
        status = "warn"

    fix = _first_fix(issues)
    if not fix and not has_ds and not validated_by_resolver:
        fix = "Add a DS record at your domain registrar to complete the DNSSEC chain of trust."

    result = {
        "name": "DNSSEC",
        "status": status,
        "verdict": verdict,
        "record": None,
        "configured": True,
        "explanation": (
            "DNSSEC is enabled. Your DNS records are cryptographically signed per "
            "<a href=\"https://datatracker.ietf.org/doc/html/rfc4033\" target=\"_blank\" rel=\"noopener\">RFC 4033</a>/4034/4035, allowing validating resolvers to confirm that responses "
            "have not been tampered with. This prevents cache poisoning and DNS spoofing, "
            "and is required for DANE to function."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
    }
    if dnssec_state == "signed_unanchored":
        result["pill_label"] = "Signed but unanchored"
    return result


# ============================================================
# CAA
# ============================================================

def transform_caa(raw: Dict, domain: str) -> Dict:
    # At least one level of the CAA tree walk (RFC 8659 section 3) never
    # completed, so the walk cannot say the tree published nothing: the
    # level that failed might have carried a CAA record. Reporting "any CA
    # can issue" from an incomplete walk is a claim about the whole parent
    # chain that no query supported.
    if raw.get("lookup_failed"):
        return _lookup_unavailable_card("CAA", raw, "CAA records")

    record_count = raw.get("record_count", 0)
    records = raw.get("records", [])
    authorized_cas = raw.get("authorized_cas", [])
    wildcard_cas = raw.get("wildcard_cas", [])
    has_issue = raw.get("has_issue", False)
    has_issuewild = raw.get("has_issuewild", False)
    has_iodef = raw.get("has_iodef", False)
    iodef_destinations = raw.get("iodef_destinations", [])
    issues = raw.get("issues", [])
    status = _map_status(raw.get("status", "warning"))

    if record_count == 0:
        details = []
        for issue in issues:
            details.append(_issue_to_detail(issue))
        if not details:
            details.append({"type": "warning", "text": "Any Certificate Authority can issue certificates for this domain"})

        return {
            "name": "CAA",
            "status": "warn",
            "pill_label": "Not configured",
            "verdict": "No CAA records found",
            "record": None,
            "configured": False,
            "explanation": (
                "CAA records (<a href=\"https://datatracker.ietf.org/doc/html/rfc8659\" target=\"_blank\" rel=\"noopener\">RFC 8659</a>) specify which Certificate Authorities are authorized "
                "to issue TLS certificates for your domain. Compliant CAs must check CAA records "
                "before issuance. Without CAA records, any compliant CA may issue certificates "
                "for your domain. There is no restriction to enforce."
            ),
            "details": details,
            "fix": (
                "Publish CAA records specifying which Certificate Authorities may issue certificates "
                "for your domain. Requires knowing which CA(s) you use. Use <code>issue</code> to "
                "authorize your CA, <code>issuewild</code> for wildcard policy, and <code>iodef</code> "
                "to receive violation alerts."
            ),
            "fix_records": None,
        }

    # Has CAA records
    record_display = "\n".join(r["raw"] for r in records)

    # Build details
    details = []

    if authorized_cas:
        for ca in authorized_cas:
            details.append({"type": "good", "text": f"Authorized CA: {ca}"})
    elif has_issue:
        details.append({"type": "info", "text": "Certificate issuance restricted (issue \";\")"})

    if wildcard_cas:
        for ca in wildcard_cas:
            details.append({"type": "good", "text": f"Wildcard CA: {ca}"})
    elif has_issuewild:
        details.append({"type": "info", "text": "Wildcard issuance blocked (issuewild \";\")"})

    if has_iodef:
        for dest in iodef_destinations:
            details.append({"type": "good", "text": f"Violation reports: {dest}"})
    
    if has_issue and has_issuewild and has_iodef:
        details.append({"type": "good", "text": "Complete CAA configuration (issue + issuewild + iodef)"})

    # Append issues
    for issue in issues:
        details.append(_issue_to_detail(issue))

    # Verdict
    if authorized_cas:
        if len(authorized_cas) == 1:
            verdict = f"Restricted to {authorized_cas[0]}"
        else:
            verdict = f"{len(authorized_cas)} CAs authorized"
    else:
        verdict = "Certificate issuance restricted"

    # Status logic
    if any(i.get("severity") == "error" for i in issues):
        status = "fail"
    elif record_count > 0 and has_issue:
        status = "pass"

    # A pass card carries no fix; a suggestion like adding iodef or
    # issuewild is an optional improvement, already listed as an info
    # detail above, not something a passing card should also be fixing.
    fix = None if status == "pass" else _first_fix(issues)

    return {
        "name": "CAA",
        "status": status,
        "verdict": verdict,
        "record": record_display,
        "configured": True,
        "explanation": (
            "CAA records (<a href=\"https://datatracker.ietf.org/doc/html/rfc8659\" target=\"_blank\" rel=\"noopener\">RFC 8659</a>) restrict which Certificate Authorities may issue TLS certificates "
            "for your domain. Compliant CAs check these records before issuance and must not issue "
            "if they are not listed. Certificate Transparency logs can be used to detect issuance "
            "by CAs not authorized in your CAA records."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
    }


# ============================================================
# DANE
# ============================================================

def transform_dane(raw: Dict, domain: str) -> Dict:
    has_tlsa = raw.get("has_tlsa", False)
    # Three-state. None means the DNSSEC check did not complete, so this card
    # may not say DNSSEC is missing, and may not say the DANE chain is valid.
    dnssec_ok = raw.get("dnssec_validated", False)
    mx_checked = raw.get("mx_hosts_checked", 0)
    mx_with_tlsa = raw.get("mx_hosts_with_tlsa", 0)
    tlsa_records = raw.get("tlsa_records", [])
    issues = raw.get("issues", [])

    # The MX lookup never completed, so "no MX hosts" was never established.
    # This branch used to answer pass / "N/A" / "No MX hosts to check": a green
    # card asserting something about the domain that no query supported.
    if raw.get("mx_unavailable"):
        return _lookup_unavailable_card("DANE", raw, "MX records, which DANE is keyed on")

    # No MX hosts to check
    if mx_checked == 0:
        return {
            "name": "DANE",
            "status": "pass",
            "pill_label": "N/A",
            "verdict": "No MX hosts to check",
            "record": None,
            "configured": False,
            "explanation": (
                "DANE (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a>) publishes TLSA records that allow sending servers to verify "
                "your mail server's TLS certificate directly via DNS, without relying on a CA. "
                "This domain has no MX records, so DANE is not applicable."
            ),
            "details": [{"type": "info", "text": "No MX hosts. DANE check not applicable"}],
            "fix": None,
            "fix_records": None,
        }

    # Has TLSA, DNSSEC state never established
    if has_tlsa and dnssec_ok is None:
        details = []
        for hr in tlsa_records:
            if hr.get("found"):
                for rec in hr.get("records", []):
                    details.append({
                        "type": "info",
                        "text": f"{hr['mx_host']}: {rec['usage_name']}, {rec['selector_name']}, {rec['matching_type_name']}"
                    })
        details.append({
            "type": "info",
            "text": "The DNSSEC check did not complete, so DANE effectiveness was not assessed"
        })
        for issue in issues:
            details.append(_issue_to_detail(issue))
        return {
            "name": "DANE",
            # Not "warn". The explanation below says this is a gap in the audit
            # and not a finding about the domain, and a warn contradicted it by
            # counting on the PDF cover and in the front end's tallies. Every
            # other check that reaches this state answers "unavailable", which
            # is neither a pass nor a finding. The pill still says what was and
            # was not established, which is the part the reader needs.
            "status": "unavailable",
            "pill_label": "Partly checked",
            "verdict": "TLSA records published, DNSSEC state not confirmed",
            "record": None,
            "configured": True,
            "explanation": (
                "TLSA records are published for this domain's MX hosts. DANE "
                "(<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a>) "
                "requires DNSSEC to be effective, and the DNSSEC check did not complete on "
                "this run, so this audit cannot say whether these records are trusted by "
                "sending servers. This is a gap in the audit, not a finding about the domain."
            ),
            "details": details,
            "fix": None,
            "fix_records": None,
            "dane_deep": _build_dane_deep(tlsa_records, dnssec_ok),
            "ttl_info": format_ttl(raw.get("ttl")),
        }

    # Has TLSA but no DNSSEC. Not-enabled and signed-but-unanchored both
    # collapse to dnssec_ok == False, but they are different domain states
    # with different fixes: an unanchored zone already has DNSKEY published,
    # so "enable DNSSEC" is a step already done. The missing piece is the DS
    # record at the registrar.
    if has_tlsa and not dnssec_ok:
        signed_unanchored = raw.get("dnssec_state") == "signed_unanchored"
        details = []
        for hr in tlsa_records:
            if hr.get("found"):
                for rec in hr.get("records", []):
                    details.append({
                        "type": "info",
                        "text": f"{hr['mx_host']}: {rec['usage_name']}, {rec['selector_name']}, {rec['matching_type_name']}"
                    })
        details.append({
            "type": "error",
            "text": (
                "TLSA records found but DNSSEC is signed and not anchored at the "
                "parent, so DANE is ineffective"
                if signed_unanchored else
                "TLSA records found but DNSSEC is not enabled, so DANE is ineffective"
            )
        })
        for issue in issues:
            if "dnssec" not in (issue.get("issue") or "").lower():
                details.append(_issue_to_detail(issue))

        if signed_unanchored:
            return {
                "name": "DANE",
                "status": "warn",
                "verdict": "TLSA found but DNSSEC unanchored",
                "record": None,
                "configured": True,
                "explanation": (
                    "DANE TLSA records are published for your MX hosts, and DNSSEC keys are "
                    "published for your domain, but no DS record was found at the parent "
                    "zone. DANE requires DNSSEC (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a> Section 2.2) to be anchored to the "
                    "global trust chain. Without the DS record, validating resolvers treat "
                    "this zone as unsigned, so an attacker can forge or strip TLSA records, "
                    "completely defeating the authentication."
                ),
                "details": details,
                "fix": "Add a DS record for your domain at your registrar, pointing to your published DNSKEY. Once the chain is anchored, your existing TLSA records will become effective.",
                "fix_records": None,
                "ttl_info": format_ttl(raw.get("ttl")),
            }

        return {
            "name": "DANE",
            "status": "warn",
            "verdict": "TLSA found but DNSSEC missing",
            "record": None,
            "configured": True,
            "explanation": (
                "DANE TLSA records are published for your MX hosts, but DNSSEC is not enabled. "
                "DANE requires DNSSEC (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a> Section 2.2). Without it, an attacker can forge "
                "or strip TLSA records, completely defeating the authentication. "
                "Senders that implement RFC 7672 will ignore TLSA records that are not DNSSEC-validated."
            ),
            "details": details,
            "fix": "Enable DNSSEC for your domain before relying on DANE. Once DNSSEC is active, your existing TLSA records will become effective.",
            "fix_records": None,  # DNSSEC activation required first; TLSA records already exist
            "ttl_info": format_ttl(raw.get("ttl")),
        }

    # Has TLSA + DNSSEC
    if has_tlsa and dnssec_ok:
        details = []
        for hr in tlsa_records:
            if hr.get("found"):
                for rec in hr.get("records", []):
                    details.append({
                        "type": "good",
                        "text": f"{hr['mx_host']}: {rec['usage_name']}, {rec['selector_name']}, {rec['matching_type_name']}"
                    })
            elif hr.get("error"):
                details.append({"type": "warning", "text": f"{hr['mx_host']}: {hr['error']}"})

        if mx_with_tlsa == mx_checked:
            details.append({"type": "good", "text": f"All {mx_checked} MX host{'s' if mx_checked != 1 else ''} have TLSA records"})
        else:
            missing = [h["mx_host"] for h in tlsa_records if not h["found"] and not h.get("error")]
            if missing:
                details.append({"type": "warning", "text": f"Missing DANE on: {', '.join(missing)}"})

        details.append({"type": "good", "text": "DNSSEC is enabled and the DANE chain of trust is valid"})

        for issue in issues:
            details.append(_issue_to_detail(issue))

        status = "pass"
        if any(i.get("severity") == "warning" for i in issues) or mx_with_tlsa < mx_checked:
            status = "warn"

        verdict = f"DANE-protected ({mx_with_tlsa}/{mx_checked} MX hosts)"
        fix = _first_fix(issues)
        if not fix and mx_with_tlsa < mx_checked:
            missing = [h["mx_host"] for h in tlsa_records if not h["found"] and not h.get("error")]
            fix = f"Add TLSA records for: {', '.join(missing)}"

        return {
            "name": "DANE",
            "status": status,
            "verdict": verdict,
            "record": None,
            "configured": True,
            "explanation": (
                "DANE (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a>) is configured and backed by DNSSEC. Sending mail servers that "
                "implement RFC 7672 can verify your mail server's TLS certificate through DNS-based "
                "TLSA records, independent of the Certificate Authority infrastructure. "
                "This allows senders to authenticate the TLS certificate without relying on the "
                "public CA trust model."
            ),
            "details": details,
            "fix": fix,
            "fix_records": None,
            "dane_deep": _build_dane_deep(tlsa_records, dnssec_ok),
            "ttl_info": format_ttl(raw.get("ttl")),
        }

    # No TLSA, and the MX host belongs to someone else.
    #
    # RFC 7672 section 3 puts TLSA records at the MX host, so who operates that
    # host decides whether the domain owner can act on this card at all. Telling
    # an operator to "generate a TLSA record" for a name they do not control is
    # advice they cannot follow, and a warning they cannot clear is information
    # wearing a warning's colour.
    _providers = raw.get("mx_providers") or []
    _hosts = [h.lower() for h in (raw.get("mx_hostnames") or [])]

    if any(p.startswith("Google Workspace") for p in _providers):
        # Verified 2026-09-08: no TLSA at smtp.google.com, aspmx.l.google.com or
        # alt1.aspmx.l.google.com, and google.com publishes no DS record. Google
        # neither publishes TLSA for its MX hosts nor signs the zone they live
        # in, so a Workspace-hosted domain cannot do DANE by any action of its
        # own. MTA-STS is the transport protection that applies instead.
        return {
            "name": "DANE",
            "status": "pass",
            "pill_label": "N/A",
            "verdict": "DANE is not available on Google Workspace",
            "record": None,
            "configured": False,
            "explanation": (
                "DANE (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" "
                "target=\"_blank\" rel=\"noopener\">RFC 7672</a>) requires a TLSA record "
                "published at the mail server's own hostname, inside a DNSSEC-signed zone. "
                "This domain's mail is handled by Google Workspace, so those hostnames "
                "belong to Google, and Google publishes no TLSA records for them. There is "
                "nothing the domain owner can publish to change that. "
                "MTA-STS is the transport protection that applies to this configuration."
            ),
            "details": [
                {"type": "info", "text": "Mail is handled by Google Workspace, so the MX hostnames are not under this domain's control"},
                {"type": "info", "text": "Google publishes no TLSA records for its Workspace MX hosts"},
                {"type": "info", "text": "MTA-STS is the transport protection available here. See the MTA-STS card above."},
            ],
            "fix": None,
            "fix_records": None,
            "dane_deep": _build_dane_deep(tlsa_records, dnssec_ok),
            "ttl_info": format_ttl(raw.get("ttl")),
        }

    _LEGACY_MS_MX = (
        ".mail.protection.outlook.com",
        ".mail.eo.outlook.com",
        ".mail.protection.outlook.de",
    )
    if (any(p.startswith("Microsoft 365") for p in _providers)
            and any(h.endswith(_LEGACY_MS_MX) for h in _hosts)):
        # Microsoft supports inbound SMTP DANE, but not by the owner publishing
        # TLSA: Exchange Online issues a new MX host under mx.microsoft and
        # publishes the TLSA for it. Every step below is from Microsoft's "How
        # SMTP DNS-based Authentication of Named Entities (DANE) works", section
        # "Inbound SMTP DANE with DNSSEC", read 2026-09-08. Nothing here is
        # inferred: the two-stage priority change in particular is theirs.
        return {
            "name": "DANE",
            "status": "warn",
            "pill_label": "Available, not enabled",
            "verdict": "DANE is available through Exchange Online but not enabled",
            "record": None,
            "configured": False,
            "explanation": (
                "DANE (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" "
                "target=\"_blank\" rel=\"noopener\">RFC 7672</a>) requires a TLSA record at "
                "the mail server's hostname. This domain's mail is handled by Microsoft 365 "
                "on a legacy MX host, so that record is Microsoft's to publish, not yours. "
                "Exchange Online supports inbound SMTP DANE: you enable DNSSEC for the "
                "domain, move the MX to the <strong>mx.microsoft</strong> host that "
                "Exchange Online issues, and Microsoft publishes the TLSA records for it."
            ),
            "details": [
                {"type": "info", "text": "Mail is handled by Microsoft 365 on a legacy mail.protection.outlook.com MX host"},
                {"type": "info", "text": "Enable-DnssecForVerifiedDomain returns a new MX target ending in mx.microsoft; Microsoft publishes the TLSA records for that host"},
                {"type": "warning", "text": "If this domain uses MTA-STS, set the policy mode to testing and update the policy id, then wait out max_age before changing the MX"},
            ],
            "fix": (
                "In Exchange Online PowerShell, run <strong>Enable-DnssecForVerifiedDomain "
                "-DomainName &lt;domain&gt;</strong>. It returns a DnssecMxValue ending in "
                "<strong>mx.microsoft</strong>. Add that as a new MX record at priority 20, "
                "verify it with the Remote Connectivity Analyzer inbound SMTP test, then set "
                "the new record to priority 0 and the legacy record to 30 before deleting the "
                "legacy MX. Finally run <strong>Enable-SmtpDaneInbound -DomainName "
                "&lt;domain&gt;</strong>. Full procedure: "
                "<a href=\"https://learn.microsoft.com/exchange/security-and-compliance/how-dane-secures-email\" "
                "target=\"_blank\" rel=\"noopener\">How SMTP DANE works</a>."
            ),
            "fix_records": None,
            "dane_deep": _build_dane_deep(tlsa_records, dnssec_ok),
            "ttl_info": format_ttl(raw.get("ttl")),
        }

    # No TLSA, has MX
    details = [
        {"type": "warning", "text": f"Checked {mx_checked} MX host{'s' if mx_checked != 1 else ''}, but no TLSA records found"},
    ]
    if dnssec_ok:
        details.append({"type": "good", "text": "DNSSEC is enabled and ready for DANE deployment"})
    elif dnssec_ok is None:
        details.append({"type": "info", "text": "DNSSEC is also required for DANE to work. The DNSSEC check did not complete on this run"})
    else:
        details.append({"type": "info", "text": "DNSSEC is also required for DANE to work"})

    for issue in issues:
        details.append(_issue_to_detail(issue))

    # Build example TLSA record using first MX host
    example_host = tlsa_records[0]["mx_host"] if tlsa_records else "mail.example.com"
    fix_parts = [
        "DANE implementation requires multiple steps:<br>"
        "<strong>1.</strong> DNSSEC must be enabled and validated for your domain.<br>"
        "<strong>2.</strong> Generate a TLSA record containing the SHA-256 hash of your mail server's "
        "TLS certificate (SPKI). The record goes at <strong>_25._tcp.&lt;mx-host&gt;</strong>.<br>"
        "<strong>3.</strong> TLSA records must be updated every time you rotate your mail server's TLS certificate, "
        "or use DANE-TA (usage 2) to pin the CA certificate instead."
    ]
    if dnssec_ok is False:
        fix_parts.insert(0, "<strong>Prerequisite:</strong> DNSSEC is not enabled. DANE cannot function without it.<br><br>")

    fix = "".join(fix_parts)

    return {
        "name": "DANE",
        "status": "warn",
        "pill_label": "Not configured",
        "verdict": "No DANE TLSA records",
        "record": None,
        "configured": False,
        "explanation": (
            "DANE (<a href=\"https://datatracker.ietf.org/doc/html/rfc7672\" target=\"_blank\" rel=\"noopener\">RFC 7672</a>) uses TLSA records to let sending mail servers verify your mail "
            "server's TLS certificate through DNS, without depending on the CA infrastructure. "
            "DANE requires DNSSEC to be effective. Without it, TLSA records cannot be trusted. "
            "DANE and MTA-STS serve complementary roles for enforcing SMTP TLS."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
        "dane_deep": _build_dane_deep(tlsa_records, dnssec_ok),
        "ttl_info": format_ttl(raw.get("ttl")),
    }


# ============================================================
# DANE Deep Analysis (Prompt 10)
# ============================================================

_TLSA_USAGE = {
    0: ("PKIX-TA", "CA constraint with standard validation."),
    1: ("PKIX-EE", "End entity with CA validation."),
    2: ("DANE-TA", "Trust anchor. Specified cert trusted as CA without standard trust store."),
    3: ("DANE-EE", "End entity. Pins the exact certificate. Most common for SMTP."),
}

_TLSA_SELECTOR = {
    0: ("Full cert", "Full certificate matched."),
    1: ("SPKI", "Public key only. Recommended. Allows cert renewal without TLSA update."),
}

_TLSA_MATCHING = {
    0: ("Exact", "Exact match."),
    1: ("SHA-256", "SHA-256 hash. Recommended."),
    2: ("SHA-512", "SHA-512 hash."),
}


def _build_dane_deep(tlsa_records: List[Dict], dnssec_ok: bool) -> Optional[Dict]:
    """DANE/TLSA deep analysis: field breakdown, DNSSEC dependency, MX coverage."""
    if not tlsa_records:
        return None

    # DNSSEC gate
    if dnssec_ok is None and any(r.get("found") for r in tlsa_records):
        dnssec_status = {"status": "info", "text": (
            "TLSA records are published. The DNSSEC check did not complete, so "
            "whether DANE is effective here was not established."
        )}
    elif dnssec_ok and any(r.get("found") for r in tlsa_records):
        dnssec_status = {"status": "pass", "text": "DANE fully functional."}
    elif not dnssec_ok and any(r.get("found") for r in tlsa_records):
        dnssec_status = {"status": "fail", "text": (
            "DANE is INEFFECTIVE. Without DNSSEC, attackers can forge TLSA records. "
            "Senders implementing RFC 7672 will ignore non-DNSSEC TLSA records."
        )}
    elif dnssec_ok:
        dnssec_status = {"status": "partial", "text": (
            "DNSSEC active. Your domain supports DANE. Adding TLSA records provides "
            "certificate verification independent of CAs."
        )}
    else:
        dnssec_status = {"status": "info", "text": "Neither DNSSEC nor DANE configured."}

    # MX coverage
    hosts_with = [r["mx_host"] for r in tlsa_records if r.get("found")]
    hosts_without = [r["mx_host"] for r in tlsa_records if not r.get("found") and not r.get("error")]

    # Parse TLSA fields from records that were found
    parsed_tlsa = []
    for r in tlsa_records:
        if not r.get("found") or not r.get("records"):
            continue
        for rec in r.get("records", []):
            try:
                # Records are dicts with usage/selector/matching_type keys
                if isinstance(rec, dict):
                    usage = int(rec.get("usage", -1))
                    selector = int(rec.get("selector", -1))
                    matching = int(rec.get("matching_type", -1))
                else:
                    # Legacy fallback: raw string "usage selector matching data"
                    parts = rec.strip().split()
                    if len(parts) < 4:
                        continue
                    usage = int(parts[0])
                    selector = int(parts[1])
                    matching = int(parts[2])

                usage_info = _TLSA_USAGE.get(usage, ("Unknown", f"Usage {usage}"))
                sel_info = _TLSA_SELECTOR.get(selector, ("Unknown", f"Selector {selector}"))
                match_info = _TLSA_MATCHING.get(matching, ("Unknown", f"Matching {matching}"))

                is_best = usage == 3 and selector == 1 and matching == 1
                rotation_safe = selector == 1

                parsed_tlsa.append({
                    "mx_host": r["mx_host"],
                    "usage": usage, "usage_label": usage_info[0], "usage_desc": usage_info[1],
                    "selector": selector, "selector_label": sel_info[0], "selector_desc": sel_info[1],
                    "matching": matching, "matching_label": match_info[0], "matching_desc": match_info[1],
                    "is_best_practice": is_best,
                    "rotation_safe": rotation_safe,
                })
            except (ValueError, IndexError, TypeError):
                pass

    return {
        "dnssec_status": dnssec_status,
        "hosts_with_tlsa": hosts_with,
        "hosts_without_tlsa": hosts_without,
        "parsed_records": parsed_tlsa,
    }


# ============================================================
# Nameservers
# ============================================================

def _is_subdomain(domain: str) -> bool:
    """Return True if the domain appears to be a subdomain (3 or more labels)."""
    if not domain:
        return False
    labels = domain.rstrip(".").split(".")
    return len(labels) >= 3


def transform_nameservers(raw: Dict, domain: str = "") -> Dict:
    # A SERVFAIL, NoNameservers, or a timeout never produced a real answer,
    # so ns_count staying 0 here is not evidence the domain has no NS
    # records. This is what 28c644c already fixed for DNSSEC and CAA;
    # nameservers reached the same failure mode through
    # _raw_check_nameservers's generic DNSException handler and was missed.
    if raw.get("lookup_failed"):
        return _lookup_unavailable_card("Nameservers", raw, "nameserver records")

    ns_count = raw.get("ns_count", 0)
    nameservers = raw.get("nameservers", [])
    providers = raw.get("providers", [])
    networks = raw.get("networks", [])
    issues = raw.get("issues", [])
    status = _map_status(raw.get("status", "ok"))

    if ns_count == 0:
        if _is_subdomain(domain):
            return {
                "name": "Nameservers",
                "status": "pass",
                "pill_label": "Inherited",
                "verdict": "Nameservers inherited from parent zone",
                "record": None,
                "explanation": (
                    "This is a subdomain, so it uses the nameservers from its parent zone. "
                    "This is normal. Subdomains do not need their own NS delegation unless "
                    "they are a separate DNS zone."
                ),
                "details": [
                    {"type": "info", "text": "Subdomain - NS records are at the parent zone level"},
                ],
                "fix": None,
                "fix_records": None,
            }

        details = []
        for issue in issues:
            details.append(_issue_to_detail(issue))

        return {
            "name": "Nameservers",
            "status": "fail",
            "pill_label": "Missing",
            "verdict": "No nameservers found",
            "record": None,
            "explanation": (
                "No nameserver records could be found for this domain. Nameservers are the "
                "foundation of DNS. Without them, nothing works: no website, no email, no DNS resolution."
            ),
            "details": details,
            "fix": "Configure NS records with your domain registrar.",
            "fix_records": None,
        }

    # Build record display
    record_lines = []
    for ns in nameservers:
        ips = []
        if ns.get("ipv4"):
            ips.extend(ns["ipv4"])
        if ns.get("ipv6"):
            ips.extend(ns["ipv6"])
        ip_str = f" ({', '.join(ips)})" if ips else ""
        record_lines.append(f"{ns['hostname']}{ip_str}")
    record = "\n".join(record_lines)

    # Details
    details = []

    # NS count
    if ns_count >= 3:
        details.append({"type": "good", "text": f"{ns_count} nameservers configured (good redundancy)"})
    elif ns_count == 2:
        details.append({"type": "good", "text": "2 nameservers configured (minimum redundancy)"})
    elif ns_count == 1:
        details.append({"type": "error", "text": "Only 1 nameserver (single point of failure)"})

    # Resolution and authoritative status
    resolving = [ns for ns in nameservers if ns.get("resolves")]
    not_resolving = [ns for ns in nameservers if not ns.get("resolves")]
    if not_resolving:
        for ns in not_resolving:
            details.append({"type": "error", "text": f"{ns['hostname']} does not resolve (lame delegation)"})
    if resolving:
        for ns in resolving:
            ip = ns.get("ipv4", [""])[0] if ns.get("ipv4") else ""
            ip_part = f" ({ip})" if ip else ""
            auth = ns.get("authoritative")
            rtt = ns.get("response_time_ms")
            if auth is True:
                rtt_str = f", {rtt}ms" if rtt is not None else ""
                details.append({"type": "good", "text": f"{ns['hostname']}{ip_part}: authoritative{rtt_str}"})
            elif auth is False:
                details.append({"type": "error", "text": f"{ns['hostname']}{ip_part}: NOT authoritative (lame delegation)"})
            else:
                # auth is None -- query failed or not attempted
                ipv4_str = ", ".join(ns.get("ipv4", []))
                ipv6_count = len(ns.get("ipv6", []))
                ip_info = ipv4_str
                if ipv6_count:
                    ip_info += f" + {ipv6_count} IPv6"
                if ip_info:
                    details.append({"type": "good", "text": f"{ns['hostname']} resolves ({ip_info})"})
                else:
                    details.append({"type": "good", "text": f"{ns['hostname']} resolves"})

    # SOA serial consistency
    soa_consistent = raw.get("soa_serials_consistent")
    soa_serial = raw.get("soa_serial")
    if soa_consistent is True and soa_serial is not None:
        details.append({"type": "good", "text": f"SOA serials consistent ({soa_serial})"})
    elif soa_consistent is False:
        details.append({"type": "warning", "text": "SOA serial mismatch across nameservers (zone sync issue)"})

    # Network diversity
    if len(networks) >= 2:
        details.append({"type": "good", "text": f"Network diversity: {len(networks)} distinct /24 networks"})

    # Providers
    if providers:
        if len(providers) >= 2:
            details.append({"type": "good", "text": f"Multi-provider: {', '.join(providers)}"})
        else:
            details.append({"type": "info", "text": f"Provider: {providers[0]}"})

    # IPv6
    has_ipv6 = any(ns.get("ipv6") for ns in nameservers)
    if has_ipv6:
        details.append({"type": "good", "text": "IPv6 nameserver support (AAAA records present)"})

    # Where the blocklist check used to be. This audit does not test blocklist
    # listings: Spamhaus refuses DNSBL queries from public and cloud resolvers
    # and this service runs on both, so the check never returned a result in
    # production. Rather than keep a card that assessed nothing, the pointer
    # goes here, on the DNS infrastructure card, for anyone who wants one.
    details.append({
        "type": "info",
        "text": (
            "This audit does not check blocklist listings. Blocklist operators "
            "refuse queries from cloud-hosted resolvers, so the answer would not "
            "be reliable. Check yours at check.spamhaus.org"
        ),
    })

    # Append issues (skip ones already covered by hardcoded details above)
    covered_keywords = {"only one nameserver", "lame delegation", "does not resolve"}
    for issue in issues:
        text = (issue.get("issue") or "").lower()
        if not any(kw in text for kw in covered_keywords):
            details.append(_issue_to_detail(issue))

    # Verdict
    if providers:
        verdict = ", ".join(providers)
    else:
        verdict = f"{ns_count} nameserver{'s' if ns_count != 1 else ''}"

    # A pass card carries no fix; a suggestion like adding a secondary
    # provider is an optional improvement, already listed as an info
    # detail above, not something a passing card should also be fixing.
    fix = None if status == "pass" else _first_fix(issues)

    return {
        "name": "Nameservers",
        "status": status,
        "verdict": verdict,
        "record": record,
        "explanation": (
            f"Found <strong>{ns_count}</strong> nameserver{'s' if ns_count != 1 else ''} for this domain. "
            "Nameservers are authoritative for your DNS zone. They answer queries for all your "
            "DNS records. Multiple nameservers on distinct network paths reduce the risk of a "
            "single point of failure causing a full DNS outage for your domain."
        ),
        "details": details,
        "fix": fix,
        "fix_records": None,
        "ttl_info": format_ttl(raw.get("ttl")),
    }


# ============================================================
# Certificate Transparency
# ============================================================

def transform_ct(raw: Dict, domain: str) -> Dict:
    total = raw.get("total_certs", 0)
    active = raw.get("active_certs", 0)
    issuers = raw.get("issuers", [])
    wildcards = raw.get("wildcards", [])
    expiring = raw.get("expiring_soon", [])
    expired = raw.get("expired_recent", [])
    subdomains = raw.get("subdomains_found", [])
    caa_mismatches = raw.get("caa_mismatches", [])
    issues = raw.get("issues", [])
    raw_status = raw.get("status", "info")
    unavailable_reason = raw.get("unavailable_reason")

    # Query failed or data was unavailable -- distinguish from a genuine empty result
    if raw_status in ("warning", "unavailable") and total == 0:
        if unavailable_reason == "response_too_large":
            verdict = "CT log query unavailable (too many certificates)"
            explanation = (
                "The Certificate Transparency log query returned more data than could be processed. "
                "This domain has a very large number of certificates on record. "
                "Use crt.sh directly to browse certificates for this domain."
            )
            detail_text = "CT log response too large to analyze automatically"
        else:
            verdict = "Not checked by this audit"
            explanation = (
                "Certificate Transparency was not assessed for this domain. This audit reads CT "
                "data from the public crt.sh service, which is frequently unavailable, and no "
                "result was returned in time. Nothing here reflects your domain's certificates "
                "one way or the other. To review them yourself, search this domain on "
                "<a href=\"https://crt.sh\" target=\"_blank\" rel=\"noopener\">crt.sh</a>."
            )
            detail_text = (
                "This check depends on an external service that did not respond. It is a gap in "
                "the audit, not a finding about your domain."
            )
        return {
            "name": "Certificate Transparency",
            # Not "pass". Nothing about the domain was assessed, and a green
            # card for a check that never ran is the most misleading state
            # this card can be in.
            "status": "unavailable",
            "pill_label": "Not checked",
            "verdict": verdict,
            "record": None,
            "explanation": explanation,
            "details": [
                {"type": "info", "text": detail_text},
            ],
            "fix": None,
            "fix_records": None,
        }

    # No certs found (genuine empty result, not an error)
    if total == 0:
        return {
            "name": "Certificate Transparency",
            "status": "pass",
            "pill_label": "No certs",
            "verdict": "No certificates found in CT logs",
            "record": None,
            "explanation": (
                "No certificates were found in Certificate Transparency logs for this domain. "
                "This likely means the domain has never had HTTPS configured."
            ),
            "details": [
                {"type": "info", "text": "No certificates found in public CT logs"},
            ],
            "fix": None,
            "fix_records": None,
        }

    # Determine status
    status = "pass"
    pill_label = None
    if caa_mismatches:
        status = "warn"
        pill_label = "CAA mismatch"
    elif expiring:
        status = "warn"
        pill_label = "Expiring"
    elif active == 0:
        # Certificates exist in CT logs but none are currently active. A
        # domain with no valid certificate on record is not a pass.
        status = "warn"
        pill_label = "No active certs"
    else:
        pill_label = f"{active} cert{'s' if active != 1 else ''}"

    # Verdict
    issuer_summary = ", ".join(i["name"] for i in issuers[:2])
    if len(issuers) > 2:
        issuer_summary += f" +{len(issuers) - 2} more"
    verdict = f"{active} active cert{'s' if active != 1 else ''} from {len(issuers)} issuer{'s' if len(issuers) != 1 else ''}"

    # Explanation
    explanation = (
        f"Found <strong>{total}</strong> certificate{'s' if total != 1 else ''} in Certificate Transparency logs "
        f"(<a href=\"https://datatracker.ietf.org/doc/html/rfc6962\" target=\"_blank\" rel=\"noopener\">RFC 6962</a>), of which <strong>{active}</strong> {'are' if active != 1 else 'is'} currently active. "
        f"CT logs provide a publicly auditable record of all certificates issued for your domain."
    )
    if caa_mismatches:
        explanation += (
            " <strong>Note:</strong> Some certificates were issued by CAs not listed in your CAA records. "
            "This may indicate issuance before CAA was configured, or a CAA policy gap."
        )

    # Details
    details = []
    details.append({
        "type": "good" if active else "warning",
        "text": f"{active} active cert{'s' if active != 1 else ''} from {len(issuers)} issuer{'s' if len(issuers) != 1 else ''}",
    })

    # Issuer breakdown
    issuer_parts = []
    for i in issuers[:5]:
        issuer_parts.append(f"{i['name']} ({i['count']})")
    if issuer_parts:
        details.append({"type": "info", "text": f"Issuers: {', '.join(issuer_parts)}"})

    # CAA mismatches
    for mm in caa_mismatches:
        details.append({
            "type": "warning",
            "text": f"CAA allows [{', '.join(mm['caa_allows'])}] but certs found from {mm['cert_issuer']}",
        })

    # Wildcards
    if wildcards:
        details.append({"type": "info", "text": f"{len(wildcards)} wildcard certificate{'s' if len(wildcards) != 1 else ''} found"})

    # Expiring
    for exp in expiring[:3]:
        _days = exp["days_left"]
        if _days == 0:
            _when = "Expiring today"
        else:
            _when = f"Expiring in {_days} day{'s' if _days != 1 else ''}"
        details.append({
            "type": "warning",
            "text": f"{_when}: {exp['common_name']}",
        })

    # Recently expired. The CT check has always collected these; nothing
    # displayed them.
    for exp in expired[:3]:
        details.append({
            "type": "info",
            "text": f"Expired in the last 90 days: {exp['common_name']}",
        })
    if len(expired) > 3:
        details.append({
            "type": "info",
            "text": f"{len(expired) - 3} further certificates expired in the last 90 days",
        })

    # Certificate sprawl
    if len(issuers) > 5:
        details.append({"type": "info", "text": f"Certificates from {len(issuers)} different CAs. Consider consolidating"})

    # Subdomains
    if subdomains:
        details.append({"type": "info", "text": f"{len(subdomains)} unique subdomain{'s' if len(subdomains) != 1 else ''} discovered via CT"})

    # Append raw issues
    for issue in issues:
        details.append(_issue_to_detail(issue))

    # Fix (only for CAA mismatches)
    fix = None
    if caa_mismatches:
        mismatched_cas = ", ".join(mm["cert_issuer"] for mm in caa_mismatches[:3])
        fix = (
            f"Review certificates from <strong>{_e(mismatched_cas)}</strong>. "
            f"If these CAs should be authorized, add them to your CAA record. "
            f"If they should not be, consider requesting revocation. "
            f"Certificates issued before CAA records were in place will expire naturally."
        )

    return {
        "name": "Certificate Transparency",
        "status": status,
        "pill_label": pill_label,
        "verdict": verdict,
        "record": None,
        "explanation": explanation,
        "details": details,
        "fix": fix,
        "fix_records": None,
    }




# ============================================================
# Provider Intelligence (Prompt 19)
# ============================================================

# --- Provider detection rules ---

_PROVIDER_MX_PATTERNS: List[Tuple[str, str, str]] = [
    # (substring in MX host, provider_id, category)
    (".google.com", "google_workspace", "mailbox"),
    (".googlemail.com", "google_workspace", "mailbox"),
    (".mail.protection.outlook.com", "microsoft_365", "mailbox"),
    (".pphosted.com", "proofpoint", "gateway"),
    (".mimecast.com", "mimecast", "gateway"),
    (".barracudanetworks.com", "barracuda", "gateway"),
    (".zoho.com", "zoho", "mailbox"),
    (".protonmail.ch", "protonmail", "mailbox"),
    (".fastmail.com", "fastmail", "mailbox"),
]

_PROVIDER_SPF_PATTERNS: List[Tuple[str, str, str]] = [
    ("include:_spf.google.com", "google_workspace", "mailbox"),
    ("include:spf.protection.outlook.com", "microsoft_365", "mailbox"),
    ("include:pphosted.com", "proofpoint", "gateway"),
    ("include:_netblocks.mimecast.com", "mimecast", "gateway"),
    ("include:spf.barracudanetworks.com", "barracuda", "gateway"),
    ("include:zoho.com", "zoho", "mailbox"),
    ("include:_spf.protonmail.ch", "protonmail", "mailbox"),
    ("include:spf.messagingengine.com", "fastmail", "mailbox"),
    ("include:amazonses.com", "amazon_ses", "sending"),
    # Sending services
    ("include:sendgrid.net", "sendgrid", "sending"),
    ("include:servers.mcsv.net", "mailchimp", "sending"),
    ("include:mailgun.org", "mailgun", "sending"),
    ("include:mandrillapp.com", "mandrill", "sending"),
    ("include:hubspot.com", "hubspot", "sending"),
    ("include:_spf.salesforce.com", "salesforce", "sending"),
    ("include:mail.zendesk.com", "zendesk", "sending"),
    ("include:email.freshdesk.com", "freshdesk", "sending"),
    ("include:ccsend.com", "constant_contact", "sending"),
    ("include:_spf.createsend.com", "campaign_monitor", "sending"),
]

_PROVIDER_DKIM_SELECTORS: Dict[str, Tuple[str, str]] = {
    "google": ("google_workspace", "mailbox"),
    "selector1": ("microsoft_365", "mailbox"),
    "selector2": ("microsoft_365", "mailbox"),
    "s1": ("sendgrid", "sending"),
    "s2": ("sendgrid", "sending"),
    "k1": ("mailchimp", "sending"),
    "mandrill": ("mandrill", "sending"),
    "hubspot": ("hubspot", "sending"),
    "salesforce": ("salesforce", "sending"),
    "zendesk1": ("zendesk", "sending"),
    "zendesk2": ("zendesk", "sending"),
    "protonmail": ("protonmail", "mailbox"),
    "fm1": ("fastmail", "mailbox"),
    "fm2": ("fastmail", "mailbox"),
    "fm3": ("fastmail", "mailbox"),
}

_PROVIDER_META: Dict[str, Dict] = {
    "google_workspace": {
        "name": "Google Workspace",
        "category": "mailbox",
        "badge_class": "pi-badge-google",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": True,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": False,
            "bimi": True,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Google Workspace supports 2048-bit DKIM. Enable in "
                    "Admin Console > Apps > Google Workspace > Gmail > Authenticate Email."
                ),
            },
            {
                "topic": "DMARC",
                "text": (
                    "Google recommends setting up rua= first, monitoring for 2 weeks, "
                    "then moving to enforcement."
                ),
            },
            {
                "topic": "Known issue",
                "text": (
                    "Google rewrites the envelope sender for forwarded mail, which can "
                    "break SPF alignment. DKIM is the more reliable alignment mechanism."
                ),
            },
        ],
    },
    "microsoft_365": {
        "name": "Microsoft 365",
        "category": "mailbox",
        "badge_class": "pi-badge-microsoft",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": True,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": True,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Enable DKIM signing in Microsoft 365 Defender > "
                    "Email Authentication > DKIM. Both selector1 and selector2 "
                    "should be published."
                ),
            },
            {
                "topic": "DMARC",
                "text": (
                    "Microsoft DMARC reporting can be configured in the "
                    "Microsoft 365 admin center."
                ),
            },
            {
                "topic": "Known issue",
                "text": (
                    "Microsoft 365 uses selector1 and selector2 DKIM selectors. "
                    "Both must be rotated when key rotation is needed."
                ),
            },
        ],
    },
    "proofpoint": {
        "name": "Proofpoint",
        "category": "gateway",
        "badge_class": "pi-badge-proofpoint",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": True,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "Gateway",
                "text": (
                    "Proofpoint acts as a mail gateway. DMARC alignment depends on "
                    "Proofpoint's configuration of envelope sender and DKIM signing."
                ),
            },
            {
                "topic": "SPF efficiency",
                "text": (
                    "Proofpoint's macro-based SPF "
                    "(%{ir}.%{v}.%{d}.spf.has.pphosted.com) is efficient, "
                    "using only 1 DNS lookup regardless of IP count."
                ),
            },
        ],
    },
    "mimecast": {
        "name": "Mimecast",
        "category": "gateway",
        "badge_class": "pi-badge-mimecast",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": True,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "Gateway",
                "text": (
                    "Mimecast acts as a mail gateway. Ensure DKIM signing is "
                    "configured in Mimecast to maintain alignment through the gateway."
                ),
            },
        ],
    },
    "barracuda": {
        "name": "Barracuda",
        "category": "gateway",
        "badge_class": "pi-badge-barracuda",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "Gateway",
                "text": (
                    "Barracuda acts as a mail gateway. Verify DKIM signing "
                    "is configured to preserve alignment."
                ),
            },
        ],
    },
    "zoho": {
        "name": "Zoho Mail",
        "category": "mailbox",
        "badge_class": "pi-badge-zoho",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": False,
            "bimi": True,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Zoho supports 2048-bit DKIM. Enable in Zoho Mail Admin > "
                    "Email Authentication > DKIM."
                ),
            },
        ],
    },
    "protonmail": {
        "name": "ProtonMail",
        "category": "mailbox",
        "badge_class": "pi-badge-protonmail",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": False,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "ProtonMail automatically manages DKIM signing with "
                    "2048-bit keys for custom domains."
                ),
            },
        ],
    },
    "fastmail": {
        "name": "Fastmail",
        "category": "mailbox",
        "badge_class": "pi-badge-fastmail",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": True,
            "mta_sts": True,
            "tls_rpt": True,
            "dane": False,
            "bimi": True,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Fastmail automatically manages DKIM keys (fm1, fm2, fm3 selectors) "
                    "and supports automatic key rotation."
                ),
            },
        ],
    },
    "amazon_ses": {
        "name": "Amazon SES",
        "category": "sending",
        "badge_class": "pi-badge-ses",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Amazon SES uses Easy DKIM with automatic 2048-bit key rotation. "
                    "Enable in SES Console > Verified Identities > Authentication."
                ),
            },
        ],
    },
    "sendgrid": {
        "name": "SendGrid",
        "category": "sending",
        "badge_class": "pi-badge-sendgrid",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "SendGrid supports automated domain authentication with DKIM. "
                    "Configure in Settings > Sender Authentication."
                ),
            },
        ],
    },
    "mailchimp": {
        "name": "Mailchimp",
        "category": "sending",
        "badge_class": "pi-badge-mailchimp",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [
            {
                "topic": "DKIM",
                "text": (
                    "Mailchimp requires custom DKIM (k1 selector) for authenticated "
                    "sending. Set up in Account > Domains > Verify."
                ),
            },
        ],
    },
    "mailgun": {
        "name": "Mailgun",
        "category": "sending",
        "badge_class": "pi-badge-mailgun",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": True,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "mandrill": {
        "name": "Mandrill",
        "category": "sending",
        "badge_class": "pi-badge-mandrill",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "hubspot": {
        "name": "HubSpot",
        "category": "sending",
        "badge_class": "pi-badge-hubspot",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "salesforce": {
        "name": "Salesforce",
        "category": "sending",
        "badge_class": "pi-badge-salesforce",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "zendesk": {
        "name": "Zendesk",
        "category": "sending",
        "badge_class": "pi-badge-zendesk",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "freshdesk": {
        "name": "Freshdesk",
        "category": "sending",
        "badge_class": "pi-badge-freshdesk",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "constant_contact": {
        "name": "Constant Contact",
        "category": "sending",
        "badge_class": "pi-badge-constantcontact",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
    "campaign_monitor": {
        "name": "Campaign Monitor",
        "category": "sending",
        "badge_class": "pi-badge-campaignmonitor",
        "capabilities": {
            "dkim_2048": True,
            "dkim_auto_rotation": False,
            "arc": False,
            "mta_sts": False,
            "tls_rpt": False,
            "dane": False,
            "bimi": False,
        },
        "guidance": [],
    },
}

_CATEGORY_LABELS = {
    "mailbox": "Email Provider",
    "gateway": "Security Gateway",
    "sending": "Sending Service",
}

_FEATURE_LABELS = {
    "dkim_2048": "DKIM 2048-bit",
    "dkim_auto_rotation": "DKIM auto-rotation",
    "arc": "ARC (forwarding)",
    "mta_sts": "MTA-STS",
    "tls_rpt": "TLS-RPT",
    "dane": "DANE",
    "bimi": "BIMI",
}


def _detect_providers(raw_results: Dict) -> Dict[str, Dict]:
    """Detect email providers from MX, SPF, and DKIM data.

    Returns dict of provider_id -> {source: set of detection sources}.
    """
    detected: Dict[str, Dict] = {}

    def _add(pid: str, source: str, category: str):
        if pid not in detected:
            detected[pid] = {"sources": set(), "category": category}
        detected[pid]["sources"].add(source)

    # MX records
    mx_raw = raw_results.get("mx", {})
    mx_records = mx_raw.get("records", []) or []
    for rec in mx_records:
        host = rec.split()[-1].lower() if rec else ""
        for pattern, pid, cat in _PROVIDER_MX_PATTERNS:
            if pattern in host:
                _add(pid, "MX", cat)

    # SPF record
    spf_raw = raw_results.get("spf", {})
    spf_record = (spf_raw.get("record") or "").lower()
    for pattern, pid, cat in _PROVIDER_SPF_PATTERNS:
        if pattern in spf_record:
            _add(pid, "SPF", cat)

    # Also check for Proofpoint macro-based SPF
    if "pphosted.com" in spf_record:
        _add("proofpoint", "SPF", "gateway")

    # DKIM selectors
    dkim_raw = raw_results.get("dkim", {})
    found_selectors = dkim_raw.get("found_selectors", []) or []
    for sel in found_selectors:
        sel_name = (sel.get("selector") or "").lower()
        if sel_name in _PROVIDER_DKIM_SELECTORS:
            pid, cat = _PROVIDER_DKIM_SELECTORS[sel_name]
            _add(pid, "DKIM", cat)
        # Amazon SES pattern: selectors containing "ses"
        if "ses" in sel_name and "amazon_ses" not in detected:
            _add("amazon_ses", "DKIM", "sending")

    return detected


def _check_domain_features(raw_results: Dict, checks: List[Dict]) -> Dict[str, str]:
    """Check which security features the domain has enabled.

    Returns feature_id -> "yes" | "no" | "unknown".
    """
    result = {}
    check_map = {(c.get("name") or "").upper(): c for c in checks}

    # DKIM 2048-bit: check if any found key is >= 2048 bits.
    #
    # Live keys only. A revoked selector (empty p=, RFC 6376 3.6.1) yields no
    # bit length, so counting one as "has DKIM" scored the domain "no" on this
    # row: an assertion that its keys fall short of 2048 bits, about a domain
    # with no keys. google.com published five revoked selectors and nothing
    # live, and this row contradicted its own DKIM card two sections above.
    # Same expression, same fix as remediation_planner._has_live_dkim_key.
    dkim_raw = raw_results.get("dkim", {})
    found_selectors, _revoked = _split_dkim_selectors(
        dkim_raw.get("found_selectors", []) or []
    )
    has_2048 = False
    has_any_dkim = bool(found_selectors)
    for sel in found_selectors:
        rec = sel.get("record", "")
        if rec:
            analysis = analyze_dkim_key_strength(rec)
            if analysis.get("key_bits", 0) >= 2048:
                has_2048 = True
                break
    if has_any_dkim:
        result["dkim_2048"] = "yes" if has_2048 else "no"
    else:
        result["dkim_2048"] = "unknown"

    # DKIM auto-rotation: cannot determine from DNS alone
    result["dkim_auto_rotation"] = "unknown"

    # ARC: cannot determine from DNS alone (header-based)
    result["arc"] = "n/a"

    # MTA-STS
    mta_sts_check = check_map.get("MTA-STS", {})
    mta_sts_status = mta_sts_check.get("status", "")
    if mta_sts_status == "pass":
        result["mta_sts"] = "yes"
    elif mta_sts_status in ("fail", "warn"):
        result["mta_sts"] = "no"
    else:
        result["mta_sts"] = "unknown"

    # TLS-RPT
    tls_rpt_check = check_map.get("TLS-RPT", {})
    tls_rpt_status = tls_rpt_check.get("status", "")
    if tls_rpt_status == "pass":
        result["tls_rpt"] = "yes"
    elif tls_rpt_status in ("fail", "warn"):
        result["tls_rpt"] = "no"
    else:
        result["tls_rpt"] = "unknown"

    # DANE
    dane_check = check_map.get("DANE", {})
    dane_status = dane_check.get("status", "")
    if dane_status == "pass":
        result["dane"] = "yes"
    elif dane_status in ("fail", "warn"):
        result["dane"] = "no"
    else:
        result["dane"] = "unknown"

    # BIMI
    bimi_check = check_map.get("BIMI", {})
    bimi_status = bimi_check.get("status", "")
    if bimi_status == "pass":
        result["bimi"] = "yes"
    elif bimi_status in ("fail", "warn"):
        result["bimi"] = "no"
    else:
        result["bimi"] = "unknown"

    return result


def _build_provider_intelligence(
    raw_results: Dict, checks: List[Dict]
) -> Optional[Dict]:
    """Build provider intelligence data for the frontend.

    Identifies what email platform/provider the domain uses and provides
    provider-specific guidance, detection sources, and a security scorecard.

    Returns None if no providers are detected.
    """
    detected = _detect_providers(raw_results)
    if not detected:
        return None

    domain_features = _check_domain_features(raw_results, checks)

    # Separate into primary (mailbox/gateway) and sending services
    primary_providers = []
    sending_services = []

    for pid, info in detected.items():
        meta = _PROVIDER_META.get(pid)
        if not meta:
            continue

        category = meta["category"]
        sources = sorted(info["sources"])

        # Build scorecard for this provider
        scorecard = []
        caps = meta.get("capabilities", {})
        for feat_id, feat_label in _FEATURE_LABELS.items():
            provider_supports = caps.get(feat_id, False)
            domain_status = domain_features.get(feat_id, "unknown")

            scorecard.append({
                "feature": feat_label,
                "provider_supports": provider_supports,
                "domain_status": domain_status,
            })

        provider_data = {
            "id": pid,
            "name": meta["name"],
            "category": category,
            "category_label": _CATEGORY_LABELS.get(category, category),
            "badge_class": meta.get("badge_class", ""),
            "detected_via": sources,
            "guidance": meta.get("guidance", []),
            "scorecard": scorecard,
        }

        if category in ("mailbox", "gateway"):
            primary_providers.append(provider_data)
        else:
            sending_services.append(provider_data)

    if not primary_providers and not sending_services:
        return None

    # Detect gateway + upstream pattern (e.g., Proofpoint + Google Workspace)
    gateway_upstream = None
    gateways = [p for p in primary_providers if p["category"] == "gateway"]
    mailboxes = [p for p in primary_providers if p["category"] == "mailbox"]
    if gateways and mailboxes:
        gateway_upstream = {
            "gateway": gateways[0]["name"],
            "upstream": mailboxes[0]["name"],
            "note": (
                f"{gateways[0]['name']} is routing mail to {mailboxes[0]['name']}. "
                f"DKIM signing and SPF alignment must be configured at both layers."
            ),
        }

    return {
        "primary_providers": primary_providers,
        "sending_services": sending_services,
        "gateway_upstream": gateway_upstream,
    }
