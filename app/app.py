"""
DNS Security Auditor - Streamlit Web Interface
Run with: PYTHONPATH=src streamlit run app/app.py
"""

import json
import streamlit as st

from dns_security_auditor.dns_tools import (
    check_dmarc,
    check_spf,
    check_dkim,
    check_mx,
    check_mta_sts,
    check_tls_rpt,
    check_dnssec,
    check_caa,
    check_ns,
    check_zone_transfer,
    check_subdomain_takeover,
    format_report,
    normalize_domain,
    build_priority_fixes,
)

st.set_page_config(page_title="DNS Security Auditor", page_icon="🛡️", layout="wide")

# ------------------------------------------------------------
# Scope Definitions
# ------------------------------------------------------------
SCOPES = {
    "DMARC Check": {
        "description": "SPF, DKIM, DMARC, MX — core email authentication",
        "checks": ["mx", "spf", "dkim", "dmarc"],
    },
    "Transport Security": {
        "description": "MTA-STS + TLS-RPT — encrypted delivery & reporting",
        "checks": ["mta_sts", "tls_rpt"],
    },
    "Email Security (Full)": {
        "description": "All email checks combined",
        "checks": ["mx", "spf", "dkim", "dmarc", "mta_sts", "tls_rpt"],
    },
    "DNS Infrastructure": {
        "description": "DNSSEC, CAA, NS — DNS hardening",
        "checks": ["dnssec", "caa", "ns"],
    },
    "Security Scan": {
        "description": "Zone Transfer, Subdomain Takeover — vulnerability checks",
        "checks": ["zone_transfer", "subdomain_takeover"],
    },
    "Complete Audit": {
        "description": "Everything",
        "checks": ["mx", "spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "dnssec", "caa", "ns", "zone_transfer", "subdomain_takeover"],
    },
}

CHECK_FUNCTIONS = {
    "mx": ("MX", check_mx),
    "spf": ("SPF", check_spf),
    "dkim": ("DKIM", check_dkim),
    "dmarc": ("DMARC", check_dmarc),
    "mta_sts": ("MTA-STS", check_mta_sts),
    "tls_rpt": ("TLS-RPT", check_tls_rpt),
    "dnssec": ("DNSSEC", check_dnssec),
    "caa": ("CAA", check_caa),
    "ns": ("NS", check_ns),
    "zone_transfer": ("Zone Transfer", check_zone_transfer),
    "subdomain_takeover": ("Subdomain Takeover", check_subdomain_takeover),
}

# ------------------------------------------------------------
# Custom CSS
# ------------------------------------------------------------
st.markdown("""
<style>
    /* Status cards */
    .status-card {
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
    
    /* Priority fixes box */
    .priority-box {
        background-color: #fff3cd;
        border: 2px solid #ffc107;
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    /* Record display */
    .record-display {
        background-color: #1e1e1e;
        color: #d4d4d4;
        border-radius: 0.25rem;
        padding: 0.75rem;
        font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
        font-size: 0.8rem;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
    }
    
    /* Scope description */
    .scope-desc {
        color: #666;
        font-size: 0.85rem;
        margin-top: -0.5rem;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------
st.title("🛡️ DNS Security Auditor")
st.caption("Audit email authentication and DNS security configurations")

# ------------------------------------------------------------
# Input Form
# ------------------------------------------------------------
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    domain = st.text_input("Domain to audit", placeholder="example.com")
    
    scope = st.radio(
        "What do you want to check?",
        list(SCOPES.keys()),
        index=0,
        horizontal=False,
    )
    st.markdown(f'<p class="scope-desc">{SCOPES[scope]["description"]}</p>', unsafe_allow_html=True)
    
    # Show DKIM selector input only for scopes that include DKIM
    if "dkim" in SCOPES[scope]["checks"]:
        dkim_selectors_raw = st.text_input(
            "DKIM selectors (optional)",
            placeholder="google, selector1, selector2",
            help="Enter known selectors for more accurate DKIM results"
        )
    else:
        dkim_selectors_raw = ""
    
    run = st.button("🚀 Run Audit", type="primary", use_container_width=True)


# ------------------------------------------------------------
# Run Audit
# ------------------------------------------------------------
def run_audit(domain: str, scope_name: str, dkim_selectors: list[str] | None = None) -> dict:
    """Run selected checks and compile results."""
    from datetime import datetime
    
    results = {
        "domain": domain,
        "audit_type": scope_name,
        "timestamp": datetime.now().isoformat(),
        "checks": {},
        "summary": {"ok": 0, "warning": 0, "error": 0},
        "priority_fixes": [],
    }
    
    checks_to_run = SCOPES[scope_name]["checks"]
    
    for check_key in checks_to_run:
        display_name, check_func = CHECK_FUNCTIONS[check_key]
        
        try:
            # Special handling for DKIM (needs selectors)
            if check_key == "dkim":
                check_result = check_func(domain, selectors=dkim_selectors)
            else:
                check_result = check_func(domain)
        except Exception as e:
            check_result = {
                "check": display_name,
                "status": "error",
                "issues": [f"Check failed: {e}"],
                "warnings": [],
                "recommendations": [],
            }
        
        results["checks"][check_key] = check_result
        status = check_result.get("status", "unknown")
        if status in results["summary"]:
            results["summary"][status] += 1
    
    results["priority_fixes"] = build_priority_fixes(results["checks"])
    return results


# ------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------
def get_status_style(status: str) -> tuple[str, str, str]:
    """Return (bg_color, border_color, icon) for status."""
    styles = {
        "ok": ("#d4edda", "#28a745", "✅"),
        "warning": ("#fff3cd", "#ffc107", "⚠️"),
        "error": ("#f8d7da", "#dc3545", "🔴"),
    }
    return styles.get(status, ("#e2e3e5", "#6c757d", "❓"))


def render_status_card(label: str, count: int, status: str):
    """Render a colored status metric card."""
    bg, border, icon = get_status_style(status)
    st.markdown(f"""
        <div style="background-color: {bg}; border-left: 4px solid {border}; 
                    padding: 1rem; border-radius: 0.5rem; text-align: center;">
            <div style="font-size: 1.75rem; font-weight: bold;">{count}</div>
            <div style="font-size: 0.85rem; color: #555;">{icon} {label}</div>
        </div>
    """, unsafe_allow_html=True)


def render_record(record: str):
    """Render a DNS record with dark theme monospace formatting."""
    if record:
        # Escape HTML
        import html
        escaped = html.escape(str(record))
        st.markdown(f'<div class="record-display">{escaped}</div>', unsafe_allow_html=True)


# ------------------------------------------------------------
# Display Results
# ------------------------------------------------------------
if run and domain:
    domain = normalize_domain(domain)
    dkim_selectors = [s.strip() for s in (dkim_selectors_raw or "").split(",") if s.strip()] or None

    with st.spinner(f"Analyzing {domain}..."):
        results = run_audit(domain, scope, dkim_selectors)

    # --------------------------------------------------------
    # Summary Cards
    # --------------------------------------------------------
    st.subheader(f"Results for `{domain}`")
    
    s = results.get("summary", {})
    total = sum(s.values())
    
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total", total)
    with c2:
        render_status_card("Passed", s.get("ok", 0), "ok")
    with c3:
        render_status_card("Warnings", s.get("warning", 0), "warning")
    with c4:
        render_status_card("Failed", s.get("error", 0), "error")

    st.markdown("<br>", unsafe_allow_html=True)

    # --------------------------------------------------------
    # Priority Fixes (at top, prominent)
    # --------------------------------------------------------
    if results.get("priority_fixes"):
        st.markdown("### 🎯 Fix These First")
        for i, fix in enumerate(results["priority_fixes"][:5], 1):
            # Parse out check name
            if fix.startswith("["):
                parts = fix.split("]", 1)
                check_tag = parts[0] + "]"
                fix_text = parts[1].strip() if len(parts) > 1 else ""
            else:
                check_tag = ""
                fix_text = fix
            
            # Show first line only, truncate if needed
            first_line = fix_text.split("\n")[0]
            if len(first_line) > 150:
                first_line = first_line[:147] + "..."
            
            st.warning(f"**{i}. {check_tag}** {first_line}")
        
        st.markdown("<br>", unsafe_allow_html=True)

    # --------------------------------------------------------
    # Detailed Results
    # --------------------------------------------------------
    st.markdown("### 📋 Details")
    
    checks = results.get("checks", {})
    
    # Sort: errors first, then warnings, then ok
    def sort_key(item):
        status = item[1].get("status", "unknown")
        return {"error": 0, "warning": 1, "ok": 2}.get(status, 3)
    
    sorted_checks = sorted(checks.items(), key=sort_key)
    
    for check_key, check in sorted_checks:
        status = check.get("status", "unknown")
        bg, border, icon = get_status_style(status)
        display_name = CHECK_FUNCTIONS.get(check_key, (check_key.upper(), None))[0]
        
        # Auto-expand failures/warnings, collapse passes
        expanded = status != "ok"
        
        with st.expander(f"{icon} {display_name}", expanded=expanded):
            # Record display
            record = check.get("record") or check.get("value")
            if record:
                render_record(record)
                st.markdown("")
            
            # DKIM: selector info
            if check_key == "dkim":
                selectors_found = check.get("selectors_found", [])
                selectors_checked = check.get("selectors_checked", [])
                
                if selectors_found:
                    st.success(f"Selectors found: {', '.join(selectors_found)}")
                elif selectors_checked:
                    sample = selectors_checked[:5]
                    more = f"... +{len(selectors_checked) - 5} more" if len(selectors_checked) > 5 else ""
                    st.info(f"Selectors checked: {', '.join(sample)}{more}")
                    st.caption(
                        "💡 No selectors found. To find yours: send a test email and check "
                        "the DKIM-Signature header for `s=selectorname`"
                    )
            
            # SPF: lookup count
            if check.get("dns_lookups") is not None:
                lookups = check["dns_lookups"]
                limit = check.get("lookup_limit", 10)
                pct = int((lookups / limit) * 100)
                
                if lookups > 10:
                    st.error(f"⚠️ DNS Lookups: **{lookups}/{limit}** — Exceeds RFC 7208 limit!")
                elif lookups > 7:
                    st.warning(f"DNS Lookups: **{lookups}/{limit}** — Approaching limit")
                else:
                    st.info(f"DNS Lookups: **{lookups}/{limit}**")
                
                st.progress(min(pct, 100) / 100)
            
            # Issues
            for issue in check.get("issues", []):
                st.error(issue)
            
            # Warnings/status messages
            for warn in check.get("warnings", []):
                if status == "ok":
                    st.success(warn)
                else:
                    st.warning(warn)
            
            # Recommendations
            for rec in check.get("recommendations", []):
                st.info(f"💡 {rec}")

    # --------------------------------------------------------
    # Downloads
    # --------------------------------------------------------
    st.divider()
    
    col_a, col_b = st.columns(2)
    with col_a:
        st.download_button(
            "📄 Download Text Report",
            format_report(results, "full"),
            f"audit-{domain}.txt",
            "text/plain",
            use_container_width=True,
        )
    with col_b:
        st.download_button(
            "📊 Download JSON",
            json.dumps(results, indent=2, default=str),
            f"audit-{domain}.json",
            "application/json",
            use_container_width=True,
        )

elif run:
    st.error("Please enter a domain")