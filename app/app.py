# app/app.py
import os
import sys
import streamlit as st

# Add src/ to Python path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from dns_security_auditor.dns_tools import (
    audit_email_security,
    audit_dns_security,
    format_report,
    normalize_domain,
)

# Page Config (mobile optimized)
st.set_page_config(
    page_title="DNS Security Auditor",
    page_icon="🛡️",
    layout="centered",
)

# Custom Styles
theme_css = """
<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 900px;
        margin: auto;
    }
    div.stButton > button:first-child {
        background-color: #4a90e2;
        color: white;
        border: none;
        padding: 0.5rem 1.25rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 1rem;
    }
    div.stButton > button:hover {
        background-color: #3978c0;
        color: #fff;
    }
    .stTextInput > div > input,
    .stSelectbox > div > div > select,
    .stRadio > div,
    .stTextArea > div > textarea {
        font-size: 0.95rem;
    }
    .stMarkdown h3 {
        margin-top: 1.5rem;
        margin-bottom: 0.5rem;
    }
</style>
"""

st.markdown(theme_css, unsafe_allow_html=True)

# Check Categories
def get_check_categories():
    return {
        "Email Authentication": ["spf", "dkim", "dmarc"],
        "Email Transport Security": ["mta_sts", "tls_rpt", "bimi"],
        "DNS Infrastructure": ["mx", "dnssec", "caa", "ns"],
        "Security Risk Surface": ["zone_transfer", "subdomain_takeover"],
    }

CHECK_FUNCTIONS = {
    "mx": ("MX", lambda domain: audit_email_security(domain)["checks"].get("mx")),
    "spf": ("SPF", lambda domain: audit_email_security(domain)["checks"].get("spf")),
    "dkim": ("DKIM", lambda domain: audit_email_security(domain)["checks"].get("dkim")),
    "dmarc": ("DMARC", lambda domain: audit_email_security(domain)["checks"].get("dmarc")),
    "mta_sts": ("MTA-STS", lambda domain: audit_email_security(domain)["checks"].get("mta_sts")),
    "tls_rpt": ("TLS-RPT", lambda domain: audit_email_security(domain)["checks"].get("tls_rpt")),
    "dnssec": ("DNSSEC", lambda domain: audit_dns_security(domain)["checks"].get("dnssec")),
    "caa": ("CAA", lambda domain: audit_dns_security(domain)["checks"].get("caa")),
    "ns": ("NS", lambda domain: audit_dns_security(domain)["checks"].get("ns")),
    "zone_transfer": ("Zone Transfer", lambda domain: audit_dns_security(domain)["checks"].get("zone_transfer")),
    "subdomain_takeover": ("Subdomain Takeover", lambda domain: audit_dns_security(domain)["checks"].get("subdomain_takeover")),
    "bimi": ("BIMI", lambda domain: {"status": "warning", "issues": ["BIMI check not yet implemented"]}),
}

# Title
st.title("🛡️ DNS Security Auditor")
st.markdown("Audit DNS and Email Security for any domain.")

st.divider()

# Input Form
with st.form("audit_form"):
    st.subheader("🔍 Audit Configuration")

    domain_input = st.text_input("Domain", placeholder="example.com", help="Enter the domain you want to audit")

    mode = st.radio("Audit Mode", ["Predefined Scope", "Custom Selection"], horizontal=True)

    selected_checks = []

    if mode == "Predefined Scope":
        scope_option = st.selectbox("Audit Scope", list(get_check_categories().keys()))
        selected_checks = get_check_categories()[scope_option]
    else:
        st.markdown("**Select Individual Checks:**")
        for category, checks in get_check_categories().items():
            with st.expander(category):
                for check in checks:
                    if st.checkbox(CHECK_FUNCTIONS[check][0], key=check):
                        selected_checks.append(check)

    selectors_input = st.text_input("DKIM selectors (optional)", placeholder="selector1,selector2")
    submitted = st.form_submit_button("Run Audit", use_container_width=True)

# Run Audit
if submitted:
    if not domain_input:
        st.error("Please enter a domain.")
        st.stop()

    domain = normalize_domain(domain_input)
    dkim_selectors = [s.strip() for s in selectors_input.split(",") if s.strip()]

    with st.spinner(f"Auditing {domain}..."):
        results = {"checks": {}, "summary": {"ok": 0, "warning": 0, "error": 0}, "priority_fixes": []}
        for check in selected_checks:
            try:
                result = CHECK_FUNCTIONS[check][1](domain)
                results["checks"][check] = result
                status = result.get("status", "")
                if status in results["summary"]:
                    results["summary"][status] += 1
            except Exception as e:
                results["checks"][check] = {"status": "error", "issues": [str(e)]}
                results["summary"]["error"] += 1

    st.subheader(f"📊 Results for {domain}")
    summary = results.get("summary", {})
    st.markdown(f"✅ **Passed**: {summary.get('ok', 0)} | ⚠️ **Warnings**: {summary.get('warning', 0)} | 🔴 **Errors**: {summary.get('error', 0)}")

    if results.get("priority_fixes"):
        st.markdown("### 🎯 Priority Fixes")
        for fix in results["priority_fixes"]:
            st.markdown(f"- {fix}")

    with st.expander("📄 Full Report", expanded=True):
        report_text = format_report(results, "full")
        st.text_area("Audit Report", value=report_text, height=300)

    with st.expander("🔎 Raw JSON"):
        st.json(results)
