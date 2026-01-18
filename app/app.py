"""
DNS Security Auditor - Streamlit Web Interface
Run with: streamlit run app.py
"""

import streamlit as st
import json
from datetime import datetime
from dns_security_auditor.dns_tools import audit_email_security, audit_dns_security, format_report, normalize_domain

st.set_page_config(page_title="DNS Security Auditor", page_icon="🛡️", layout="wide")

st.title("🛡️ DNS Security Auditor")
st.write("Email authentication & DNS security analysis")

# Input
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    domain = st.text_input("Domain to audit", placeholder="example.com")
    scope = st.radio("Scope", ["Email Security", "Full DNS Security"], horizontal=True)
    run = st.button("🚀 Run Audit", type="primary", use_container_width=True)


@st.cache_data(ttl=300)
def run_audit_cached(domain: str, scope: str):
    if scope == "Full DNS Security":
        return audit_dns_security(domain)
    return audit_email_security(domain)
if run and domain:
    domain = normalize_domain(domain)
    
    with st.spinner(f"Analyzing {domain}..."):
        results = run_audit_cached(domain, scope)
    
    # Summary
    s = results["summary"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total", sum(s.values()))
    c2.metric("✅ Pass", s["ok"])
    c3.metric("⚠️ Warn", s["warning"])
    c4.metric("🔴 Fail", s["error"])
    
    # Priority fixes
    if results.get("priority_fixes"):
        st.subheader("🎯 Priority Fixes")
        for i, fix in enumerate(results["priority_fixes"][:5], 1):
            st.warning(f"{i}. {fix[:200]}...")
    
    # Results
    st.subheader("📋 Results")
    for name, check in results["checks"].items():
        status = check.get("status", "unknown")
        icon = {"ok": "✅", "warning": "⚠️", "error": "🔴"}.get(status, "❓")
        
        with st.expander(f"{icon} {check.get('check', name.upper())}", expanded=(status != "ok")):
            if check.get("record"):
                st.code(check["record"], language="text")
            
            for issue in check.get("issues", []):
                st.error(issue)
            for warn in check.get("warnings", []):
                st.info(warn) if status == "ok" else st.warning(warn)
            for rec in check.get("recommendations", []):
                st.info(f"💡 {rec}")
    
    # Export
    st.divider()
    col_a, col_b = st.columns(2)
    with col_a:
        st.download_button("📄 Download Report", format_report(results, "full"), f"audit-{domain}.txt", "text/plain")
    with col_b:
        st.download_button("📊 Download JSON", json.dumps(results, indent=2, default=str), f"audit-{domain}.json", "application/json")

elif run:
    st.error("Please enter a domain")
