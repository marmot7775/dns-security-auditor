"""
app.py - Streamlit Web Interface for DNS Security Auditor
Run with: streamlit run app.py
"""

import streamlit as st
import json
from dns_auditor.dns_tools import (
    audit_email_security,
    audit_dns_security,
    format_report,
)

# ----------------------------
# Load external CSS
# ----------------------------
def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

st.set_page_config(
    page_title="DNS Security Auditor",
    page_icon="🛡️",
    layout="wide",
)

# ----------------------------
# Header
# ----------------------------
st.title("🛡️ DNS Security Auditor")
st.caption(
    "Audit DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and DNS security with prioritized, actionable fixes."
)

# ----------------------------
# Form (grouped, centered)
# ----------------------------
with st.form("audit_form"):
    domain = st.text_input(
        "Domain",
        placeholder="example.com",
        label_visibility="collapsed",
    )

    scope = st.radio(
        "Audit Scope",
        ["Email Security", "Full DNS Security"],
        horizontal=True,
        label_visibility="collapsed",
    )

    submitted = st.form_submit_button("🚀 Run Audit")

# ----------------------------
# Results
# ----------------------------
if submitted and domain:
    domain = (
        domain.strip()
        .lower()
        .replace("http://", "")
        .replace("https://", "")
        .replace("www.", "")
        .split("/")[0]
    )

    with st.spinner(f"Auditing {domain}…"):
        results = (
            audit_dns_security(domain)
            if scope == "Full DNS Security"
            else audit_email_security(domain)
        )

    summary = results.get("summary", {})

    st.markdown(
        f"""
        <div style="text-align:center; font-size:1.1rem;">
            <b>✅ Passed</b>: {summary.get("ok", 0)}
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <b>⚠️ Warnings</b>: {summary.get("warning", 0)}
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <b>🔴 Errors</b>: {summary.get("error", 0)}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Priority Fixes
    if results.get("priority_fixes"):
        st.subheader("🎯 Priority Fixes")
        for fix in results["priority_fixes"]:
            st.warning(fix)

    # Detailed Results
    st.subheader("🔎 Detailed Results")
    for key, check in results.get("checks", {}).items():
        status = check.get("status", "unknown")
        icon = {"ok": "✅", "warning": "⚠️", "error": "🔴"}.get(status, "❓")
        expanded = status != "ok"

        with st.expander(
            f"{icon} {check.get('check', key.upper())}",
            expanded=expanded,
        ):
            if check.get("record"):
                st.code(check["record"])

            for issue in check.get("issues", []):
                st.error(issue)

            for warning in check.get("warnings", []):
                st.warning(warning)

            for rec in check.get("recommendations", []):
                st.info(f"💡 {rec}")

    # Full report + export
    st.divider()
    with st.expander("📄 Full Report & Export", expanded=False):
        st.download_button(
            "Download Text Report",
            format_report(results, "full"),
            file_name=f"audit-{domain}.txt",
            mime="text/plain",
        )

        st.download_button(
            "Download JSON",
            json.dumps(results, indent=2),
            file_name=f"audit-{domain}.json",
            mime="application/json",
        )

        st.text_area(
            "Full Report",
            value=format_report(results, "full"),
            height=300,
            label_visibility="collapsed",
        )

elif submitted:
    st.error("Please enter a domain.")

