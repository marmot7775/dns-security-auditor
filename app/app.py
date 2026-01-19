"""
DNS Security Auditor - Streamlit Web Interface
Run with: PYTHONPATH=src streamlit run app/app.py
"""

import streamlit as st
import json
from dns_security_auditor.dns_tools import (
    audit_email_security,
    audit_dns_security,
    format_report,
    normalize_domain,
)

st.set_page_config(page_title="DNS Security Auditor", page_icon="🛡️", layout="wide")

st.title("🛡️ DNS Security Auditor")
st.write("Audit DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and key DNS security signals with prioritized fixes.")
st.caption("Tip: If you know DKIM selectors, add them to improve DKIM accuracy.")

# Input
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    domain = st.text_input("Domain to audit", placeholder="example.com")
    dkim_selectors_raw = st.text_input(
        "DKIM selectors (comma-separated, optional)",
        placeholder
