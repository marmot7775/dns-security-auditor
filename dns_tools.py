import streamlit as st
import dns.resolver
import requests
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

# HELPERS
def normalize_domain(value: str) -> str:
    if not value: return ""
    domain = str(value).strip().lower()
    if "@" in domain: domain = domain.split("@")[-1]
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    return domain.split("/")[0].split("?")[0].rstrip(".")

def _lookup_txt(name: str) -> List[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(name, "TXT")
        return ["".join([p.decode() if isinstance(p, bytes) else str(p) for p in rdata.strings]) for rdata in answers]
    except:
        return []

# CACHED AUDIT FUNCTIONS
@st.cache_data(ttl=3600)
def audit_email_security(domain: str) -> Dict[str, Any]:
    domain = normalize_domain(domain)
    results = {
        "domain": domain,
        "summary": {"ok": 0, "warning": 0, "error": 0},
        "checks": {},
        "priority_fixes": []
    }
    
    # 1. Check DMARC
    dmarc_recs = _lookup_txt(f"_dmarc.{domain}")
    if not dmarc_recs:
        results["checks"]["dmarc"] = {"check": "DMARC", "status": "error", "issues": ["No DMARC record found"], "recommendations": ["Add v=DMARC1 record to prevent email spoofing"]}
    else:
        results["checks"]["dmarc"] = {"check": "DMARC", "status": "ok", "record": dmarc_recs[0], "issues": [], "recommendations": []}

    # 2. Check SPF
    spf_recs = [r for r in _lookup_txt(domain) if "v=spf1" in r.lower()]
    if not spf_recs:
        results["checks"]["spf"] = {"check": "SPF", "status": "error", "issues": ["No SPF record found"], "recommendations": ["Add SPF record to authorize your mail servers"]}
    else:
        results["checks"]["spf"] = {"check": "SPF", "status": "ok", "record": spf_recs[0], "issues": [], "recommendations": []}

    # Aggregate Summary
    for c in results["checks"].values():
        results["summary"][c["status"]] += 1
        if c["status"] != "ok":
            results["priority_fixes"].extend(c["recommendations"])
            
    return results

@st.cache_data(ttl=3600)
def audit_dns_security(domain: str) -> Dict[str, Any]:
    # Start with email checks
    res = audit_email_security(domain)
    
    # Add DNSSEC check
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        res["checks"]["dnssec"] = {"check": "DNSSEC", "status": "ok", "issues": [], "recommendations": []}
    except:
        res["checks"]["dnssec"] = {"check": "DNSSEC", "status": "warning", "issues": ["DNSSEC not enabled"], "recommendations": ["Enable DNSSEC to prevent DNS hijacking"]}
    
    # Re-calculate summary
    res["summary"] = {"ok": 0, "warning": 0, "error": 0}
    for c in res["checks"].values():
        res["summary"][c["status"]] += 1
        
    return res

def format_report(results: Dict[str, Any], output_format: str) -> str:
    return f"DNS Security Report for {results['domain']}\nGenerated: {datetime.now()}"