import streamlit as st
import dns.resolver
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

# --- 1. DATA LOADER SKELETON ---
@st.cache_data(ttl=3600)
def load_selector_data() -> Dict[str, str]:
    """
    Loads your proprietary selector list.
    Expected format: JSON {"selector_name": "ISP/Company Name"}
    """
    # Look for the data folder relative to this file
    base_path = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(base_path, "..", "data", "selectors.json")
    
    if os.path.exists(data_path):
        try:
            with open(data_path, "r") as f:
                return json.load(f)
        except Exception as e:
            # Silently fail or log error, returning empty dict so app doesn't crash
            return {}
    return {}

# --- 2. HELPERS ---
def _lookup_txt(name: str) -> List[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(name, "TXT")
        return ["".join([p.decode() if isinstance(p, bytes) else str(p) for p in rdata.strings]) for rdata in answers]
    except:
        return []

def normalize_domain(value: str) -> str:
    if not value: return ""
    domain = str(value).strip().lower()
    if "@" in domain: domain = domain.split("@")[-1]
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    return domain.split("/")[0].split("?")[0].rstrip(".")

# --- 3. AUDIT LOGIC ---
@st.cache_data(ttl=3600)
def check_subdomain_takeover(domain: str) -> Dict[str, Any]:
    targets = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "s3.amazonaws.com": "AWS S3",
        "azurewebsites.net": "Azure Website",
        "bitbucket.io": "Bitbucket",
        "wordpress.com": "WordPress",
        "pantheonsite.io": "Pantheon"
    }
    
    issues, recs = [], []
    found_cname = None
    
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            found_cname = str(rdata.target).lower().rstrip(".")
            for sig, service in targets.items():
                if sig in found_cname:
                    # Logic: If it points to a service but that destination doesn't resolve, it's claimable.
                    try:
                        dns.resolver.resolve(found_cname, "A")
                    except:
                        issues.append(f"🚨 Potential Takeover: Points to dead {service} target ({found_cname})")
                        recs.append(f"Immediate: Remove CNAME record for {domain} or claim the resource on {service}.")
    except:
        pass 

    status = "error" if issues else "ok"
    return {
        "check": "Subdomain Takeover",
        "status": status,
        "record": found_cname,
        "issues": issues,
        "recommendations": recs
    }

@st.cache_data(ttl=3600)
def audit_email_security(domain: str) -> Dict[str, Any]:
    domain = normalize_domain(domain)
    # Load your proprietary data (will be empty for now)
    selector_db = load_selector_data()
    
    results = {
        "domain": domain,
        "summary": {"ok": 0, "warning": 0, "error": 0},
        "checks": {},
        "priority_fixes": []
    }
    
    # DMARC
    dmarc_recs = _lookup_txt(f"_dmarc.{domain}")
    if not dmarc_recs:
        results["checks"]["dmarc"] = {"check": "DMARC", "status": "error", "issues": ["No DMARC record found"], "recommendations": ["Add v=DMARC1 record"]}
    else:
        results["checks"]["dmarc"] = {"check": "DMARC", "status": "ok", "record": dmarc_recs[0], "issues": [], "recommendations": []}

    # SPF
    spf_recs = [r for r in _lookup_txt(domain) if "v=spf1" in r.lower()]
    if not spf_recs:
        results["checks"]["spf"] = {"check": "SPF", "status": "error", "issues": ["No SPF record found"], "recommendations": ["Add SPF record"]}
    else:
        rec = spf_recs[0]
        # Future hook: Cross-reference IPs/Include domains with selector_db here
        results["checks"]["spf"] = {"check": "SPF", "status": "ok", "record": rec, "issues": [], "recommendations": []}

    # Summary Stats
    for c in results["checks"].values():
        results["summary"][c["status"]] += 1
        if c["status"] != "ok":
            results["priority_fixes"].extend(c["recommendations"])
            
    return results

@st.cache_data(ttl=3600)
def audit_dns_security(domain: str) -> Dict[str, Any]:
    # 1. Run standard Email Checks
    res = audit_email_security(domain)
    
    # 2. Add Subdomain Takeover Check
    res["checks"]["takeover"] = check_subdomain_takeover(domain)
    
    # 3. Add DNSSEC Check
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        res["checks"]["dnssec"] = {"check": "DNSSEC", "status": "ok", "issues": [], "recommendations": []}
    except:
        res["checks"]["dnssec"] = {"check": "DNSSEC", "status": "warning", "issues": ["DNSSEC not enabled"], "recommendations": ["Enable DNSSEC"]}
    
    # Recalculate summary
    res["summary"] = {"ok": 0, "warning": 0, "error": 0}
    for c in res["checks"].values():
        res["summary"][c["status"]] += 1
        
    return res

def format_report(results: Dict[str, Any], output_format: str) -> str:
    return f"Security Audit for {results['domain']}\nGenerated: {datetime.now()}\nChecks Passed: {results['summary']['ok']}"