"""
DNS Security Auditor - Complete Application
Integrates all enterprise features into one comprehensive tool
"""

import streamlit as st
from datetime import datetime
import sys
import os

# Add modules to path
sys.path.insert(0, os.path.dirname(__file__))

# Import all our modules
from spf_intelligence import smart_dkim_check
from comprehensive_selectors import COMPREHENSIVE_DKIM_SELECTORS, COMPREHENSIVE_SPF_VENDOR_MAP
from dkim_formatter import format_dkim_summary
from advanced_fingerprinting import AdvancedVendorFingerprinter
from dkim_tag_analyzer import DKIMTagAnalyzer
from dkim_key_age import DKIMKeyAgeAnalyzer
from email_header_validator import EmailHeaderDKIMValidator
from security_scoring import EmailSecurityScorer
from dns_error_handling import SmartDNSResolver

# Page config
st.set_page_config(
    page_title="DNS Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #667eea;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #6b7280;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
    }
    .issue-critical {
        background: #fee;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #dc2626;
        margin: 0.5rem 0;
    }
    .issue-warning {
        background: #fef3c7;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #f59e0b;
        margin: 0.5rem 0;
    }
    .fix-box {
        background: #f0f9ff;
        padding: 1rem;
        border-radius: 8px;
        font-family: monospace;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'audit_results' not in st.session_state:
    st.session_state.audit_results = None
if 'dns_resolver' not in st.session_state:
    st.session_state.dns_resolver = SmartDNSResolver()

# Sidebar
with st.sidebar:
    st.markdown("## 🛡️ DNS Security Auditor")
    st.markdown("---")
    
    st.markdown("### Features")
    st.markdown("""
    ✅ SPF Analysis  
    ✅ DKIM Discovery (339 selectors)  
    ✅ DMARC Policy Check  
    ✅ Vendor Fingerprinting  
    ✅ Key Age Tracking  
    ✅ Security Scoring (0-100)  
    ✅ Email Header Validation  
    """)
    
    st.markdown("---")
    
    # Mode selection
    mode = st.radio(
        "Select Mode",
        ["Single Domain Audit", "Email Header Validation", "Multi-Domain Dashboard"],
        help="Choose your auditing mode"
    )
    
    st.markdown("---")
    
    # Cache stats
    if st.session_state.dns_resolver:
        stats = st.session_state.dns_resolver.get_cache_stats()
        st.markdown("### 📊 Cache Stats")
        st.metric("Hit Rate", f"{stats['hit_rate']}%")
        st.metric("Cached Entries", stats['cached_entries'])
        
        if st.button("🔄 Clear Cache"):
            st.session_state.dns_resolver = SmartDNSResolver()
            st.success("Cache cleared!")

# Main content
st.markdown('<div class="main-header">🛡️ DNS Security Auditor</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Enterprise-grade email authentication analysis</div>', unsafe_allow_html=True)

# ============================================================================
# MODE 1: SINGLE DOMAIN AUDIT
# ============================================================================

if mode == "Single Domain Audit":
    
    # Input
    col1, col2 = st.columns([3, 1])
    
    with col1:
        domain = st.text_input(
            "Enter domain to audit",
            placeholder="example.com",
            help="Enter the domain name without http:// or www"
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        audit_button = st.button("🔍 Run Audit", type="primary", use_container_width=True)
    
    if audit_button and domain:
        
        with st.spinner(f"Auditing {domain}..."):
            
            # Run comprehensive audit
            audit_results = {}
            
            # 1. SPF Check
            st.markdown("#### 1️⃣ Checking SPF...")
            spf_result = st.session_state.dns_resolver.query(domain, 'TXT')
            audit_results['spf'] = spf_result
            
            # 2. DKIM Discovery
            st.markdown("#### 2️⃣ Discovering DKIM keys...")
            
            # FIXED: Filter for SPF record instead of taking first TXT record
            spf_record = None
            if spf_result['success']:
                for record in spf_result['records']:
                    if record.startswith('v=spf1'):
                        spf_record = record
                        break
            
            dkim_result = smart_dkim_check(domain, spf_record)
            audit_results['dkim'] = dkim_result
            
            # 3. DMARC Check
            st.markdown("#### 3️⃣ Checking DMARC...")
            dmarc_result = st.session_state.dns_resolver.query(f'_dmarc.{domain}', 'TXT')
            audit_results['dmarc'] = dmarc_result
            
            # 4. Vendor Fingerprinting
            st.markdown("#### 4️⃣ Fingerprinting vendors...")
            fingerprinter = AdvancedVendorFingerprinter(domain, verbose=False)
            vendor_results = fingerprinter.fingerprint_all()
            audit_results['vendors'] = vendor_results
            
            # 5. Key Age Analysis
            if dkim_result['found_selectors']:
                st.markdown("#### 5️⃣ Analyzing key age...")
                key_age_analyzer = DKIMKeyAgeAnalyzer(domain)
                
                for selector_info in dkim_result['found_selectors']:
                    # Estimate key size from record
                    key_size = 2048  # Default assumption
                    if '1024' in selector_info.get('key_type', ''):
                        key_size = 1024
                    elif '4096' in selector_info.get('key_type', ''):
                        key_size = 4096
                    
                    key_age_analyzer.analyze_key(
                        selector_info['selector'],
                        selector_info.get('record', ''),
                        key_size
                    )
                
                audit_results['key_age'] = key_age_analyzer.get_security_hygiene_score()
            
            # 6. Calculate Security Score
            st.markdown("#### 6️⃣ Calculating security score...")
            scorer = EmailSecurityScorer()
            
            # Format results for scorer
            scorer_input = {
                'dmarc_results': {
                    'record': dmarc_result['success'],
                    'policy': 'unknown'  # Would parse from record
                },
                'spf_results': {
                    'record': spf_result['success'],
                    'lookup_count': 5  # Would calculate
                },
                'dkim_results': dkim_result,
                'key_age_analysis': audit_results.get('key_age', {}),
                'vendor_fingerprint': vendor_results
            }
            
            score_result = scorer.calculate_score(scorer_input)
            audit_results['score'] = score_result
            
            st.session_state.audit_results = audit_results
        
        st.success("✅ Audit complete!")
    
    # Display results
    if st.session_state.audit_results:
        results = st.session_state.audit_results
        
        st.markdown("---")
        
        # Security Score Header
        score = results['score']
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Security Score",
                f"{score['total_score']}/100",
                delta=None
            )
        
        with col2:
            grade_color = {
                'A': '🌟',
                'B': '✅',
                'C': '⚠️',
                'D': '⚠️',
                'F': '❌'
            }
            st.metric(
                "Grade",
                f"{grade_color.get(score['grade'], '')} {score['grade']}"
            )
        
        with col3:
            status = "Excellent" if score['total_score'] >= 90 else \
                     "Good" if score['total_score'] >= 75 else \
                     "Needs Work" if score['total_score'] >= 60 else "Critical"
            st.metric("Status", status)
        
        # Tabs for detailed results
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Summary", 
            "🔍 SPF", 
            "🔑 DKIM", 
            "🛡️ DMARC",
            "🏢 Vendors"
        ])
        
        with tab1:
            st.markdown("### Security Score Breakdown")
            
            # Category scores
            for category, weight in {
                'dmarc': 25,
                'spf': 20,
                'dkim': 25,
                'key_security': 15,
                'vendor_intelligence': 10,
                'best_practices': 5
            }.items():
                cat_score = score['category_scores'][category]
                percentage = (cat_score / weight) * 100
                
                st.markdown(f"**{category.replace('_', ' ').title()}**")
                st.progress(percentage / 100)
                st.caption(f"{cat_score:.1f}/{weight} points ({percentage:.0f}%)")
            
            # Top Recommendations
            if score['recommendations']:
                st.markdown("### 📋 Top Recommendations")
                for i, rec in enumerate(score['recommendations'], 1):
                    st.info(f"{i}. {rec}")
        
        with tab2:
            st.markdown("### SPF Analysis")
            spf = results['spf']
            
            if spf['success']:
                # Filter for SPF record
                spf_record = None
                for record in spf['records']:
                    if record.startswith('v=spf1'):
                        spf_record = record
                        break
                
                if spf_record:
                    st.success("✅ SPF record found")
                    st.code(spf_record, language=None)
                else:
                    st.warning("⚠️ TXT records found but no SPF record")
                    st.info("Found these TXT records:")
                    for record in spf['records'][:5]:  # Show first 5
                        st.caption(f"• {record[:100]}...")
            else:
                st.error(f"❌ {spf['error']['user_message']}")
                
                if spf['error']['retry_recommended']:
                    if st.button("🔄 Retry SPF Check"):
                        st.rerun()
        
        with tab3:
            st.markdown("### DKIM Discovery")
            dkim = results['dkim']
            
            # Show summary
            st.markdown(format_dkim_summary(domain, dkim, show_intelligence=True))
            
            # Key age analysis
            if 'key_age' in results:
                st.markdown("---")
                st.markdown("### 🔑 Key Age & Rotation")
                key_age = results['key_age']
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Current Keys", key_age.get('current', 0))
                with col2:
                    st.metric("Due Soon", key_age.get('due_soon', 0))
                with col3:
                    st.metric("Overdue", key_age.get('overdue', 0))
                
                st.metric(
                    "Key Hygiene Score",
                    f"{key_age.get('score', 0)}/100",
                    delta=f"Grade: {key_age.get('grade', 'N/A')}"
                )
        
        with tab4:
            st.markdown("### DMARC Policy")
            dmarc = results['dmarc']
            
            if dmarc['success']:
                st.success("✅ DMARC record found")
                st.code(dmarc['records'][0], language=None)
            else:
                st.error(f"❌ {dmarc['error']['user_message']}")
                
                st.warning("""
                **No DMARC record found!**
                
                This means:
                - You can't see who's sending email using your domain
                - No enforcement of SPF/DKIM authentication
                - Your domain can be easily spoofed
                
                **Recommended fix:**
                Add this DNS TXT record:
                """)
                
                st.code(f"_dmarc.{domain} TXT v=DMARC1; p=none; rua=mailto:dmarc@{domain}", language=None)
        
        with tab5:
            st.markdown("### Vendor Intelligence")
            vendors = results['vendors']
            
            if vendors['vendors']:
                for vendor in vendors['vendors']:
                    conf_pct = int(vendor['confidence'] * 100)
                    
                    if conf_pct >= 90:
                        st.success(f"**{vendor['vendor']}** ({conf_pct}% confidence)")
                    elif conf_pct >= 75:
                        st.info(f"**{vendor['vendor']}** ({conf_pct}% confidence)")
                    else:
                        st.warning(f"**{vendor['vendor']}** ({conf_pct}% confidence)")
                    
                    with st.expander("View Evidence"):
                        for signal in vendor['signals']:
                            st.caption(f"• {signal['technique']}: {signal['evidence']}")
            else:
                st.info("No vendors detected")

# ============================================================================
# MODE 2: EMAIL HEADER VALIDATION
# ============================================================================

elif mode == "Email Header Validation":
    
    st.markdown("### 📧 Validate DKIM from Email Headers")
    st.markdown("Paste email headers to validate actual DKIM signatures")
    
    headers = st.text_area(
        "Email Headers",
        height=300,
        placeholder="""Paste email headers here, including:
- From:
- DKIM-Signature:
- Other headers...
""",
        help="Paste the raw email headers from your email client"
    )
    
    if st.button("🔍 Validate Headers", type="primary"):
        if headers:
            validator = EmailHeaderDKIMValidator()
            result = validator.validate_email_headers(headers)
            report = validator.format_validation_report(result)
            
            st.markdown("### Validation Results")
            
            if result['status'] == 'pass':
                st.success("✅ DKIM PASS")
            elif result['status'] == 'fail':
                st.error("❌ DKIM FAIL")
            else:
                st.warning("⚠️ DKIM TEMPERROR")
            
            st.code(report, language=None)
        else:
            st.warning("Please paste email headers first")

# ============================================================================
# MODE 3: MULTI-DOMAIN DASHBOARD
# ============================================================================

elif mode == "Multi-Domain Dashboard":
    
    st.markdown("### 🏢 Multi-Domain Dashboard")
    st.info("📌 **Coming Soon**: Batch domain scanning for MSPs and enterprises")
    
    st.markdown("""
    This feature will allow you to:
    - Scan multiple domains simultaneously
    - Compare security posture across domains
    - Get priority alerts for critical issues
    - Export portfolio reports
    
    Perfect for:
    - MSPs managing 50+ client domains
    - Enterprises with multiple brands
    - Security consultants tracking projects
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #6b7280; font-size: 0.9rem;'>
    DNS Security Auditor v1.0 | Built with ❤️ for email security professionals
</div>
""", unsafe_allow_html=True)
