"""
DNS Security Auditor - Complete Application
Integrates all enterprise features into one comprehensive tool
"""

import streamlit as st
from datetime import datetime
import sys
import os
import re

# Add modules to path
sys.path.insert(0, os.path.dirname(__file__))

# Import all our modules
from spf_intelligence import smart_dkim_check
from comprehensive_selectors import COMPREHENSIVE_DKIM_SELECTORS, COMPREHENSIVE_SPF_VENDOR_MAP
from dkim_formatter import format_dkim_summary
from advanced_fingerprinting import AdvancedVendorFingerprinter
from dmarc_tree_walk import dmarc_tree_walk
from dkim_tag_analyzer import DKIMTagAnalyzer
from dkim_key_age import DKIMKeyAgeAnalyzer
from email_header_validator import EmailHeaderDKIMValidator
from security_scoring import EmailSecurityScorer
from dns_error_handling import SmartDNSResolver

# ============================================================================
# HELPER FUNCTIONS - DMARC & SPF PARSING
# ============================================================================

def parse_dmarc_policy(dmarc_record: str) -> dict:
    """
    Parse DMARC record and extract policy details with plain-English explanations
    """
    if not dmarc_record:
        return {
            'valid': False,
            'policy': None,
            'explanation': 'No DMARC record found'
        }
    
    result = {
        'valid': True,
        'raw_record': dmarc_record
    }
    
    # Extract policy (p=)
    policy_match = re.search(r'p=(\w+)', dmarc_record)
    if policy_match:
        policy = policy_match.group(1).lower()
        result['policy'] = policy
        
        if policy == 'none':
            result['policy_explanation'] = "⚠️ **MONITORING ONLY** - DMARC is not blocking or quarantining any emails. Failed emails are delivered normally."
            result['policy_severity'] = 'warning'
        elif policy == 'quarantine':
            result['policy_explanation'] = "🟡 **PARTIAL ENFORCEMENT** - Failed emails are marked as suspicious (usually sent to spam folder)."
            result['policy_severity'] = 'medium'
        elif policy == 'reject':
            result['policy_explanation'] = "✅ **FULL ENFORCEMENT** - Failed emails are completely blocked and never reach the recipient."
            result['policy_severity'] = 'good'
    else:
        result['policy'] = 'none'
        result['policy_explanation'] = "Policy not specified (defaults to none)"
    
    # Extract subdomain policy (sp=)
    sp_match = re.search(r'sp=(\w+)', dmarc_record)
    if sp_match:
        result['subdomain_policy'] = sp_match.group(1).lower()
    else:
        result['subdomain_policy'] = result.get('policy', 'none')
    
    # Extract percentage (pct=)
    pct_match = re.search(r'pct=(\d+)', dmarc_record)
    if pct_match:
        result['percentage'] = int(pct_match.group(1))
    else:
        result['percentage'] = 100  # Default
    
    # Extract aggregate reports (rua=)
    rua_match = re.search(r'rua=([^;]+)', dmarc_record)
    if rua_match:
        result['aggregate_reports'] = rua_match.group(1).strip()
        result['reporting_enabled'] = True
    else:
        result['reporting_enabled'] = False
    
    # Extract forensic reports (ruf=)
    ruf_match = re.search(r'ruf=([^;]+)', dmarc_record)
    if ruf_match:
        result['forensic_reports'] = ruf_match.group(1).strip()
    
    # Extract alignment modes
    aspf_match = re.search(r'aspf=([rs])', dmarc_record)
    result['spf_alignment'] = aspf_match.group(1) if aspf_match else 'r'
    
    adkim_match = re.search(r'adkim=([rs])', dmarc_record)
    result['dkim_alignment'] = adkim_match.group(1) if adkim_match else 'r'
    
    return result


def analyze_spf_errors(spf_record: str, domain: str) -> dict:
    """
    Analyze SPF record for common errors and issues
    """
    if not spf_record or not spf_record.startswith('v=spf1'):
        return {
            'valid': False,
            'errors': ['No valid SPF record found'],
            'warnings': [],
            'info': []
        }
    
    errors = []
    warnings = []
    info = []
    
    # Count DNS lookups (mechanisms that require lookups)
    lookup_mechanisms = re.findall(r'\b(include:|a:|mx:|ptr:|exists:)', spf_record, re.IGNORECASE)
    lookup_count = len(lookup_mechanisms)
    
    # Check for +all (allows anyone to send)
    if re.search(r'\+all', spf_record):
        errors.append("🔴 **CRITICAL**: '+all' mechanism allows ANYONE to send email on your behalf!")
    
    # Check for ?all (neutral - no protection)
    if re.search(r'\?all', spf_record):
        warnings.append("⚠️ **WARNING**: '?all' provides no anti-spoofing protection")
    
    # Check for missing termination
    if not re.search(r'[-~?+]all', spf_record):
        warnings.append("⚠️ Missing 'all' mechanism - should end with -all or ~all")
    
    # Check lookup count
    if lookup_count > 10:
        errors.append(f"🔴 **CRITICAL**: {lookup_count} DNS lookups exceeds the limit of 10! SPF will FAIL for all emails.")
    elif lookup_count > 8:
        warnings.append(f"⚠️ **WARNING**: {lookup_count} DNS lookups is close to the limit of 10")
    elif lookup_count <= 5:
        info.append(f"✅ {lookup_count} DNS lookups (well under the limit of 10)")
    
    # Check for ptr mechanism (deprecated)
    if re.search(r'\bptr:', spf_record, re.IGNORECASE):
        warnings.append("⚠️ 'ptr' mechanism is deprecated and unreliable")
    
    # Check for redirect vs include
    has_redirect = bool(re.search(r'redirect=', spf_record))
    has_include = bool(re.search(r'include:', spf_record))
    
    if has_redirect and has_include:
        warnings.append("⚠️ Using both 'redirect' and 'include' can cause confusion")
    
    # Check for IP4/IP6 addresses (good practice)
    ip4_count = len(re.findall(r'ip4:', spf_record))
    ip6_count = len(re.findall(r'ip6:', spf_record))
    
    if ip4_count > 0 or ip6_count > 0:
        info.append(f"✅ Direct IP authorization: {ip4_count} IPv4, {ip6_count} IPv6")
    
    # Good termination?
    if re.search(r'-all', spf_record):
        info.append("✅ Hard fail (-all) - strong anti-spoofing protection")
    elif re.search(r'~all', spf_record):
        info.append("✅ Soft fail (~all) - good anti-spoofing protection")
    
    return {
        'valid': True,
        'lookup_count': lookup_count,
        'errors': errors,
        'warnings': warnings,
        'info': info
    }


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
    .issue-good {
        background: #dcfce7;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #16a34a;
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

# Sidebar - FIXED: Mode selection at top
with st.sidebar:
    st.markdown("## 🛡️ DNS Security Auditor")
    st.markdown("---")
    
    # Mode selection FIRST (above the fold)
    mode = st.radio(
        "Select Mode",
        ["Single Domain Audit", "Email Header Validation", "Multi-Domain Dashboard"],
        help="Choose your auditing mode"
    )
    
    st.markdown("---")
    
    # Condensed features (to fit better)
    with st.expander("📋 Features"):
        st.markdown("""
        ✅ SPF Analysis & Error Detection  
        ✅ DKIM Discovery (339 selectors)  
        ✅ DMARC Policy Parsing  
        ✅ Vendor Fingerprinting  
        ✅ Key Age Tracking  
        ✅ Security Scoring (0-100)  
        ✅ Email Header Validation  
        """)
    
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
st.markdown('<div class="sub-header">Professional email authentication analysis</div>', unsafe_allow_html=True)

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
            
            # FIXED: Filter for SPF record instead of taking first TXT record
            spf_record = None
            if spf_result['success']:
                for record in spf_result['records']:
                    if record.startswith('v=spf1'):
                        spf_record = record
                        break
            
            # Analyze SPF for errors
            spf_analysis = analyze_spf_errors(spf_record, domain)
            audit_results['spf_analysis'] = spf_analysis
            
            # 2. DKIM Discovery
            st.markdown("#### 2️⃣ Discovering DKIM keys...")
            dkim_result = smart_dkim_check(domain, spf_record)
            audit_results['dkim'] = dkim_result
            
            # 3. DMARC Check
            st.markdown("#### 3️⃣ Checking DMARC...")
            dmarc_result = st.session_state.dns_resolver.query(f'_dmarc.{domain}', 'TXT')
            audit_results['dmarc'] = dmarc_result
            
            # Parse DMARC policy
            dmarc_record = dmarc_result['records'][0] if dmarc_result['success'] and dmarc_result['records'] else None
            dmarc_parsed = parse_dmarc_policy(dmarc_record)
            audit_results['dmarc_parsed'] = dmarc_parsed
            
            # 3.5 DMARC DNS Tree Walk (dmarcbis-41)
            try:
                tree_walk_data = dmarc_tree_walk(domain)
                audit_results['tree_walk'] = tree_walk_data
            except Exception:
                audit_results['tree_walk'] = None

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
                    'policy': dmarc_parsed.get('policy', 'none'),
                    'pct': dmarc_parsed.get('percentage', 100),
                    'rua': dmarc_parsed.get('aggregate_reports'),
                    'ruf': dmarc_parsed.get('forensic_reports'),
                    'sp': dmarc_parsed.get('subdomain_policy')
                },
                'spf_results': {
                    'record': spf_result['success'],
                    'all': '-all' if spf_record and '-all' in spf_record else ('~all' if spf_record and '~all' in spf_record else 'none'),
                    'lookup_count': spf_analysis.get('lookup_count', 0),
                    'include_count': len(re.findall(r'include:', spf_record or ''))
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
                f"{grade_color.get(score['grade'], '')} {score['grade']}",
                delta=None
            )
        
        with col3:
            status_text = {
                'A': 'Excellent',
                'B': 'Good',
                'C': 'Fair',
                'D': 'Needs Work',
                'F': 'Critical'
            }
            st.metric(
                "Status",
                status_text.get(score['grade'], 'Unknown'),
                delta=None
            )
        
        # Tabs for detailed results
        st.markdown("---")
        st.markdown("### 📊 Summary")
        
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Summary",
            "🔍 SPF",
            "🔑 DKIM",
            "🛡️ DMARC",
            "🏢 Vendors"
        ])
        
        with tab1:
            # Security Score Breakdown
            st.markdown("#### Security Score Breakdown")
            
            for category, weight in score['category_scores'].items():
                max_score = {
                    'dmarc': 25,
                    'spf': 20,
                    'dkim': 25,
                    'key_security': 15,
                    'vendor_intelligence': 10,
                    'best_practices': 5
                }[category]
                
                percentage = (weight / max_score) * 100
                
                category_name = category.replace('_', ' ').title()
                
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.progress(percentage / 100, text=f"{category_name}")
                with col2:
                    st.write(f"{weight:.1f}/{max_score} points ({percentage:.0f}%)")
            
            # Top Recommendations
            st.markdown("---")
            st.markdown("#### 📋 Top Recommendations")
            
            if score['recommendations']:
                for i, rec in enumerate(score['recommendations'], 1):
                    st.markdown(f"{i}. {rec}")
            else:
                st.success("✅ No critical issues found!")
        
        with tab2:
            # SPF Tab
            st.markdown("#### 🔍 SPF Analysis")
            
            spf_analysis = results.get('spf_analysis', {})
            
            if results['spf']['success']:
                # Show the record
                st.markdown("**SPF Record:**")
                spf_record_display = None
                for record in results['spf']['records']:
                    if record.startswith('v=spf1'):
                        spf_record_display = record
                        break
                
                st.code(spf_record_display if spf_record_display else "No SPF record found", language="text")
                
                # Show errors
                if spf_analysis.get('errors'):
                    st.markdown("**❌ Critical Errors:**")
                    for error in spf_analysis['errors']:
                        st.markdown(f'<div class="issue-critical">{error}</div>', unsafe_allow_html=True)
                
                # Show warnings
                if spf_analysis.get('warnings'):
                    st.markdown("**⚠️ Warnings:**")
                    for warning in spf_analysis['warnings']:
                        st.markdown(f'<div class="issue-warning">{warning}</div>', unsafe_allow_html=True)
                
                # Show info
                if spf_analysis.get('info'):
                    st.markdown("**✅ Good Practices:**")
                    for info in spf_analysis['info']:
                        st.markdown(f'<div class="issue-good">{info}</div>', unsafe_allow_html=True)
                
                # DNS Lookup Count
                st.markdown("---")
                st.markdown(f"**DNS Lookups:** {spf_analysis.get('lookup_count', 0)}/10")
                if spf_analysis.get('lookup_count', 0) > 10:
                    st.error("⚠️ EXCEEDS LIMIT - SPF will fail!")
                elif spf_analysis.get('lookup_count', 0) > 8:
                    st.warning("⚠️ Close to limit")
                else:
                    st.success("✅ Within safe limits")
                
            else:
                st.error("❌ No SPF record found!")
                st.markdown("""
                **What is SPF?**
                SPF (Sender Policy Framework) tells email servers which IP addresses are allowed to send email for your domain.
                
                **Why you need it:**
                Without SPF, spammers can easily forge emails claiming to be from your domain.
                """)
        
        with tab3:
            # DKIM Tab
            st.markdown("#### 🔑 DKIM Discovery Results")
            
            if results['dkim']['found_selectors']:
                st.success(f"✅ Found {len(results['dkim']['found_selectors'])} DKIM key(s)")
                
                # FIXED: Correct parameter order
                formatted_output = format_dkim_summary(domain, results['dkim'])
                st.markdown(formatted_output)
                
            else:
                st.warning("⚠️ No DKIM keys found")
                st.markdown(f"Tested {results['dkim'].get('selectors_tested', 0)} selectors")
        
        with tab4:
            # DMARC Tab
            st.markdown("#### 🛡️ DMARC Policy Analysis")
            
            dmarc_parsed = results.get('dmarc_parsed', {})
            
            if dmarc_parsed.get('valid'):
                # Show raw record
                st.markdown("**DMARC Record:**")
                st.code(dmarc_parsed.get('raw_record', ''), language="text")
                
                st.markdown("---")
                
                # Policy explanation
                st.markdown("**Policy:**")
                policy_severity = dmarc_parsed.get('policy_severity', 'warning')
                policy_class = {
                    'good': 'issue-good',
                    'medium': 'issue-warning',
                    'warning': 'issue-warning'
                }.get(policy_severity, 'issue-warning')
                
                st.markdown(f'<div class="{policy_class}">{dmarc_parsed.get("policy_explanation", "")}</div>', unsafe_allow_html=True)
                
                # Enforcement percentage
                st.markdown("---")
                st.markdown(f"**Enforcement Percentage:** {dmarc_parsed.get('percentage', 100)}%")
                if dmarc_parsed.get('percentage', 100) < 100:
                    st.info(f"ℹ️ Policy only applies to {dmarc_parsed.get('percentage')}% of emails")
                
                # Reporting
                st.markdown("---")
                st.markdown("**Reporting:**")
                if dmarc_parsed.get('reporting_enabled'):
                    st.success(f"✅ Aggregate reports: {dmarc_parsed.get('aggregate_reports', 'N/A')}")
                    if dmarc_parsed.get('forensic_reports'):
                        st.success(f"✅ Forensic reports: {dmarc_parsed.get('forensic_reports')}")
                else:
                    st.warning("⚠️ No reporting configured - you won't receive DMARC feedback")
                
                # Alignment
                st.markdown("---")
                st.markdown("**Alignment Mode:**")
                st.write(f"- SPF: {'Strict' if dmarc_parsed.get('spf_alignment') == 's' else 'Relaxed'}")
                st.write(f"- DKIM: {'Strict' if dmarc_parsed.get('dkim_alignment') == 's' else 'Relaxed'}")
                
                # Subdomain policy
                if dmarc_parsed.get('subdomain_policy'):
                    st.markdown("---")
                    st.markdown(f"**Subdomain Policy:** {dmarc_parsed.get('subdomain_policy')}")
                
            else:
                st.error("❌ No DMARC record found!")
                st.markdown("""
                **What is DMARC?**
                DMARC (Domain-based Message Authentication, Reporting & Conformance) tells email servers what to do when SPF or DKIM checks fail.
                
                **Why you need it:**
                - Protects your domain from phishing and spoofing
                - Provides visibility into who's sending email using your domain
                - Required by major email providers (Google, Yahoo, etc.)
                """)
        
            # --- DMARC DNS Tree Walk Visualization ---
            st.markdown("---")
            st.markdown("#### 🌳 DMARC Policy Discovery (DNS Tree Walk)")
            st.caption("Per [draft-ietf-dmarc-dmarcbis](https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/) Section 4.10")
            
            tw = results.get('tree_walk')
            if tw and tw.get('steps'):
                st.markdown(
                    f"When a mail receiver gets email from **{tw['domain']}**, "
                    f"it walks up the DNS hierarchy looking for a DMARC policy:"
                )
                
                for i, step in enumerate(tw['steps']):
                    if step['found']:
                        icon = "✅"
                        color = "#10b981"
                        status_text = "Record found"
                    else:
                        icon = "❌"
                        color = "#94a3b8"
                        status_text = "No record"
                    
                    is_match = step['found'] and step['domain'] == tw.get('policy_source')
                    
                    # Build the node
                    if is_match:
                        st.markdown(
                            f'<div style="border-left:3px solid #10b981; padding:0.75rem 1rem; margin:0.5rem 0; '
                            f'background:linear-gradient(135deg,#ecfdf5,#d1fae5); border-radius:0 8px 8px 0;">'
                            f'<div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#64748b;margin-bottom:0.2rem;">{step["label"]}</div>'
                            f'<div style="display:flex;align-items:center;gap:0.5rem;">'
                            f'{icon} <code>_dmarc.{step["domain"]}</code> '
                            f'<span style="font-size:0.7rem;font-weight:600;background:#ecfdf5;color:#065f46;padding:0.15rem 0.5rem;border-radius:99px;">{status_text}</span>'
                            f'</div>'
                            f'{"<div style=\"margin-top:0.5rem;padding:0.4rem 0.6rem;background:rgba(16,185,129,0.08);border-radius:6px;\"><code style=\"font-size:0.75rem;color:#065f46;\">" + step["record"][:100] + "</code></div>" if step.get("record") else ""}'
                            f'</div>',
                            unsafe_allow_html=True
                        )
                    else:
                        st.markdown(
                            f'<div style="border-left:3px solid {color}; padding:0.75rem 1rem; margin:0.5rem 0; '
                            f'background:#f8fafc; border-radius:0 8px 8px 0;">'
                            f'<div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#64748b;margin-bottom:0.2rem;">{step["label"]}</div>'
                            f'<div style="display:flex;align-items:center;gap:0.5rem;">'
                            f'{icon} <code>_dmarc.{step["domain"]}</code> '
                            f'<span style="font-size:0.7rem;font-weight:600;background:#f1f5f9;color:#64748b;padding:0.15rem 0.5rem;border-radius:99px;">{status_text}</span>'
                            f'</div></div>',
                            unsafe_allow_html=True
                        )
                
                # Summary
                if tw.get('policy_source'):
                    policy = tw.get('effective_policy', 'none')
                    policy_colors = {'none': ('#fef3c7', '#92400e'), 'quarantine': ('#fff7ed', '#9a3412'), 'reject': ('#ecfdf5', '#065f46')}
                    bg, fg = policy_colors.get(policy, ('#f1f5f9', '#334155'))
                    
                    tag_desc = {'p': 'direct policy', 'sp': 'subdomain policy', 'np': 'non-existent subdomain policy'}
                    tag_name = tag_desc.get(tw.get('applied_tag', 'p'), tw.get('applied_tag', 'p'))
                    
                    st.success(
                        f"**Policy found at {tw['policy_source']}** — "
                        f"Effective policy: **{policy}** (via *{tag_name}* tag)"
                        f"{'  \n⚠️ This domain inherits its DMARC policy from a parent domain.' if tw.get('is_subdomain') else ''}"
                    )
                else:
                    st.error(
                        "**No DMARC policy found at any level.**  \n"
                        "Anyone can send email pretending to be from this domain. "
                        "Mail receivers have no guidance on how to handle unauthenticated messages."
                    )
            else:
                st.info("Tree walk data not available for this domain.")
        
        with tab5:
            # Vendors Tab - FIXED: Use .get() for evidence
            st.markdown("#### 🏢 Detected Email Vendors")
            
            if results['vendors']['vendors']:
                for vendor in results['vendors']['vendors']:
                    confidence = vendor['confidence'] * 100
                    
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**{vendor['vendor']}**")
                        # FIXED: Use .get() to avoid KeyError
                        st.caption(f"Evidence: {vendor.get('evidence', 'Multiple detection signals')}")
                    with col2:
                        st.metric("Confidence", f"{confidence:.0f}%")
            else:
                st.info("No vendors detected")

# ============================================================================
# MODE 2: EMAIL HEADER VALIDATION
# ============================================================================

elif mode == "Email Header Validation":
    st.markdown("### 📧 Email Header DKIM Validator")
    st.markdown("Paste the full email headers to validate DKIM signatures")
    
    headers = st.text_area(
        "Email Headers",
        height=300,
        placeholder="Paste full email headers including DKIM-Signature..."
    )
    
    if st.button("🔍 Validate DKIM", type="primary"):
        if headers:
            validator = EmailHeaderDKIMValidator()
            result = validator.validate_from_headers(headers)
            
            st.markdown("---")
            
            if result['valid']:
                st.success("✅ DKIM Signature Valid!")
                
                st.markdown("**Signature Details:**")
                st.json(result['details'])
            else:
                st.error(f"❌ DKIM Validation Failed: {result.get('error', 'Unknown error')}")
        else:
            st.warning("Please paste email headers")

# ============================================================================
# MODE 3: MULTI-DOMAIN DASHBOARD
# ============================================================================

elif mode == "Multi-Domain Dashboard":
    st.markdown("### 📊 Multi-Domain Dashboard")
    st.info("🚧 Coming in future release - batch audit multiple domains at once")
    
    st.markdown("""
    **Planned Features:**
    - Upload CSV with multiple domains
    - Side-by-side comparison
    - Export comprehensive report
    - Track changes over time
    """)
