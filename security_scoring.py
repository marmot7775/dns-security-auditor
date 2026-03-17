"""
COMPREHENSIVE EMAIL SECURITY SCORING SYSTEM

Gives non-technical users clear, actionable security ratings.

Scoring categories:
1. DMARC Configuration (30 points) - most critical
2. SPF Configuration (25 points) - foundational
3. DKIM Configuration (20 points) - important but detection is imperfect
4. Best Practices (10 points) - MTA-STS, TLS-RPT, DANE
5. Key Security (10 points) - key hygiene bonus
6. Vendor Intelligence (5 points) - detection bonus

Total: 100 points with letter grade (A-F)
"""

from typing import Dict, List, Tuple
import re

class EmailSecurityScorer:
    """
    Comprehensive email security scoring system
    """
    
    def __init__(self):
        self.max_score = 100
        self.category_weights = {
            'dmarc': 30,
            'spf': 25,
            'dkim': 20,
            'best_practices': 10,
            'key_security': 10,
            'vendor_intelligence': 5,
        }
    
    def calculate_score(self, audit_results: Dict) -> Dict:
        """
        Calculate comprehensive security score.

        Context-aware: if the domain has no MX records (doesn't receive/send
        mail), email-specific categories (SPF, DKIM, best-practices) are
        scored generously so a perfectly valid non-mail subdomain doesn't
        get an F.
        """
        scores = {}
        details = {}
        has_mx = audit_results.get('has_mx', True)  # default True for backward compat

        # 1. DMARC Score (30 points)
        dmarc_score, dmarc_details = self._score_dmarc(
            audit_results.get('dmarc_results', {})
        )
        scores['dmarc'] = dmarc_score
        details['dmarc'] = dmarc_details

        # 2. SPF Score (25 points)
        if has_mx:
            spf_score, spf_details = self._score_spf(
                audit_results.get('spf_results', {})
            )
        else:
            # No MX = no mail sending expected. Give full credit if there's
            # an inherited DMARC reject (domain is protected), partial otherwise.
            inherited = audit_results.get('dmarc_results', {}).get('inherited_policy')
            if inherited in ('reject', 'quarantine'):
                spf_score, spf_details = 25, {'reason': 'N/A: non-mail subdomain (protected by DMARC)'}
            else:
                spf_score, spf_details = self._score_spf(audit_results.get('spf_results', {}))
        scores['spf'] = spf_score
        details['spf'] = spf_details

        # 3. DKIM Score (20 points)
        if has_mx:
            dkim_score, dkim_details = self._score_dkim(
                audit_results.get('dkim_results', {})
            )
        else:
            inherited = audit_results.get('dmarc_results', {}).get('inherited_policy')
            if inherited in ('reject', 'quarantine'):
                dkim_score, dkim_details = 20, {'reason': 'N/A: non-mail subdomain (protected by DMARC)'}
            else:
                dkim_score, dkim_details = self._score_dkim(audit_results.get('dkim_results', {}))
        scores['dkim'] = dkim_score
        details['dkim'] = dkim_details

        # 4. Key Security Score (10 points)
        if has_mx:
            key_score, key_details = self._score_key_security(
                audit_results.get('dkim_results', {}),
                audit_results.get('key_age_analysis', {})
            )
        else:
            key_score, key_details = 10, {'reason': 'N/A: non-mail subdomain'}
        scores['key_security'] = key_score
        details['key_security'] = key_details

        # 5. Vendor Intelligence Score (5 points)
        vendor_score, vendor_details = self._score_vendor_intelligence(
            audit_results.get('vendor_fingerprint', {})
        )
        scores['vendor_intelligence'] = vendor_score
        details['vendor_intelligence'] = vendor_details

        # 6. Best Practices Score (10 points)
        if has_mx:
            practices_score, practices_details = self._score_best_practices(
                audit_results
            )
        else:
            inherited = audit_results.get('dmarc_results', {}).get('inherited_policy')
            if inherited in ('reject', 'quarantine'):
                practices_score, practices_details = 10, {'reason': 'N/A: non-mail subdomain (protected by DMARC)'}
            else:
                practices_score, practices_details = self._score_best_practices(audit_results)
        scores['best_practices'] = practices_score
        details['best_practices'] = practices_details

        # Calculate total
        total_score = sum(scores.values())
        grade = self._calculate_grade(total_score)

        # Identify strengths and weaknesses
        strengths, weaknesses = self._identify_strengths_weaknesses(scores, details)

        # Generate recommendations
        recommendations = self._generate_recommendations(scores, details, audit_results)

        return {
            'total_score': round(total_score, 1),
            'grade': grade,
            'category_scores': scores,
            'category_details': details,
            'strengths': strengths,
            'weaknesses': weaknesses,
            'recommendations': recommendations
        }
    
    def _score_dmarc(self, dmarc: Dict) -> Tuple[float, Dict]:
        """Score DMARC configuration (30 points max).

        Handles both direct records and inherited policies from tree walk.
        """
        score = 0
        details = {}

        inherited_policy = dmarc.get('inherited_policy')
        has_record = dmarc.get('record')

        # No record AND no inherited policy
        if not has_record and not inherited_policy:
            return 0, {'reason': 'No DMARC record', 'impact': 'CRITICAL'}

        # Inherited policy (subdomain without own record)
        if not has_record and inherited_policy:
            details['inherited'] = True
            # Credit the inherited policy — the domain IS protected
            if inherited_policy == 'reject':
                score = 26  # Full policy credit, slight deduction for no own record
                details['policy'] = 'reject (inherited, excellent)'
            elif inherited_policy == 'quarantine':
                score = 22
                details['policy'] = 'quarantine (inherited, good)'
            elif inherited_policy == 'none':
                score = 8
                details['policy'] = 'none (inherited, monitoring only)'
            else:
                score = 5
            return min(score, 30), details

        # Has own record: +6 points
        score += 6
        details['has_record'] = True

        # Policy level
        policy = (dmarc.get('policy') or '').lower()
        if policy == 'reject':
            score += 12  # Best
            details['policy'] = 'reject (excellent)'
        elif policy == 'quarantine':
            score += 8   # Good
            details['policy'] = 'quarantine (good)'
        elif policy == 'none':
            score += 3   # Monitoring only
            details['policy'] = 'none (monitoring only)'

        # Percentage
        pct = dmarc.get('pct') or 100
        if pct == 100:
            score += 6
            details['percentage'] = '100% (full enforcement)'
        elif pct >= 50:
            score += 3
            details['percentage'] = f'{pct}% (partial enforcement)'
        else:
            score += 1
            details['percentage'] = f'{pct}% (minimal enforcement)'

        # Reporting configured
        if dmarc.get('rua') or dmarc.get('ruf'):
            score += 4
            details['reporting'] = 'Configured'
        else:
            score += 1
            details['reporting'] = 'Not configured'

        # Subdomain policy
        if dmarc.get('sp'):
            score += 2
            details['subdomain_policy'] = 'Configured'

        return min(score, 30), details
    
    def _score_spf(self, spf: Dict) -> Tuple[float, Dict]:
        """Score SPF configuration (25 points max)"""
        score = 0
        details = {}

        if not spf.get('record'):
            return 0, {'reason': 'No SPF record', 'impact': 'CRITICAL'}

        # Has record: +6 points
        score += 6
        details['has_record'] = True

        # All mechanism (policy)
        all_mechanism = (spf.get('all') or '').lower()
        if all_mechanism in ['-all', '~all']:
            score += 10  # Strict
            details['all_mechanism'] = f'{all_mechanism} (good)'
        elif all_mechanism == '?all':
            score += 5  # Neutral
            details['all_mechanism'] = '?all (neutral)'
        else:
            score += 2
            details['all_mechanism'] = '+all or missing (weak)'

        # Lookup count (max 10)
        lookup_count = spf.get('lookup_count', 0)
        if lookup_count <= 8:
            score += 6
            details['lookup_count'] = f'{lookup_count} (good)'
        elif lookup_count <= 10:
            score += 4
            details['lookup_count'] = f'{lookup_count} (at limit)'
        else:
            score += 0
            details['lookup_count'] = f'{lookup_count} (EXCEEDS LIMIT!)'

        # Include count (fewer is better)
        include_count = spf.get('include_count', 0)
        if include_count <= 3:
            score += 3
            details['includes'] = f'{include_count} includes (clean)'
        elif include_count <= 5:
            score += 1
            details['includes'] = f'{include_count} includes (acceptable)'

        return min(score, 25), details
    
    def _analyze_key_from_record(self, record: str) -> Dict:
        """Analyze DKIM key strength from record string"""
        # Check for Ed25519 key type first
        if 'k=ed25519' in record.lower():
            return {'bits': 256, 'strength': 'strong', 'type': 'ed25519'}

        # Extract public key
        key_match = re.search(r'p=([A-Za-z0-9+/=]+)', record)
        if not key_match:
            return {'bits': 0, 'strength': 'invalid'}

        key_data = key_match.group(1)
        key_len = len(key_data)

        # Estimate RSA key size from base64 length
        if key_len < 200:
            return {'bits': 1024, 'strength': 'weak'}
        elif key_len < 500:
            return {'bits': 2048, 'strength': 'strong'}
        else:
            return {'bits': 4096, 'strength': 'strong'}
    
    def _score_dkim(self, dkim: Dict) -> Tuple[float, Dict]:
        """Score DKIM configuration (20 points max)"""
        score = 0
        details = {}

        found_selectors = dkim.get('found_selectors', [])
        if not found_selectors:
            return 0, {'reason': 'No DKIM keys found', 'impact': 'HIGH'}

        # Has at least one key: +8 points
        score += 8
        details['keys_found'] = len(found_selectors)

        # Multiple keys (redundancy): +4 points
        if len(found_selectors) >= 2:
            score += 4
            details['redundancy'] = 'Multiple keys (good)'
        else:
            score += 2
            details['redundancy'] = 'Single key (acceptable)'

        # Key strength analysis
        strong_keys = 0
        weak_keys = 0

        for selector_info in found_selectors:
            record = selector_info.get('record', '')
            if record:
                key_analysis = self._analyze_key_from_record(record)
                if key_analysis['strength'] == 'strong':
                    strong_keys += 1
                elif key_analysis['strength'] == 'weak':
                    weak_keys += 1

        # Award points for key strength
        if weak_keys == 0 and strong_keys > 0:
            score += 8
            details['key_strength'] = f'All {strong_keys} key(s) are 2048-bit or stronger (excellent)'
        elif weak_keys > 0 and strong_keys > 0:
            score += 5
            details['key_strength'] = f'{strong_keys} strong key(s), {weak_keys} weak 1024-bit key(s) (upgrade recommended)'
        elif weak_keys > 0 and strong_keys == 0:
            score += 2
            details['key_strength'] = f'All {weak_keys} key(s) are weak 1024-bit (UPGRADE REQUIRED)'
        else:
            score += 0
            details['key_strength'] = 'Unable to determine key strength'

        return min(score, 20), details
    
    def _score_key_security(self, dkim: Dict, key_age: Dict) -> Tuple[float, Dict]:
        """Score key security practices (10 points max)"""
        score = 0
        details = {}

        found_selectors = dkim.get('found_selectors', [])
        if not found_selectors:
            return 0, {'reason': 'No keys to evaluate'}

        # Key age/rotation status
        overdue = key_age.get('overdue', 0)

        if overdue == 0:
            score += 5
            details['rotation_status'] = 'No overdue keys'
        elif overdue <= 2:
            score += 2
            details['rotation_status'] = f'{overdue} key(s) overdue for rotation'
        else:
            score += 0
            details['rotation_status'] = f'{overdue} keys OVERDUE (rotate immediately!)'

        # Testing mode check
        testing_mode = any('t=y' in str(s.get('record', '')) for s in found_selectors)
        if not testing_mode:
            score += 3
            details['testing_mode'] = 'Production keys'
        else:
            score += 0
            details['testing_mode'] = 'Testing mode enabled (remove t=y)'

        # Algorithm check
        modern_algorithms = sum(1 for s in found_selectors
                              if 'sha256' in str(s.get('record', '')).lower() or 'ed25519' in str(s.get('record', '')).lower())
        if modern_algorithms > 0:
            score += 2
            details['algorithms'] = 'Modern algorithms (SHA-256 or Ed25519)'
        else:
            score += 1
            details['algorithms'] = 'Legacy algorithms'

        return min(score, 10), details
    
    def _score_vendor_intelligence(self, vendors: Dict) -> Tuple[float, Dict]:
        """Score vendor configuration (5 points max)"""
        score = 0
        details = {}

        detected_vendors = vendors.get('vendors', [])

        if not detected_vendors:
            return 3, {'reason': 'No vendor detection available'}

        # Has vendor intelligence: +2 points
        score += 2
        details['vendors_detected'] = len(detected_vendors)

        # High confidence detections: +2 points
        high_conf = sum(1 for v in detected_vendors if v.get('confidence', 0) >= 0.9)
        if high_conf > 0:
            score += 2
            details['confidence'] = f'{high_conf} high-confidence'
        else:
            score += 1
            details['confidence'] = 'Lower confidence'

        # Multiple vendors: +1 point
        if len(detected_vendors) >= 2:
            score += 1
            details['diversity'] = 'Multiple vendors configured'

        return min(score, 5), details
    
    def _score_best_practices(self, audit_results: Dict) -> Tuple[float, Dict]:
        """Score adherence to best practices (10 points max)"""
        score = 0
        details = {}

        # MTA-STS configured — check for txt_record or configured flag
        mta_sts = audit_results.get('mta_sts', {})
        if mta_sts.get('configured') or mta_sts.get('txt_record'):
            score += 4
            details['mta_sts'] = 'Configured'

        # TLS-RPT configured — check for record or configured flag
        tls_rpt = audit_results.get('tls_rpt', {})
        if tls_rpt.get('configured') or tls_rpt.get('record'):
            score += 4
            details['tls_rpt'] = 'Configured'

        # DANE configured
        dane = audit_results.get('dane', {})
        if dane.get('configured'):
            score += 2
            details['dane'] = 'Configured'

        return min(score, 10), details
    
    def _calculate_grade(self, score: float) -> str:
        """Convert score to letter grade"""
        if score >= 85:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 55:
            return 'C'
        elif score >= 40:
            return 'D'
        else:
            return 'F'
    
    def _identify_strengths_weaknesses(self, scores: Dict, details: Dict) -> Tuple[List[str], List[str]]:
        """Identify top strengths and critical weaknesses"""
        strengths = []
        weaknesses = []
        
        # Check each category
        for category, score in scores.items():
            max_score = self.category_weights[category]
            percentage = (score / max_score) * 100 if max_score > 0 else 0
            
            category_name = category.replace('_', ' ').title()
            
            if percentage >= 90:
                strengths.append(f"✓ {category_name}: Excellent ({score:.1f}/{max_score})")
            elif percentage < 50:
                weaknesses.append(f"⚠️ {category_name}: Needs improvement ({score:.1f}/{max_score})")
        
        return strengths, weaknesses
    
    def _generate_recommendations(self, scores: Dict, details: Dict, audit_results: Dict) -> List[str]:
        """Generate prioritized, actionable recommendations"""
        recommendations = []

        # DMARC recommendations
        dmarc = audit_results.get('dmarc_results', {})
        inherited = dmarc.get('inherited_policy')
        if not dmarc.get('record') and not inherited:
            domain = dmarc.get('domain', 'yourdomain.com')
            recommendations.append(
                f"🔴 CRITICAL: Publish a DMARC record. Add this TXT record at _dmarc.{domain}: "
                f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; fo=1"
            )
        elif not dmarc.get('record') and inherited == 'none':
            recommendations.append(
                "🟡 HIGH: Inherited DMARC policy is p=none (monitoring only). "
                "Upgrade the parent domain's policy or publish a dedicated record with stronger enforcement"
            )
        elif dmarc.get('policy') == 'none':
            recommendations.append(
                "🟡 HIGH: Upgrade DMARC from p=none (monitoring) to p=quarantine, "
                "then p=reject once you've confirmed all legitimate senders pass authentication"
            )
        elif not dmarc.get('rua'):
            recommendations.append(
                "🟡 MEDIUM: Add DMARC aggregate reporting (rua) to gain visibility into authentication results"
            )

        # SPF recommendations
        has_mx = audit_results.get('has_mx', True)
        spf = audit_results.get('spf_results', {})
        if not spf.get('record') and has_mx:
            recommendations.append("🔴 CRITICAL: Publish an SPF record listing your authorized sending servers")
        elif spf.get('lookup_count', 0) > 10:
            count = spf['lookup_count']
            recommendations.append(
                f"🟡 HIGH: SPF has {count} DNS lookups (limit is 10). "
                f"Flatten includes to IP addresses or remove unused sending services"
            )

        # DKIM recommendations (only for mail-sending domains)
        if has_mx:
            dkim_score = scores['dkim']
            if dkim_score == 0:
                recommendations.append(
                    "🟡 HIGH: No DKIM keys were detected. Verify DKIM signing is enabled with your email provider "
                    "and confirm the public key is published in DNS"
                )
            elif dkim_score < 12:
                dkim_details = details.get('dkim', {})
                if 'weak' in str(dkim_details.get('key_strength', '')).lower():
                    recommendations.append("🟡 HIGH: Upgrade 1024-bit DKIM keys to 2048-bit or stronger")

            # Key security recommendations
            if scores['key_security'] > 0 and scores['key_security'] < 6:
                key_details = details.get('key_security', {})
                if 'overdue' in str(key_details.get('rotation_status', '')).lower():
                    recommendations.append("🟡 MEDIUM: Rotate overdue DKIM keys for better security")

        # Best practices (only for mail-sending domains)
        if has_mx and scores['best_practices'] < 4:
            mta_sts = audit_results.get('mta_sts', {})
            tls_rpt = audit_results.get('tls_rpt', {})
            if not mta_sts.get('configured') and not tls_rpt.get('configured'):
                recommendations.append(
                    "🟢 LOW: Implement MTA-STS and TLS-RPT to enforce TLS encryption for inbound email"
                )

        # DANE recommendation when MTA-STS exists but DANE doesn't
        if has_mx:
            dane = audit_results.get('dane', {})
            mta_sts = audit_results.get('mta_sts', {})
            if not dane.get('configured') and (mta_sts.get('configured') or mta_sts.get('txt_record')):
                recommendations.append(
                    "🟢 LOW: Add DANE TLSA records to complement MTA-STS with DNS-based certificate verification"
                )

        return recommendations[:5]
    
    def format_score_report(self, score_result: Dict) -> str:
        """Generate human-readable score report"""
        lines = []
        
        lines.append("\n🎯 EMAIL SECURITY SCORE")
        lines.append("=" * 70)
        
        # Overall score
        score = score_result['total_score']
        grade = score_result['grade']
        
        grade_display = {
            'A': '🌟 A (Excellent)',
            'B': '✓ B (Good)',
            'C': '⚠️  C (Fair)',
            'D': '⚠️  D (Poor)',
            'F': '❌ F (Failing)'
        }.get(grade, grade)
        
        lines.append(f"\nOverall Score: {score}/100")
        lines.append(f"Grade: {grade_display}\n")
        
        # Category breakdown
        lines.append("📊 CATEGORY BREAKDOWN:")
        lines.append("")
        
        for category, weight in self.category_weights.items():
            cat_score = score_result['category_scores'][category]
            percentage = (cat_score / weight) * 100
            
            bar = '█' * int(percentage / 5) + '░' * (20 - int(percentage / 5))
            category_name = category.replace('_', ' ').title()
            
            lines.append(f"  {category_name:25} {cat_score:5.1f}/{weight:2} [{bar}] {percentage:5.1f}%")
        
        # Strengths
        if score_result['strengths']:
            lines.append(f"\n💪 STRENGTHS:")
            for strength in score_result['strengths']:
                lines.append(f"  {strength}")
        
        # Weaknesses
        if score_result['weaknesses']:
            lines.append(f"\n⚠️  AREAS FOR IMPROVEMENT:")
            for weakness in score_result['weaknesses']:
                lines.append(f"  {weakness}")
        
        # Recommendations
        if score_result['recommendations']:
            lines.append(f"\n📋 TOP RECOMMENDATIONS:")
            for i, rec in enumerate(score_result['recommendations'], 1):
                lines.append(f"  {i}. {rec}")
        
        return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    # Sample audit results
    sample_audit = {
        'dmarc_results': {
            'record': True,
            'policy': 'quarantine',
            'pct': 100,
            'rua': 'mailto:dmarc@example.com'
        },
        'spf_results': {
            'record': True,
            'all': '-all',
            'lookup_count': 7,
            'include_count': 3
        },
        'dkim_results': {
            'found_selectors': [
                {'selector': 'google', 'record': 'v=DKIM1; k=rsa; p=' + 'A'*344},
                {'selector': 'selector1', 'record': 'v=DKIM1; k=rsa; p=' + 'A'*172}
            ]
        },
        'key_age_analysis': {
            'overdue': 0,
            'due_soon': 1,
            'current': 1
        },
        'vendor_fingerprint': {
            'vendors': [
                {'vendor': 'Google Workspace', 'confidence': 0.95},
                {'vendor': 'Microsoft 365', 'confidence': 0.90}
            ]
        },
        'mta_sts': {'configured': True},
        'tls_rpt': {'configured': True},
        'bimi': {'configured': False}
    }
    
    scorer = EmailSecurityScorer()
    result = scorer.calculate_score(sample_audit)
    
    print(scorer.format_score_report(result))

