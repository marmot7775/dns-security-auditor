"""
COMPREHENSIVE EMAIL SECURITY SCORING SYSTEM

Gives non-technical users clear, actionable security ratings.

Scoring categories:
1. DMARC Configuration (25 points)
2. SPF Configuration (20 points)
3. DKIM Configuration (25 points)
4. Key Security (15 points)
5. Vendor Intelligence (10 points)
6. Best Practices (5 points)

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
            'dmarc': 25,
            'spf': 20,
            'dkim': 25,
            'key_security': 15,
            'vendor_intelligence': 10,
            'best_practices': 5
        }
    
    def calculate_score(self, audit_results: Dict) -> Dict:
        """
        Calculate comprehensive security score
        
        Args:
            audit_results: Complete audit data from all checks
            
        Returns:
            {
                'total_score': int (0-100),
                'grade': str (A-F),
                'category_scores': dict,
                'strengths': list,
                'weaknesses': list,
                'recommendations': list
            }
        """
        scores = {}
        details = {}
        
        # 1. DMARC Score (25 points)
        dmarc_score, dmarc_details = self._score_dmarc(
            audit_results.get('dmarc_results', {})
        )
        scores['dmarc'] = dmarc_score
        details['dmarc'] = dmarc_details
        
        # 2. SPF Score (20 points)
        spf_score, spf_details = self._score_spf(
            audit_results.get('spf_results', {})
        )
        scores['spf'] = spf_score
        details['spf'] = spf_details
        
        # 3. DKIM Score (25 points)
        dkim_score, dkim_details = self._score_dkim(
            audit_results.get('dkim_results', {})
        )
        scores['dkim'] = dkim_score
        details['dkim'] = dkim_details
        
        # 4. Key Security Score (15 points)
        key_score, key_details = self._score_key_security(
            audit_results.get('dkim_results', {}),
            audit_results.get('key_age_analysis', {})
        )
        scores['key_security'] = key_score
        details['key_security'] = key_details
        
        # 5. Vendor Intelligence Score (10 points)
        vendor_score, vendor_details = self._score_vendor_intelligence(
            audit_results.get('vendor_fingerprint', {})
        )
        scores['vendor_intelligence'] = vendor_score
        details['vendor_intelligence'] = vendor_details
        
        # 6. Best Practices Score (5 points)
        practices_score, practices_details = self._score_best_practices(
            audit_results
        )
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
        """Score DMARC configuration (25 points max)"""
        score = 0
        details = {}
        
        if not dmarc.get('record'):
            return 0, {'reason': 'No DMARC record', 'impact': 'CRITICAL'}
        
        # Has record: +5 points
        score += 5
        details['has_record'] = True
        
        # Policy level
        policy = dmarc.get('policy', '').lower()
        if policy == 'reject':
            score += 10  # Best
            details['policy'] = 'reject (excellent)'
        elif policy == 'quarantine':
            score += 7   # Good
            details['policy'] = 'quarantine (good)'
        elif policy == 'none':
            score += 3   # Monitoring only
            details['policy'] = 'none (monitoring only)'
        
        # Percentage
        pct = dmarc.get('pct', 100)
        if pct == 100:
            score += 5
            details['percentage'] = '100% (full enforcement)'
        elif pct >= 50:
            score += 3
            details['percentage'] = f'{pct}% (partial enforcement)'
        else:
            score += 1
            details['percentage'] = f'{pct}% (minimal enforcement)'
        
        # Reporting configured
        if dmarc.get('rua') or dmarc.get('ruf'):
            score += 3
            details['reporting'] = 'Configured'
        else:
            score += 1
            details['reporting'] = 'Not configured'
        
        # Subdomain policy
        if dmarc.get('sp'):
            score += 2
            details['subdomain_policy'] = 'Configured'
        
        return min(score, 25), details
    
    def _score_spf(self, spf: Dict) -> Tuple[float, Dict]:
        """Score SPF configuration (20 points max)"""
        score = 0
        details = {}
        
        if not spf.get('record'):
            return 0, {'reason': 'No SPF record', 'impact': 'CRITICAL'}
        
        # Has record: +5 points
        score += 5
        details['has_record'] = True
        
        # All mechanism (policy)
        all_mechanism = spf.get('all', '').lower()
        if all_mechanism in ['-all', '~all']:
            score += 8  # Strict
            details['all_mechanism'] = f'{all_mechanism} (good)'
        elif all_mechanism == '?all':
            score += 4  # Neutral
            details['all_mechanism'] = '?all (neutral)'
        else:
            score += 2
            details['all_mechanism'] = '+all or missing (weak)'
        
        # Lookup count (max 10)
        lookup_count = spf.get('lookup_count', 0)
        if lookup_count <= 8:
            score += 5
            details['lookup_count'] = f'{lookup_count} (good)'
        elif lookup_count <= 10:
            score += 3
            details['lookup_count'] = f'{lookup_count} (at limit)'
        else:
            score += 0
            details['lookup_count'] = f'{lookup_count} (EXCEEDS LIMIT!)'
        
        # Include count (fewer is better)
        include_count = spf.get('include_count', 0)
        if include_count <= 3:
            score += 2
            details['includes'] = f'{include_count} includes (clean)'
        elif include_count <= 5:
            score += 1
            details['includes'] = f'{include_count} includes (acceptable)'
        
        return min(score, 20), details
    
    def _analyze_key_from_record(self, record: str) -> Dict:
        """Analyze DKIM key strength from record string"""
        # Extract public key
        key_match = re.search(r'p=([A-Za-z0-9+/=]+)', record)
        if not key_match:
            return {'bits': 0, 'strength': 'invalid'}
        
        key_data = key_match.group(1)
        key_len = len(key_data)
        
        # Estimate key size from base64 length
        if key_len < 200:
            return {'bits': 1024, 'strength': 'weak'}
        elif key_len < 500:
            return {'bits': 2048, 'strength': 'strong'}
        else:
            return {'bits': 4096, 'strength': 'strong'}
    
    def _score_dkim(self, dkim: Dict) -> Tuple[float, Dict]:
        """Score DKIM configuration (25 points max) - FIXED VERSION"""
        score = 0
        details = {}
        
        found_selectors = dkim.get('found_selectors', [])
        if not found_selectors:
            return 0, {'reason': 'No DKIM keys found', 'impact': 'CRITICAL'}
        
        # Has at least one key: +10 points
        score += 10
        details['keys_found'] = len(found_selectors)
        
        # Multiple keys (redundancy): +5 points
        if len(found_selectors) >= 2:
            score += 5
            details['redundancy'] = 'Multiple keys (good)'
        else:
            score += 2
            details['redundancy'] = 'Single key (acceptable)'
        
        # Key strength analysis - FIXED to actually analyze the records
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
            # All keys are strong (2048-bit or higher)
            score += 8
            details['key_strength'] = f'All {strong_keys} key(s) are 2048-bit or stronger (excellent)'
        elif weak_keys > 0 and strong_keys > 0:
            # Mixed - some weak, some strong
            score += 5
            details['key_strength'] = f'{strong_keys} strong key(s), {weak_keys} weak 1024-bit key(s) (upgrade recommended)'
        elif weak_keys > 0 and strong_keys == 0:
            # All keys are weak (1024-bit)
            score += 2
            details['key_strength'] = f'All {weak_keys} key(s) are weak 1024-bit (UPGRADE REQUIRED)'
        else:
            # No valid keys detected
            score += 0
            details['key_strength'] = 'Unable to determine key strength'
        
        return min(score, 25), details
    
    def _score_key_security(self, dkim: Dict, key_age: Dict) -> Tuple[float, Dict]:
        """Score key security practices (15 points max)"""
        score = 0
        details = {}
        
        found_selectors = dkim.get('found_selectors', [])
        if not found_selectors:
            return 0, {'reason': 'No keys to evaluate'}
        
        # Key age/rotation status
        overdue = key_age.get('overdue', 0)
        due_soon = key_age.get('due_soon', 0)
        current = key_age.get('current', 0)
        
        if overdue == 0:
            score += 8
            details['rotation_status'] = 'No overdue keys'
        elif overdue <= 2:
            score += 4
            details['rotation_status'] = f'{overdue} key(s) overdue for rotation'
        else:
            score += 0
            details['rotation_status'] = f'{overdue} keys OVERDUE (rotate immediately!)'
        
        # Testing mode check
        testing_mode = any('t=y' in str(s.get('record', '')) for s in found_selectors)
        if not testing_mode:
            score += 4
            details['testing_mode'] = 'Production keys'
        else:
            score += 0
            details['testing_mode'] = 'Testing mode enabled (remove t=y)'
        
        # Algorithm check
        modern_algorithms = sum(1 for s in found_selectors 
                              if 'sha256' in str(s.get('record', '')).lower() or 'ed25519' in str(s.get('record', '')).lower())
        if modern_algorithms > 0:
            score += 3
            details['algorithms'] = 'Modern algorithms (SHA-256 or Ed25519)'
        else:
            score += 1
            details['algorithms'] = 'Legacy algorithms'
        
        return min(score, 15), details
    
    def _score_vendor_intelligence(self, vendors: Dict) -> Tuple[float, Dict]:
        """Score vendor configuration (10 points max)"""
        score = 0
        details = {}
        
        detected_vendors = vendors.get('vendors', [])
        
        if not detected_vendors:
            return 5, {'reason': 'No vendor detection available'}
        
        # Has vendor intelligence: +3 points
        score += 3
        details['vendors_detected'] = len(detected_vendors)
        
        # High confidence detections: +4 points
        high_conf = sum(1 for v in detected_vendors if v.get('confidence', 0) >= 0.9)
        if high_conf > 0:
            score += 4
            details['confidence'] = f'{high_conf} high-confidence'
        else:
            score += 2
            details['confidence'] = 'Lower confidence'
        
        # Multiple vendors properly configured: +3 points
        if len(detected_vendors) >= 2:
            score += 3
            details['diversity'] = 'Multiple vendors configured'
        
        return min(score, 10), details
    
    def _score_best_practices(self, audit_results: Dict) -> Tuple[float, Dict]:
        """Score adherence to best practices (5 points max)"""
        score = 0
        details = {}
        
        # MTA-STS configured
        if audit_results.get('mta_sts', {}).get('configured'):
            score += 2
            details['mta_sts'] = 'Configured'
        
        # TLS-RPT configured
        if audit_results.get('tls_rpt', {}).get('configured'):
            score += 2
            details['tls_rpt'] = 'Configured'
        
        # BIMI configured
        if audit_results.get('bimi', {}).get('configured'):
            score += 1
            details['bimi'] = 'Configured'
        
        return min(score, 5), details
    
    def _calculate_grade(self, score: float) -> str:
        """Convert score to letter grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
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
        """Generate prioritized recommendations"""
        recommendations = []
        
        # DMARC recommendations
        if scores['dmarc'] < 15:
            dmarc = audit_results.get('dmarc_results', {})
            if not dmarc.get('record'):
                recommendations.append("🔴 CRITICAL: Implement DMARC record immediately")
            elif dmarc.get('policy') == 'none':
                recommendations.append("🟡 HIGH: Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")
        
        # SPF recommendations
        if scores['spf'] < 12:
            spf = audit_results.get('spf_results', {})
            if not spf.get('record'):
                recommendations.append("🔴 CRITICAL: Implement SPF record")
            elif spf.get('lookup_count', 0) > 10:
                recommendations.append("🟡 HIGH: Reduce SPF lookups to 10 or fewer")
        
        # DKIM recommendations - FIXED to be more accurate
        dkim_score = scores['dkim']
        if dkim_score == 0:
            recommendations.append("🔴 CRITICAL: Configure DKIM signing immediately")
        elif dkim_score < 15:
            recommendations.append("🟡 HIGH: Upgrade weak 1024-bit DKIM keys to 2048-bit or stronger")
        elif dkim_score < 20:
            # Has keys but could be better
            dkim_details = details.get('dkim', {})
            if 'weak' in str(dkim_details.get('key_strength', '')).lower():
                recommendations.append("🟡 MEDIUM: Upgrade 1024-bit DKIM keys to 2048-bit for better security")
            else:
                recommendations.append("🟢 LOW: Consider adding backup DKIM selector for redundancy")
        
        # Key security recommendations
        if scores['key_security'] < 10:
            key_details = details.get('key_security', {})
            if 'overdue' in str(key_details.get('rotation_status', '')).lower():
                recommendations.append("🟡 HIGH: Rotate overdue DKIM keys immediately")
            if 'testing' in str(key_details.get('testing_mode', '')).lower():
                recommendations.append("🟡 MEDIUM: Remove testing mode (t=y) from production DKIM keys")
        
        return recommendations[:5]  # Top 5
    
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
