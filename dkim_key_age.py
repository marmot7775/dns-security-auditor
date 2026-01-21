"""
DKIM KEY AGE & ROTATION ANALYZER

Tracks DKIM key age and rotation patterns to show security hygiene.

Features:
- Key age estimation from selector patterns
- Rotation recommendations based on industry standards
- Historical tracking of key changes
- Security hygiene scoring

Best Practice: Rotate DKIM keys every 6-12 months
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib

class DKIMKeyAgeAnalyzer:
    """
    Analyzes DKIM key age and rotation patterns
    """
    
    # Common selector naming patterns that indicate age
    SELECTOR_PATTERNS = {
        'date_based': [
            r'(\d{4})(\d{2})',  # YYYYMM (e.g., 202401)
            r'(\d{4})-(\d{2})',  # YYYY-MM
            r'(\d{2})(\d{2})',   # YYMM (e.g., 2401)
        ],
        'versioned': [
            r'v(\d+)',           # v1, v2, v3
            r'key(\d+)',         # key1, key2
            r'dkim(\d+)',        # dkim1, dkim2
        ],
        'vendor_standard': {
            'google': 'Rotated by Google automatically',
            'selector1': 'Microsoft standard (usually rotated semi-annually)',
            'selector2': 'Microsoft backup selector',
        }
    }
    
    # Rotation recommendations by key size
    ROTATION_SCHEDULE = {
        1024: {
            'max_age_months': 3,
            'recommended_months': 1,
            'urgency': 'CRITICAL',
            'reason': '1024-bit keys are weak and should be rotated immediately'
        },
        2048: {
            'max_age_months': 12,
            'recommended_months': 6,
            'urgency': 'STANDARD',
            'reason': 'Industry standard rotation period'
        },
        4096: {
            'max_age_months': 24,
            'recommended_months': 12,
            'urgency': 'LOW',
            'reason': 'Strong keys can rotate less frequently'
        }
    }
    
    def __init__(self, domain: str):
        self.domain = domain
        self.keys_analyzed = []
    
    def analyze_key(self, selector: str, dkim_record: str, 
                    key_size: int) -> Dict:
        """
        Analyze a single DKIM key for age and rotation status
        
        Returns:
            {
                'selector': str,
                'estimated_age': str or None,
                'age_confidence': str,
                'rotation_status': str,
                'recommendation': str,
                'urgency': str,
                'key_hash': str (for tracking changes)
            }
        """
        # Extract public key and create hash for tracking
        key_match = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_record)
        key_hash = None
        if key_match:
            key_data = key_match.group(1)
            key_hash = hashlib.sha256(key_data.encode()).hexdigest()[:16]
        
        # Estimate age from selector pattern
        estimated_age, confidence = self._estimate_age_from_selector(selector)
        
        # Get rotation recommendation
        rotation_rec = self.ROTATION_SCHEDULE.get(
            key_size,
            self.ROTATION_SCHEDULE[2048]  # Default to 2048
        )
        
        # Determine rotation status
        rotation_status = self._determine_rotation_status(
            estimated_age,
            rotation_rec['max_age_months']
        )
        
        # Build recommendation
        recommendation = self._build_recommendation(
            selector,
            estimated_age,
            confidence,
            key_size,
            rotation_rec
        )
        
        result = {
            'selector': selector,
            'estimated_age': estimated_age,
            'age_confidence': confidence,
            'rotation_status': rotation_status,
            'recommendation': recommendation,
            'urgency': rotation_rec['urgency'],
            'key_hash': key_hash,
            'key_size': key_size
        }
        
        self.keys_analyzed.append(result)
        return result
    
    def _estimate_age_from_selector(self, selector: str) -> Tuple[Optional[str], str]:
        """
        Estimate key age from selector naming pattern
        
        Returns:
            (age_string, confidence_level)
        """
        selector_lower = selector.lower()
        
        # Check for date-based patterns
        for pattern in self.SELECTOR_PATTERNS['date_based']:
            match = re.search(pattern, selector)
            if match:
                try:
                    if len(match.groups()) == 2:
                        year = int(match.group(1))
                        month = int(match.group(2))
                        
                        # Handle 2-digit years
                        if year < 100:
                            year = 2000 + year if year < 50 else 1900 + year
                        
                        # Create date
                        key_date = datetime(year, month, 1)
                        age_months = (datetime.now() - key_date).days // 30
                        
                        if age_months < 0:
                            return None, 'LOW'
                        
                        return f"~{age_months} months", 'HIGH'
                except:
                    pass
        
        # Check for version numbers
        for pattern in self.SELECTOR_PATTERNS['versioned']:
            match = re.search(pattern, selector_lower)
            if match:
                version = int(match.group(1))
                # Higher version = newer key (probably)
                if version == 1:
                    return "Possibly original key", 'MEDIUM'
                else:
                    return f"Version {version} (rotated {version-1} times)", 'MEDIUM'
        
        # Check vendor standard patterns
        for vendor_selector, description in self.SELECTOR_PATTERNS['vendor_standard'].items():
            if vendor_selector in selector_lower:
                return description, 'MEDIUM'
        
        # No pattern detected
        return "Unknown age", 'LOW'
    
    def _determine_rotation_status(self, estimated_age: Optional[str], 
                                   max_age_months: int) -> str:
        """Determine if key needs rotation"""
        
        if not estimated_age or 'Unknown' in estimated_age:
            return 'UNKNOWN'
        
        # Extract months from age string
        month_match = re.search(r'~?(\d+)\s*months?', estimated_age)
        if month_match:
            age_months = int(month_match.group(1))
            
            if age_months > max_age_months:
                return 'OVERDUE'
            elif age_months > max_age_months * 0.8:
                return 'DUE_SOON'
            else:
                return 'CURRENT'
        
        return 'UNKNOWN'
    
    def _build_recommendation(self, selector: str, estimated_age: Optional[str],
                             confidence: str, key_size: int, 
                             rotation_rec: Dict) -> str:
        """Build rotation recommendation"""
        
        if not estimated_age or confidence == 'LOW':
            return (f"⚠️ Cannot determine key age from selector pattern. "
                   f"Recommended rotation: every {rotation_rec['recommended_months']} months")
        
        if 'months' in estimated_age:
            month_match = re.search(r'~?(\d+)\s*months?', estimated_age)
            if month_match:
                age = int(month_match.group(1))
                
                if age > rotation_rec['max_age_months']:
                    return (f"🔴 KEY ROTATION OVERDUE! "
                           f"Key is ~{age} months old (max recommended: {rotation_rec['max_age_months']} months). "
                           f"Rotate immediately.")
                elif age > rotation_rec['recommended_months']:
                    return (f"🟡 Consider rotating soon. "
                           f"Key is ~{age} months old (recommended rotation: {rotation_rec['recommended_months']} months).")
                else:
                    return (f"✓ Key age is acceptable (~{age} months old). "
                           f"Next rotation due in ~{rotation_rec['recommended_months'] - age} months.")
        
        return f"ℹ️ {estimated_age}. Rotate every {rotation_rec['recommended_months']} months."
    
    def generate_rotation_report(self) -> str:
        """Generate comprehensive key rotation report"""
        if not self.keys_analyzed:
            return "No keys analyzed yet."
        
        lines = []
        lines.append("\n🔑 DKIM KEY AGE & ROTATION ANALYSIS")
        lines.append("=" * 70)
        lines.append(f"\nDomain: {self.domain}")
        lines.append(f"Keys Analyzed: {len(self.keys_analyzed)}\n")
        
        # Sort by urgency
        urgency_order = {'CRITICAL': 0, 'STANDARD': 1, 'LOW': 2}
        sorted_keys = sorted(self.keys_analyzed, 
                           key=lambda x: (urgency_order.get(x['urgency'], 3),
                                        x['rotation_status'] == 'OVERDUE'))
        
        for i, key in enumerate(sorted_keys, 1):
            status_icon = {
                'OVERDUE': '🔴',
                'DUE_SOON': '🟡',
                'CURRENT': '✓',
                'UNKNOWN': '❓'
            }.get(key['rotation_status'], '❓')
            
            lines.append(f"{i}. {status_icon} Selector: {key['selector']}")
            lines.append(f"   Key Size: {key['key_size']}-bit")
            lines.append(f"   Estimated Age: {key['estimated_age']} (confidence: {key['age_confidence']})")
            lines.append(f"   Status: {key['rotation_status']}")
            lines.append(f"   {key['recommendation']}")
            
            if key['key_hash']:
                lines.append(f"   Key Hash: {key['key_hash']} (for tracking)")
            
            lines.append("")
        
        # Summary
        overdue_count = sum(1 for k in self.keys_analyzed if k['rotation_status'] == 'OVERDUE')
        due_soon_count = sum(1 for k in self.keys_analyzed if k['rotation_status'] == 'DUE_SOON')
        current_count = sum(1 for k in self.keys_analyzed if k['rotation_status'] == 'CURRENT')
        
        lines.append("=" * 70)
        lines.append("📊 ROTATION STATUS SUMMARY:")
        lines.append(f"  🔴 Overdue: {overdue_count}")
        lines.append(f"  🟡 Due Soon: {due_soon_count}")
        lines.append(f"  ✓ Current: {current_count}")
        
        if overdue_count > 0:
            lines.append(f"\n⚠️  ACTION REQUIRED: {overdue_count} key(s) need immediate rotation!")
        elif due_soon_count > 0:
            lines.append(f"\nℹ️  PLAN AHEAD: {due_soon_count} key(s) should be rotated soon.")
        else:
            lines.append("\n✓ All keys are within recommended rotation periods.")
        
        return "\n".join(lines)
    
    def get_security_hygiene_score(self) -> Dict:
        """
        Calculate security hygiene score based on key age and rotation
        
        Returns score 0-100 with breakdown
        """
        if not self.keys_analyzed:
            return {'score': 0, 'grade': 'N/A', 'details': 'No keys analyzed'}
        
        total_score = 0
        max_score = len(self.keys_analyzed) * 100
        
        for key in self.keys_analyzed:
            # Score each key
            if key['rotation_status'] == 'CURRENT':
                total_score += 100
            elif key['rotation_status'] == 'DUE_SOON':
                total_score += 70
            elif key['rotation_status'] == 'OVERDUE':
                total_score += 30
            elif key['rotation_status'] == 'UNKNOWN':
                total_score += 50  # Neutral score for unknown
        
        final_score = int(total_score / max_score * 100)
        
        # Assign grade
        if final_score >= 90:
            grade = 'A'
        elif final_score >= 80:
            grade = 'B'
        elif final_score >= 70:
            grade = 'C'
        elif final_score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        return {
            'score': final_score,
            'grade': grade,
            'total_keys': len(self.keys_analyzed),
            'overdue': sum(1 for k in self.keys_analyzed if k['rotation_status'] == 'OVERDUE'),
            'due_soon': sum(1 for k in self.keys_analyzed if k['rotation_status'] == 'DUE_SOON'),
            'current': sum(1 for k in self.keys_analyzed if k['rotation_status'] == 'CURRENT')
        }


# Example usage
if __name__ == "__main__":
    analyzer = DKIMKeyAgeAnalyzer("example.com")
    
    # Test keys with different patterns
    test_keys = [
        ("google", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...", 2048),
        ("202401", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...", 2048),
        ("202201", "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNA...", 1024),
        ("v3", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...", 4096),
    ]
    
    for selector, record, key_size in test_keys:
        analyzer.analyze_key(selector, record, key_size)
    
    # Generate report
    print(analyzer.generate_rotation_report())
    
    # Show score
    print("\n" + "=" * 70)
    score = analyzer.get_security_hygiene_score()
    print(f"🏆 SECURITY HYGIENE SCORE: {score['score']}/100 (Grade: {score['grade']})")
    print(f"   Keys analyzed: {score['total_keys']}")
    print(f"   Current: {score['current']} | Due soon: {score['due_soon']} | Overdue: {score['overdue']}")
