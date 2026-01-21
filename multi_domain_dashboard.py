"""
MULTI-DOMAIN DASHBOARD

For MSPs and organizations managing multiple domains/brands.

Features:
- Batch domain scanning
- Comparative analysis
- Priority alerting
- Export/reporting for all domains
- Trend tracking

Perfect for:
- MSPs managing 10-100+ clients
- Enterprises with multiple brands
- Email security consultants
"""

from typing import Dict, List, Optional
from datetime import datetime
import json

class MultiDomainDashboard:
    """
    Manages and analyzes multiple domains simultaneously
    """
    
    def __init__(self):
        self.domains = {}
        self.scan_history = []
    
    def add_domain(self, domain: str, audit_results: Dict):
        """
        Add domain with audit results
        
        Args:
            domain: Domain name
            audit_results: Complete audit data including:
                - dkim_results
                - spf_results
                - dmarc_results
                - vendor_fingerprint
                - key_age_analysis
                - overall_score
        """
        self.domains[domain] = {
            'domain': domain,
            'last_scanned': datetime.now().isoformat(),
            'audit_results': audit_results,
            'status': self._determine_status(audit_results)
        }
        
        self.scan_history.append({
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'score': audit_results.get('overall_score', {}).get('score', 0)
        })
    
    def _determine_status(self, results: Dict) -> str:
        """Determine domain status from results"""
        score = results.get('overall_score', {}).get('score', 0)
        
        if score >= 90:
            return 'EXCELLENT'
        elif score >= 75:
            return 'GOOD'
        elif score >= 60:
            return 'WARNING'
        elif score >= 40:
            return 'CRITICAL'
        else:
            return 'FAILING'
    
    def get_summary_stats(self) -> Dict:
        """Get summary statistics across all domains"""
        if not self.domains:
            return {
                'total_domains': 0,
                'status_breakdown': {},
                'average_score': 0
            }
        
        status_counts = {}
        total_score = 0
        
        for domain_data in self.domains.values():
            status = domain_data['status']
            status_counts[status] = status_counts.get(status, 0) + 1
            
            score = domain_data['audit_results'].get('overall_score', {}).get('score', 0)
            total_score += score
        
        return {
            'total_domains': len(self.domains),
            'status_breakdown': status_counts,
            'average_score': round(total_score / len(self.domains), 1) if self.domains else 0,
            'excellent': status_counts.get('EXCELLENT', 0),
            'good': status_counts.get('GOOD', 0),
            'warning': status_counts.get('WARNING', 0),
            'critical': status_counts.get('CRITICAL', 0),
            'failing': status_counts.get('FAILING', 0)
        }
    
    def get_priority_alerts(self) -> List[Dict]:
        """Get prioritized list of issues requiring attention"""
        alerts = []
        
        for domain, data in self.domains.items():
            results = data['audit_results']
            score = results.get('overall_score', {}).get('score', 0)
            
            # Critical: No DMARC or policy=none
            dmarc = results.get('dmarc_results', {})
            if not dmarc.get('record'):
                alerts.append({
                    'domain': domain,
                    'severity': 'CRITICAL',
                    'category': 'DMARC',
                    'issue': 'No DMARC record',
                    'impact': 'Domain vulnerable to spoofing',
                    'priority': 1
                })
            elif dmarc.get('policy') == 'none':
                alerts.append({
                    'domain': domain,
                    'severity': 'HIGH',
                    'category': 'DMARC',
                    'issue': 'DMARC policy=none (monitoring only)',
                    'impact': 'Not enforcing email authentication',
                    'priority': 2
                })
            
            # High: Weak DKIM keys
            dkim = results.get('dkim_results', {})
            weak_keys = [s for s in dkim.get('found_selectors', []) 
                        if '1024' in s.get('key_type', '')]
            if weak_keys:
                alerts.append({
                    'domain': domain,
                    'severity': 'HIGH',
                    'category': 'DKIM',
                    'issue': f'{len(weak_keys)} weak 1024-bit key(s)',
                    'impact': 'Cryptographically weak signatures',
                    'priority': 2
                })
            
            # High: Overdue key rotation
            key_age = results.get('key_age_analysis', {})
            if key_age.get('overdue', 0) > 0:
                alerts.append({
                    'domain': domain,
                    'severity': 'HIGH',
                    'category': 'Key Rotation',
                    'issue': f'{key_age["overdue"]} key(s) overdue for rotation',
                    'impact': 'Increased security risk',
                    'priority': 2
                })
            
            # Medium: SPF issues
            spf = results.get('spf_results', {})
            if spf.get('lookup_count', 0) > 10:
                alerts.append({
                    'domain': domain,
                    'severity': 'MEDIUM',
                    'category': 'SPF',
                    'issue': f'SPF has {spf["lookup_count"]} lookups (max 10)',
                    'impact': 'SPF validation may fail',
                    'priority': 3
                })
        
        # Sort by priority then severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        alerts.sort(key=lambda x: (x['priority'], severity_order.get(x['severity'], 4)))
        
        return alerts
    
    def generate_comparison_matrix(self) -> Dict:
        """Generate comparison matrix across domains"""
        if not self.domains:
            return {}
        
        matrix = {
            'domains': list(self.domains.keys()),
            'dmarc_enforcement': {},
            'dkim_configured': {},
            'spf_configured': {},
            'overall_scores': {},
            'vendor_diversity': {}
        }
        
        for domain, data in self.domains.items():
            results = data['audit_results']
            
            # DMARC enforcement level
            dmarc = results.get('dmarc_results', {})
            policy = dmarc.get('policy', 'none')
            matrix['dmarc_enforcement'][domain] = policy
            
            # DKIM
            dkim = results.get('dkim_results', {})
            matrix['dkim_configured'][domain] = len(dkim.get('found_selectors', []))
            
            # SPF
            spf = results.get('spf_results', {})
            matrix['spf_configured'][domain] = bool(spf.get('record'))
            
            # Score
            score = results.get('overall_score', {}).get('score', 0)
            matrix['overall_scores'][domain] = score
            
            # Vendor diversity
            vendors = results.get('vendor_fingerprint', {}).get('vendors', [])
            matrix['vendor_diversity'][domain] = len(vendors)
        
        return matrix
    
    def generate_dashboard_report(self) -> str:
        """Generate comprehensive multi-domain dashboard report"""
        lines = []
        
        lines.append("\n📊 MULTI-DOMAIN EMAIL SECURITY DASHBOARD")
        lines.append("=" * 80)
        
        # Summary stats
        stats = self.get_summary_stats()
        lines.append(f"\n🏢 PORTFOLIO OVERVIEW:")
        lines.append(f"  Total Domains: {stats['total_domains']}")
        lines.append(f"  Average Score: {stats['average_score']}/100")
        lines.append("")
        lines.append(f"  Status Breakdown:")
        lines.append(f"    ✓ Excellent ({stats['excellent']}) | Good ({stats['good']}) | " 
                    f"⚠️  Warning ({stats['warning']}) | 🔴 Critical ({stats['critical']}) | "
                    f"❌ Failing ({stats['failing']})")
        
        # Priority alerts
        alerts = self.get_priority_alerts()
        if alerts:
            lines.append(f"\n🚨 PRIORITY ALERTS ({len(alerts)} total):")
            lines.append("")
            
            # Show top 10 alerts
            for i, alert in enumerate(alerts[:10], 1):
                severity_icon = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟡',
                    'MEDIUM': '🟠',
                    'LOW': 'ℹ️'
                }.get(alert['severity'], 'ℹ️')
                
                lines.append(f"{i}. {severity_icon} [{alert['severity']}] {alert['domain']}")
                lines.append(f"   Category: {alert['category']}")
                lines.append(f"   Issue: {alert['issue']}")
                lines.append(f"   Impact: {alert['impact']}")
                lines.append("")
            
            if len(alerts) > 10:
                lines.append(f"   ... and {len(alerts) - 10} more alerts")
        
        # Domain-by-domain summary
        lines.append("\n" + "=" * 80)
        lines.append("📋 DOMAIN SUMMARY:")
        lines.append("=" * 80)
        
        # Sort by score (worst first)
        sorted_domains = sorted(
            self.domains.items(),
            key=lambda x: x[1]['audit_results'].get('overall_score', {}).get('score', 0)
        )
        
        for domain, data in sorted_domains:
            results = data['audit_results']
            score = results.get('overall_score', {}).get('score', 0)
            grade = results.get('overall_score', {}).get('grade', 'F')
            status = data['status']
            
            status_icon = {
                'EXCELLENT': '✓',
                'GOOD': '✓',
                'WARNING': '⚠️',
                'CRITICAL': '🔴',
                'FAILING': '❌'
            }.get(status, '?')
            
            lines.append(f"\n{status_icon} {domain}")
            lines.append(f"  Score: {score}/100 (Grade: {grade}) | Status: {status}")
            
            # Quick checks
            dmarc = results.get('dmarc_results', {})
            dkim = results.get('dkim_results', {})
            spf = results.get('spf_results', {})
            
            checks = []
            checks.append(f"DMARC: {dmarc.get('policy', 'none')}")
            checks.append(f"DKIM: {len(dkim.get('found_selectors', []))} key(s)")
            checks.append(f"SPF: {'✓' if spf.get('record') else '❌'}")
            
            lines.append(f"  {' | '.join(checks)}")
            
            # Last scanned
            lines.append(f"  Last scanned: {data['last_scanned']}")
        
        return "\n".join(lines)
    
    def export_to_json(self, filename: str):
        """Export dashboard data to JSON"""
        export_data = {
            'export_date': datetime.now().isoformat(),
            'summary': self.get_summary_stats(),
            'alerts': self.get_priority_alerts(),
            'domains': self.domains,
            'comparison_matrix': self.generate_comparison_matrix()
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return f"Exported to {filename}"


# Example usage
if __name__ == "__main__":
    dashboard = MultiDomainDashboard()
    
    # Sample domains with different statuses
    sample_domains = [
        ('client1.com', {'overall_score': {'score': 95, 'grade': 'A'}, 
                        'dmarc_results': {'record': True, 'policy': 'reject'},
                        'dkim_results': {'found_selectors': [{'key_type': 'RSA 2048-bit'}]},
                        'spf_results': {'record': True, 'lookup_count': 5},
                        'key_age_analysis': {'overdue': 0}}),
        
        ('client2.com', {'overall_score': {'score': 65, 'grade': 'D'},
                        'dmarc_results': {'record': True, 'policy': 'none'},
                        'dkim_results': {'found_selectors': []},
                        'spf_results': {'record': True, 'lookup_count': 12},
                        'key_age_analysis': {'overdue': 0}}),
        
        ('client3.com', {'overall_score': {'score': 40, 'grade': 'F'},
                        'dmarc_results': {'record': False, 'policy': None},
                        'dkim_results': {'found_selectors': [{'key_type': 'RSA 1024-bit'}]},
                        'spf_results': {'record': False, 'lookup_count': 0},
                        'key_age_analysis': {'overdue': 2}}),
    ]
    
    for domain, results in sample_domains:
        dashboard.add_domain(domain, results)
    
    # Generate report
    print(dashboard.generate_dashboard_report())
    
    # Export
    print("\n" + "=" * 80)
    print(dashboard.export_to_json('/tmp/dashboard_export.json'))
