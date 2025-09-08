from typing import Dict, List, Set
import logging
from collections import defaultdict, Counter
from datetime import datetime

from app.core.config import settings

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    """Analyzes vulnerability scan results and provides insights"""
    
    def __init__(self):
        self.risk_scores = {
            'high': 9,
            'medium': 6,
            'low': 3,
            'info': 1
        }
    
    def analyze_scan_results(self, scan_data: Dict) -> Dict:
        """Perform comprehensive analysis of scan results"""
        results = scan_data.get('results', {})
        
        analysis = {
            'overall_risk_score': 0,
            'risk_level': 'low',
            'vulnerability_summary': self._analyze_vulnerabilities(results),
            'owasp_breakdown': self._analyze_owasp_categories(results),
            'scanner_comparison': self._compare_scanners(results),
            'recommendations': self._generate_recommendations(results),
            'trends': self._analyze_trends(results),
            'compliance_status': self._assess_compliance(results)
        }
        
        analysis['overall_risk_score'] = self._calculate_risk_score(analysis['vulnerability_summary'])
        analysis['risk_level'] = self._determine_risk_level(analysis['overall_risk_score'])
        
        return analysis
    
    def _analyze_vulnerabilities(self, results: Dict) -> Dict:
        """Analyze vulnerability distribution and severity"""
        total_vulns = 0
        severity_counts = defaultdict(int)
        confidence_counts = defaultdict(int)
        scanner_vulns = defaultdict(int)
        unique_vulns = set()
        
        for scanner_name, scanner_results in results.items():
            if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                vulns = scanner_results['vulnerabilities']
                scanner_vulns[scanner_name] = len(vulns)
                
                for vuln in vulns:
                    total_vulns += 1
                    severity = vuln.get('severity', 'info')
                    confidence = vuln.get('confidence', 'unknown')
                    vuln_id = vuln.get('id', 'unknown')
                    
                    severity_counts[severity] += 1
                    confidence_counts[confidence] += 1
                    unique_vulns.add(vuln_id)
        
        return {
            'total_vulnerabilities': total_vulns,
            'unique_vulnerabilities': len(unique_vulns),
            'severity_distribution': dict(severity_counts),
            'confidence_distribution': dict(confidence_counts),
            'scanner_coverage': dict(scanner_vulns),
            'duplication_rate': self._calculate_duplication_rate(total_vulns, len(unique_vulns))
        }
    
    def _analyze_owasp_categories(self, results: Dict) -> Dict:
        """Analyze vulnerabilities by OWASP Top 10 categories"""
        owasp_counts = defaultdict(int)
        owasp_severity = defaultdict(lambda: defaultdict(int))
        
        for scanner_name, scanner_results in results.items():
            if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                for vuln in scanner_results['vulnerabilities']:
                    category = vuln.get('owasp_category', 'Unknown')
                    severity = vuln.get('severity', 'info')
                    
                    owasp_counts[category] += 1
                    owasp_severity[category][severity] += 1
        
        # Calculate risk score for each category
        category_risks = {}
        for category, count in owasp_counts.items():
            risk_score = sum(
                self.risk_scores.get(sev, 1) * cnt 
                for sev, cnt in owasp_severity[category].items()
            )
            category_risks[category] = {
                'count': count,
                'risk_score': risk_score,
                'severity_breakdown': dict(owasp_severity[category])
            }
        
        return {
            'category_distribution': dict(owasp_counts),
            'category_risks': category_risks,
            'most_affected_categories': sorted(
                owasp_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]
        }
    
    def _compare_scanners(self, results: Dict) -> Dict:
        """Compare scanner effectiveness and coverage"""
        scanner_metrics = {}
        
        for scanner_name, scanner_results in results.items():
            if isinstance(scanner_results, dict):
                vulns = scanner_results.get('vulnerabilities', [])
                summary = scanner_results.get('summary', {})
                
                scanner_metrics[scanner_name] = {
                    'total_findings': len(vulns),
                    'high_severity': summary.get('high', 0),
                    'medium_severity': summary.get('medium', 0),
                    'low_severity': summary.get('low', 0),
                    'info_severity': summary.get('info', 0),
                    'unique_categories': len(set(
                        v.get('owasp_category', 'Unknown') for v in vulns
                    )),
                    'average_confidence': self._calculate_avg_confidence(vulns),
                    'coverage_score': self._calculate_coverage_score(vulns)
                }
        
        return {
            'scanner_metrics': scanner_metrics,
            'best_coverage': max(
                scanner_metrics.items(),
                key=lambda x: x[1]['coverage_score'],
                default=(None, {})
            )[0],
            'most_findings': max(
                scanner_metrics.items(),
                key=lambda x: x[1]['total_findings'],
                default=(None, {})
            )[0]
        }
    
    def _generate_recommendations(self, results: Dict) -> List[Dict]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Analyze vulnerability patterns
        all_vulns = []
        for scanner_results in results.values():
            if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                all_vulns.extend(scanner_results['vulnerabilities'])
        
        # High-priority recommendations
        high_severity_count = len([v for v in all_vulns if v.get('severity') == 'high'])
        if high_severity_count > 0:
            recommendations.append({
                'priority': 'critical',
                'category': 'Immediate Action Required',
                'title': f'Address {high_severity_count} High-Severity Vulnerabilities',
                'description': 'High-severity vulnerabilities pose immediate security risks and should be patched immediately.',
                'action_items': [
                    'Review all high-severity findings',
                    'Prioritize fixes based on exploitability',
                    'Implement temporary mitigations if immediate fixes are not possible'
                ]
            })
        
        # OWASP category recommendations
        owasp_analysis = self._analyze_owasp_categories(results)
        top_categories = owasp_analysis['most_affected_categories'][:3]
        
        for category, count in top_categories:
            if count > 2:  # Only recommend if significant findings
                recommendations.append({
                    'priority': 'high',
                    'category': 'OWASP Top 10',
                    'title': f'Address {category} Issues',
                    'description': f'Found {count} vulnerabilities in {category}',
                    'action_items': self._get_category_recommendations(category)
                })
        
        # General security recommendations
        recommendations.extend([
            {
                'priority': 'medium',
                'category': 'Security Practices',
                'title': 'Implement Security Headers',
                'description': 'Ensure proper security headers are implemented',
                'action_items': [
                    'Configure Content Security Policy (CSP)',
                    'Set X-Frame-Options header',
                    'Enable HSTS for HTTPS sites',
                    'Set X-Content-Type-Options: nosniff'
                ]
            },
            {
                'priority': 'medium',
                'category': 'Monitoring',
                'title': 'Enhance Security Monitoring',
                'description': 'Implement comprehensive security monitoring',
                'action_items': [
                    'Set up intrusion detection systems',
                    'Implement log monitoring and SIEM',
                    'Configure automated vulnerability scanning',
                    'Establish incident response procedures'
                ]
            }
        ])
        
        return recommendations[:10]  # Return top 10 recommendations
    
    def _analyze_trends(self, results: Dict) -> Dict:
        """Analyze vulnerability trends and patterns"""
        return {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'common_vulnerabilities': self._find_common_vulnerabilities(results),
            'risk_indicators': self._identify_risk_indicators(results),
            'improvement_areas': self._identify_improvement_areas(results)
        }
    
    def _assess_compliance(self, results: Dict) -> Dict:
        """Assess compliance with security standards"""
        all_vulns = []
        for scanner_results in results.values():
            if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                all_vulns.extend(scanner_results['vulnerabilities'])
        
        high_medium_count = len([v for v in all_vulns if v.get('severity') in ['high', 'medium']])
        
        return {
            'owasp_compliance': 'fail' if high_medium_count > 5 else 'pass',
            'security_grade': self._calculate_security_grade(all_vulns),
            'compliance_score': max(0, 100 - (high_medium_count * 10)),
            'requirements_met': high_medium_count == 0,
            'recommendations_count': len(self._generate_recommendations(results))
        }
    
    # Helper methods
    def _calculate_risk_score(self, vuln_summary: Dict) -> float:
        """Calculate overall risk score"""
        severity_dist = vuln_summary.get('severity_distribution', {})
        
        score = sum(
            self.risk_scores.get(severity, 1) * count
            for severity, count in severity_dist.items()
        )
        
        return min(score, 100)  # Cap at 100
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score"""
        if risk_score >= 70:
            return 'critical'
        elif risk_score >= 40:
            return 'high'
        elif risk_score >= 15:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_duplication_rate(self, total: int, unique: int) -> float:
        """Calculate vulnerability duplication rate"""
        if total == 0:
            return 0.0
        return round((1 - unique / total) * 100, 2)
    
    def _calculate_avg_confidence(self, vulns: List[Dict]) -> str:
        """Calculate average confidence level"""
        if not vulns:
            return 'unknown'
        
        confidence_map = {'high': 3, 'medium': 2, 'low': 1}
        scores = [confidence_map.get(v.get('confidence', 'low'), 1) for v in vulns]
        avg_score = sum(scores) / len(scores)
        
        if avg_score >= 2.5:
            return 'high'
        elif avg_score >= 1.5:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_coverage_score(self, vulns: List[Dict]) -> float:
        """Calculate scanner coverage score"""
        if not vulns:
            return 0.0
        
        categories_covered = len(set(v.get('owasp_category', 'Unknown') for v in vulns))
        severity_variety = len(set(v.get('severity', 'info') for v in vulns))
        
        return (categories_covered * 5) + (severity_variety * 2) + len(vulns)
    
    def _get_category_recommendations(self, category: str) -> List[str]:
        """Get specific recommendations for OWASP category"""
        recommendations_map = {
            "A01:2024-Broken Access Control": [
                "Implement Zero Trust architecture with proper access controls",
                "Use principle of least privilege and role-based access control (RBAC)",
                "Regular access control testing with automated tools"
            ],
            "A02:2024-Cryptographic Failures": [
                "Use modern encryption algorithms (AES-256, RSA-4096+)",
                "Implement proper cryptographic key management and rotation",
                "Encrypt sensitive data in transit (TLS 1.3+) and at rest"
            ],
            "A03:2024-Injection": [
                "Use parameterized queries, prepared statements, and ORM frameworks", 
                "Implement comprehensive input validation and output encoding",
                "Deploy Web Application Firewalls (WAF) with injection protection"
            ],
            "A04:2024-Insecure Design": [
                "Implement secure-by-design principles in development lifecycle",
                "Conduct regular threat modeling and security architecture reviews",
                "Use established security design patterns and frameworks"
            ],
            "A05:2024-Security Misconfiguration": [
                "Implement Infrastructure as Code (IaC) with security templates",
                "Regular automated security configuration scanning",
                "Disable unnecessary features, services, and default accounts"
            ],
            "A06:2024-Vulnerable and Outdated Components": [
                "Implement automated dependency scanning in CI/CD pipeline", 
                "Maintain software bill of materials (SBOM)",
                "Regular patching and component lifecycle management"
            ],
            "A07:2024-Identification and Authentication Failures": [
                "Implement multi-factor authentication (MFA) everywhere",
                "Use modern authentication protocols (OAuth 2.1, OpenID Connect)",
                "Deploy adaptive authentication and session management"
            ],
            "A08:2024-Software and Data Integrity Failures": [
                "Implement digital signatures for software updates",
                "Use secure CI/CD pipelines with integrity checks",
                "Deploy supply chain security measures"
            ],
            "A09:2024-Security Logging and Monitoring Failures": [
                "Implement comprehensive security monitoring (SIEM/SOAR)",
                "Deploy real-time threat detection and automated response",
                "Ensure proper log retention and forensic capabilities"
            ],
            "A10:2024-Server-Side Request Forgery (SSRF)": [
                "Implement strict input validation for URLs and network requests",
                "Use allowlists for external service communications",
                "Deploy network segmentation and egress filtering"
            ]
        }
        
        return recommendations_map.get(category, [
            "Review and remediate identified vulnerabilities",
            "Implement security best practices",
            "Regular security assessments"
        ])
    
    def _find_common_vulnerabilities(self, results: Dict) -> List[str]:
        """Find most common vulnerability types"""
        vuln_names = []
        for scanner_results in results.values():
            if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                vuln_names.extend([v.get('name', 'Unknown') for v in scanner_results['vulnerabilities']])
        
        common = Counter(vuln_names).most_common(5)
        return [name for name, count in common]
    
    def _identify_risk_indicators(self, results: Dict) -> List[str]:
        """Identify key risk indicators"""
        indicators = []
        
        all_vulns = []
        for scanner_results in results.values():
            if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                all_vulns.extend(scanner_results['vulnerabilities'])
        
        high_count = len([v for v in all_vulns if v.get('severity') == 'high'])
        if high_count > 3:
            indicators.append(f"High number of critical vulnerabilities ({high_count})")
        
        injection_count = len([v for v in all_vulns if 'injection' in v.get('name', '').lower()])
        if injection_count > 0:
            indicators.append(f"Injection vulnerabilities detected ({injection_count})")
        
        return indicators
    
    def _identify_improvement_areas(self, results: Dict) -> List[str]:
        """Identify areas for security improvement"""
        return [
            "Implement automated security testing in CI/CD pipeline",
            "Regular security training for development team",
            "Establish secure coding standards",
            "Implement security code review process"
        ]
    
    def _calculate_security_grade(self, vulns: List[Dict]) -> str:
        """Calculate security grade (A-F)"""
        high_count = len([v for v in vulns if v.get('severity') == 'high'])
        medium_count = len([v for v in vulns if v.get('severity') == 'medium'])
        
        if high_count == 0 and medium_count == 0:
            return 'A'
        elif high_count == 0 and medium_count <= 2:
            return 'B'
        elif high_count <= 1 and medium_count <= 5:
            return 'C'
        elif high_count <= 3 and medium_count <= 10:
            return 'D'
        else:
            return 'F'