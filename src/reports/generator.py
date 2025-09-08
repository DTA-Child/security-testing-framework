"""Report generation module"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
import logging
from jinja2 import Environment, FileSystemLoader
import weasyprint

from src.core.config import settings
from src.core.scanner import orchestrator

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate security scan reports in multiple formats"""
    
    def __init__(self):
        self.reports_dir = Path(settings.REPORTS_DIR)
        self.reports_dir.mkdir(exist_ok=True)
        
        # Setup Jinja2 for report templates
        self.template_env = Environment(
            loader=FileSystemLoader('templates/reports'),
            autoescape=True
        )
    
    def generate_html_report(self, scan_id: str) -> str:
        """Generate HTML report for a scan"""
        scan_data = orchestrator.get_scan(scan_id)
        if not scan_data:
            raise ValueError(f"Scan {scan_id} not found")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self._generate_html_report(scan_data, scan_id, timestamp)
    
    def generate_pdf_report(self, scan_id: str) -> str:
        """Generate PDF report for a scan"""
        scan_data = orchestrator.get_scan(scan_id)
        if not scan_data:
            raise ValueError(f"Scan {scan_id} not found")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self._generate_pdf_report(scan_data, scan_id, timestamp)
    
    def generate_json_report(self, scan_id: str) -> str:
        """Generate JSON report for a scan"""
        scan_data = orchestrator.get_scan(scan_id)
        if not scan_data:
            raise ValueError(f"Scan {scan_id} not found")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self._generate_json_report(scan_data, scan_id, timestamp)
    
    def _generate_html_report(self, scan_data: Dict, report_id: str, timestamp: str) -> str:
        """Generate HTML report"""
        try:
            # Prepare report data
            report_data = self._prepare_report_data(scan_data)
            
            # Prepare template data
            template_data = self._prepare_template_data(scan_data)
            
            # Load and render template
            template = self.template_env.get_template('security_report.html')
            html_content = template.render(**template_data)
            
            # Save HTML file
            filename = f"security_report_{report_id}_{timestamp}.html"
            filepath = self.reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {filename}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")
            raise
    
    def _generate_pdf_report(self, scan_data: Dict, report_id: str, timestamp: str) -> str:
        """Generate PDF report"""
        try:
            # First generate HTML
            html_file = self._generate_html_report(scan_data, report_id, timestamp)
            
            # Convert HTML to PDF
            filename = f"security_report_{report_id}_{timestamp}.pdf"
            pdf_filepath = self.reports_dir / filename
            
            # Read HTML content
            with open(html_file, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Convert to PDF using WeasyPrint
            weasyprint.HTML(string=html_content, base_url=str(self.reports_dir)).write_pdf(str(pdf_filepath))
            
            logger.info(f"PDF report generated: {filename}")
            return str(pdf_filepath)
            
        except Exception as e:
            logger.error(f"PDF report generation failed: {e}")
            # Return HTML file as fallback
            return html_file if 'html_file' in locals() else None
    
    def _generate_json_report(self, scan_data: Dict, report_id: str, timestamp: str) -> str:
        """Generate JSON report"""
        try:
            # Prepare report data
            report_data = self._prepare_report_data(scan_data)
            
            # Add metadata
            report_data['report_metadata'] = {
                'generated_at': datetime.now().isoformat(),
                'report_id': report_id,
                'format': 'json',
                'generator': f"{settings.APP_NAME} v{settings.VERSION}"
            }
            
            # Save JSON file
            filename = f"security_report_{report_id}_{timestamp}.json"
            filepath = self.reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"JSON report generated: {filename}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"JSON report generation failed: {e}")
            raise
    
    def _prepare_template_data(self, scan_data: Dict) -> Dict:
        """Prepare data for the HTML template"""
        # Basic scan info
        scan_info = {
            'target': scan_data.get('target_url', 'Unknown'),
            'start_time': self._format_datetime(scan_data.get('created_at')),
            'end_time': self._format_datetime(scan_data.get('updated_at')),
            'duration': self._calculate_duration(scan_data),
            'scan_type': ', '.join(scan_data.get('scan_types', [])),
            'status': scan_data.get('status', 'unknown'),
            'scanners_used': []
        }
        
        # Collect vulnerabilities from all scanners
        all_vulnerabilities = []
        scanner_summaries = []
        
        for scanner_name, result in scan_data.get('results', {}).items():
            scanner_summaries.append({
                'name': scanner_name.upper(),
                'findings_count': len(result.get('vulnerabilities', [])),
                'status': 'completed'
            })
            
            for vuln in result.get('vulnerabilities', []):
                all_vulnerabilities.append({
                    'title': vuln.get('name', vuln.get('title', 'Unknown Issue')),
                    'description': vuln.get('description', 'No description available'),
                    'severity': vuln.get('severity', 'info').lower(),
                    'url': vuln.get('url', scan_info['target']),
                    'evidence': vuln.get('evidence', ''),
                    'scanner': scanner_name.upper(),
                    'owasp_category': vuln.get('owasp_category', ''),
                    'recommendation': vuln.get('recommendation', '')
                })
        
        scan_info['scanners_used'] = scanner_summaries
        
        # Group vulnerabilities by severity
        vulnerabilities = {
            'critical': [v for v in all_vulnerabilities if v['severity'] == 'critical'],
            'high': [v for v in all_vulnerabilities if v['severity'] == 'high'],
            'medium': [v for v in all_vulnerabilities if v['severity'] == 'medium'],
            'low': [v for v in all_vulnerabilities if v['severity'] == 'low'],
            'info': [v for v in all_vulnerabilities if v['severity'] in ['info', 'informational']]
        }
        
        # Calculate summary statistics
        total_vulnerabilities = len(all_vulnerabilities)
        critical_count = len(vulnerabilities['critical'])
        high_count = len(vulnerabilities['high'])
        medium_count = len(vulnerabilities['medium'])
        low_count = len(vulnerabilities['low'])
        
        # Calculate security score
        if total_vulnerabilities == 0:
            security_score = 100
            score_level = 'Excellent'
            score_description = 'No security vulnerabilities detected'
        else:
            penalty = critical_count * 20 + high_count * 10 + medium_count * 5 + low_count * 2
            security_score = max(0, 100 - penalty)
            
            if security_score >= 90:
                score_level = 'Excellent'
                score_description = 'Very strong security posture'
            elif security_score >= 75:
                score_level = 'Good'
                score_description = 'Good security with minor improvements needed'
            elif security_score >= 50:
                score_level = 'Fair'
                score_description = 'Moderate security issues requiring attention'
            elif security_score >= 25:
                score_level = 'Poor'
                score_description = 'Significant security vulnerabilities detected'
            else:
                score_level = 'Critical'
                score_description = 'Critical security issues require immediate action'
        
        summary = {
            'total_vulnerabilities': total_vulnerabilities,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'security_score': security_score,
            'security_score_level': score_level,
            'security_score_description': score_description
        }
        
        # OWASP categories (simplified)
        owasp_categories = {}
        for vuln in all_vulnerabilities:
            if vuln['owasp_category']:
                cat = vuln['owasp_category']
                if cat not in owasp_categories:
                    owasp_categories[cat] = {
                        'count': 0,
                        'max_severity': 'info',
                        'description': f'Issues related to {cat}'
                    }
                owasp_categories[cat]['count'] += 1
                
                # Update max severity
                current_max = owasp_categories[cat]['max_severity']
                vuln_severity = vuln['severity']
                severity_order = ['info', 'low', 'medium', 'high', 'critical']
                if severity_order.index(vuln_severity) > severity_order.index(current_max):
                    owasp_categories[cat]['max_severity'] = vuln_severity
        
        return {
            'scan_info': scan_info,
            'summary': summary,
            'vulnerabilities': vulnerabilities,
            'owasp_categories': owasp_categories,
            'generation_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def _format_datetime(self, dt_str: str) -> str:
        """Format datetime string for display"""
        if not dt_str:
            return 'N/A'
        try:
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return dt_str
    
    def _prepare_report_data(self, scan_data: Dict) -> Dict:
        """Prepare and enrich scan data for reporting"""
        # Create a copy to avoid modifying original data
        report_data = scan_data.copy()
        
        # Calculate summary statistics
        summary_stats = self._calculate_summary_stats(scan_data)
        report_data['summary_stats'] = summary_stats
        
        # Categorize vulnerabilities by OWASP
        owasp_categories = self._categorize_by_owasp(scan_data)
        report_data['owasp_breakdown'] = owasp_categories
        
        # Add severity analysis
        severity_analysis = self._analyze_severity(scan_data)
        report_data['severity_analysis'] = severity_analysis
        
        # Add recommendations
        recommendations = self._generate_recommendations(scan_data)
        report_data['recommendations'] = recommendations
        
        return report_data
    
    def _calculate_summary_stats(self, scan_data: Dict) -> Dict:
        """Calculate summary statistics"""
        stats = {
            'total_vulnerabilities': 0,
            'high_risk_count': 0,
            'medium_risk_count': 0,
            'low_risk_count': 0,
            'info_count': 0,
            'scanners_used': len(scan_data.get('scan_types', [])),
            'scan_duration': self._calculate_duration(scan_data),
            'security_score': 0
        }
        
        # Count vulnerabilities by severity
        if scan_data.get('results'):
            for scanner_name, result in scan_data['results'].items():
                if result.get('summary'):
                    summary = result['summary']
                    stats['total_vulnerabilities'] += summary.get('total', 0)
                    stats['high_risk_count'] += summary.get('high', 0)
                    stats['medium_risk_count'] += summary.get('medium', 0)
                    stats['low_risk_count'] += summary.get('low', 0)
                    stats['info_count'] += summary.get('info', 0)
        
        # Calculate security score (0-100, higher is better)
        total_vulns = stats['total_vulnerabilities']
        if total_vulns == 0:
            stats['security_score'] = 100
        else:
            # Weighted score based on severity
            penalty = (stats['high_risk_count'] * 10 + 
                      stats['medium_risk_count'] * 5 + 
                      stats['low_risk_count'] * 2 + 
                      stats['info_count'] * 1)
            stats['security_score'] = max(0, 100 - penalty)
        
        return stats
    
    def _calculate_duration(self, scan_data: Dict) -> str:
        """Calculate scan duration"""
        try:
            if scan_data.get('created_at') and scan_data.get('completed_at'):
                start = datetime.fromisoformat(scan_data['created_at'].replace('Z', '+00:00'))
                end = datetime.fromisoformat(scan_data['completed_at'].replace('Z', '+00:00'))
                duration = end - start
                
                minutes, seconds = divmod(duration.total_seconds(), 60)
                if minutes > 0:
                    return f"{int(minutes)}m {int(seconds)}s"
                else:
                    return f"{int(seconds)}s"
            return "Unknown"
        except:
            return "Unknown"
    
    def _categorize_by_owasp(self, scan_data: Dict) -> Dict:
        """Categorize vulnerabilities by OWASP Top 10"""
        categories = {}
        
        if scan_data.get('results'):
            for scanner_name, result in scan_data['results'].items():
                if result.get('vulnerabilities'):
                    for vuln in result['vulnerabilities']:
                        owasp_cat = vuln.get('owasp_category', 'Uncategorized')
                        if owasp_cat not in categories:
                            categories[owasp_cat] = {
                                'count': 0,
                                'high': 0,
                                'medium': 0,
                                'low': 0,
                                'info': 0,
                                'vulnerabilities': []
                            }
                        
                        categories[owasp_cat]['count'] += 1
                        severity = vuln.get('severity', 'info').lower()
                        categories[owasp_cat][severity] = categories[owasp_cat].get(severity, 0) + 1
                        categories[owasp_cat]['vulnerabilities'].append(vuln)
        
        return categories
    
    def _analyze_severity(self, scan_data: Dict) -> Dict:
        """Analyze severity distribution"""
        analysis = {
            'risk_level': 'Unknown',
            'primary_concerns': [],
            'severity_distribution': {
                'high': {'count': 0, 'percentage': 0},
                'medium': {'count': 0, 'percentage': 0},
                'low': {'count': 0, 'percentage': 0},
                'info': {'count': 0, 'percentage': 0}
            }
        }
        
        total_vulns = 0
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        if scan_data.get('results'):
            for scanner_name, result in scan_data['results'].items():
                if result.get('vulnerabilities'):
                    for vuln in result['vulnerabilities']:
                        severity = vuln.get('severity', 'info').lower()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                            total_vulns += 1
        
        # Calculate percentages
        if total_vulns > 0:
            for severity, count in severity_counts.items():
                analysis['severity_distribution'][severity] = {
                    'count': count,
                    'percentage': round((count / total_vulns) * 100, 1)
                }
        
        # Determine overall risk level
        if severity_counts['high'] > 0:
            analysis['risk_level'] = 'High Risk'
            analysis['primary_concerns'].append('Critical security vulnerabilities detected')
        elif severity_counts['medium'] > 3:
            analysis['risk_level'] = 'Medium Risk'
            analysis['primary_concerns'].append('Multiple medium-severity issues')
        elif severity_counts['medium'] > 0 or severity_counts['low'] > 5:
            analysis['risk_level'] = 'Low Risk'
            analysis['primary_concerns'].append('Minor security improvements needed')
        else:
            analysis['risk_level'] = 'Minimal Risk'
            analysis['primary_concerns'].append('No significant security issues detected')
        
        return analysis
    
    def _generate_recommendations(self, scan_data: Dict) -> list:
        """Generate security recommendations"""
        recommendations = []
        
        # Default recommendations
        recommendations.append({
            'priority': 'High',
            'category': 'General',
            'title': 'Regular Security Scanning',
            'description': 'Implement regular security scanning as part of your development lifecycle.',
            'action': 'Schedule automated scans weekly or after major code changes.'
        })
        
        # Analyze results for specific recommendations
        if scan_data.get('results'):
            high_count = 0
            medium_count = 0
            
            for scanner_name, result in scan_data['results'].items():
                if result.get('summary'):
                    high_count += result['summary'].get('high', 0)
                    medium_count += result['summary'].get('medium', 0)
            
            if high_count > 0:
                recommendations.insert(0, {
                    'priority': 'Critical',
                    'category': 'Immediate Action Required',
                    'title': 'Address High-Severity Vulnerabilities',
                    'description': f'Found {high_count} high-severity vulnerabilities requiring immediate attention.',
                    'action': 'Review and fix high-severity issues within 24-48 hours.'
                })
            
            if medium_count > 2:
                recommendations.append({
                    'priority': 'High',
                    'category': 'Security Hardening',
                    'title': 'Improve Security Configuration',
                    'description': f'Multiple medium-severity issues ({medium_count}) indicate configuration problems.',
                    'action': 'Review security headers, SSL configuration, and access controls.'
                })
        
        recommendations.append({
            'priority': 'Medium',
            'category': 'Best Practices',
            'title': 'Security Monitoring',
            'description': 'Implement continuous security monitoring and logging.',
            'action': 'Set up security monitoring tools and incident response procedures.'
        })
        
        return recommendations

# Global report generator instance
report_generator = ReportGenerator()