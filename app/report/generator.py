import os
import json
from datetime import datetime
from typing import Dict, Optional
import logging
from jinja2 import Environment, FileSystemLoader, select_autoescape
import weasyprint

from app.report.analyzer import VulnerabilityAnalyzer  
from app.core.config import settings

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates security scan reports in various formats"""
    
    def __init__(self):
        self.analyzer = VulnerabilityAnalyzer()
        self.template_dir = "templates"
        
        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Ensure reports directory exists
        os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
    
    async def generate_html_report(self, scan_id: str, scan_data: Dict) -> str:
        """Generate HTML report with vulnerability tabs"""
        try:
            logger.info(f"Generating HTML report for scan {scan_id}")
            
            # Perform analysis
            analysis = self.analyzer.analyze_scan_results(scan_data)
            
            # Prepare template data
            template_data = {
                'scan_id': scan_id,
                'scan_data': scan_data,
                'analysis': analysis,
                'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'owasp_categories': settings.OWASP_CATEGORIES,
                'vulnerabilities_by_category': self._group_vulnerabilities_by_category(scan_data),
                'severity_colors': {
                    'high': '#dc3545',
                    'medium': '#fd7e14', 
                    'low': '#ffc107',
                    'info': '#17a2b8'
                }
            }
            
            # Load and render template
            template = self.jinja_env.get_template('report_template.html')
            html_content = template.render(**template_data)
            
            # Save report
            report_filename = f"security_report_{scan_id}.html"
            report_path = os.path.join(settings.REPORT_OUTPUT_DIR, report_filename)
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise
    
    async def generate_pdf_report(self, scan_id: str, scan_data: Dict) -> str:
        """Generate PDF report from HTML template"""
        try:
            logger.info(f"Generating PDF report for scan {scan_id}")
            
            # First generate HTML report
            html_path = await self.generate_html_report(scan_id, scan_data)
            
            # Convert to PDF
            pdf_filename = f"security_report_{scan_id}.pdf"
            pdf_path = os.path.join(settings.REPORT_OUTPUT_DIR, pdf_filename)
            
            weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
            
            logger.info(f"PDF report generated: {pdf_path}")
            return pdf_path
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise
    
    async def generate_json_report(self, scan_id: str, scan_data: Dict) -> str:
        """Generate structured JSON report"""
        try:
            logger.info(f"Generating JSON report for scan {scan_id}")
            
            # Perform analysis
            analysis = self.analyzer.analyze_scan_results(scan_data)
            
            # Create comprehensive report data
            report_data = {
                'report_info': {
                    'scan_id': scan_id,
                    'generated_at': datetime.utcnow().isoformat(),
                    'report_version': '1.0.0',
                    'format': 'json'
                },
                'scan_metadata': {
                    'target_url': scan_data.get('target_url'),
                    'scan_types': scan_data.get('scan_types', []),
                    'status': scan_data.get('status'),
                    'created_at': scan_data.get('created_at'),
                    'completed_at': scan_data.get('completed_at', ''),
                    'progress': scan_data.get('progress', 0)
                },
                'scan_results': scan_data.get('results', {}),
                'analysis': analysis,
                'vulnerabilities_by_category': self._group_vulnerabilities_by_category(scan_data),
                'executive_summary': self._create_executive_summary(analysis)
            }
            
            # Save JSON report
            json_filename = f"security_report_{scan_id}.json"
            json_path = os.path.join(settings.REPORT_OUTPUT_DIR, json_filename)
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {json_path}")
            return json_path
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise
    
    def _group_vulnerabilities_by_category(self, scan_data: Dict) -> Dict:
        """Group vulnerabilities by OWASP categories"""
        category_groups = {}
        
        # Initialize all OWASP categories
        for category in settings.OWASP_CATEGORIES:
            category_groups[category] = []
        
        # Add 'Other' category for unmapped vulnerabilities
        category_groups['Other'] = []
        
        # Group vulnerabilities
        results = scan_data.get('results', {})
        for scanner_name, scanner_results in results.items():
            if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                for vuln in scanner_results['vulnerabilities']:
                    category = vuln.get('owasp_category', 'Other')
                    
                    # Add scanner information to vulnerability
                    vuln_with_scanner = vuln.copy()
                    vuln_with_scanner['scanner'] = scanner_name
                    
                    if category in category_groups:
                        category_groups[category].append(vuln_with_scanner)
                    else:
                        category_groups['Other'].append(vuln_with_scanner)
        
        # Remove empty categories for cleaner display
        return {k: v for k, v in category_groups.items() if v}
    
    def _create_executive_summary(self, analysis: Dict) -> Dict:
        """Create executive summary of findings"""
        vuln_summary = analysis.get('vulnerability_summary', {})
        compliance = analysis.get('compliance_status', {})
        
        return {
            'overall_security_posture': analysis.get('risk_level', 'unknown'),
            'security_grade': compliance.get('security_grade', 'F'),
            'total_vulnerabilities': vuln_summary.get('total_vulnerabilities', 0),
            'critical_issues': vuln_summary.get('severity_distribution', {}).get('high', 0),
            'risk_score': analysis.get('overall_risk_score', 0),
            'compliance_score': compliance.get('compliance_score', 0),
            'key_findings': [
                f"Found {vuln_summary.get('total_vulnerabilities', 0)} total vulnerabilities",
                f"Security grade: {compliance.get('security_grade', 'F')}",
                f"Overall risk level: {analysis.get('risk_level', 'unknown').title()}"
            ],
            'immediate_actions': [
                rec['title'] for rec in analysis.get('recommendations', [])[:3]
                if rec.get('priority') in ['critical', 'high']
            ]
        }
    
    def get_report_path(self, scan_id: str, format: str = 'html') -> str:
        """Get path to existing report file"""
        filename = f"security_report_{scan_id}.{format}"
        return os.path.join(settings.REPORT_OUTPUT_DIR, filename)
    
    def report_exists(self, scan_id: str, format: str = 'html') -> bool:
        """Check if report file exists"""
        report_path = self.get_report_path(scan_id, format)
        return os.path.exists(report_path)
    
    def delete_report(self, scan_id: str, format: str = 'html') -> bool:
        """Delete report file"""
        try:
            report_path = self.get_report_path(scan_id, format)
            if os.path.exists(report_path):
                os.remove(report_path)
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete report: {e}")
            return False
    
    def get_report_stats(self) -> Dict:
        """Get statistics about generated reports"""
        try:
            if not os.path.exists(settings.REPORT_OUTPUT_DIR):
                return {'total_reports': 0, 'formats': {}}
            
            files = os.listdir(settings.REPORT_OUTPUT_DIR)
            format_counts = {}
            
            for file in files:
                if file.startswith('security_report_'):
                    ext = file.split('.')[-1]
                    format_counts[ext] = format_counts.get(ext, 0) + 1
            
            return {
                'total_reports': len(files),
                'formats': format_counts,
                'report_directory': settings.REPORT_OUTPUT_DIR
            }
            
        except Exception as e:
            logger.error(f"Failed to get report stats: {e}")
            return {'total_reports': 0, 'formats': {}}