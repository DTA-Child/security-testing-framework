#!/usr/bin/env python3
"""Test script for report generation functionality"""

import json
from datetime import datetime
from src.core.scanner import orchestrator
from src.reports.generator import ReportGenerator

def create_mock_scan():
    """Create a mock completed scan for testing report generation"""
    
    # Mock scan data with vulnerabilities
    mock_scan = {
        'id': 'test-scan-123',
        'target_url': 'https://example.com',
        'scan_types': ['zap', 'nuclei', 'nikto'],
        'status': 'completed',
        'created_at': '2024-01-15T10:00:00Z',
        'updated_at': '2024-01-15T10:15:00Z',
        'progress': 100,
        'errors': [],
        'results': {
            'zap': {
                'vulnerabilities': [
                    {
                        'name': 'SQL Injection',
                        'description': 'SQL injection vulnerability found in login form',
                        'severity': 'high',
                        'url': 'https://example.com/login',
                        'evidence': 'Error-based SQL injection detected',
                        'owasp_category': 'A03:2024 - Injection',
                        'recommendation': 'Use parameterized queries and input validation'
                    },
                    {
                        'name': 'Cross-Site Scripting (XSS)',
                        'description': 'Reflected XSS vulnerability in search parameter',
                        'severity': 'medium',
                        'url': 'https://example.com/search?q=<script>alert(1)</script>',
                        'evidence': 'Script tag reflected in response',
                        'owasp_category': 'A03:2024 - Injection',
                        'recommendation': 'Implement proper output encoding and CSP'
                    }
                ]
            },
            'nuclei': {
                'vulnerabilities': [
                    {
                        'name': 'Missing Security Headers',
                        'description': 'Security headers not implemented properly',
                        'severity': 'medium',
                        'url': 'https://example.com/',
                        'evidence': 'X-Frame-Options, CSP headers missing',
                        'owasp_category': 'A05:2024 - Security Misconfiguration',
                        'recommendation': 'Implement proper security headers'
                    },
                    {
                        'name': 'Directory Listing Enabled',
                        'description': 'Directory listing is enabled on web server',
                        'severity': 'low',
                        'url': 'https://example.com/uploads/',
                        'evidence': 'Directory listing visible',
                        'owasp_category': 'A05:2024 - Security Misconfiguration',
                        'recommendation': 'Disable directory listing in web server configuration'
                    }
                ]
            },
            'nikto': {
                'vulnerabilities': [
                    {
                        'name': 'Outdated Server Software',
                        'description': 'Server is running outdated software version',
                        'severity': 'medium',
                        'url': 'https://example.com/',
                        'evidence': 'Server: Apache/2.4.29',
                        'owasp_category': 'A06:2024 - Vulnerable and Outdated Components',
                        'recommendation': 'Update server software to latest version'
                    },
                    {
                        'name': 'Information Disclosure',
                        'description': 'Server version disclosed in response headers',
                        'severity': 'info',
                        'url': 'https://example.com/',
                        'evidence': 'Server header reveals version information',
                        'owasp_category': 'A01:2024 - Broken Access Control',
                        'recommendation': 'Configure server to hide version information'
                    }
                ]
            }
        }
    }
    
    # Add the mock scan to the orchestrator
    orchestrator.scans[mock_scan['id']] = mock_scan
    return mock_scan['id']

def test_report_generation():
    """Test report generation in all formats"""
    
    print("🔬 Testing Report Generation Functionality")
    print("=" * 50)
    
    # Create mock scan
    scan_id = create_mock_scan()
    print(f"✅ Created mock scan with ID: {scan_id}")
    
    # Test report generator
    generator = ReportGenerator()
    
    try:
        # Test HTML report
        print("📄 Generating HTML report...")
        html_path = generator.generate_html_report(scan_id)
        print(f"✅ HTML report generated: {html_path}")
        
        # Test PDF report  
        print("📄 Generating PDF report...")
        pdf_path = generator.generate_pdf_report(scan_id)
        print(f"✅ PDF report generated: {pdf_path}")
        
        # Test JSON report
        print("📄 Generating JSON report...")
        json_path = generator.generate_json_report(scan_id)
        print(f"✅ JSON report generated: {json_path}")
        
        print("\n🎉 All report generation tests completed successfully!")
        print(f"\n📊 Test Results Summary:")
        print(f"   - Mock scan created with 6 vulnerabilities")
        print(f"   - HTML, PDF, and JSON reports generated")
        print(f"   - Reports saved to reports/ directory")
        print(f"\n🌐 Test report download URLs:")
        print(f"   - HTML: /api/scan/{scan_id}/report/html")
        print(f"   - PDF:  /api/scan/{scan_id}/report/pdf") 
        print(f"   - JSON: /api/scan/{scan_id}/report/json")
        
    except Exception as e:
        print(f"❌ Error during report generation: {e}")
        return False
    
    return True

if __name__ == "__main__":
    test_report_generation()