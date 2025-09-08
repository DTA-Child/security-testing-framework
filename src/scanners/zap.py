"""OWASP ZAP Security Scanner"""

import asyncio
import logging
from typing import Dict, List
import requests
import ssl
import socket
from urllib.parse import urlparse

from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

class ZAPScanner(BaseScanner):
    """Web Application Security Scanner using HTTP analysis"""
    
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute web security scan"""
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting web security scan for {target_url}")
            
            alerts = []
            
            # HTTP Header Analysis
            header_alerts = await self._check_security_headers(target_url)
            alerts.extend(header_alerts)
            
            # SSL/TLS Analysis
            if target_url.startswith('https://'):
                ssl_alerts = await self._check_ssl_configuration(target_url)
                alerts.extend(ssl_alerts)
            
            # Basic vulnerability checks
            vuln_alerts = await self._check_basic_vulnerabilities(target_url)
            alerts.extend(vuln_alerts)
            
            logger.info(f"Web scan completed with {len(alerts)} findings")
            
            return {
                'scanner': 'zap',
                'target_url': target_url,
                'alerts': alerts,
                'scan_summary': {'total_alerts': len(alerts)}
            }
            
        except Exception as e:
            logger.error(f"Web scan failed: {e}")
            return {
                'scanner': 'zap',
                'target_url': target_url,
                'error': str(e),
                'alerts': []
            }
    
    async def _check_security_headers(self, target_url: str) -> List[Dict]:
        """Check for missing security headers"""
        alerts = []
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'Missing MIME-sniffing protection',
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-XSS-Protection': 'Missing XSS protection',
                'Strict-Transport-Security': 'Missing HTTPS enforcement',
                'Content-Security-Policy': 'Missing content security policy'
            }
            
            for header, description in security_headers.items():
                if header.lower() not in [h.lower() for h in headers.keys()]:
                    alerts.append({
                        'name': f'{header} Header Missing',
                        'description': description,
                        'severity': 'Medium',
                        'url': target_url,
                        'evidence': f'Header {header} not found'
                    })
                    
        except Exception as e:
            logger.error(f"Header check failed: {e}")
            
        return alerts
    
    async def _check_ssl_configuration(self, target_url: str) -> List[Dict]:
        """Check SSL/TLS configuration"""
        alerts = []
        try:
            parsed_url = urlparse(target_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    if cipher and len(cipher) >= 3:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5']):
                            alerts.append({
                                'name': 'Weak SSL Cipher',
                                'description': f'Weak cipher suite detected: {cipher_name}',
                                'severity': 'Medium',
                                'url': target_url,
                                'evidence': f'Cipher: {cipher_name}'
                            })
                    
        except Exception as e:
            logger.error(f"SSL check failed: {e}")
            
        return alerts
    
    async def _check_basic_vulnerabilities(self, target_url: str) -> List[Dict]:
        """Check for information disclosure"""
        alerts = []
        try:
            response = requests.get(target_url, timeout=10)
            
            # Server header disclosure
            if 'Server' in response.headers:
                server_header = response.headers['Server']
                alerts.append({
                    'name': 'Server Information Disclosure',
                    'description': 'Web server reveals version information',
                    'severity': 'Low',
                    'url': target_url,
                    'evidence': f'Server: {server_header}'
                })
                
            # X-Powered-By disclosure
            if 'X-Powered-By' in response.headers:
                powered_by = response.headers['X-Powered-By']
                alerts.append({
                    'name': 'Technology Stack Disclosure',
                    'description': 'Application reveals technology information',
                    'severity': 'Low',
                    'url': target_url,
                    'evidence': f'X-Powered-By: {powered_by}'
                })
                
        except Exception as e:
            logger.error(f"Basic vulnerability check failed: {e}")
            
        return alerts
    
    async def parse_results(self, raw_results: Dict) -> Dict:
        """Parse results into standardized format"""
        if 'error' in raw_results:
            return {
                'scanner': 'zap',
                'vulnerabilities': [],
                'summary': {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'error': raw_results['error']
            }
        
        vulnerabilities = []
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for alert in raw_results.get('alerts', []):
            severity = alert.get('severity', 'info').lower()
            if severity not in severity_counts:
                severity = 'info'
            
            severity_counts[severity] += 1
            
            vulnerabilities.append({
                'name': alert.get('name', 'Unknown'),
                'description': alert.get('description', ''),
                'severity': severity,
                'url': alert.get('url', ''),
                'evidence': alert.get('evidence', ''),
                'owasp_category': self._map_to_owasp(alert.get('name', ''))
            })
        
        return {
            'scanner': 'zap',
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                **severity_counts
            }
        }
    
    def _map_to_owasp(self, vulnerability_name: str) -> str:
        """Map vulnerability to OWASP Top 10 2024"""
        name_lower = vulnerability_name.lower()
        
        if 'header' in name_lower or 'configuration' in name_lower:
            return "A05:2024-Security Misconfiguration"
        elif 'ssl' in name_lower or 'cipher' in name_lower:
            return "A02:2024-Cryptographic Failures"
        elif 'disclosure' in name_lower:
            return "A05:2024-Security Misconfiguration"
        else:
            return "A04:2024-Insecure Design"