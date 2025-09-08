import asyncio
import json
import logging
import subprocess
from typing import Dict, List, Optional
import tempfile
import os

from app.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class NucleiScanner(BaseScanner):
    """Nuclei Vulnerability Scanner"""
    
    def __init__(self):
        self.version = "2.9.4"
        self.description = "Nuclei Community Edition - Vulnerability Scanner"
    
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute Nuclei scan"""
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting Nuclei scan for {target_url}")
            
            # Try real Nuclei first, then fallback to mock data
            try:
                # Create temporary file for results
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                    temp_filename = temp_file.name
                
                # Build nuclei command
                cmd = [
                    'nuclei',
                    '-target', target_url,
                    '-json',
                    '-output', temp_filename,
                    '-severity', options.get('severity', 'critical,high,medium,low,info'),
                    '-timeout', str(options.get('timeout', 5)),
                    '-retries', str(options.get('retries', 1)),
                    '-rate-limit', str(options.get('rate_limit', 150)),
                    '-no-color',
                    '-silent'
                ]
                
                # Run nuclei with timeout
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                except asyncio.TimeoutError:
                    logger.warning("Nuclei scan timed out")
                    process.kill()
                    return {
                        'scanner': 'nuclei',
                        'target_url': target_url,
                        'findings': [],
                        'timeout': True,
                        'scan_summary': {'total_findings': 0}
                    }
                
                # Parse results from file
                findings = []
                if os.path.exists(temp_filename):
                    try:
                        with open(temp_filename, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    findings.append(json.loads(line))
                    except Exception as e:
                        logger.error(f"Failed to parse Nuclei results: {e}")
                    finally:
                        os.unlink(temp_filename)
                
                # Return real results even if empty
                if len(findings) == 0:
                    logger.info(f"Nuclei scan completed with no vulnerabilities found for {target_url}")
                    return {
                        'scanner': 'nuclei',
                        'target_url': target_url,
                        'findings': [],
                        'scan_summary': {'total_findings': 0}
                    }
                
                logger.info(f"Nuclei scan completed with {len(findings)} findings")
                
                return {
                    'scanner': 'nuclei',
                    'target_url': target_url,
                    'findings': findings,
                    'scan_summary': {
                        'total_findings': len(findings)
                    }
                }
                
            except FileNotFoundError:
                logger.error("Nuclei binary not found. Please install Nuclei.")
                return {
                    'scanner': 'nuclei',
                    'target_url': target_url,
                    'error': 'Nuclei binary not found. Please install Nuclei.',
                    'findings': []
                }
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return {
                'scanner': 'nuclei',
                'target_url': target_url,
                'error': str(e),
                'findings': []
            }
    
    def _get_mock_nuclei_data(self, target_url: str) -> Dict:
        """Generate mock Nuclei findings for demo purposes"""
        findings = [
            {
                'template-id': 'tech-detect',
                'info': {
                    'name': 'Technology Detection',
                    'description': 'Detected web technologies and frameworks',
                    'severity': 'info',
                    'tags': ['tech', 'fingerprint']
                },
                'matched-at': target_url,
                'extracted-results': ['nginx/1.18.0', 'PHP/7.4.3'],
                'type': 'http'
            },
            {
                'template-id': 'missing-headers',
                'info': {
                    'name': 'Missing Security Headers',
                    'description': 'Important security headers are missing from the response',
                    'severity': 'medium',
                    'tags': ['misconfig', 'headers'],
                    'reference': ['https://owasp.org/Top10/A05_2024-Security_Misconfiguration/']
                },
                'matched-at': target_url,
                'extracted-results': ['X-Frame-Options', 'X-Content-Type-Options'],
                'type': 'http'
            },
            {
                'template-id': 'ssl-weak-cipher',
                'info': {
                    'name': 'Weak SSL Cipher Suites',
                    'description': 'Server supports weak SSL/TLS cipher suites that can be exploited',
                    'severity': 'medium',
                    'tags': ['ssl', 'crypto', 'tls'],
                    'reference': ['https://owasp.org/Top10/A02_2024-Cryptographic_Failures/']
                },
                'matched-at': target_url.replace('http://', 'https://'),
                'extracted-results': ['TLS_RSA_WITH_RC4_128_SHA'],
                'type': 'ssl'
            },
            {
                'template-id': 'cve-2023-demo',
                'info': {
                    'name': 'Outdated Component Version',
                    'description': 'Application uses components with known vulnerabilities',
                    'severity': 'high',
                    'tags': ['cve', 'component', 'version'],
                    'reference': ['https://owasp.org/Top10/A06_2024-Vulnerable_and_Outdated_Components/']
                },
                'matched-at': target_url + '/admin',
                'extracted-results': ['CVE-2023-DEMO'],
                'type': 'http'
            }
        ]
        
        return {
            'scanner': 'nuclei',
            'target_url': target_url,
            'findings': findings,
            'scan_summary': {
                'total_findings': len(findings)
            }
        }
    
    async def parse_results(self, raw_results: Dict) -> Dict:
        """Parse Nuclei results into standardized format"""
        if 'error' in raw_results:
            return {
                'scanner': 'nuclei',
                'vulnerabilities': [],
                'summary': {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'error': raw_results['error']
            }
        
        vulnerabilities = []
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in raw_results.get('findings', []):
            # Map nuclei severity to standard severity
            nuclei_severity = finding.get('info', {}).get('severity', 'info').lower()
            if nuclei_severity == 'critical':
                severity = 'high'  # Map critical to high
            else:
                severity = nuclei_severity
            
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['info'] += 1
                severity = 'info'
            
            vulnerability = {
                'id': finding.get('template-id', 'unknown'),
                'name': finding.get('info', {}).get('name', 'Unknown Vulnerability'),
                'description': finding.get('info', {}).get('description', ''),
                'severity': severity,  
                'confidence': 'high',  # Nuclei templates are generally high confidence
                'url': finding.get('matched-at', ''),
                'param': '',
                'evidence': finding.get('extracted-results', []),
                'solution': finding.get('info', {}).get('remediation', ''),
                'reference': ', '.join(finding.get('info', {}).get('reference', [])),
                'owasp_category': self._map_to_owasp_category(finding.get('info', {}).get('tags', [])),
                'cwe_id': self._extract_cwe_from_tags(finding.get('info', {}).get('tags', [])),
                'template_path': finding.get('template', ''),
                'matcher_name': finding.get('matcher-name', ''),
                'type': finding.get('type', '')
            }
            vulnerabilities.append(vulnerability)
        
        return {
            'scanner': 'nuclei',
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                **severity_counts
            },
            'scan_info': {
                'target_url': raw_results.get('target_url', ''),
                'templates_used': len(set(v['template_path'] for v in vulnerabilities))
            }
        }
    
    def _map_to_owasp_category(self, tags: List[str]) -> str:
        """Map nuclei tags to OWASP Top 10 category"""
        if not tags:
            return "A04:2021-Insecure Design"
        
        tags_str = ' '.join(tags).lower()
        
        # OWASP Top 10 2024 mapping based on nuclei tags
        if any(term in tags_str for term in ['sqli', 'xss', 'injection', 'rce', 'lfi', 'rfi']):
            return "A03:2024-Injection"
        elif any(term in tags_str for term in ['auth', 'login', 'session', 'jwt']):
            return "A07:2024-Identification and Authentication Failures"
        elif any(term in tags_str for term in ['idor', 'access-control', 'privilege']):
            return "A01:2024-Broken Access Control"
        elif any(term in tags_str for term in ['ssl', 'tls', 'crypto', 'hash']):
            return "A02:2024-Cryptographic Failures"
        elif any(term in tags_str for term in ['config', 'disclosure', 'exposure', 'misconfig']):
            return "A05:2024-Security Misconfiguration"
        elif any(term in tags_str for term in ['cve', 'version', 'outdated', 'component']):
            return "A06:2024-Vulnerable and Outdated Components"
        elif any(term in tags_str for term in ['log', 'monitor', 'debug']):
            return "A09:2024-Security Logging and Monitoring Failures"
        elif any(term in tags_str for term in ['ssrf', 'redirect']):
            return "A10:2024-Server-Side Request Forgery (SSRF)"
        elif any(term in tags_str for term in ['integrity', 'supply-chain']):
            return "A08:2024-Software and Data Integrity Failures"
        else:
            return "A04:2024-Insecure Design"
    
    def _extract_cwe_from_tags(self, tags: List[str]) -> str:
        """Extract CWE ID from nuclei tags"""
        for tag in tags:
            if tag.lower().startswith('cwe-'):
                return tag.upper()
        return ''