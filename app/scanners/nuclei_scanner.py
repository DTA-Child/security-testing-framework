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
                '-timeout', str(options.get('timeout', 10)),
                '-retries', str(options.get('retries', 1)),
                '-rate-limit', str(options.get('rate_limit', 150))
            ]
            
            # Add templates if specified
            if 'templates' in options:
                cmd.extend(['-templates', options['templates']])
            
            # Run nuclei
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0 and process.returncode != 1:  # 1 is normal for nuclei when no vulns found
                logger.error(f"Nuclei scan failed: {stderr.decode()}")
                return {
                    'scanner': 'nuclei',
                    'target_url': target_url,
                    'error': f"Nuclei execution failed: {stderr.decode()}",
                    'findings': []
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
            error_msg = "Nuclei binary not found. Please install Nuclei."
            logger.error(error_msg)
            return {
                'scanner': 'nuclei',
                'target_url': target_url,
                'error': error_msg,
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
        
        # Map based on common nuclei tags
        if any(term in tags_str for term in ['sqli', 'xss', 'injection', 'rce', 'lfi', 'rfi']):
            return "A03:2021-Injection"
        elif any(term in tags_str for term in ['auth', 'login', 'session', 'jwt']):
            return "A07:2021-Identification and Authentication Failures"
        elif any(term in tags_str for term in ['idor', 'access-control', 'privilege']):
            return "A01:2021-Broken Access Control"
        elif any(term in tags_str for term in ['ssl', 'tls', 'crypto', 'hash']):
            return "A02:2021-Cryptographic Failures"
        elif any(term in tags_str for term in ['config', 'disclosure', 'exposure', 'misconfig']):
            return "A05:2021-Security Misconfiguration"
        elif any(term in tags_str for term in ['cve', 'version', 'outdated', 'component']):
            return "A06:2021-Vulnerable and Outdated Components"
        elif any(term in tags_str for term in ['log', 'monitor', 'debug']):
            return "A09:2021-Security Logging and Monitoring Failures"
        elif any(term in tags_str for term in ['ssrf', 'redirect']):
            return "A10:2021-Server-Side Request Forgery"
        elif any(term in tags_str for term in ['integrity', 'supply-chain']):
            return "A08:2021-Software and Data Integrity Failures"
        else:
            return "A04:2021-Insecure Design"
    
    def _extract_cwe_from_tags(self, tags: List[str]) -> str:
        """Extract CWE ID from nuclei tags"""
        for tag in tags:
            if tag.lower().startswith('cwe-'):
                return tag.upper()
        return ''