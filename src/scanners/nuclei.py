"""Nuclei Vulnerability Scanner - Enhanced Version"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
from typing import Dict, List

from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class NucleiScanner(BaseScanner):
    """Enhanced Nuclei template-based vulnerability scanner"""
    
    # Scan timeout in seconds (increased from 60 to 300)
    SCAN_TIMEOUT = 300  # 5 minutes
    
    # Request timeout
    REQUEST_TIMEOUT = 15  # seconds per request
    
    # Rate limit (requests per second)
    RATE_LIMIT = 100
    
    # Bulk size for concurrent requests
    BULK_SIZE = 50
    
    # Template categories to scan
    TEMPLATE_TAGS = [
        'cve',           # Known CVEs
        'panel',         # Admin panels
        'exposure',      # Information exposure
        'misconfig',     # Misconfigurations
        'default-login', # Default credentials
        'takeover',      # Subdomain takeover
        'tech',          # Technology detection
        'token',         # API tokens/keys exposure
        'config',        # Configuration files
        'backup',        # Backup files
    ]
    
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute enhanced Nuclei scan"""
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting enhanced Nuclei scan for {target_url}")
            
            # Create temporary file for results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            # Build nuclei command with enhanced options
            cmd = [
                'nuclei',
                '-target', target_url,
                '-json',
                '-output', temp_filename,
                '-severity', 'critical,high,medium,low,info',
                '-timeout', str(self.REQUEST_TIMEOUT),
                '-retries', '2',
                '-rate-limit', str(self.RATE_LIMIT),
                '-bulk-size', str(self.BULK_SIZE),
                '-concurrency', '25',
                '-no-color',
                '-silent',
                '-stats',
                # Scan specific template categories
                '-tags', ','.join(self.TEMPLATE_TAGS),
                # Enable automatic template updates check
                '-update-templates',
            ]
            
            # Add specific template paths if available
            template_paths = options.get('template_paths', [])
            for path in template_paths:
                cmd.extend(['-t', path])
            
            # Add custom headers if provided
            custom_headers = options.get('headers', {})
            for header_name, header_value in custom_headers.items():
                cmd.extend(['-H', f'{header_name}: {header_value}'])
            
            logger.info(f"Running Nuclei with timeout: {self.SCAN_TIMEOUT}s")
            
            # Run nuclei with extended timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=self.SCAN_TIMEOUT
                )
                
                # Log any stderr output for debugging
                if stderr:
                    stderr_text = stderr.decode('utf-8', errors='ignore')
                    if stderr_text.strip():
                        logger.debug(f"Nuclei stderr: {stderr_text[:500]}")
                        
            except asyncio.TimeoutError:
                logger.warning(f"Nuclei scan timeout ({self.SCAN_TIMEOUT}s) for {target_url}")
                process.kill()
                await process.wait()
                
                # Still try to parse partial results
                findings = self._parse_output_file(temp_filename)
                
                return {
                    'scanner': 'nuclei',
                    'target_url': target_url,
                    'findings': findings,
                    'timeout': True,
                    'message': f'Scan timed out after {self.SCAN_TIMEOUT}s, partial results returned'
                }
            
            # Parse results
            findings = self._parse_output_file(temp_filename)
            
            # Cleanup temp file
            try:
                if os.path.exists(temp_filename):
                    os.unlink(temp_filename)
            except Exception:
                pass
            
            logger.info(f"Nuclei scan completed with {len(findings)} findings")
            
            return {
                'scanner': 'nuclei',
                'target_url': target_url,
                'findings': findings,
                'scan_info': {
                    'timeout': self.SCAN_TIMEOUT,
                    'template_tags': self.TEMPLATE_TAGS,
                    'rate_limit': self.RATE_LIMIT
                }
            }
            
        except FileNotFoundError:
            logger.error("Nuclei binary not found - please install nuclei")
            return {
                'scanner': 'nuclei',
                'target_url': target_url,
                'error': 'Nuclei not installed. Install from: https://github.com/projectdiscovery/nuclei',
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
    
    def _parse_output_file(self, filename: str) -> List[Dict]:
        """Parse Nuclei JSON output file"""
        findings = []
        
        if not os.path.exists(filename):
            return findings
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Failed to parse Nuclei results: {e}")
        
        return findings
    
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
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in raw_results.get('findings', []):
            # Extract severity
            info = finding.get('info', {})
            nuclei_severity = info.get('severity', 'info').lower()
            
            # Normalize severity
            if nuclei_severity == 'critical':
                severity = 'critical'
            elif nuclei_severity in severity_counts:
                severity = nuclei_severity
            else:
                severity = 'info'
            
            severity_counts[severity] += 1
            
            # Extract additional metadata
            tags = info.get('tags', [])
            reference = info.get('reference', [])
            if isinstance(reference, str):
                reference = [reference]
            
            # Build vulnerability entry
            vuln = {
                'name': info.get('name', 'Unknown Vulnerability'),
                'description': info.get('description', 'No description available'),
                'severity': severity,
                'url': finding.get('matched-at', finding.get('host', '')),
                'template': finding.get('template-id', ''),
                'template_path': finding.get('template', ''),
                'matcher_name': finding.get('matcher-name', ''),
                'matched_line': finding.get('matched-line', ''),
                'extracted_results': finding.get('extracted-results', []),
                'tags': tags,
                'reference': reference,
                'curl_command': finding.get('curl-command', ''),
                'owasp_category': self._map_to_owasp(info, tags),
                'cve_id': self._extract_cve(tags, info),
                'cvss_score': info.get('classification', {}).get('cvss-score', ''),
                'cwe_id': info.get('classification', {}).get('cwe-id', []),
            }
            
            vulnerabilities.append(vuln)
        
        # Calculate summary with critical
        summary = {
            'total': len(vulnerabilities),
            'critical': severity_counts['critical'],
            'high': severity_counts['high'] + severity_counts['critical'],  # Include critical in high for compatibility
            'medium': severity_counts['medium'],
            'low': severity_counts['low'],
            'info': severity_counts['info']
        }
        
        return {
            'scanner': 'nuclei',
            'vulnerabilities': vulnerabilities,
            'summary': summary,
            'timeout': raw_results.get('timeout', False),
            'scan_info': raw_results.get('scan_info', {})
        }
    
    def _extract_cve(self, tags: List[str], info: Dict) -> str:
        """Extract CVE ID from tags or info"""
        # Check tags for CVE
        for tag in tags:
            if tag.upper().startswith('CVE-'):
                return tag.upper()
        
        # Check classification
        classification = info.get('classification', {})
        cve_id = classification.get('cve-id', '')
        if cve_id:
            if isinstance(cve_id, list):
                return cve_id[0] if cve_id else ''
            return cve_id
        
        # Check name for CVE pattern
        name = info.get('name', '')
        import re
        cve_match = re.search(r'CVE-\d{4}-\d+', name, re.IGNORECASE)
        if cve_match:
            return cve_match.group().upper()
        
        return ''
    
    def _map_to_owasp(self, info: Dict, tags: List[str]) -> str:
        """Map vulnerability to OWASP Top 10 2024 based on tags and info"""
        if not tags:
            tags = []
        
        tags_str = ' '.join(tags).lower()
        name = info.get('name', '').lower()
        description = info.get('description', '').lower()
        combined = f"{tags_str} {name} {description}"
        
        # A01:2024 - Broken Access Control
        if any(term in combined for term in ['idor', 'access control', 'authorization', 'privilege', 'path traversal', 'lfi', 'rfi', 'directory traversal']):
            return "A01:2024-Broken Access Control"
        
        # A02:2024 - Cryptographic Failures
        if any(term in combined for term in ['ssl', 'tls', 'crypto', 'cipher', 'certificate', 'encryption', 'weak-crypto', 'exposed-tokens']):
            return "A02:2024-Cryptographic Failures"
        
        # A03:2024 - Injection
        if any(term in combined for term in ['sqli', 'sql-injection', 'xss', 'injection', 'ssti', 'xxe', 'command-injection', 'ldap', 'nosql', 'template-injection']):
            return "A03:2024-Injection"
        
        # A04:2024 - Insecure Design
        if any(term in combined for term in ['insecure-design', 'business-logic', 'race-condition']):
            return "A04:2024-Insecure Design"
        
        # A05:2024 - Security Misconfiguration
        if any(term in combined for term in ['misconfig', 'misconfiguration', 'exposure', 'disclosure', 'panel', 'default-login', 'debug', 'config', 'backup', 'listing']):
            return "A05:2024-Security Misconfiguration"
        
        # A06:2024 - Vulnerable and Outdated Components
        if any(term in combined for term in ['cve', 'version', 'outdated', 'vulnerable', 'eol', 'end-of-life']):
            return "A06:2024-Vulnerable and Outdated Components"
        
        # A07:2024 - Identification and Authentication Failures
        if any(term in combined for term in ['auth', 'login', 'password', 'credential', 'session', 'token', 'jwt', 'oauth', 'brute']):
            return "A07:2024-Identification and Authentication Failures"
        
        # A08:2024 - Software and Data Integrity Failures
        if any(term in combined for term in ['deserialization', 'integrity', 'ci-cd', 'supply-chain', 'update']):
            return "A08:2024-Software and Data Integrity Failures"
        
        # A09:2024 - Security Logging and Monitoring Failures
        if any(term in combined for term in ['logging', 'monitoring', 'audit']):
            return "A09:2024-Security Logging and Monitoring Failures"
        
        # A10:2024 - Server-Side Request Forgery
        if any(term in combined for term in ['ssrf', 'server-side request forgery']):
            return "A10:2024-Server-Side Request Forgery (SSRF)"
        
        # Default to Security Misconfiguration for general findings
        return "A05:2024-Security Misconfiguration"
