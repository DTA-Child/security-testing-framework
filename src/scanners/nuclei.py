"""Nuclei Vulnerability Scanner - Fixed Version for Nuclei v3.x"""

import asyncio
import json
import logging
import tempfile
import os
from typing import Dict, List

from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class NucleiScanner(BaseScanner):
    """Fixed Nuclei template-based vulnerability scanner for v3.x"""
    
    # Scan timeout in seconds
    SCAN_TIMEOUT = 300  # 5 minutes
    
    # Request timeout per request
    REQUEST_TIMEOUT = 10  # seconds
    
    # Rate limit (requests per second)
    RATE_LIMIT = 150  # default in nuclei v3
    
    # Bulk size for concurrent requests
    BULK_SIZE = 25  # default in nuclei v3
    
    # Concurrency (templates executed in parallel)
    CONCURRENCY = 25  # default in nuclei v3
    
    # Template tags to scan (common vulnerability categories)
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
        """Execute Nuclei scan with proper v3.x command line options"""
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting Nuclei scan for {target_url}")
            
            # Create temporary file for results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.jsonl', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            # Build nuclei command for v3.x
            # Reference: nuclei -h
            cmd = [
                'nuclei',
                '-u', target_url,                    # -u or -target for single target
                '-jsonl',                            # Use -jsonl (not -json) for JSONL output
                '-o', temp_filename,                 # -o or -output
                '-s', 'critical,high,medium,low,info',  # -s or -severity
                '-timeout', str(self.REQUEST_TIMEOUT),  # request timeout
                '-rl', str(self.RATE_LIMIT),         # -rl or -rate-limit
                '-bs', str(self.BULK_SIZE),          # -bs or -bulk-size  
                '-c', str(self.CONCURRENCY),         # -c or -concurrency
                '-nc',                               # -nc or -no-color
                '-duc',                              # -duc: disable update check (CRITICAL!)
                '-ni',                               # -ni or -no-interactsh (avoid external OAST)
            ]
            
            # Add tags for template filtering
            tags = options.get('tags', self.TEMPLATE_TAGS)
            if tags:
                cmd.extend(['-tags', ','.join(tags)])
            
            # Add specific template paths if provided
            template_paths = options.get('template_paths', [])
            for path in template_paths:
                cmd.extend(['-t', path])
            
            # Add custom headers if provided
            custom_headers = options.get('headers', {})
            for header_name, header_value in custom_headers.items():
                cmd.extend(['-H', f'{header_name}: {header_value}'])
            
            # Optional: enable stats output (flag only, no value)
            if options.get('show_stats', False):
                cmd.append('-stats')
            
            # Optional: silent mode (only show findings)
            if options.get('silent', True):
                cmd.append('-silent')
            
            # Optional: follow redirects
            if options.get('follow_redirects', False):
                cmd.append('-fr')  # -fr or -follow-redirects
            
            logger.info(f"Running Nuclei command: {' '.join(cmd)}")
            logger.info(f"Scan timeout: {self.SCAN_TIMEOUT}s")
            
            # Run nuclei with timeout
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
                
                # Log stderr for debugging (nuclei outputs info to stderr)
                if stderr:
                    stderr_text = stderr.decode('utf-8', errors='ignore')
                    if stderr_text.strip():
                        # Filter out banner and info messages
                        for line in stderr_text.split('\n'):
                            if '[ERR]' in line or '[WRN]' in line:
                                logger.warning(f"Nuclei: {line.strip()}")
                            elif '[INF]' in line:
                                logger.debug(f"Nuclei: {line.strip()}")
                
                # Log stdout if any
                if stdout:
                    stdout_text = stdout.decode('utf-8', errors='ignore')
                    if stdout_text.strip():
                        logger.debug(f"Nuclei stdout: {stdout_text[:500]}")
                        
            except asyncio.TimeoutError:
                logger.warning(f"Nuclei scan timeout ({self.SCAN_TIMEOUT}s) for {target_url}")
                process.kill()
                await process.wait()
                
                # Still try to parse partial results
                findings = self._parse_output_file(temp_filename)
                
                # Cleanup
                self._cleanup_temp_file(temp_filename)
                
                return {
                    'scanner': 'nuclei',
                    'target_url': target_url,
                    'findings': findings,
                    'timeout': True,
                    'message': f'Scan timed out after {self.SCAN_TIMEOUT}s, partial results returned'
                }
            
            # Parse results from output file
            findings = self._parse_output_file(temp_filename)
            
            # Cleanup temp file
            self._cleanup_temp_file(temp_filename)
            
            logger.info(f"Nuclei scan completed with {len(findings)} findings")
            
            return {
                'scanner': 'nuclei',
                'target_url': target_url,
                'findings': findings,
                'scan_info': {
                    'timeout': self.SCAN_TIMEOUT,
                    'template_tags': tags,
                    'rate_limit': self.RATE_LIMIT
                }
            }
            
        except FileNotFoundError:
            logger.error("Nuclei binary not found - please install nuclei")
            return {
                'scanner': 'nuclei',
                'target_url': target_url,
                'error': 'Nuclei not installed. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
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
    
    def _cleanup_temp_file(self, filename: str):
        """Safely cleanup temporary file"""
        try:
            if os.path.exists(filename):
                os.unlink(filename)
        except Exception as e:
            logger.debug(f"Failed to cleanup temp file {filename}: {e}")
    
    def _parse_output_file(self, filename: str) -> List[Dict]:
        """Parse Nuclei JSONL output file"""
        findings = []
        
        if not os.path.exists(filename):
            logger.debug(f"Output file not found: {filename}")
            return findings
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError as e:
                            logger.debug(f"Failed to parse line {line_num}: {e}")
                            continue
        except Exception as e:
            logger.error(f"Failed to read Nuclei results file: {e}")
        
        return findings
    
    async def parse_results(self, raw_results: Dict) -> Dict:
        """Parse Nuclei results into standardized format"""
        if 'error' in raw_results:
            return {
                'scanner': 'nuclei',
                'vulnerabilities': [],
                'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'error': raw_results['error']
            }
        
        vulnerabilities = []
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in raw_results.get('findings', []):
            # Extract info block
            info = finding.get('info', {})
            
            # Get severity and normalize
            nuclei_severity = info.get('severity', 'info').lower()
            if nuclei_severity not in severity_counts:
                nuclei_severity = 'info'
            
            severity_counts[nuclei_severity] += 1
            
            # Extract tags
            tags = info.get('tags', [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',')]
            
            # Extract references
            reference = info.get('reference', [])
            if isinstance(reference, str):
                reference = [reference] if reference else []
            
            # Extract classification data
            classification = info.get('classification', {})
            
            # Build vulnerability entry
            vuln = {
                'name': info.get('name', 'Unknown Vulnerability'),
                'description': info.get('description', 'No description available'),
                'severity': nuclei_severity,
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
                'cvss_score': classification.get('cvss-score', ''),
                'cvss_metrics': classification.get('cvss-metrics', ''),
                'cwe_id': classification.get('cwe-id', []),
            }
            
            vulnerabilities.append(vuln)
        
        # Build summary
        summary = {
            'total': len(vulnerabilities),
            'critical': severity_counts['critical'],
            'high': severity_counts['high'],
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
        import re
        
        # Check tags for CVE
        for tag in tags:
            if isinstance(tag, str) and tag.upper().startswith('CVE-'):
                return tag.upper()
        
        # Check classification
        classification = info.get('classification', {})
        cve_id = classification.get('cve-id', '')
        if cve_id:
            if isinstance(cve_id, list):
                return cve_id[0] if cve_id else ''
            return str(cve_id)
        
        # Check name for CVE pattern
        name = info.get('name', '')
        cve_match = re.search(r'CVE-\d{4}-\d+', name, re.IGNORECASE)
        if cve_match:
            return cve_match.group().upper()
        
        return ''
    
    def _map_to_owasp(self, info: Dict, tags: List[str]) -> str:
        """Map vulnerability to OWASP Top 10 2024 based on tags and info"""
        if not tags:
            tags = []
        
        # Combine all text for matching
        tags_str = ' '.join(str(t) for t in tags).lower()
        name = info.get('name', '').lower()
        description = info.get('description', '').lower()
        combined = f"{tags_str} {name} {description}"
        
        # A01:2024 - Broken Access Control
        if any(term in combined for term in ['idor', 'access control', 'authorization', 'privilege', 
                                              'path traversal', 'lfi', 'rfi', 'directory traversal',
                                              'unauthorized', 'forbidden bypass']):
            return "A01:2024-Broken Access Control"
        
        # A02:2024 - Cryptographic Failures
        if any(term in combined for term in ['ssl', 'tls', 'crypto', 'cipher', 'certificate', 
                                              'encryption', 'weak-crypto', 'exposed-tokens',
                                              'cleartext', 'plaintext']):
            return "A02:2024-Cryptographic Failures"
        
        # A03:2024 - Injection
        if any(term in combined for term in ['sqli', 'sql-injection', 'xss', 'injection', 'ssti', 
                                              'xxe', 'command-injection', 'ldap', 'nosql', 
                                              'template-injection', 'code-injection', 'rce']):
            return "A03:2024-Injection"
        
        # A04:2024 - Insecure Design
        if any(term in combined for term in ['insecure-design', 'business-logic', 'race-condition',
                                              'security-design']):
            return "A04:2024-Insecure Design"
        
        # A05:2024 - Security Misconfiguration
        if any(term in combined for term in ['misconfig', 'misconfiguration', 'exposure', 'disclosure', 
                                              'panel', 'default-login', 'debug', 'config', 'backup', 
                                              'listing', 'directory listing', 'admin panel',
                                              'phpinfo', 'swagger', 'graphql']):
            return "A05:2024-Security Misconfiguration"
        
        # A06:2024 - Vulnerable and Outdated Components
        if any(term in combined for term in ['cve', 'version', 'outdated', 'vulnerable', 'eol', 
                                              'end-of-life', 'known vulnerability']):
            return "A06:2024-Vulnerable and Outdated Components"
        
        # A07:2024 - Identification and Authentication Failures
        if any(term in combined for term in ['auth', 'login', 'password', 'credential', 'session', 
                                              'token', 'jwt', 'oauth', 'brute', 'weak password',
                                              '2fa', 'mfa']):
            return "A07:2024-Identification and Authentication Failures"
        
        # A08:2024 - Software and Data Integrity Failures
        if any(term in combined for term in ['deserialization', 'integrity', 'ci-cd', 'supply-chain', 
                                              'update', 'signature', 'unsigned']):
            return "A08:2024-Software and Data Integrity Failures"
        
        # A09:2024 - Security Logging and Monitoring Failures
        if any(term in combined for term in ['logging', 'monitoring', 'audit', 'log']):
            return "A09:2024-Security Logging and Monitoring Failures"
        
        # A10:2024 - Server-Side Request Forgery
        if any(term in combined for term in ['ssrf', 'server-side request forgery']):
            return "A10:2024-Server-Side Request Forgery (SSRF)"
        
        # Default to Security Misconfiguration for general findings
        return "A05:2024-Security Misconfiguration"
