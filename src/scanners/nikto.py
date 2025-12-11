import asyncio
import logging
import subprocess
import tempfile
import os
import xml.etree.ElementTree as ET
import re
from typing import Dict, List

from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class NiktoScanner(BaseScanner):
    """Enhanced Nikto web server vulnerability scanner"""
    
    # Scan timeout in seconds (increased from 60 to 600 - 10 minutes)
    SCAN_TIMEOUT = 600  # 10 minutes for comprehensive scan
    
    # Request timeout
    REQUEST_TIMEOUT = 15
    
    # Pause between requests (to avoid rate limiting)
    PAUSE_BETWEEN_REQUESTS = 1
    
    # Nikto tuning options (which tests to perform)
    # 1 - Interesting File / Seen in logs
    # 2 - Misconfiguration / Default File
    # 3 - Information Disclosure
    # 4 - Injection (XSS/Script/HTML)
    # 5 - Remote File Retrieval - Inside Web Root
    # 6 - Denial of Service
    # 7 - Remote File Retrieval - Server Wide
    # 8 - Command Execution / Remote Shell
    # 9 - SQL Injection
    # 0 - File Upload
    # a - Authentication Bypass
    # b - Software Identification
    # c - Remote source inclusion
    # x - Reverse Tuning Options (exclude)
    TUNING_OPTIONS = '123457890abc'  # All except DoS (6)
    
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute enhanced Nikto scan"""
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting enhanced Nikto scan for {target_url}")
            
            # Create temporary file for XML results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            # Build nikto command with enhanced options
            cmd = [
                'nikto',
                '-h', target_url,
                '-Format', 'xml',
                '-output', temp_filename,
                '-timeout', str(self.REQUEST_TIMEOUT),
                '-maxtime', str(self.SCAN_TIMEOUT // 60) + 'm',  # Convert to minutes
                '-Pause', str(self.PAUSE_BETWEEN_REQUESTS),
                '-Tuning', self.TUNING_OPTIONS,
                '-no404',        # Disable 404 guessing
                '-nointeractive', # Non-interactive mode
                '-ask', 'no',    # Don't ask for confirmation
            ]
            
            # Add SSL option if HTTPS
            if target_url.startswith('https://'):
                cmd.append('-ssl')
            
            # Add custom options
            if options.get('follow_redirects', True):
                cmd.append('-followredirects')
            
            # Add user agent if specified
            user_agent = options.get('user_agent')
            if user_agent:
                cmd.extend(['-useragent', user_agent])
            
            # Add authentication if provided
            auth = options.get('auth')
            if auth:
                cmd.extend(['-id', auth])  # Format: id:password
            
            # Add cookies if provided
            cookies = options.get('cookies')
            if cookies:
                cmd.extend(['-Cookies', cookies])
            
            logger.info(f"Running Nikto with timeout: {self.SCAN_TIMEOUT}s (tuning: {self.TUNING_OPTIONS})")
            
            # Run nikto with extended timeout
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=self.SCAN_TIMEOUT
                )
                
                # Log stderr for debugging
                if stderr:
                    stderr_text = stderr.decode('utf-8', errors='ignore')
                    if stderr_text.strip() and 'error' in stderr_text.lower():
                        logger.warning(f"Nikto stderr: {stderr_text[:500]}")
                
            except asyncio.TimeoutError:
                logger.warning(f"Nikto scan timeout ({self.SCAN_TIMEOUT}s) for {target_url}")
                if process and process.returncode is None:
                    process.terminate()
                    await asyncio.sleep(2)
                    if process.returncode is None:
                        process.kill()
                
                # Still try to parse partial results
                findings = self._parse_xml_results(temp_filename)
                self._cleanup_temp_file(temp_filename)
                
                return {
                    'scanner': 'nikto',
                    'target_url': target_url,
                    'findings': findings,
                    'timeout': True,
                    'message': f'Scan timed out after {self.SCAN_TIMEOUT}s, partial results returned'
                }
            
            # Parse results
            findings = self._parse_xml_results(temp_filename)
            
            # Cleanup
            self._cleanup_temp_file(temp_filename)
            
            logger.info(f"Nikto scan completed with {len(findings)} findings")
            
            return {
                'scanner': 'nikto',
                'target_url': target_url,
                'findings': findings,
                'scan_info': {
                    'timeout': self.SCAN_TIMEOUT,
                    'tuning': self.TUNING_OPTIONS
                }
            }
            
        except FileNotFoundError:
            logger.error("Nikto binary not found - please install nikto")
            return {
                'scanner': 'nikto',
                'target_url': target_url,
                'error': 'Nikto not installed. Install from: https://github.com/sullo/nikto',
                'findings': []
            }
        except Exception as e:
            logger.error(f"Nikto scan failed: {e}")
            return {
                'scanner': 'nikto',
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
            logger.warning(f"Failed to cleanup temp file: {e}")
    
    def _parse_xml_results(self, xml_file: str) -> List[Dict]:
        """Parse Nikto XML results with enhanced extraction"""
        findings = []
        
        if not os.path.exists(xml_file):
            return findings
        
        try:
            # Read file content first
            with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip():
                return findings
            
            # Parse XML
            root = ET.fromstring(content)
            
            # Extract scan info
            scan_details = root.find('.//scandetails')
            target_info = {}
            if scan_details is not None:
                target_info = {
                    'target_ip': scan_details.get('targetip', ''),
                    'target_port': scan_details.get('targetport', ''),
                    'target_banner': scan_details.get('targetbanner', ''),
                    'start_time': scan_details.get('starttime', ''),
                    'site_name': scan_details.get('sitename', ''),
                }
            
            # Parse items (vulnerabilities)
            for item in root.findall('.//item'):
                finding = {
                    'id': item.get('id', 'unknown'),
                    'osvdb_id': item.get('osvdbid', ''),
                    'osvdb_link': item.get('osvdblink', ''),
                    'method': item.get('method', 'GET'),
                    'uri': '',
                    'description': '',
                    'name_link': '',
                    'ip_link': '',
                }
                
                # Extract child elements
                description_elem = item.find('description')
                if description_elem is not None and description_elem.text:
                    finding['description'] = description_elem.text.strip()
                
                uri_elem = item.find('uri')
                if uri_elem is not None and uri_elem.text:
                    finding['uri'] = uri_elem.text.strip()
                
                namelink_elem = item.find('namelink')
                if namelink_elem is not None and namelink_elem.text:
                    finding['name_link'] = namelink_elem.text.strip()
                
                iplink_elem = item.find('iplink')
                if iplink_elem is not None and iplink_elem.text:
                    finding['ip_link'] = iplink_elem.text.strip()
                
                # Add target info
                finding['target_info'] = target_info
                
                # Only add if we have meaningful data
                if finding['description'] or finding['uri']:
                    findings.append(finding)
                    
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            # Try to extract any useful info from malformed XML
            findings.extend(self._parse_malformed_output(xml_file))
        except Exception as e:
            logger.error(f"Error parsing Nikto results: {e}")
        
        return findings
    
    def _parse_malformed_output(self, filename: str) -> List[Dict]:
        """Attempt to extract findings from malformed/partial output"""
        findings = []
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Try to extract items using regex
            item_pattern = r'<item[^>]*>(.*?)</item>'
            items = re.findall(item_pattern, content, re.DOTALL)
            
            for item_content in items:
                finding = {'description': '', 'uri': '', 'method': 'GET'}
                
                desc_match = re.search(r'<description>(.*?)</description>', item_content, re.DOTALL)
                if desc_match:
                    finding['description'] = desc_match.group(1).strip()
                
                uri_match = re.search(r'<uri>(.*?)</uri>', item_content, re.DOTALL)
                if uri_match:
                    finding['uri'] = uri_match.group(1).strip()
                
                if finding['description'] or finding['uri']:
                    findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Failed to parse malformed output: {e}")
        
        return findings
    
    async def parse_results(self, raw_results: Dict) -> Dict:
        """Parse Nikto results into standardized format"""
        if 'error' in raw_results:
            return {
                'scanner': 'nikto',
                'vulnerabilities': [],
                'summary': {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'error': raw_results['error']
            }
        
        vulnerabilities = []
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in raw_results.get('findings', []):
            description = finding.get('description', '')
            uri = finding.get('uri', '')
            
            # Determine severity based on content
            severity = self._determine_severity(description, uri)
            severity_counts[severity] += 1
            
            # Create display name
            name = self._create_finding_name(description)
            
            vulnerabilities.append({
                'name': name,
                'description': description,
                'severity': severity,
                'url': uri,
                'method': finding.get('method', 'GET'),
                'osvdb_id': finding.get('osvdb_id', ''),
                'reference': finding.get('name_link', '') or finding.get('osvdb_link', ''),
                'owasp_category': self._map_to_owasp(description, uri)
            })
        
        return {
            'scanner': 'nikto',
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                **severity_counts
            },
            'timeout': raw_results.get('timeout', False),
            'scan_info': raw_results.get('scan_info', {})
        }
    
    def _create_finding_name(self, description: str) -> str:
        """Create a concise name from description"""
        if not description:
            return 'Unknown Finding'
        
        # Truncate long descriptions
        name = description[:100]
        if len(description) > 100:
            name += '...'
        
        return name
    
    def _determine_severity(self, description: str, uri: str) -> str:
        """Determine severity from description and URI"""
        desc_lower = description.lower()
        uri_lower = uri.lower() if uri else ''
        combined = f"{desc_lower} {uri_lower}"
        
        # High severity indicators
        high_indicators = [
            'remote code execution', 'rce', 'command execution', 'shell',
            'sql injection', 'sqli', 'arbitrary file', 'file inclusion',
            'lfi', 'rfi', 'remote file', 'code injection',
            'critical vulnerability', 'exploit', 'backdoor',
            'authentication bypass', 'admin access', 'root access',
            'upload vulnerability', 'unrestricted upload'
        ]
        
        # Medium severity indicators
        medium_indicators = [
            'xss', 'cross-site scripting', 'csrf',
            'information disclosure', 'sensitive', 'password',
            'credential', 'api key', 'token', 'secret',
            'directory listing', 'directory traversal',
            'path disclosure', 'configuration', 'config file',
            'backup file', 'database', '.sql', '.db',
            'phpinfo', 'debug', 'error message', 'stack trace',
            'admin panel', 'login', 'authentication',
            'session', 'cookie', 'exposure'
        ]
        
        # Low severity indicators  
        low_indicators = [
            'version', 'banner', 'server header', 'x-powered-by',
            'outdated', 'deprecated', 'default file', 'default page',
            'robots.txt', 'sitemap', 'readme', 'changelog',
            'common file', 'interesting file', 'informational'
        ]
        
        # Check high first
        if any(indicator in combined for indicator in high_indicators):
            return 'high'
        
        # Then medium
        if any(indicator in combined for indicator in medium_indicators):
            return 'medium'
        
        # Then low
        if any(indicator in combined for indicator in low_indicators):
            return 'low'
        
        # Default to info
        return 'info'
    
    def _map_to_owasp(self, description: str, uri: str) -> str:
        """Map to OWASP Top 10 2024"""
        desc_lower = description.lower()
        uri_lower = uri.lower() if uri else ''
        combined = f"{desc_lower} {uri_lower}"
        
        # A01:2024 - Broken Access Control
        if any(term in combined for term in [
            'directory listing', 'directory traversal', 'path traversal',
            'lfi', 'rfi', 'file disclosure', 'unauthorized', 'access control',
            'admin', 'restricted', 'forbidden', 'backup'
        ]):
            return "A01:2024-Broken Access Control"
        
        # A02:2024 - Cryptographic Failures
        if any(term in combined for term in [
            'ssl', 'tls', 'certificate', 'cipher', 'crypto', 'encryption',
            'https', 'secure cookie', 'password', 'cleartext'
        ]):
            return "A02:2024-Cryptographic Failures"
        
        # A03:2024 - Injection
        if any(term in combined for term in [
            'injection', 'sql', 'xss', 'cross-site', 'script',
            'command', 'ldap', 'xpath', 'nosql', 'template'
        ]):
            return "A03:2024-Injection"
        
        # A05:2024 - Security Misconfiguration
        if any(term in combined for term in [
            'configuration', 'config', 'server', 'header', 'default',
            'debug', 'error', 'phpinfo', 'version', 'banner',
            'listing', 'disclosure', 'misconfiguration'
        ]):
            return "A05:2024-Security Misconfiguration"
        
        # A06:2024 - Vulnerable and Outdated Components
        if any(term in combined for term in [
            'version', 'outdated', 'vulnerable', 'cve', 'update',
            'patch', 'upgrade', 'old', 'deprecated', 'eol'
        ]):
            return "A06:2024-Vulnerable and Outdated Components"
        
        # A07:2024 - Identification and Authentication Failures
        if any(term in combined for term in [
            'authentication', 'auth', 'login', 'session', 'credential',
            'brute', 'password', 'token', 'cookie'
        ]):
            return "A07:2024-Identification and Authentication Failures"
        
        # Default
        return "A05:2024-Security Misconfiguration"
