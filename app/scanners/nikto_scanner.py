import asyncio
import json
import logging
import subprocess
import tempfile
import os
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

from app.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class NiktoScanner(BaseScanner):
    """Nikto Web Server Scanner"""
    
    def __init__(self):
        self.version = "2.1.6"
        self.description = "Nikto Web Server Security Scanner"
    
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute Nikto scan"""
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting Nikto scan for {target_url}")
            
            # Create temporary file for XML results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            # Build nikto command
            cmd = [
                'nikto',
                '-h', target_url,
                '-Format', 'xml',
                '-output', temp_filename,
                '-timeout', str(options.get('timeout', 10)),
                '-maxtime', str(options.get('maxtime', 3600))  # 1 hour max
            ]
            
            # Add SSL option if HTTPS
            if target_url.startswith('https://'):
                cmd.extend(['-ssl'])
            
            # Add additional options
            if 'plugins' in options:
                cmd.extend(['-Plugins', options['plugins']])
            
            if 'tuning' in options:
                cmd.extend(['-Tuning', options['tuning']])
            
            # Run nikto
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Nikto returns non-zero even on successful scans, so we check differently
            findings = []
            if os.path.exists(temp_filename):
                try:
                    findings = self._parse_xml_results(temp_filename)
                except Exception as e:
                    logger.error(f"Failed to parse Nikto XML results: {e}")
                finally:
                    os.unlink(temp_filename)
            
            # If XML parsing failed, try to parse stdout
            if not findings and stdout:
                findings = self._parse_text_output(stdout.decode())
            
            logger.info(f"Nikto scan completed with {len(findings)} findings")
            
            return {
                'scanner': 'nikto',
                'target_url': target_url,
                'findings': findings,
                'scan_summary': {
                    'total_findings': len(findings)
                }
            }
            
        except FileNotFoundError:
            error_msg = "Nikto binary not found. Please install Nikto."
            logger.error(error_msg)
            return {
                'scanner': 'nikto',
                'target_url': target_url,
                'error': error_msg,
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
    
    def _parse_xml_results(self, xml_file: str) -> List[Dict]:
        """Parse Nikto XML results"""
        findings = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for scan in root.findall('.//scan'):
                for item in scan.findall('.//item'):
                    finding = {
                        'id': item.get('id', 'unknown'),
                        'osvdb': item.get('osvdbid', ''),
                        'method': item.get('method', 'GET'),
                        'uri': item.find('uri').text if item.find('uri') is not None else '',
                        'description': item.find('description').text if item.find('description') is not None else '',
                        'namelink': item.find('namelink').text if item.find('namelink') is not None else '',
                        'iplink': item.find('iplink').text if item.find('iplink') is not None else ''
                    }
                    findings.append(finding)
                    
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
        
        return findings
    
    def _parse_text_output(self, output: str) -> List[Dict]:
        """Parse Nikto text output as fallback"""
        findings = []
        
        for line in output.split('\\n'):
            line = line.strip()
            if line.startswith('+') and 'OSVDB' in line:
                # Simple parsing of text output
                finding = {
                    'id': 'text_parsed',
                    'osvdb': '',
                    'method': 'GET',
                    'uri': '',
                    'description': line,
                    'namelink': '',
                    'iplink': ''
                }
                findings.append(finding)
        
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
            # Determine severity based on content
            severity = self._determine_severity(finding.get('description', ''))
            severity_counts[severity] += 1
            
            vulnerability = {
                'id': finding.get('id', 'unknown'),
                'name': self._extract_vulnerability_name(finding.get('description', '')),
                'description': finding.get('description', ''),
                'severity': severity,
                'confidence': 'medium',  # Nikto findings are generally medium confidence
                'url': finding.get('uri', ''),
                'param': '',
                'evidence': finding.get('namelink', ''),
                'solution': 'Review the identified issue and apply appropriate security measures.',
                'reference': finding.get('iplink', ''),
                'owasp_category': self._map_to_owasp_category(finding.get('description', '')),
                'osvdb_id': finding.get('osvdb', ''),
                'method': finding.get('method', 'GET')
            }
            vulnerabilities.append(vulnerability)
        
        return {
            'scanner': 'nikto',
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                **severity_counts
            },
            'scan_info': {
                'target_url': raw_results.get('target_url', ''),
                'scan_type': 'web_server_scan'
            }
        }
    
    def _determine_severity(self, description: str) -> str:
        """Determine severity based on finding description"""
        desc_lower = description.lower()
        
        # High severity indicators
        if any(term in desc_lower for term in ['vulnerability', 'exploit', 'backdoor', 'shell', 'rce']):
            return 'high'
        # Medium severity indicators  
        elif any(term in desc_lower for term in ['disclosure', 'exposure', 'misconfiguration', 'auth']):
            return 'medium'
        # Low severity indicators
        elif any(term in desc_lower for term in ['version', 'banner', 'path', 'directory']):
            return 'low'
        # Default to info
        else:
            return 'info'
    
    def _extract_vulnerability_name(self, description: str) -> str:
        """Extract vulnerability name from description"""
        # Take first 80 characters as name
        name = description[:80]
        if len(description) > 80:
            name += "..."
        return name
    
    def _map_to_owasp_category(self, description: str) -> str:
        """Map finding to OWASP Top 10 category"""
        desc_lower = description.lower()
        
        if any(term in desc_lower for term in ['directory listing', 'file disclosure', 'path traversal']):
            return "A01:2021-Broken Access Control"
        elif any(term in desc_lower for term in ['ssl', 'tls', 'certificate', 'crypto']):
            return "A02:2021-Cryptographic Failures"
        elif any(term in desc_lower for term in ['injection', 'xss', 'sql']):
            return "A03:2021-Injection"
        elif any(term in desc_lower for term in ['authentication', 'login', 'password']):
            return "A07:2021-Identification and Authentication Failures"
        elif any(term in desc_lower for term in ['configuration', 'server', 'header', 'banner']):
            return "A05:2021-Security Misconfiguration"
        elif any(term in desc_lower for term in ['version', 'outdated', 'vulnerable']):
            return "A06:2021-Vulnerable and Outdated Components"
        elif any(term in desc_lower for term in ['redirect', 'ssrf']):
            return "A10:2021-Server-Side Request Forgery"
        else:
            return "A04:2021-Insecure Design"