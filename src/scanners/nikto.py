"""Nikto Web Server Scanner"""

import asyncio
import logging
import subprocess
import tempfile
import os
import xml.etree.ElementTree as ET
from typing import Dict, List

from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

class NiktoScanner(BaseScanner):
    """Nikto web server vulnerability scanner"""
    
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
                '-timeout', '10',
                '-maxtime', '60',
                '-no404',
                '-Pause', '1'
            ]
            
            # Add SSL option if HTTPS
            if target_url.startswith('https://'):
                cmd.append('-ssl')
            
            # Run nikto with timeout
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                await asyncio.wait_for(process.communicate(), timeout=60)
                
            except asyncio.TimeoutError:
                logger.warning(f"Nikto scan timeout for {target_url}")
                if process and process.returncode is None:
                    process.terminate()
                    await asyncio.sleep(1)
                    if process.returncode is None:
                        process.kill()
                return {
                    'scanner': 'nikto',
                    'target_url': target_url,
                    'findings': [],
                    'timeout': True
                }
            
            # Parse results
            findings = []
            if os.path.exists(temp_filename):
                try:
                    findings = self._parse_xml_results(temp_filename)
                except Exception as e:
                    logger.error(f"Failed to parse Nikto XML results: {e}")
                finally:
                    try:
                        os.unlink(temp_filename)
                    except Exception:
                        pass
            
            logger.info(f"Nikto scan completed with {len(findings)} findings")
            
            return {
                'scanner': 'nikto',
                'target_url': target_url,
                'findings': findings
            }
            
        except FileNotFoundError:
            logger.error("Nikto binary not found")
            return {
                'scanner': 'nikto',
                'target_url': target_url,
                'error': 'Nikto not installed',
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
                        'method': item.get('method', 'GET'),
                        'uri': item.find('uri').text if item.find('uri') is not None else '',
                        'description': item.find('description').text if item.find('description') is not None else '',
                        'osvdb_id': item.get('osvdbid', '')
                    }
                    findings.append(finding)
                    
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
        
        return findings
    
    async def parse_results(self, raw_results: Dict) -> Dict:
        """Parse Nikto results"""
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
            severity = self._determine_severity(finding.get('description', ''))
            severity_counts[severity] += 1
            
            vulnerabilities.append({
                'name': finding.get('description', '')[:80] + ('...' if len(finding.get('description', '')) > 80 else ''),
                'description': finding.get('description', ''),
                'severity': severity,
                'url': finding.get('uri', ''),
                'method': finding.get('method', 'GET'),
                'owasp_category': self._map_to_owasp(finding.get('description', ''))
            })
        
        return {
            'scanner': 'nikto',
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                **severity_counts
            }
        }
    
    def _determine_severity(self, description: str) -> str:
        """Determine severity from description"""
        desc_lower = description.lower()
        
        if any(term in desc_lower for term in ['vulnerability', 'exploit', 'rce']):
            return 'high'
        elif any(term in desc_lower for term in ['disclosure', 'exposure', 'auth']):
            return 'medium'
        elif any(term in desc_lower for term in ['version', 'banner', 'directory']):
            return 'low'
        else:
            return 'info'
    
    def _map_to_owasp(self, description: str) -> str:
        """Map to OWASP Top 10 2024"""
        desc_lower = description.lower()
        
        if any(term in desc_lower for term in ['directory', 'file disclosure']):
            return "A01:2024-Broken Access Control"
        elif any(term in desc_lower for term in ['ssl', 'certificate']):
            return "A02:2024-Cryptographic Failures"
        elif any(term in desc_lower for term in ['injection', 'xss']):
            return "A03:2024-Injection"
        elif any(term in desc_lower for term in ['authentication', 'login']):
            return "A07:2024-Identification and Authentication Failures"
        elif any(term in desc_lower for term in ['configuration', 'server', 'header']):
            return "A05:2024-Security Misconfiguration"
        else:
            return "A04:2024-Insecure Design"