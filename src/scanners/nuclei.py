"""Nuclei Vulnerability Scanner"""

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
    """Nuclei template-based vulnerability scanner"""
    
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
                '-severity', 'critical,high,medium,low,info',
                '-timeout', '10',
                '-retries', '1',
                '-rate-limit', '50',
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
                await asyncio.wait_for(process.communicate(), timeout=60)
            except asyncio.TimeoutError:
                logger.warning(f"Nuclei scan timeout for {target_url}")
                process.kill()
                return {
                    'scanner': 'nuclei',
                    'target_url': target_url,
                    'findings': [],
                    'timeout': True
                }
            
            # Parse results
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
                'findings': findings
            }
            
        except FileNotFoundError:
            logger.error("Nuclei binary not found")
            return {
                'scanner': 'nuclei',
                'target_url': target_url,
                'error': 'Nuclei not installed',
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
        """Parse Nuclei results"""
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
            # Map nuclei severity
            nuclei_severity = finding.get('info', {}).get('severity', 'info').lower()
            if nuclei_severity == 'critical':
                severity = 'high'
            else:
                severity = nuclei_severity
            
            if severity not in severity_counts:
                severity = 'info'
            
            severity_counts[severity] += 1
            
            vulnerabilities.append({
                'name': finding.get('info', {}).get('name', 'Unknown'),
                'description': finding.get('info', {}).get('description', ''),
                'severity': severity,
                'url': finding.get('matched-at', ''),
                'template': finding.get('template-id', ''),
                'owasp_category': self._map_to_owasp(finding.get('info', {}).get('tags', []))
            })
        
        return {
            'scanner': 'nuclei',
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                **severity_counts
            }
        }
    
    def _map_to_owasp(self, tags: List[str]) -> str:
        """Map tags to OWASP Top 10 2024"""
        if not tags:
            return "A04:2024-Insecure Design"
        
        tags_str = ' '.join(tags).lower()
        
        if any(term in tags_str for term in ['sqli', 'xss', 'injection']):
            return "A03:2024-Injection"
        elif any(term in tags_str for term in ['auth', 'login']):
            return "A07:2024-Identification and Authentication Failures"
        elif any(term in tags_str for term in ['ssl', 'tls', 'crypto']):
            return "A02:2024-Cryptographic Failures"
        elif any(term in tags_str for term in ['config', 'disclosure']):
            return "A05:2024-Security Misconfiguration"
        elif any(term in tags_str for term in ['cve', 'version']):
            return "A06:2024-Vulnerable and Outdated Components"
        else:
            return "A04:2024-Insecure Design"