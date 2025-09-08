import asyncio
import logging
from typing import Dict, List, Optional
from zapv2 import ZAPv2
import requests
from urllib.parse import urljoin

from app.scanners.base_scanner import BaseScanner
from app.core.config import settings

logger = logging.getLogger(__name__)

class ZAPScanner(BaseScanner):
    """OWASP ZAP Security Scanner"""
    
    def __init__(self):
        self.version = "2.12.0"
        self.description = "OWASP ZAP Web Application Security Scanner"
        self.zap = None
    
    def _initialize_zap(self):
        """Initialize ZAP connection"""
        try:
            self.zap = ZAPv2(proxies={
                'http': f'http://{settings.ZAP_HOST}:{settings.ZAP_PORT}',
                'https': f'http://{settings.ZAP_HOST}:{settings.ZAP_PORT}'
            })
            # Test connection
            self.zap.core.version
            logger.info("ZAP connection established")
        except Exception as e:
            logger.error(f"Failed to connect to ZAP: {e}")
            raise
    
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute ZAP scan"""
        if not self.zap:
            self._initialize_zap()
        
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting ZAP scan for {target_url}")
            
            # Spider the target
            spider_id = self.zap.spider.scan(target_url)
            logger.info(f"Spider scan started with ID: {spider_id}")
            
            # Wait for spider to complete
            while int(self.zap.spider.status(spider_id)) < 100:
                await asyncio.sleep(2)
            
            logger.info("Spider scan completed")
            
            # Active scan
            active_scan_id = self.zap.ascan.scan(target_url)
            logger.info(f"Active scan started with ID: {active_scan_id}")
            
            # Wait for active scan to complete
            while int(self.zap.ascan.status(active_scan_id)) < 100:
                await asyncio.sleep(5)
                progress = self.zap.ascan.status(active_scan_id)
                logger.info(f"Active scan progress: {progress}%")
            
            logger.info("Active scan completed")
            
            # Get alerts
            alerts = self.zap.core.alerts(baseurl=target_url)
            
            return {
                'scanner': 'zap',
                'target_url': target_url,
                'alerts': alerts,
                'spider_results': self.zap.spider.results(spider_id),
                'scan_summary': {
                    'total_alerts': len(alerts),
                    'spider_urls': len(self.zap.spider.results(spider_id))
                }
            }
            
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            return {
                'scanner': 'zap',
                'target_url': target_url,
                'error': str(e),
                'alerts': []
            }
    
    async def parse_results(self, raw_results: Dict) -> Dict:
        """Parse ZAP results into standardized format"""
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
            severity = self._map_zap_risk_to_severity(alert.get('risk', 'Informational'))
            severity_counts[severity] += 1
            
            vulnerability = {
                'id': alert.get('pluginId', 'unknown'),
                'name': alert.get('name', 'Unknown Vulnerability'),
                'description': alert.get('description', ''),
                'severity': severity,
                'confidence': alert.get('confidence', 'Unknown'),
                'url': alert.get('url', ''),
                'param': alert.get('param', ''),
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'owasp_category': self._map_to_owasp_category(alert.get('name', '')),
                'cwe_id': alert.get('cweid', ''),
                'wasc_id': alert.get('wascid', '')
            }
            vulnerabilities.append(vulnerability)
        
        return {
            'scanner': 'zap',
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                **severity_counts
            },
            'scan_info': {
                'target_url': raw_results.get('target_url', ''),
                'scan_time': raw_results.get('scan_time', ''),
                'urls_found': len(raw_results.get('spider_results', []))
            }
        }
    
    def _map_zap_risk_to_severity(self, risk: str) -> str:
        """Map ZAP risk levels to standard severity"""
        risk_mapping = {
            'High': 'high',
            'Medium': 'medium', 
            'Low': 'low',
            'Informational': 'info'
        }
        return risk_mapping.get(risk, 'info')
    
    def _map_to_owasp_category(self, vulnerability_name: str) -> str:
        """Map vulnerability to OWASP Top 10 category"""
        name_lower = vulnerability_name.lower()
        
        # OWASP Top 10 2024 mapping based on vulnerability names
        if any(term in name_lower for term in ['sql injection', 'xss', 'script', 'injection']):
            return "A03:2024-Injection"
        elif any(term in name_lower for term in ['authentication', 'session', 'login']):
            return "A07:2024-Identification and Authentication Failures"
        elif any(term in name_lower for term in ['access control', 'authorization', 'privilege']):
            return "A01:2024-Broken Access Control"
        elif any(term in name_lower for term in ['crypto', 'ssl', 'tls', 'certificate']):
            return "A02:2024-Cryptographic Failures"
        elif any(term in name_lower for term in ['configuration', 'header', 'server']):
            return "A05:2024-Security Misconfiguration"
        elif any(term in name_lower for term in ['component', 'library', 'version']):
            return "A06:2024-Vulnerable and Outdated Components"
        elif any(term in name_lower for term in ['logging', 'monitoring']):
            return "A09:2024-Security Logging and Monitoring Failures"
        elif any(term in name_lower for term in ['ssrf', 'request forgery']):
            return "A10:2024-Server-Side Request Forgery (SSRF)"
        else:
            return "A04:2024-Insecure Design"  # Default category