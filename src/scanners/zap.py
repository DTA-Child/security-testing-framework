"""OWASP ZAP-Style Security Scanner - Enhanced Version"""

import asyncio
import logging
import re
from typing import Dict, List
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import requests
import ssl
import socket

from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings()


class ZAPScanner(BaseScanner):
    """Enhanced Web Application Security Scanner"""
    
    # SQL Injection payloads
    SQL_PAYLOADS = [
        "'",
        "''",
        "1' OR '1'='1",
        "1' OR '1'='1'--",
        "1' OR '1'='1'/*",
        "' OR ''='",
        "1; DROP TABLE users--",
        "1' AND '1'='1",
        "' UNION SELECT NULL--",
        "1' WAITFOR DELAY '0:0:5'--",
    ]
    
    # SQL Error patterns
    SQL_ERRORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Driver.*SQL Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Microsoft SQL Native Client",
        r"ODBC SQL Server Driver",
        r"SQLite.*error",
        r"SQLITE_ERROR",
        r"sqlite3.OperationalError",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
        r"Syntax error.*in query expression",
        r"SQL command not properly ended",
        r"unexpected end of SQL command",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
    ]
    
    # XSS payloads
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "'-alert('XSS')-'",
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
    ]
    
    # Common sensitive directories
    COMMON_PATHS = [
        '/admin', '/administrator', '/admin.php', '/admin/login',
        '/wp-admin', '/wp-login.php', '/wordpress/wp-admin',
        '/phpmyadmin', '/pma', '/phpMyAdmin',
        '/config', '/configuration', '/conf', '/settings',
        '/.git', '/.git/config', '/.git/HEAD',
        '/.env', '/env', '/.environment',
        '/.htaccess', '/.htpasswd',
        '/backup', '/backups', '/bak', '/db_backup',
        '/database', '/db', '/sql', '/mysql',
        '/api', '/api/v1', '/api/v2', '/swagger', '/api-docs',
        '/debug', '/trace', '/test', '/testing',
        '/logs', '/log', '/error_log', '/access_log',
        '/server-status', '/server-info',
        '/web.config', '/crossdomain.xml', '/robots.txt', '/sitemap.xml',
        '/console', '/shell', '/cmd',
        '/upload', '/uploads', '/files', '/documents',
        '/tmp', '/temp', '/cache',
        '/cgi-bin', '/scripts',
        '/.DS_Store', '/Thumbs.db',
        '/package.json', '/composer.json', '/Gemfile',
    ]
    
    # Security headers to check
    SECURITY_HEADERS = {
        'X-Content-Type-Options': {
            'description': 'Missing MIME-sniffing protection',
            'recommendation': 'Add header: X-Content-Type-Options: nosniff'
        },
        'X-Frame-Options': {
            'description': 'Missing clickjacking protection',
            'recommendation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-XSS-Protection': {
            'description': 'Missing XSS filter protection',
            'recommendation': 'Add header: X-XSS-Protection: 1; mode=block'
        },
        'Strict-Transport-Security': {
            'description': 'Missing HTTPS enforcement (HSTS)',
            'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'description': 'Missing Content Security Policy',
            'recommendation': 'Implement a strict Content-Security-Policy header'
        },
        'Referrer-Policy': {
            'description': 'Missing Referrer Policy',
            'recommendation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'description': 'Missing Permissions Policy (formerly Feature-Policy)',
            'recommendation': 'Add header: Permissions-Policy to control browser features'
        }
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityScanner/1.0'
        })
    
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute comprehensive web security scan"""
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting enhanced security scan for {target_url}")
            
            alerts = []
            
            # 1. Security Headers Analysis
            logger.info("Checking security headers...")
            header_alerts = await self._check_security_headers(target_url)
            alerts.extend(header_alerts)
            
            # 2. SSL/TLS Analysis
            if target_url.startswith('https://'):
                logger.info("Checking SSL/TLS configuration...")
                ssl_alerts = await self._check_ssl_configuration(target_url)
                alerts.extend(ssl_alerts)
            
            # 3. Information Disclosure
            logger.info("Checking information disclosure...")
            info_alerts = await self._check_information_disclosure(target_url)
            alerts.extend(info_alerts)
            
            # 4. SQL Injection Testing
            logger.info("Testing for SQL Injection...")
            sqli_alerts = await self._test_sql_injection(target_url)
            alerts.extend(sqli_alerts)
            
            # 5. XSS Testing
            logger.info("Testing for XSS vulnerabilities...")
            xss_alerts = await self._test_xss(target_url)
            alerts.extend(xss_alerts)
            
            # 6. Directory/Path Discovery
            logger.info("Discovering sensitive paths...")
            path_alerts = await self._discover_paths(target_url)
            alerts.extend(path_alerts)
            
            # 7. Cookie Security
            logger.info("Checking cookie security...")
            cookie_alerts = await self._check_cookie_security(target_url)
            alerts.extend(cookie_alerts)
            
            # 8. CORS Misconfiguration
            logger.info("Checking CORS configuration...")
            cors_alerts = await self._check_cors(target_url)
            alerts.extend(cors_alerts)
            
            logger.info(f"Enhanced scan completed with {len(alerts)} findings")
            
            return {
                'scanner': 'zap',
                'target_url': target_url,
                'alerts': alerts,
                'scan_summary': {
                    'total_alerts': len(alerts),
                    'checks_performed': [
                        'Security Headers',
                        'SSL/TLS Configuration',
                        'Information Disclosure',
                        'SQL Injection',
                        'Cross-Site Scripting (XSS)',
                        'Sensitive Path Discovery',
                        'Cookie Security',
                        'CORS Configuration'
                    ]
                }
            }
            
        except Exception as e:
            logger.error(f"Enhanced scan failed: {e}")
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
            response = self.session.get(target_url, timeout=10)
            headers = response.headers
            
            for header, info in self.SECURITY_HEADERS.items():
                if header.lower() not in [h.lower() for h in headers.keys()]:
                    alerts.append({
                        'name': f'{header} Header Missing',
                        'description': info['description'],
                        'severity': 'Medium',
                        'url': target_url,
                        'evidence': f'Header {header} not found in response',
                        'recommendation': info['recommendation']
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
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check for weak ciphers
                    if cipher and len(cipher) >= 1:
                        cipher_name = cipher[0]
                        weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            alerts.append({
                                'name': 'Weak SSL/TLS Cipher Suite',
                                'description': f'Server supports weak cipher: {cipher_name}',
                                'severity': 'High',
                                'url': target_url,
                                'evidence': f'Cipher: {cipher_name}',
                                'recommendation': 'Disable weak cipher suites and use strong ciphers like AES-GCM'
                            })
                    
                    # Check TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1']:
                        alerts.append({
                            'name': 'Outdated TLS Version',
                            'description': f'Server supports outdated TLS version: {version}',
                            'severity': 'Medium',
                            'url': target_url,
                            'evidence': f'TLS Version: {version}',
                            'recommendation': 'Upgrade to TLS 1.2 or TLS 1.3'
                        })
                    
        except ssl.SSLError as e:
            alerts.append({
                'name': 'SSL/TLS Configuration Error',
                'description': f'SSL configuration issue detected',
                'severity': 'High',
                'url': target_url,
                'evidence': str(e),
                'recommendation': 'Review and fix SSL/TLS configuration'
            })
        except Exception as e:
            logger.error(f"SSL check failed: {e}")
            
        return alerts
    
    async def _check_information_disclosure(self, target_url: str) -> List[Dict]:
        """Check for information disclosure vulnerabilities"""
        alerts = []
        try:
            response = self.session.get(target_url, timeout=10)
            headers = response.headers
            
            # Server header disclosure
            if 'Server' in headers:
                server_value = headers['Server']
                # Check if version is disclosed
                if re.search(r'[\d.]+', server_value):
                    alerts.append({
                        'name': 'Server Version Disclosure',
                        'description': 'Web server reveals detailed version information',
                        'severity': 'Low',
                        'url': target_url,
                        'evidence': f'Server: {server_value}',
                        'recommendation': 'Configure server to hide version information'
                    })
                else:
                    alerts.append({
                        'name': 'Server Information Disclosure',
                        'description': 'Web server reveals server type',
                        'severity': 'Info',
                        'url': target_url,
                        'evidence': f'Server: {server_value}',
                        'recommendation': 'Consider hiding server type information'
                    })
            
            # X-Powered-By disclosure
            if 'X-Powered-By' in headers:
                alerts.append({
                    'name': 'Technology Stack Disclosure',
                    'description': 'Application reveals technology stack information',
                    'severity': 'Low',
                    'url': target_url,
                    'evidence': f'X-Powered-By: {headers["X-Powered-By"]}',
                    'recommendation': 'Remove X-Powered-By header'
                })
            
            # X-AspNet-Version disclosure
            if 'X-AspNet-Version' in headers:
                alerts.append({
                    'name': 'ASP.NET Version Disclosure',
                    'description': 'Application reveals ASP.NET version',
                    'severity': 'Low',
                    'url': target_url,
                    'evidence': f'X-AspNet-Version: {headers["X-AspNet-Version"]}',
                    'recommendation': 'Remove X-AspNet-Version header in web.config'
                })
            
            # Check response body for sensitive info
            body = response.text.lower()
            
            # Stack traces
            if 'stack trace' in body or 'traceback' in body:
                alerts.append({
                    'name': 'Stack Trace Disclosure',
                    'description': 'Application exposes stack trace information',
                    'severity': 'Medium',
                    'url': target_url,
                    'evidence': 'Stack trace found in response',
                    'recommendation': 'Disable detailed error messages in production'
                })
            
            # Debug mode indicators
            debug_indicators = ['debug=true', 'debug mode', 'development mode', 'django debug']
            if any(indicator in body for indicator in debug_indicators):
                alerts.append({
                    'name': 'Debug Mode Enabled',
                    'description': 'Application appears to be running in debug mode',
                    'severity': 'High',
                    'url': target_url,
                    'evidence': 'Debug mode indicators found',
                    'recommendation': 'Disable debug mode in production'
                })
                
        except Exception as e:
            logger.error(f"Information disclosure check failed: {e}")
            
        return alerts
    
    async def _test_sql_injection(self, target_url: str) -> List[Dict]:
        """Test for SQL Injection vulnerabilities"""
        alerts = []
        tested_params = set()
        
        try:
            # Get the page and find forms/parameters
            response = self.session.get(target_url, timeout=10)
            
            # Parse URL for existing parameters
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)
            
            # Test URL parameters
            if params:
                for param_name in params.keys():
                    if param_name in tested_params:
                        continue
                    tested_params.add(param_name)
                    
                    for payload in self.SQL_PAYLOADS[:5]:  # Test first 5 payloads
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        try:
                            test_response = self.session.get(test_url, timeout=10)
                            
                            # Check for SQL errors
                            for pattern in self.SQL_ERRORS:
                                if re.search(pattern, test_response.text, re.IGNORECASE):
                                    alerts.append({
                                        'name': 'SQL Injection Vulnerability',
                                        'description': f'SQL Injection found in parameter: {param_name}',
                                        'severity': 'High',
                                        'url': test_url,
                                        'evidence': f'SQL error pattern matched: {pattern}',
                                        'parameter': param_name,
                                        'payload': payload,
                                        'recommendation': 'Use parameterized queries or prepared statements'
                                    })
                                    break
                        except:
                            continue
            
            # Test common API endpoints
            api_endpoints = [
                '/api/search?q=',
                '/api/user?id=',
                '/search?query=',
                '/products?id=',
                '/rest/products/search?q=',
                '/api/v1/users?id=',
            ]
            
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for endpoint in api_endpoints:
                for payload in self.SQL_PAYLOADS[:3]:
                    test_url = f"{base_url}{endpoint}{payload}"
                    try:
                        test_response = self.session.get(test_url, timeout=5)
                        
                        for pattern in self.SQL_ERRORS:
                            if re.search(pattern, test_response.text, re.IGNORECASE):
                                alerts.append({
                                    'name': 'SQL Injection Vulnerability',
                                    'description': f'SQL Injection found at endpoint: {endpoint}',
                                    'severity': 'High',
                                    'url': test_url,
                                    'evidence': f'SQL error triggered with payload',
                                    'payload': payload,
                                    'recommendation': 'Use parameterized queries or prepared statements'
                                })
                                break
                    except:
                        continue
                        
        except Exception as e:
            logger.error(f"SQL Injection test failed: {e}")
            
        return alerts
    
    async def _test_xss(self, target_url: str) -> List[Dict]:
        """Test for Cross-Site Scripting vulnerabilities"""
        alerts = []
        
        try:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)
            
            # Test URL parameters for reflected XSS
            if params:
                for param_name in params.keys():
                    for payload in self.XSS_PAYLOADS[:3]:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        try:
                            test_response = self.session.get(test_url, timeout=10)
                            
                            # Check if payload is reflected
                            if payload in test_response.text:
                                alerts.append({
                                    'name': 'Reflected XSS Vulnerability',
                                    'description': f'XSS payload reflected in parameter: {param_name}',
                                    'severity': 'High',
                                    'url': test_url,
                                    'evidence': f'Payload reflected in response',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'recommendation': 'Implement proper output encoding and input validation'
                                })
                                break
                        except:
                            continue
            
            # Test common search/input endpoints
            xss_endpoints = [
                '/search?q=',
                '/api/search?query=',
                '/?search=',
                '/?q=',
            ]
            
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for endpoint in xss_endpoints:
                test_payload = '<script>alert(1)</script>'
                test_url = f"{base_url}{endpoint}{test_payload}"
                try:
                    test_response = self.session.get(test_url, timeout=5)
                    if test_payload in test_response.text:
                        alerts.append({
                            'name': 'Reflected XSS Vulnerability',
                            'description': f'XSS payload reflected at endpoint: {endpoint}',
                            'severity': 'High',
                            'url': test_url,
                            'evidence': 'Script payload reflected without encoding',
                            'recommendation': 'Implement proper output encoding'
                        })
                except:
                    continue
                    
        except Exception as e:
            logger.error(f"XSS test failed: {e}")
            
        return alerts
    
    async def _discover_paths(self, target_url: str) -> List[Dict]:
        """Discover sensitive paths and directories"""
        alerts = []
        
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for path in self.COMMON_PATHS:
                test_url = f"{base_url}{path}"
                try:
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Found accessible resource
                    if response.status_code == 200:
                        severity = 'High' if any(s in path for s in ['.git', '.env', 'admin', 'backup', 'config']) else 'Medium'
                        alerts.append({
                            'name': 'Sensitive Path Discovered',
                            'description': f'Accessible sensitive path found: {path}',
                            'severity': severity,
                            'url': test_url,
                            'evidence': f'HTTP {response.status_code} - Path accessible',
                            'recommendation': 'Restrict access to sensitive paths or remove them'
                        })
                    
                    # Directory listing
                    if response.status_code == 200 and 'index of' in response.text.lower():
                        alerts.append({
                            'name': 'Directory Listing Enabled',
                            'description': f'Directory listing enabled at: {path}',
                            'severity': 'Medium',
                            'url': test_url,
                            'evidence': 'Directory listing page detected',
                            'recommendation': 'Disable directory listing in web server configuration'
                        })
                        
                except:
                    continue
                    
        except Exception as e:
            logger.error(f"Path discovery failed: {e}")
            
        return alerts
    
    async def _check_cookie_security(self, target_url: str) -> List[Dict]:
        """Check cookie security attributes"""
        alerts = []
        
        try:
            response = self.session.get(target_url, timeout=10)
            cookies = response.cookies
            
            for cookie in cookies:
                issues = []
                
                # Check Secure flag
                if not cookie.secure and target_url.startswith('https://'):
                    issues.append('Missing Secure flag')
                
                # Check HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in str(cookie).lower():
                    issues.append('Missing HttpOnly flag')
                
                # Check SameSite attribute
                if 'samesite' not in str(cookie).lower():
                    issues.append('Missing SameSite attribute')
                
                if issues:
                    alerts.append({
                        'name': 'Insecure Cookie Configuration',
                        'description': f'Cookie "{cookie.name}" has security issues',
                        'severity': 'Medium',
                        'url': target_url,
                        'evidence': f'Issues: {", ".join(issues)}',
                        'recommendation': 'Set Secure, HttpOnly, and SameSite attributes on cookies'
                    })
                    
        except Exception as e:
            logger.error(f"Cookie security check failed: {e}")
            
        return alerts
    
    async def _check_cors(self, target_url: str) -> List[Dict]:
        """Check for CORS misconfiguration"""
        alerts = []
        
        try:
            # Test with arbitrary origin
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(target_url, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            # Check for wildcard with credentials
            if acao == '*' and acac.lower() == 'true':
                alerts.append({
                    'name': 'CORS Misconfiguration - Wildcard with Credentials',
                    'description': 'CORS allows any origin with credentials',
                    'severity': 'High',
                    'url': target_url,
                    'evidence': f'Access-Control-Allow-Origin: * with credentials',
                    'recommendation': 'Do not use wildcard origin with credentials'
                })
            
            # Check if evil origin is reflected
            elif acao == 'https://evil.com':
                severity = 'High' if acac.lower() == 'true' else 'Medium'
                alerts.append({
                    'name': 'CORS Misconfiguration - Origin Reflection',
                    'description': 'CORS reflects arbitrary origins',
                    'severity': severity,
                    'url': target_url,
                    'evidence': f'Origin reflected: {acao}',
                    'recommendation': 'Implement strict origin validation'
                })
            
            # Overly permissive CORS
            elif acao == '*':
                alerts.append({
                    'name': 'CORS - Wildcard Origin',
                    'description': 'CORS allows any origin (wildcard)',
                    'severity': 'Low',
                    'url': target_url,
                    'evidence': f'Access-Control-Allow-Origin: *',
                    'recommendation': 'Restrict CORS to specific trusted origins'
                })
                
        except Exception as e:
            logger.error(f"CORS check failed: {e}")
            
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
                'recommendation': alert.get('recommendation', ''),
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
        
        if 'sql injection' in name_lower:
            return "A03:2024-Injection"
        elif 'xss' in name_lower or 'cross-site scripting' in name_lower:
            return "A03:2024-Injection"
        elif 'header' in name_lower or 'configuration' in name_lower or 'cors' in name_lower:
            return "A05:2024-Security Misconfiguration"
        elif 'ssl' in name_lower or 'tls' in name_lower or 'cipher' in name_lower or 'crypto' in name_lower:
            return "A02:2024-Cryptographic Failures"
        elif 'disclosure' in name_lower or 'sensitive' in name_lower:
            return "A01:2024-Broken Access Control"
        elif 'cookie' in name_lower or 'session' in name_lower:
            return "A07:2024-Identification and Authentication Failures"
        elif 'path' in name_lower or 'directory' in name_lower:
            return "A01:2024-Broken Access Control"
        elif 'debug' in name_lower:
            return "A05:2024-Security Misconfiguration"
        else:
            return "A05:2024-Security Misconfiguration"
