#!/usr/bin/env python3
"""
Mock ZAP server for testing when real ZAP is not available
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
import time

class MockZAPHandler(BaseHTTPRequestHandler):
    """Mock ZAP API responses"""
    
    def do_GET(self):
        """Handle GET requests"""
        if '/JSON/core/view/version/' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'version': '2.12.0'}
            self.wfile.write(json.dumps(response).encode())
        elif '/JSON/spider/view/status/' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'status': '100'}  # Completed
            self.wfile.write(json.dumps(response).encode())
        elif '/JSON/ascan/view/status/' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'status': '100'}  # Completed
            self.wfile.write(json.dumps(response).encode())
        elif '/JSON/core/view/alerts/' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            # Mock vulnerability data - OWASP Top 10 2024
            response = {'alerts': [
                {
                    'pluginId': '40012',
                    'name': 'Cross Site Scripting (Reflected)',
                    'description': 'Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user\'s browser instance. Modern XSS attacks can bypass CSP and utilize DOM manipulation.',
                    'risk': 'High',
                    'confidence': 'High',
                    'url': 'https://example.com/search?q=<script>alert(1)</script>',
                    'param': 'q',
                    'evidence': '<script>alert(1)</script>',
                    'solution': 'Implement Content Security Policy (CSP), validate all input and encode all output using context-aware encoding.',
                    'reference': 'https://owasp.org/Top10/A03_2024-Injection/',
                    'cweid': '79',
                    'wascid': '8'
                },
                {
                    'pluginId': '40018',
                    'name': 'SQL Injection',
                    'description': 'SQL injection vulnerability allows attackers to interfere with database queries. This can lead to data theft, corruption, or unauthorized access.',
                    'risk': 'High',
                    'confidence': 'High',
                    'url': 'https://example.com/user?id=1\'',
                    'param': 'id',
                    'evidence': 'MySQL error: You have an error in your SQL syntax',
                    'solution': 'Use parameterized queries/prepared statements and input validation. Implement least privilege database access.',
                    'reference': 'https://owasp.org/Top10/A03_2024-Injection/',
                    'cweid': '89',
                    'wascid': '19'
                },
                {
                    'pluginId': '10021',
                    'name': 'X-Content-Type-Options Header Missing',
                    'description': 'The Anti-MIME-Sniffing header X-Content-Type-Options was not set to nosniff. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing.',
                    'risk': 'Low',
                    'confidence': 'Medium',
                    'url': 'https://example.com/',
                    'param': '',
                    'evidence': '',
                    'solution': 'Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to nosniff.',
                    'reference': 'https://owasp.org/Top10/A05_2024-Security_Misconfiguration/',
                    'cweid': '693',
                    'wascid': '15'
                },
                {
                    'pluginId': '10035',
                    'name': 'Strict-Transport-Security Header Not Set',
                    'description': 'HTTP Strict Transport Security (HSTS) is a web security policy mechanism that helps protect websites against protocol downgrade attacks and cookie hijacking.',
                    'risk': 'Low',
                    'confidence': 'High',
                    'url': 'https://example.com/',
                    'param': '',
                    'evidence': '',
                    'solution': 'Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.',
                    'reference': 'https://owasp.org/Top10/A02_2024-Cryptographic_Failures/',
                    'cweid': '319',
                    'wascid': '15'
                }
            ]}
            self.wfile.write(json.dumps(response).encode())
        elif '/JSON/spider/view/results/' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'results': ['https://example.com/', 'https://example.com/about']}
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'success': True}
            self.wfile.write(json.dumps(response).encode())
    
    def do_POST(self):
        """Handle POST requests"""
        if '/JSON/spider/action/scan/' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'scan': '0'}  # Spider scan ID
            self.wfile.write(json.dumps(response).encode())
        elif '/JSON/ascan/action/scan/' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'scan': '0'}  # Active scan ID
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'success': True}
            self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        return

def start_mock_zap():
    """Start mock ZAP server on port 8080"""
    server = HTTPServer(('localhost', 8080), MockZAPHandler)
    print("🔧 Mock ZAP server starting on http://localhost:8080")
    server.serve_forever()

if __name__ == "__main__":
    try:
        start_mock_zap()
    except KeyboardInterrupt:
        print("\n👋 Mock ZAP server stopped")