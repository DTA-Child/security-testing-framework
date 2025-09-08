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
            # Mock vulnerability data
            response = {'alerts': [
                {
                    'pluginId': '40012',
                    'name': 'Cross Site Scripting (Reflected)',
                    'description': 'Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user\'s browser instance.',
                    'risk': 'High',
                    'confidence': 'Medium',
                    'url': 'https://example.com/search?q=<script>alert(1)</script>',
                    'param': 'q',
                    'evidence': '<script>alert(1)</script>',
                    'solution': 'Validate all input and encode all output.',
                    'reference': 'https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS).html',
                    'cweid': '79',
                    'wascid': '8'
                },
                {
                    'pluginId': '40018',
                    'name': 'SQL Injection',
                    'description': 'SQL injection may be possible.',
                    'risk': 'High',
                    'confidence': 'Medium',
                    'url': 'https://example.com/user?id=1\'',
                    'param': 'id',
                    'evidence': 'MySQL error: You have an error in your SQL syntax',
                    'solution': 'Use parameterized queries.',
                    'reference': 'https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html',
                    'cweid': '89',
                    'wascid': '19'
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