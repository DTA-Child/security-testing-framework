#!/usr/bin/env python3
"""
Security Testing Framework - Main Entry Point
Comprehensive web application security scanning with OWASP ZAP, Nuclei, and Nikto
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from app.ui.web import app
from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('security_framework.log')
    ]
)

logger = logging.getLogger(__name__)

def main():
    """Main entry point for the Security Testing Framework"""
    try:
        logger.info("=" * 60)
        logger.info("🛡️  Security Testing Framework Starting")
        logger.info("=" * 60)
        logger.info(f"Application: {settings.APP_NAME}")
        logger.info(f"Host: {settings.API_HOST}")
        logger.info(f"Port: {settings.API_PORT}")
        logger.info(f"ZAP Host: {settings.ZAP_HOST}:{settings.ZAP_PORT}")
        logger.info(f"Reports Directory: {settings.REPORT_OUTPUT_DIR}")
        logger.info(f"Debug Mode: {settings.DEBUG}")
        logger.info("=" * 60)
        
        # Import and configure uvicorn
        import uvicorn
        
        # Configure uvicorn
        config = uvicorn.Config(
            app=app,
            host=settings.API_HOST,
            port=settings.API_PORT,
            log_level=settings.LOG_LEVEL.lower(),
            reload=settings.DEBUG,
            access_log=True
        )
        
        server = uvicorn.Server(config)
        
        # Display startup banner
        print_banner()
        
        # Start the server
        logger.info("🚀 Starting web server...")
        server.run()
        
    except KeyboardInterrupt:
        logger.info("\\n👋 Security Testing Framework shutting down...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Failed to start Security Testing Framework: {e}")
        sys.exit(1)

def print_banner():
    """Print startup banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          🛡️  SECURITY TESTING FRAMEWORK                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  🌐 Web Interface: http://{settings.API_HOST}:{settings.API_PORT:<20}                          ║
║  📊 API Documentation: http://{settings.API_HOST}:{settings.API_PORT}/docs{' ' * 17}              ║
║  🔧 ZAP Proxy: http://{settings.ZAP_HOST}:{settings.ZAP_PORT:<20}                             ║
║                                                                              ║
║  🔍 Available Scanners:                                                      ║
║    • OWASP ZAP - Web Application Security Scanner                           ║
║    • Nuclei - Fast Vulnerability Scanner                                    ║
║    • Nikto - Web Server Scanner                                             ║
║                                                                              ║
║  📋 OWASP Top 10 2021 Coverage:                                             ║
║    • A01:2021-Broken Access Control                                         ║
║    • A02:2021-Cryptographic Failures                                        ║
║    • A03:2021-Injection                                                     ║
║    • A04:2021-Insecure Design                                               ║
║    • A05:2021-Security Misconfiguration                                     ║
║    • A06:2021-Vulnerable and Outdated Components                            ║
║    • A07:2021-Identification and Authentication Failures                    ║
║    • A08:2021-Software and Data Integrity Failures                         ║
║    • A09:2021-Security Logging and Monitoring Failures                     ║
║    • A10:2021-Server-Side Request Forgery                                   ║
║                                                                              ║
║  🚀 Ready to secure your applications!                                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

if __name__ == "__main__":
    main()