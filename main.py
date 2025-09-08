#!/usr/bin/env python3
"""
Security Testing Framework
A comprehensive web security scanner with ZAP, Nuclei, and Nikto integration
"""

import uvicorn
import logging
from pathlib import Path

from src.core.config import settings
from src.api.server import create_app

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create reports directory
Path("reports").mkdir(exist_ok=True)

# Create FastAPI app for uvicorn
app = create_app()

def main():
    """Main application entry point for direct execution"""
    logger.info("🛡️  Security Testing Framework")
    logger.info("=" * 50)
    logger.info(f"Host: {settings.API_HOST}")
    logger.info(f"Port: {settings.API_PORT}")
    logger.info(f"Environment: {'Development' if settings.DEBUG else 'Production'}")
    logger.info("=" * 50)
    
    # Start server
    uvicorn.run(
        app,
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level=settings.LOG_LEVEL.lower()
    )

if __name__ == "__main__":
    main()