"""Application configuration settings"""

from pydantic_settings import BaseSettings
from typing import List, ClassVar

class Settings(BaseSettings):
    """Application configuration"""
    
    # Basic Settings
    APP_NAME: str = "Security Testing Framework"
    VERSION: str = "1.0.0"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    
    # Scanner Settings
    MAX_CONCURRENT_SCANS: int = 3
    SCAN_TIMEOUT: int = 300  # 5 minutes
    
    # Logging
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # Directories
    REPORTS_DIR: str = "reports"
    
    # OWASP Top 10 2024
    OWASP_CATEGORIES: ClassVar[List[str]] = [
        "A01:2024-Broken Access Control",
        "A02:2024-Cryptographic Failures", 
        "A03:2024-Injection",
        "A04:2024-Insecure Design",
        "A05:2024-Security Misconfiguration",
        "A06:2024-Vulnerable and Outdated Components",
        "A07:2024-Identification and Authentication Failures",
        "A08:2024-Software and Data Integrity Failures",
        "A09:2024-Security Logging and Monitoring Failures",
        "A10:2024-Server-Side Request Forgery (SSRF)"
    ]
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": True
    }

# Global settings instance
settings = Settings()