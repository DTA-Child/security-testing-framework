from pydantic import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    APP_NAME: str = "Security Testing Framework"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    ZAP_HOST: str = "localhost"
    ZAP_PORT: int = 8080
    REPORT_OUTPUT_DIR: str = "reports"
    
    # Additional configuration
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 3600  # 1 hour
    
    # OWASP Categories - EXACT NAMES
    OWASP_CATEGORIES = [
        "A01:2021-Broken Access Control",
        "A02:2021-Cryptographic Failures", 
        "A03:2021-Injection",
        "A04:2021-Insecure Design",
        "A05:2021-Security Misconfiguration",
        "A06:2021-Vulnerable and Outdated Components",
        "A07:2021-Identification and Authentication Failures",
        "A08:2021-Software and Data Integrity Failures",
        "A09:2021-Security Logging and Monitoring Failures",
        "A10:2021-Server-Side Request Forgery"
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Global settings instance
settings = Settings()