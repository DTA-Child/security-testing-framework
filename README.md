# Security Testing Framework

A comprehensive web security scanner that combines multiple tools (ZAP, Nuclei, Nikto) with OWASP Top 10 2024 compliance.

## Features

- **Real Vulnerability Scanning**: No fake data, only genuine security findings
- **Multiple Scanners**: ZAP, Nuclei, and Nikto integration
- **OWASP Top 10 2024**: Latest security standards
- **REST API**: Complete API with FastAPI
- **Docker Support**: Easy deployment with Docker
- **Real-time Results**: Live scan progress tracking

## Quick Start

### Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/DTA-Child/security-testing-framework.git
cd security-testing-framework

# Start with Docker Compose
docker-compose up -d

# Access the application
curl http://localhost:8000/api/health
```

### Local Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install scanning tools
# Nuclei: Download from https://github.com/projectdiscovery/nuclei/releases
# Nikto: git clone https://github.com/sullo/nikto.git

# Run application
python main.py
```

## API Usage

### Start a Scan

```bash
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

### Check Scan Status

```bash
curl "http://localhost:8000/api/scan/{scan_id}"
```

### Get All Scans

```bash
curl "http://localhost:8000/api/scans"
```

## Configuration

Environment variables:

- `API_HOST`: Host to bind to (default: 0.0.0.0)
- `API_PORT`: Port to listen on (default: 8000)
- `LOG_LEVEL`: Logging level (default: INFO)
- `MAX_CONCURRENT_SCANS`: Max parallel scans (default: 3)
- `SCAN_TIMEOUT`: Scan timeout in seconds (default: 300)

## Scanner Details

### ZAP Scanner
- HTTP header security analysis
- SSL/TLS configuration checking
- Information disclosure detection

### Nuclei Scanner
- Template-based vulnerability scanning
- CVE detection
- Misconfiguration identification

### Nikto Scanner
- Web server vulnerability scanning
- Directory enumeration
- Server fingerprinting

## OWASP Top 10 2024 Mapping

All vulnerabilities are automatically mapped to OWASP Top 10 2024 categories:

- A01:2024-Broken Access Control
- A02:2024-Cryptographic Failures
- A03:2024-Injection
- A04:2024-Insecure Design
- A05:2024-Security Misconfiguration
- A06:2024-Vulnerable and Outdated Components
- A07:2024-Identification and Authentication Failures
- A08:2024-Software and Data Integrity Failures
- A09:2024-Security Logging and Monitoring Failures
- A10:2024-Server-Side Request Forgery (SSRF)

## Development

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest

# Run with hot reload
uvicorn src.api.server:create_app --reload --host 0.0.0.0 --port 8000
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request