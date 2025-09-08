# 🛡️ Security Testing Framework

> **Comprehensive Web Application Security Scanning Platform**
> 
> Integrated security testing solution combining OWASP ZAP, Nuclei, and Nikto scanners with advanced reporting and analytics.

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.95.1-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🌟 Features

### 🔍 **Multi-Scanner Integration**
- **OWASP ZAP**: Web application security scanner with spider and active scan capabilities
- **Nuclei**: Fast and customizable vulnerability scanner with community templates
- **Nikto**: Web server scanner for identifying server misconfigurations

### 📊 **Advanced Reporting**
- **OWASP Top 10 2021** categorized vulnerability reports
- Interactive HTML reports with vulnerability tabs
- PDF export capabilities
- JSON structured reports for automation

### 🎯 **OWASP Top 10 2021 Coverage**
```
✅ A01:2021-Broken Access Control
✅ A02:2021-Cryptographic Failures  
✅ A03:2021-Injection
✅ A04:2021-Insecure Design
✅ A05:2021-Security Misconfiguration
✅ A06:2021-Vulnerable and Outdated Components
✅ A07:2021-Identification and Authentication Failures
✅ A08:2021-Software and Data Integrity Failures
✅ A09:2021-Security Logging and Monitoring Failures
✅ A10:2021-Server-Side Request Forgery
```

### 🚀 **Multiple Interfaces**
- **Web UI**: Modern Bootstrap-based interface
- **REST API**: Complete API with OpenAPI documentation
- **CLI**: Rich terminal interface with progress tracking
- **WebSocket**: Real-time scan progress updates

## 🏗️ Architecture

```
security-testing-framework/
├── app/
│   ├── core/           # Configuration and orchestration
│   ├── scanners/       # Scanner implementations (ZAP, Nuclei, Nikto)
│   ├── api/           # FastAPI routes and endpoints
│   ├── report/        # Report generation and analysis
│   └── ui/            # Web and CLI interfaces
├── templates/         # HTML templates for reports and UI
├── static/           # CSS, JS, and static assets
└── Docker files      # Container deployment files
```

## ⚡ Quick Start

### 🐳 Docker Deployment (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd security-testing-framework
   ```

2. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Access the application**
   - Web Interface: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - ZAP Proxy: http://localhost:8080

### 🔧 Manual Installation

1. **Prerequisites**
   ```bash
   # Python 3.9+
   python --version
   
   # Install system dependencies (Ubuntu/Debian)
   sudo apt-get update
   sudo apt-get install wget curl unzip git build-essential
   ```

2. **Install scanners**
   ```bash
   # Install Nuclei
   wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.4_linux_amd64.zip
   unzip nuclei_2.9.4_linux_amd64.zip
   sudo mv nuclei /usr/local/bin/
   
   # Install Nikto
   git clone https://github.com/sullo/nikto.git
   sudo ln -s $(pwd)/nikto/program/nikto.pl /usr/local/bin/nikto
   ```

3. **Setup Python environment**
   ```bash
   pip install -r requirements.txt
   ```

4. **Start ZAP daemon**
   ```bash
   # Download and run ZAP
   docker run -d -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
   ```

5. **Run the application**
   ```bash
   python main.py
   ```

## 📖 Usage Guide

### 🌐 Web Interface

1. Navigate to `http://localhost:8000`
2. Click **"Start New Scan"**
3. Enter target URL and select scanners
4. Monitor scan progress in real-time
5. View detailed reports with OWASP categorization

### 🔌 API Usage

#### Start a scan
```bash
curl -X POST "http://localhost:8000/api/scan" \\
     -H "Content-Type: application/json" \\
     -d '{
       "target_url": "https://example.com",
       "scan_types": ["zap", "nuclei", "nikto"]
     }'
```

#### Check scan status
```bash
curl "http://localhost:8000/api/scan/{scan_id}"
```

#### Get report
```bash
curl "http://localhost:8000/api/report/{scan_id}?format=html" > report.html
```

### 💻 CLI Usage

```bash
# Start a scan
python -m app.ui.cli scan https://example.com --scanner zap --scanner nuclei --wait

# Check scan status
python -m app.ui.cli status <scan_id>

# List all scans
python -m app.ui.cli list --limit 10

# Generate report
python -m app.ui.cli report <scan_id> --format html --output report.html

# Show framework info
python -m app.ui.cli info
```

## 🔧 Configuration

### Environment Variables
```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# ZAP Configuration  
ZAP_HOST=localhost
ZAP_PORT=8080

# Application Settings
DEBUG=false
LOG_LEVEL=INFO
MAX_CONCURRENT_SCANS=5
REPORT_OUTPUT_DIR=reports
```

### Custom Scanner Options
```python
# ZAP Scanner Options
zap_options = {
    "spider_max_depth": 5,
    "active_scan_policy": "Default Policy"
}

# Nuclei Scanner Options
nuclei_options = {
    "severity": "critical,high,medium",
    "templates": "/path/to/custom/templates",
    "rate_limit": 150
}

# Nikto Scanner Options  
nikto_options = {
    "timeout": 10,
    "plugins": "@@ALL",
    "tuning": "1,2,3,4,5"
}
```

## 📊 Reports & Analytics

### Report Features
- **Executive Summary**: Risk scores, security grades, compliance status
- **OWASP Categorization**: Vulnerabilities organized by OWASP Top 10
- **Scanner Comparison**: Performance metrics across different scanners
- **Detailed Findings**: Complete vulnerability information with solutions
- **Security Recommendations**: Actionable remediation guidance

### Export Formats
- **HTML**: Interactive reports with tabs and filtering
- **PDF**: Professional reports for documentation
- **JSON**: Structured data for automation and integration

## 🔗 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start new security scan |
| `GET` | `/api/scan/{scan_id}` | Get scan status and progress |
| `GET` | `/api/report/{scan_id}` | Generate and download report |
| `GET` | `/api/scans` | List all scans with pagination |
| `DELETE` | `/api/scan/{scan_id}` | Delete scan and reports |
| `GET` | `/api/health` | Health check endpoint |
| `GET` | `/api/scanners` | Get available scanner information |

## 🚀 Advanced Features

### Real-time Updates
- WebSocket connections for live scan progress
- Automatic UI refresh during scanning
- Progress indicators and ETA calculations

### Concurrent Scanning
- Multiple scans running simultaneously
- Resource management and throttling
- Queue management for scan requests

### Security Analysis
- Vulnerability risk scoring
- OWASP compliance assessment  
- Security trend analysis
- False positive filtering

## 🐛 Troubleshooting

### Common Issues

**ZAP Connection Failed**
```bash
# Check ZAP is running
curl http://localhost:8080/JSON/core/view/version/

# Restart ZAP container
docker restart <zap_container_id>
```

**Scanner Not Found**
```bash
# Verify scanner installation
nuclei -version
nikto -Version

# Check PATH
echo $PATH
which nuclei
which nikto
```

**Permission Denied**
```bash
# Fix file permissions
chmod +x /usr/local/bin/nuclei
chmod +x /usr/local/bin/nikto
```

### Debug Mode
```bash
# Enable debug logging
export DEBUG=true
export LOG_LEVEL=DEBUG
python main.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP ZAP Team** - Web application security scanner
- **ProjectDiscovery** - Nuclei vulnerability scanner  
- **Sullo** - Nikto web server scanner
- **FastAPI** - Modern Python web framework
- **Bootstrap** - Frontend UI framework

## 📞 Support

- 📧 Email: security-team@company.com
- 🐛 Issues: [GitHub Issues](https://github.com/company/security-testing-framework/issues)
- 📖 Documentation: [Wiki](https://github.com/company/security-testing-framework/wiki)
- 💬 Discussions: [GitHub Discussions](https://github.com/company/security-testing-framework/discussions)

---

<p align="center">
  <strong>🛡️ Built for Security Professionals, By Security Professionals</strong>
</p>