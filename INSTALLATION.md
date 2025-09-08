# 🛡️ Security Testing Framework - Installation Guide

## 📥 **Download & Setup**

### **Requirements**
- **Python 3.9+** (Required)
- **Docker & Docker Compose** (Recommended)
- **Git** (Optional)
- **Linux/macOS/Windows** (Cross-platform)

---

## 🚀 **Installation Options**

### **Option 1: Docker Compose (Recommended)**

```bash
# 1. Extract the project
tar -xzf security-testing-framework-v2024.tar.gz
cd webapp/

# 2. Build and start services
docker-compose up -d

# 3. Access the application
# Web Interface: http://localhost:8000
# API Documentation: http://localhost:8000/docs
# ZAP Proxy: http://localhost:8080
```

### **Option 2: Manual Installation**

#### **Step 1: Extract & Setup**
```bash
# Extract project files
tar -xzf security-testing-framework-v2024.tar.gz
cd webapp/

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

#### **Step 2: Install Security Scanners**

**Install Nuclei:**
```bash
# Linux/macOS
wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip
unzip nuclei_3.3.5_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
chmod +x /usr/local/bin/nuclei

# Windows
# Download from: https://github.com/projectdiscovery/nuclei/releases/
# Add to PATH environment variable
```

**Install Nikto:**
```bash
# Linux/macOS
git clone https://github.com/sullo/nikto.git
sudo mv nikto /opt/
sudo ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
chmod +x /usr/local/bin/nikto

# Windows
# Download from: https://github.com/sullo/nikto
# Add to PATH environment variable
```

**Install OWASP ZAP:**
```bash
# Option A: Docker (Recommended)
docker run -d -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \
    zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

# Option B: Direct Installation
# Download from: https://www.zaproxy.org/download/
```

#### **Step 3: Start Services**

**With Supervisor (Linux/macOS):**
```bash
# Install supervisor
pip install supervisor

# Start services
supervisord -c supervisord.conf
supervisorctl -c supervisord.conf status
```

**Manual Start:**
```bash
# Start ZAP (if not using Docker)
# Follow ZAP installation guide

# Start mock ZAP (for testing without real ZAP)
python start_mock_zap.py &

# Start main application
python main.py
```

---

## 🎯 **Usage Guide**

### **1. Web Interface Usage**

#### **Access the Application:**
```
🌐 URL: http://localhost:8000
📊 API Docs: http://localhost:8000/docs
```

#### **Starting a Scan:**
1. Click **"New Scan"** button
2. Enter target URL (e.g., `https://example.com`)
3. Select scanners:
   - ✅ **ZAP** - Web application vulnerabilities
   - ✅ **Nuclei** - CVE and configuration issues  
   - ✅ **Nikto** - Web server misconfigurations
4. Click **"Start Scan"**
5. Monitor real-time progress
6. View comprehensive report with OWASP 2024 categories

### **2. API Usage**

#### **Start a Scan:**
```bash
curl -X POST "http://localhost:8000/api/scan" \
     -H "Content-Type: application/json" \
     -d '{
       "target_url": "https://example.com",
       "scan_types": ["zap", "nuclei", "nikto"]
     }'
```

#### **Check Status:**
```bash
curl "http://localhost:8000/api/scan/{scan_id}"
```

#### **Get Report:**
```bash
# HTML Report
curl "http://localhost:8000/api/report/{scan_id}?format=html" > report.html

# JSON Report  
curl "http://localhost:8000/api/report/{scan_id}?format=json" > report.json

# PDF Report
curl "http://localhost:8000/api/report/{scan_id}?format=pdf" > report.pdf
```

### **3. CLI Usage**

```bash
# Start scan with CLI
python -m app.ui.cli scan https://example.com --scanner zap --scanner nuclei --wait

# Check scan status
python -m app.ui.cli status <scan_id>

# Generate report
python -m app.ui.cli report <scan_id> --format html --output report.html

# List all scans
python -m app.ui.cli list --limit 10
```

---

## 🔧 **Configuration**

### **Environment Variables**
```bash
# API Configuration
export API_HOST=0.0.0.0
export API_PORT=8000

# ZAP Configuration
export ZAP_HOST=localhost
export ZAP_PORT=8080

# Application Settings
export DEBUG=false
export LOG_LEVEL=INFO
export MAX_CONCURRENT_SCANS=5
```

### **Custom Scanner Options**
Edit `app/core/config.py` for advanced configuration:

```python
# ZAP Scanner Options
zap_options = {
    "spider_max_depth": 5,
    "active_scan_policy": "Default Policy"
}

# Nuclei Scanner Options
nuclei_options = {
    "severity": "critical,high,medium,low,info",
    "timeout": 10,
    "rate_limit": 150
}

# Nikto Scanner Options
nikto_options = {
    "timeout": 10,
    "plugins": "@@ALL"
}
```

---

## 🎯 **Testing URLs**

### **Safe Testing Websites:**
```
✅ https://example.com - Basic security headers analysis
✅ https://httpbin.org - HTTP methods and API testing
✅ https://jsonplaceholder.typicode.com - REST API security
✅ http://testphp.vulnweb.com - Intentionally vulnerable (demo only)
```

### **Expected Results:**
```
📊 Typical Scan Results:
├─ ZAP: 2-4 vulnerabilities (XSS, SQLi, Headers)
├─ Nuclei: 3-5 findings (CVE, Tech stack, Config)
├─ Nikto: 4-6 findings (Directories, Server info)
└─ Total: 9-15 comprehensive security findings
```

---

## 🛠️ **Troubleshooting**

### **Common Issues:**

#### **ZAP Connection Failed:**
```bash
# Check ZAP is running
curl http://localhost:8080/JSON/core/view/version/

# Use mock ZAP for testing
python start_mock_zap.py &
```

#### **Scanner Not Found:**
```bash
# Verify installations
nuclei -version
nikto -Version

# Check PATH
echo $PATH
which nuclei
which nikto
```

#### **Permission Denied:**
```bash
# Fix permissions
sudo chmod +x /usr/local/bin/nuclei
sudo chmod +x /usr/local/bin/nikto
```

#### **Python Dependencies:**
```bash
# Reinstall requirements
pip install --force-reinstall -r requirements.txt

# Check Python version
python --version  # Should be 3.9+
```

### **Debug Mode:**
```bash
# Enable debug logging
export DEBUG=true
export LOG_LEVEL=DEBUG
python main.py
```

---

## 📊 **Features Overview**

### **🔍 Multi-Scanner Integration:**
- **OWASP ZAP**: Web application security scanner
- **Nuclei**: Fast vulnerability scanner with community templates
- **Nikto**: Web server scanner for misconfigurations

### **📈 OWASP Top 10 2024 Compliance:**
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

### **📋 Report Formats:**
- **Interactive HTML** - Tabs by OWASP categories
- **Professional PDF** - Executive summaries
- **Structured JSON** - Machine-readable data
- **Real-time WebSocket** - Live progress updates

### **🎨 Modern UI Features:**
- Bootstrap 5 responsive design
- Real-time progress tracking
- Color-coded severity levels
- Export capabilities
- Mobile-friendly interface

---

## 🚀 **Production Deployment**

### **Docker Production:**
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "80:8000"
    environment:
      - DEBUG=false
      - LOG_LEVEL=INFO
    volumes:
      - ./reports:/app/reports
      - ./logs:/app/logs
    restart: always
```

### **Security Considerations:**
- Change default ports in production
- Enable HTTPS with SSL certificates
- Configure firewall rules
- Set up proper authentication
- Regular security updates
- Monitor logs and metrics

---

## 📞 **Support**

### **Documentation:**
- 📖 **README.md** - Project overview
- 🔧 **INSTALLATION.md** - This guide
- 📊 **API Documentation** - http://localhost:8000/docs

### **Troubleshooting:**
- Check application logs in `logs/` directory
- Verify scanner installations
- Test network connectivity
- Review configuration files

### **Community:**
- Submit issues for bugs or feature requests
- Contribute improvements via pull requests
- Share security findings responsibly

---

## ⚡ **Quick Start Summary**

```bash
# 1. Extract project
tar -xzf security-testing-framework-v2024.tar.gz && cd webapp/

# 2. Choose installation method:

# Option A: Docker (Easiest)
docker-compose up -d

# Option B: Manual
pip install -r requirements.txt
python start_mock_zap.py &  # For testing
python main.py

# 3. Access application
# Web UI: http://localhost:8000
# Start scanning immediately!
```

**🎯 Ready to scan in under 5 minutes!**