# 🐳 Docker Fix - Missing pydantic-settings

## 🚨 **Problem**
If you encounter this error when running Docker:
```
ModuleNotFoundError: No module named 'pydantic_settings'
```

## ✅ **Solution**

### **Quick Fix (If you already downloaded):**

1. **Create fixed requirements file:**
```bash
cat > requirements-docker.txt << 'EOF'
fastapi==0.116.1
uvicorn==0.35.0
pydantic==2.11.7
pydantic-settings==2.10.1
pydantic-core==2.33.2
python-owasp-zap-v2.4==0.0.20
requests==2.32.5
jinja2==3.1.6
typer==0.9.0
rich==13.3.5
weasyprint==59.0
pyyaml==6.0.2
aiofiles==23.1.0
python-multipart==0.0.6
starlette==0.47.3
anyio==4.10.0
sniffio==1.3.1
h11==0.16.0
click==8.2.1
typing-extensions==4.15.0
annotated-types==0.7.0
python-dotenv==1.1.1
supervisor==4.3.0
EOF
```

2. **Update Dockerfile:**
```bash
# Replace line in Dockerfile
sed -i 's/COPY requirements.txt ./COPY requirements-docker.txt ./' Dockerfile
sed -i 's/pip install --no-cache-dir -r requirements.txt/pip install --no-cache-dir -r requirements-docker.txt/' Dockerfile
```

3. **Rebuild Docker:**
```bash
# Stop existing containers
docker-compose down -v

# Rebuild with no cache
docker-compose build --no-cache

# Start services
docker-compose up -d

# Check status
docker-compose logs app
```

### **Alternative: Use Rebuild Script**
```bash
# Make script executable (if not already)
chmod +x docker-rebuild.sh

# Run rebuild
./docker-rebuild.sh
```

## 🎯 **Verification**

After rebuild, check if it's working:
```bash
# Test health endpoint
curl http://localhost:8000/api/health

# Should return:
# {"status":"healthy","timestamp":"...","version":"1.0.0","active_scans":0}
```

## 🌐 **Access Application**
- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **ZAP Proxy**: http://localhost:8080

## 📋 **Troubleshooting**

### **If still having issues:**
```bash
# Check container logs
docker-compose logs -f app

# Check container status
docker-compose ps

# Restart specific service
docker-compose restart app

# Complete cleanup and rebuild
docker-compose down -v
docker system prune -f
docker-compose build --no-cache
docker-compose up -d
```

### **Manual Container Debug:**
```bash
# Enter container for debugging
docker-compose exec app /bin/bash

# Check Python packages inside container
pip list | grep pydantic

# Should show:
# pydantic                 2.11.7
# pydantic-core            2.33.2
# pydantic-settings        2.10.1
```

## ✅ **Success Indicators**
- ✅ Container starts without errors
- ✅ Health endpoint responds
- ✅ Web interface loads at localhost:8000
- ✅ Can create new scans successfully

---

**🎉 After fix, your Docker setup should work perfectly!**