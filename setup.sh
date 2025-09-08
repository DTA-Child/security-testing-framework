#!/bin/bash
# Security Testing Framework - Automated Setup Script
# Supports Linux and macOS

set -e

echo "🛡️  Security Testing Framework - Automated Setup"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on supported OS
check_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_status "Detected Linux OS"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_status "Detected macOS"
    else
        print_error "Unsupported OS. This script supports Linux and macOS only."
        exit 1
    fi
}

# Check Python version
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        print_status "Found Python $PYTHON_VERSION"
        
        if (( $(echo "$PYTHON_VERSION >= 3.9" | bc -l) )); then
            print_success "Python version is compatible"
        else
            print_error "Python 3.9+ is required. Found: $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 is not installed. Please install Python 3.9+ first."
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    if [[ "$OS" == "linux" ]]; then
        # Detect Linux distribution
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y wget curl unzip git build-essential
        elif command -v yum &> /dev/null; then
            sudo yum install -y wget curl unzip git gcc gcc-c++ make
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm wget curl unzip git base-devel
        else
            print_warning "Could not detect package manager. Please install: wget, curl, unzip, git, build-essential"
        fi
    elif [[ "$OS" == "macos" ]]; then
        if ! command -v brew &> /dev/null; then
            print_warning "Homebrew not found. Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install wget curl unzip git
    fi
    
    print_success "System dependencies installed"
}

# Setup Python virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    fi
    
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    print_success "Python dependencies installed"
}

# Install Nuclei scanner
install_nuclei() {
    print_status "Installing Nuclei scanner..."
    
    if command -v nuclei &> /dev/null; then
        print_warning "Nuclei already installed: $(nuclei -version 2>&1 | head -1)"
        return
    fi
    
    NUCLEI_VERSION="3.3.5"
    
    if [[ "$OS" == "linux" ]]; then
        NUCLEI_ARCH="linux_amd64"
    elif [[ "$OS" == "macos" ]]; then
        NUCLEI_ARCH="macOS_amd64"
    fi
    
    cd /tmp
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip"
    unzip -q "nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip"
    sudo mv nuclei /usr/local/bin/
    sudo chmod +x /usr/local/bin/nuclei
    rm -f "nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip"
    cd - > /dev/null
    
    print_success "Nuclei installed successfully"
}

# Install Nikto scanner
install_nikto() {
    print_status "Installing Nikto scanner..."
    
    if command -v nikto &> /dev/null; then
        print_warning "Nikto already installed: $(nikto -Version 2>&1 | head -1)"
        return
    fi
    
    cd /tmp
    git clone --depth 1 https://github.com/sullo/nikto.git
    sudo cp -r nikto /opt/
    sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
    sudo chmod +x /usr/local/bin/nikto
    rm -rf nikto
    cd - > /dev/null
    
    print_success "Nikto installed successfully"
}

# Install Docker (optional)
install_docker() {
    print_status "Checking Docker installation..."
    
    if command -v docker &> /dev/null; then
        print_success "Docker already installed: $(docker --version)"
        return
    fi
    
    read -p "Docker not found. Would you like to install Docker? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ "$OS" == "linux" ]]; then
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            sudo usermod -aG docker $USER
            rm get-docker.sh
            print_success "Docker installed. Please log out and back in to use Docker without sudo."
        elif [[ "$OS" == "macos" ]]; then
            print_warning "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop"
        fi
    else
        print_warning "Skipping Docker installation. ZAP will use mock mode."
    fi
}

# Setup directories
setup_directories() {
    print_status "Setting up directories..."
    
    mkdir -p logs reports
    touch logs/.gitkeep reports/.gitkeep
    
    print_success "Directories created"
}

# Verify installations
verify_installation() {
    print_status "Verifying installation..."
    
    # Check Python packages
    source venv/bin/activate
    python -c "import fastapi, uvicorn; print('✅ Python packages OK')" || {
        print_error "Python package verification failed"
        exit 1
    }
    
    # Check scanners
    if command -v nuclei &> /dev/null; then
        echo "✅ Nuclei: $(nuclei -version 2>&1 | head -1 | grep -o 'v[0-9.]*')"
    else
        print_warning "❌ Nuclei not found"
    fi
    
    if command -v nikto &> /dev/null; then
        echo "✅ Nikto: $(nikto -Version 2>&1 | head -1)"
    else
        print_warning "❌ Nikto not found"
    fi
    
    if command -v docker &> /dev/null; then
        echo "✅ Docker: $(docker --version | cut -d' ' -f3 | tr -d ',')"
    else
        print_warning "❌ Docker not found (will use mock ZAP)"
    fi
    
    print_success "Installation verification completed"
}

# Create startup script
create_startup_script() {
    print_status "Creating startup script..."
    
    cat > start.sh << 'EOF'
#!/bin/bash
# Security Testing Framework Startup Script

echo "🛡️  Starting Security Testing Framework..."

# Activate virtual environment
source venv/bin/activate

# Start mock ZAP if real ZAP is not available
if ! curl -s http://localhost:8080/JSON/core/view/version/ > /dev/null 2>&1; then
    echo "Starting mock ZAP server..."
    nohup python start_mock_zap.py > logs/zap_mock.log 2>&1 &
    sleep 2
fi

# Start main application
echo "Starting main application..."
python main.py
EOF
    
    chmod +x start.sh
    print_success "Startup script created: ./start.sh"
}

# Main installation function
main() {
    print_status "Starting Security Testing Framework setup..."
    
    check_os
    check_python
    install_system_deps
    setup_python_env
    install_nuclei
    install_nikto
    install_docker
    setup_directories
    create_startup_script
    verify_installation
    
    echo ""
    echo "🎉 Installation completed successfully!"
    echo ""
    echo "📋 Quick Start:"
    echo "   1. Start the application:"
    echo "      ./start.sh"
    echo ""
    echo "   2. Open web browser:"
    echo "      http://localhost:8000"
    echo ""
    echo "   3. Start scanning!"
    echo ""
    echo "🔧 Alternative start methods:"
    echo "   • Docker: docker-compose up -d"
    echo "   • Manual: source venv/bin/activate && python main.py"
    echo ""
    echo "📖 Full documentation: cat INSTALLATION.md"
    echo ""
}

# Run main function
main "$@"