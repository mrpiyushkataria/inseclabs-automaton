#!/bin/bash

# SecLabs Automaton - Tool Installation Script
# This script installs all security tools required by the platform

set -e

echo "========================================="
echo "SecLabs Automaton Tool Installation"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation directories
TOOLS_DIR="/opt/inseclabs/tools"
BIN_DIR="/usr/local/bin"
GO_PATH="/go/bin"

# Create directories
mkdir -p $TOOLS_DIR
mkdir -p $BIN_DIR

# Function to log messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Go tools
install_go_tool() {
    local tool_name=$1
    local package=$2
    local version=$3
    
    log_info "Installing $tool_name..."
    
    if command_exists $tool_name; then
        log_warn "$tool_name already installed"
        return 0
    fi
    
    if [ -z "$version" ]; then
        go install $package@latest
    else
        go install $package@$version
    fi
    
    # Create symlink
    if [ -f "$GO_PATH/$tool_name" ]; then
        ln -sf $GO_PATH/$tool_name $BIN_DIR/
        log_info "$tool_name installed successfully"
    else
        log_error "Failed to install $tool_name"
        return 1
    fi
}

# Update system
log_info "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
log_info "Installing system dependencies..."
apt-get install -y \
    python3 python3-pip python3-venv \
    git curl wget unzip \
    nmap masscan \
    build-essential \
    libpcap-dev \
    libssl-dev \
    jq

# Install Go
if ! command_exists go; then
    log_info "Installing Go..."
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
fi

# Install Python dependencies
log_info "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install \
    sqlmap \
    wfuzz \
    wafw00f \
    whatweb

# ========== INSTALL TOOLS ==========

# ProjectDiscovery Tools
log_info "Installing ProjectDiscovery tools..."

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool "notify" "github.com/projectdiscovery/notify/cmd/notify"
install_go_tool "interactsh" "github.com/projectdiscovery/interactsh/cmd/interactsh"

# Install assetfinder
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"

# Install waybackurls
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"

# Install gau
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"

# Install ffuf
install_go_tool "ffuf" "github.com/ffuf/ffuf"

# Install amass
log_info "Installing Amass..."
if ! command_exists amass; then
    wget https://github.com/OWASP/Amass/releases/download/v3.23.3/amass_linux_amd64.zip
    unzip amass_linux_amd64.zip -d $TOOLS_DIR/amass
    ln -sf $TOOLS_DIR/amass/amass $BIN_DIR/amass
fi

# Install dirsearch
log_info "Installing Dirsearch..."
if [ ! -d "$TOOLS_DIR/dirsearch" ]; then
    git clone https://github.com/maurosoria/dirsearch.git $TOOLS_DIR/dirsearch
    pip3 install -r $TOOLS_DIR/dirsearch/requirements.txt
fi

# Install feroxbuster
log_info "Installing Feroxbuster..."
if ! command_exists feroxbuster; then
    wget https://github.com/epi052/feroxbuster/releases/download/v2.10.0/x86_64-linux-feroxbuster.zip
    unzip x86_64-linux-feroxbuster.zip -d $BIN_DIR
    chmod +x $BIN_DIR/feroxbuster
fi

# Install gowitness
log_info "Installing Gowitness..."
install_go_tool "gowitness" "github.com/sensepost/gowitness"

# Install aquatone
log_info "Installing Aquatone..."
if ! command_exists aquatone; then
    wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
    unzip aquatone_linux_amd64_1.7.0.zip -d $TOOLS_DIR/aquatone
    ln -sf $TOOLS_DIR/aquatone/aquatone $BIN_DIR/aquatone
fi

# Install arjun
log_info "Installing Arjun..."
if ! command_exists arjun; then
    pip3 install arjun
fi

# Install paramspider
log_info "Installing ParamSpider..."
if [ ! -d "$TOOLS_DIR/ParamSpider" ]; then
    git clone https://github.com/devanshbatham/ParamSpider $TOOLS_DIR/ParamSpider
    pip3 install -r $TOOLS_DIR/ParamSpider/requirements.txt
fi

# Install xsstrike
log_info "Installing XSStrike..."
if [ ! -d "$TOOLS_DIR/XSStrike" ]; then
    git clone https://github.com/s0md3v/XSStrike $TOOLS_DIR/XSStrike
    pip3 install -r $TOOLS_DIR/XSStrike/requirements.txt
fi

# Install nuclei templates
log_info "Downloading Nuclei templates..."
if [ ! -d "/root/nuclei-templates" ]; then
    nuclei -update-templates
fi

# Install chaos-client
log_info "Installing Chaos Client..."
install_go_tool "chaos" "github.com/projectdiscovery/chaos-client/cmd/chaos"

# Install findomain
log_info "Installing Findomain..."
if ! command_exists findomain; then
    wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
    chmod +x findomain-linux
    mv findomain-linux $BIN_DIR/findomain
fi

# Install shuffledns
install_go_tool "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns"

# Install puredns
install_go_tool "puredns" "github.com/d3mondev/puredns/v2"

# Install anew
install_go_tool "anew" "github.com/tomnomnom/anew"

# Install httprobe
install_go_tool "httprobe" "github.com/tomnomnom/httprobe"

# ========== POST-INSTALLATION ==========

# Create tool registry
log_info "Creating tool registry..."
cat > $TOOLS_DIR/tool_registry.json << EOF
{
    "installed_tools": [
        "subfinder",
        "httpx",
        "naabu",
        "nuclei",
        "katana",
        "dnsx",
        "assetfinder",
        "amass",
        "dirsearch",
        "feroxbuster",
        "gowitness",
        "aquatone",
        "arjun",
        "paramspider",
        "xsstrike",
        "findomain",
        "shuffledns",
        "puredns"
    ],
    "installation_date": "$(date)",
    "version": "1.0.0"
}
EOF

# Set permissions
chmod -R 755 $TOOLS_DIR
chown -R root:root $TOOLS_DIR

# Verify installations
log_info "Verifying tool installations..."
for tool in subfinder httpx naabu nuclei katana dnsx nmap; do
    if command_exists $tool; then
        log_info "$tool: $(which $tool)"
    else
        log_error "$tool: NOT FOUND"
    fi
done

echo "========================================="
echo "Installation completed!"
echo "========================================="
echo "Tools installed in: $TOOLS_DIR"
echo "Binaries available in: $BIN_DIR"
echo "========================================="
