#!/bin/bash

# Define color codes for better visibility
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Set environment variables to avoid interactive prompts
export DEBIAN_FRONTEND=noninteractive

# Define packages to install
PACKAGES=(
    # Basic utilities
    "vim"
    "tmux"
    "curl"
    "wget"
    "git"
    
    # Python
    "python3"
    "python3-pip"
    
    # Networking tools
    "openvpn"
    "iputils-ping"
    "net-tools"
    "nmap"
    "whois"
    "traceroute"
    "tcpdump"
    "netcat-traditional"
    
    # Proxy and anonymity
    "proxychains4"
    "tor"
)

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}📦 Kali Linux Package Installation Script 📦${NC}"
echo -e "${BLUE}============================================${NC}\n"

# Check architecture and platform
echo -e "${YELLOW}Checking system architecture...${NC}"
ARCH=$(dpkg --print-architecture)
echo -e "${CYAN}Current architecture: ${ARCH}${NC}"

# Configure multiple repositories for redundancy
echo -e "\n${YELLOW}Configuring repositories...${NC}"
cat > /etc/apt/sources.list <<EOF
deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
deb http://mirror.kali.org/kali kali-rolling main contrib non-free non-free-firmware
# Additional mirrors for redundancy
deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware
EOF

# Ensure keyring is properly installed
echo -e "\n${YELLOW}Verifying keyring...${NC}"
if [ ! -e /usr/share/keyrings/kali-archive-keyring.gpg ]; then
    echo -e "${YELLOW}Reinstalling kali-archive-keyring...${NC}"
    apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true
    apt-get install -y --allow-unauthenticated kali-archive-keyring
fi

# Update package lists with better retry mechanism
echo -e "\n${YELLOW}Updating package lists...${NC}"
retry_count=0
max_retries=5

while [ $retry_count -lt $max_retries ]; do
    if apt-get update; then
        echo -e "${GREEN}✅ Package lists updated successfully${NC}"
        break
    else
        retry_count=$((retry_count + 1))
        if [ $retry_count -eq $max_retries ]; then
            echo -e "${RED}❌ Failed to update package lists after multiple attempts. Trying to continue anyway.${NC}"
            break
        fi
        
        echo -e "${YELLOW}Retry $retry_count/$max_retries: Waiting before retrying...${NC}"
        sleep 5
    fi
done

# Fix broken packages first
echo -e "\n${YELLOW}Fixing any broken packages...${NC}"
apt-get --fix-broken install -y

# Clean previous apt cache
echo -e "\n${YELLOW}Cleaning existing package cache...${NC}"
apt-get clean
# rm -rf /var/lib/apt/lists/*
apt-get update --fix-missing

# Install critical base packages first - architecture-agnostic approach
echo -e "\n${YELLOW}Installing critical base packages...${NC}"
apt-get install -y apt-utils dialog apt-transport-https 2>/dev/null
apt-get install -y --no-install-recommends build-essential ca-certificates 2>/dev/null

# Now install the main packages in batches to manage dependency resolution better
echo -e "\n${YELLOW}Installing packages in groups...${NC}"
echo -e "${BLUE}============================================${NC}"

SUCCESS=()
FAILED=()

# Define package groups for better installation flow
BASIC_UTILS=("vim" "tmux" "curl" "wget" "git")
PYTHON_PKGS=("python3" "python3-pip")
NET_TOOLS=("iputils-ping" "net-tools" "whois" "traceroute" "tcpdump" "netcat-traditional")
ADVANCED_TOOLS=("openvpn" "nmap" "proxychains4" "tor")

# Function to install a group of packages with retry mechanism
install_group() {
    local group_name="$1"
    shift
    local group_packages=("$@")
    
    echo -e "\n${CYAN}Installing ${group_name}...${NC}"
    
    # Try to install the group together first with retries
    local group_retry=0
    local group_max_retries=3
    
    while [ $group_retry -lt $group_max_retries ]; do
        if apt-get install -y --no-install-recommends "${group_packages[@]}"; then
            echo -e "${GREEN}✅ SUCCESS: Installed ${group_name} as a group${NC}"
            for pkg in "${group_packages[@]}"; do
                SUCCESS+=("$pkg")
            done
            return 0
        else
            group_retry=$((group_retry + 1))
            echo -e "${YELLOW}Group install attempt $group_retry/$group_max_retries failed. Retrying...${NC}"
            apt-get update --fix-missing
            sleep 2
        fi
    done
    
    echo -e "${YELLOW}Installing ${group_name} packages individually...${NC}"
    # Install packages one by one if group install failed
    for pkg in "${group_packages[@]}"; do
        echo -e "${CYAN}Processing $pkg...${NC}"
        
        # Check if already installed
        if dpkg -l | grep -q "^ii  $pkg "; then
            echo -e "${GREEN}✅ $pkg is already installed${NC}"
            SUCCESS+=("$pkg")
            continue
        fi
        
        # Try different installation methods with retries
        local pkg_retry=0
        local pkg_max_retries=3
        
        while [ $pkg_retry -lt $pkg_max_retries ]; do
            if apt-get install -y --no-install-recommends --fix-missing $pkg; then
                echo -e "${GREEN}✅ SUCCESS: $pkg installed${NC}"
                SUCCESS+=("$pkg")
                break
            else
                pkg_retry=$((pkg_retry + 1))
                if [ $pkg_retry -eq $pkg_max_retries ]; then
                    echo -e "${RED}❌ FAILED: Could not install $pkg after multiple attempts${NC}"
                    FAILED+=("$pkg")
                    break
                fi
                
                echo -e "${YELLOW}Retrying $pkg (attempt $pkg_retry/$pkg_max_retries)...${NC}"
                apt-get update --fix-missing
                apt-get --fix-broken install -y >/dev/null 2>&1
                sleep 2
            fi
        done
    done
    
    # Fix broken packages after each group
    echo -e "${YELLOW}Fixing any broken packages after installing ${group_name}...${NC}"
    apt-get --fix-broken install -y >/dev/null 2>&1
}

# Install package groups in logical order
install_group "Basic Utilities" "${BASIC_UTILS[@]}"
install_group "Python Packages" "${PYTHON_PKGS[@]}"
install_group "Network Tools" "${NET_TOOLS[@]}"
install_group "Advanced Tools" "${ADVANCED_TOOLS[@]}"

# Generate report
echo -e "\n${BLUE}============================================${NC}"
echo -e "${BLUE}📋 INSTALLATION REPORT${NC}"
echo -e "${BLUE}============================================${NC}\n"

echo -e "${GREEN}✅ Successfully installed packages:${NC}"
if [ ${#SUCCESS[@]} -eq 0 ]; then
    echo "  None"
else
    for pkg in "${SUCCESS[@]}"; do
        echo "  - $pkg"
    done
fi

echo -e "\n${RED}❌ Failed to install packages:${NC}"
if [ ${#FAILED[@]} -eq 0 ]; then
    echo -e "  ${GREEN}None - All packages installed successfully!${NC}"
else
    for pkg in "${FAILED[@]}"; do
        echo "  - $pkg"
    done
fi

# Clean up
echo -e "\n${YELLOW}Cleaning up...${NC}"
apt-get clean
apt-get autoremove -y >/dev/null 2>&1
rm -rf /var/lib/apt/lists/*
echo -e "${GREEN}✅ Cleanup completed${NC}"

echo -e "\n${BLUE}============================================${NC}"
echo -e "${GREEN}Installation process completed!${NC}"
echo -e "${BLUE}============================================${NC}"

# Print summary
echo -e "\n${YELLOW}Summary:${NC}"
echo -e "  - ${GREEN}${#SUCCESS[@]}${NC} packages installed successfully"
echo -e "  - ${RED}${#FAILED[@]}${NC} packages failed to install"
echo -e "${BLUE}============================================${NC}"