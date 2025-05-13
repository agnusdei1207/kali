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

# Check if sources.list is properly configured
echo -e "\n${YELLOW}Verifying repository configuration...${NC}"
if [ ! -f /etc/apt/sources.list ]; then
    echo -e "${RED}❌ sources.list file is missing!${NC}"
    echo -e "${YELLOW}Creating default sources.list...${NC}"
    echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
fi

cat /etc/apt/sources.list
echo -e "${GREEN}✅ Repository configuration verified${NC}"

# Update package lists with retry mechanism
echo -e "\n${YELLOW}Updating package lists...${NC}"
retry_count=0
max_retries=3

while [ $retry_count -lt $max_retries ]; do
    if apt-get update; then
        echo -e "${GREEN}✅ Package lists updated successfully${NC}"
        break
    else
        retry_count=$((retry_count + 1))
        if [ $retry_count -eq $max_retries ]; then
            echo -e "${RED}❌ Failed to update package lists after multiple attempts. Exiting.${NC}"
            exit 1
        fi
        
        echo -e "${YELLOW}Retry $retry_count/$max_retries: Trying alternate repository...${NC}"
        if [ $retry_count -eq 1 ]; then
            echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
        elif [ $retry_count -eq 2 ]; then
            echo "deb http://mirror.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
        fi
    fi
done

# Fix broken packages first
echo -e "\n${YELLOW}Fixing any broken packages...${NC}"
apt-get --fix-broken install -y

# Install critical base packages first - architecture-agnostic approach
echo -e "\n${YELLOW}Installing critical base packages...${NC}"
apt-get install -y apt-utils dialog 2>/dev/null
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

# Function to install a group of packages
install_group() {
    local group_name="$1"
    shift
    local group_packages=("$@")
    
    echo -e "\n${CYAN}Installing ${group_name}...${NC}"
    
    # Try to install the group together first
    if apt-get install -y --no-install-recommends "${group_packages[@]}"; then
        echo -e "${GREEN}✅ SUCCESS: Installed ${group_name} as a group${NC}"
        for pkg in "${group_packages[@]}"; do
            SUCCESS+=("$pkg")
        done
    else
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
            
            # Try different installation methods
            if apt-get install -y --no-install-recommends -f $pkg; then
                echo -e "${GREEN}✅ SUCCESS: $pkg installed${NC}"
                SUCCESS+=("$pkg")
            else
                echo -e "${RED}❌ Failed to install $pkg normally, trying with force...${NC}"
                
                # Try to fix broken packages before trying again
                apt-get --fix-broken install -y >/dev/null 2>&1
                
                # Try with alternative options
                if apt-get install -y --allow-downgrades --allow-change-held-packages $pkg; then
                    echo -e "${GREEN}✅ SUCCESS: $pkg installed (with force)${NC}"
                    SUCCESS+=("$pkg")
                else
                    echo -e "${RED}❌ FAILED: Could not install $pkg${NC}"
                    FAILED+=("$pkg")
                fi
            fi
        done
    fi
    
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