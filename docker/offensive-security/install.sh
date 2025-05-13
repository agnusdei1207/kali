#!/bin/bash
# filepath: /Users/agnusdei/workspace/offensive-security/docker/offensive-security/install.sh

# Define color codes for better visibility
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Define packages to install
PACKAGES=(
    # Basic utilities
    "liblzo2-2"
    "libgpm2"
    "libsodium23"
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

# Update package lists
echo -e "${YELLOW}Updating package lists...${NC}"
if apt-get update > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Package lists updated successfully${NC}"
else
    echo -e "${RED}❌ Failed to update package lists${NC}"
    exit 1
fi

# Fix broken packages if any
echo -e "\n${YELLOW}Fixing any broken packages...${NC}"
apt-get install -y --fix-broken > /dev/null 2>&1

# Install packages with dependency resolution
echo -e "\n${YELLOW}Installing packages with dependencies...${NC}"
echo -e "${BLUE}============================================${NC}"

SUCCESS=()
FAILED=()
DEPS_INSTALLED=()

for pkg in "${PACKAGES[@]}"; do
    echo -e "${CYAN}Processing $pkg...${NC}"
    
    # Check if package exists
    if ! apt-cache show $pkg > /dev/null 2>&1; then
        echo -e "${RED}❌ Package $pkg not found in repositories${NC}"
        FAILED+=("$pkg")
        continue
    fi
    
    # Find dependencies
    echo -e "  Finding dependencies..."
    DEPS=$(apt-cache depends $pkg | grep Depends | cut -d: -f2 | tr -d "<>" | sort -u)
    
    # Install dependencies first
    for dep in $DEPS; do
        if ! dpkg -l | grep -q "ii  $dep "; then
            echo -e "  Installing dependency: $dep"
            if apt-get install -y --fix-missing $dep > /dev/null 2>&1; then
                DEPS_INSTALLED+=("$dep")
            else
                echo -e "${RED}  ❌ Failed to install dependency: $dep${NC}"
            fi
        fi
    done
    
    # Install the main package
    echo -e "  Installing $pkg..."
    if apt-get install -y --fix-missing $pkg > /dev/null 2>&1; then
        echo -e "${GREEN}  ✅ SUCCESS: $pkg installed${NC}"
        SUCCESS+=("$pkg")
    else
        echo -e "${RED}  ❌ FAILED: Could not install $pkg${NC}"
        FAILED+=("$pkg")
    fi
    
    echo ""
done

# Generate report
echo -e "\n${BLUE}============================================${NC}"
echo -e "${BLUE}📋 INSTALLATION REPORT${NC}"
echo -e "${BLUE}============================================${NC}\n"

echo -e "${CYAN}🔍 Dependencies automatically installed:${NC}"
if [ ${#DEPS_INSTALLED[@]} -eq 0 ]; then
    echo "  None (all dependencies were already satisfied)"
else
    # Remove duplicates
    UNIQUE_DEPS=($(echo "${DEPS_INSTALLED[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    for dep in "${UNIQUE_DEPS[@]}"; do
        echo "  - $dep"
    done
fi

echo -e "\n${GREEN}✅ Successfully installed packages:${NC}"
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
rm -rf /var/lib/apt/lists/*
echo -e "${GREEN}✅ Cleanup completed${NC}"

echo -e "\n${BLUE}============================================${NC}"
echo -e "${GREEN}Installation process completed!${NC}"
echo -e "${BLUE}============================================${NC}"

# Print summary
echo -e "\n${YELLOW}Summary:${NC}"
echo -e "  - ${GREEN}${#SUCCESS[@]}${NC} packages installed successfully"
echo -e "  - ${CYAN}${#UNIQUE_DEPS[@]}${NC} dependencies automatically installed"
echo -e "  - ${RED}${#FAILED[@]}${NC} packages failed to install"
echo -e "${BLUE}============================================${NC}"