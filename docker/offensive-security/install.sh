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

# Check if sources.list is properly configured
echo -e "${YELLOW}Verifying repository configuration...${NC}"
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

# Pre-install common dependencies that often cause issues
echo -e "\n${YELLOW}Installing common dependencies first...${NC}"
COMMON_DEPS=(
    "libc6"
    "libgcc-s1"
    "libstdc++6"
    "zlib1g"
    "libssl3"
    "libpcre2-8-0"
    "libpsl5"
    "libkeyutils1"
    "libsasl2-2"
    "libsasl2-modules-db"
    "libnettle8"
    "libgnutls30"
    "libidn2-0"
)

for dep in "${COMMON_DEPS[@]}"; do
    echo -e "  Pre-installing: $dep"
    apt-get install -y --fix-missing $dep || echo -e "${YELLOW}Continuing despite errors with $dep${NC}"
done

# Create a function to collect all dependencies for our packages
echo -e "\n${YELLOW}Analyzing all dependencies...${NC}"
ALL_DEPS=()

collect_all_dependencies() {
    for pkg in "${PACKAGES[@]}"; do
        echo -e "  Finding dependencies for $pkg..."
        deps=$(apt-cache depends $pkg 2>/dev/null | grep Depends | cut -d: -f2 | tr -d "<>" | sort -u)
        for dep in $deps; do
            ALL_DEPS+=("$dep")
        done
    done
    
    # Remove duplicates
    ALL_DEPS=($(echo "${ALL_DEPS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    echo -e "  ${CYAN}Total unique dependencies: ${#ALL_DEPS[@]}${NC}"
}

# Collect all dependencies
collect_all_dependencies

# Install all dependencies first
echo -e "\n${YELLOW}Installing all dependencies first...${NC}"
for dep in "${ALL_DEPS[@]}"; do
    echo -e "  Installing dependency: $dep"
    apt-get install -y --fix-missing $dep >/dev/null 2>&1 || echo -e "${YELLOW}  ⚠️ Issue with dependency: $dep${NC}"
done

# Fix any broken packages again
echo -e "\n${YELLOW}Fixing broken packages again...${NC}"
apt-get --fix-broken install -y

# Now install the main packages
echo -e "\n${YELLOW}Installing main packages...${NC}"
echo -e "${BLUE}============================================${NC}"

SUCCESS=()
FAILED=()

for pkg in "${PACKAGES[@]}"; do
    echo -e "${CYAN}Processing $pkg...${NC}"
    
    # Check if already installed
    if dpkg -l | grep -q "ii  $pkg "; then
        echo -e "${GREEN}  ✅ $pkg is already installed${NC}"
        SUCCESS+=("$pkg")
        continue
    fi
    
    # Try to install the package
    echo -e "  Installing $pkg..."
    if apt-get install -y --fix-missing $pkg; then
        echo -e "${GREEN}  ✅ SUCCESS: $pkg installed${NC}"
        SUCCESS+=("$pkg")
    else
        echo -e "${RED}  ❌ First attempt failed. Trying alternative method...${NC}"
        
        # Try with --no-install-recommends
        if apt-get install -y --no-install-recommends $pkg; then
            echo -e "${GREEN}  ✅ SUCCESS: $pkg installed (without recommends)${NC}"
            SUCCESS+=("$pkg")
        else
            # Try with force-depends
            echo -e "${YELLOW}  Last attempt with force-depends...${NC}"
            if apt-get install -y --force-yes $pkg; then
                echo -e "${GREEN}  ✅ SUCCESS: $pkg installed (with force)${NC}"
                SUCCESS+=("$pkg")
            else
                echo -e "${RED}  ❌ FAILED: Could not install $pkg${NC}"
                FAILED+=("$pkg")
            fi
        fi
    fi
    
    echo ""
done

# Generate report
echo -e "\n${BLUE}============================================${NC}"
echo -e "${BLUE}📋 INSTALLATION REPORT${NC}"
echo -e "${BLUE}============================================${NC}\n"

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
echo -e "  - ${RED}${#FAILED[@]}${NC} packages failed to install"
echo -e "${BLUE}============================================${NC}"