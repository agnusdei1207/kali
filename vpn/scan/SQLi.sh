#!/bin/bash

# SQLMap 스타일 수동 SQLi 테스터 (OSCP 허용 범위)
# 사용법: ./SQLi.sh -u "http://target.com/page.php?query=test" --payloads payloads.txt

# 초기값
TARGET_URL=""
PAYLOAD_FILE=""

# 인자 파싱
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -u) TARGET_URL="$2"; shift ;;
        --payloads) PAYLOAD_FILE="$2"; shift ;;
        *) echo "❌ 잘못된 옵션: $1" >&2; exit 1 ;;
    esac
    shift
done

# 유효성 확인
if [[ -z "$TARGET_URL" || -z "$PAYLOAD_FILE" ]]; then
    echo "❗ 사용법: $0 -u \"http://target.com/page.php?param=value\" --payloads payloads.txt"
    exit 1
fi

if [[ ! -f "$PAYLOAD_FILE" ]]; then
    echo "❌ 페이로드 파일이 존재하지 않습니다: $PAYLOAD_FILE"
    exit 1
fi

# '='를 기준으로 파라미터 분리
BASE_URL="${TARGET_URL%%=*}="
ORIGINAL_VAL="${TARGET_URL#*=}"

# 정상 응답 저장
curl -s "${BASE_URL}${ORIGINAL_VAL}" -o normal.txt
NORMAL_LEN=$(wc -c < normal.txt)

echo ""
echo "📊 SQLi 수동 테스트 결과 (변화 감지된 페이로드만 표시)"
echo "--------------------------------------------------------------------------"
printf "| %-40s | %-6s | %-35s |\n" "Payload" "변화" "응답 일부"
echo "--------------------------------------------------------------------------"

# 페이로드 순회
while IFS= read -r payload || [[ -n "$payload" ]]; do
    TEST_URL="${BASE_URL}${payload}"
    curl -s "$TEST_URL" -o test.txt
    TEST_LEN=$(wc -c < test.txt)

    if [ "$TEST_LEN" -ne "$NORMAL_LEN" ]; then
        SUMMARY=$(head -n 20 test.txt | sed 's/[^[:print:]]//g' | tr '\n' ' ' | cut -c 1-35)
        printf "| %-40s | %-6s | %-35s |\n" "$payload" "⭕" "$SUMMARY"
    fi
done < "$PAYLOAD_FILE"

echo "--------------------------------------------------------------------------"
echo "[*] 검사 완료"
