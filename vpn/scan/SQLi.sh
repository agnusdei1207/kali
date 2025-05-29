#!/bin/bash

# SQLi 수동 테스터 - OSCP 호환
# 사용법: ./SQLi.sh -u "http://target.com/page.php?id=1" --payloads payload1.txt payload2.txt ... [-o 결과파일]

TARGET_URL=""
PAYLOAD_FILES=()
OUTPUT_FILE="SQLi_result.txt"

# 인자 파싱
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -u) TARGET_URL="$2"; shift ;;
        --payloads)
            shift
            while [[ "$#" -gt 0 && ! "$1" =~ ^- ]]; do
                PAYLOAD_FILES+=("$1")
                shift
            done
            continue
            ;;
        -o) OUTPUT_FILE="$2"; shift ;;
        *) echo "❌ 잘못된 옵션: $1" >&2; exit 1 ;;
    esac
    shift
done

if [[ -z "$TARGET_URL" || "${#PAYLOAD_FILES[@]}" -eq 0 ]]; then
    echo "❗ 사용법: $0 -u \"http://target.com/page.php?id=1\" --payloads payload1.txt [payload2.txt ...] [-o 결과파일]"
    exit 1
fi

for file in "${PAYLOAD_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "❌ 페이로드 파일이 존재하지 않습니다: $file"
        exit 1
    fi
done

if ! [[ "$TARGET_URL" =~ "=" ]]; then
    echo "❌ URL에 '='가 포함된 파라미터가 없습니다."
    exit 1
fi

BASE_URL="${TARGET_URL%%=*}="
ORIGINAL_VAL="${TARGET_URL#*=}"

# 정상 응답 수집
curl -sL "${BASE_URL}${ORIGINAL_VAL}" -o normal.txt
NORMAL_LEN=$(wc -c < normal.txt)

echo "" > "$OUTPUT_FILE" # 결과파일 초기화

echo "📊 SQLi 수동 테스트 결과 (변화 감지된 페이로드만 표시)" | tee -a "$OUTPUT_FILE"
echo "--------------------------------------------------------------------------------------" | tee -a "$OUTPUT_FILE"
printf "| %-40s | %-6s | %-8s | %-20s | %-35s |\n" "Payload" "변화" "걸린시간(s)" "시간" "응답 일부" | tee -a "$OUTPUT_FILE"
echo "--------------------------------------------------------------------------------------" | tee -a "$OUTPUT_FILE"

declare -a DETECTED_PAYLOADS=()

for PAYLOAD_FILE in "${PAYLOAD_FILES[@]}"; do
    while IFS= read -r payload || [[ -n "$payload" ]]; do
        START_TIME=$(date +%s)
        CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')

        TEST_URL="${BASE_URL}${payload}"
        curl -sL "$TEST_URL" -o test.txt

        if [[ ! -f "test.txt" ]]; then
            echo "| $(printf '%-40s' "$payload") | Error |        - | $CURRENT_TIME | curl 실패 (test.txt 없음)            |" | tee -a "$OUTPUT_FILE"
            continue
        fi

        TEST_LEN=$(wc -c < test.txt)

        if ! [[ "$TEST_LEN" =~ ^[0-9]+$ ]]; then
            echo "| $(printf '%-40s' "$payload") | Error |        - | $CURRENT_TIME | 응답 길이 비정상                    |" | tee -a "$OUTPUT_FILE"
            continue
        fi

        END_TIME=$(date +%s)
        ELAPSED=$((END_TIME - START_TIME))

        if [[ "$TEST_LEN" -ne "$NORMAL_LEN" ]]; then
            SUMMARY=$(head -n 20 test.txt | sed 's/[^[:print:]]//g' | tr '\n' ' ' | cut -c 1-35)
            printf "| %-40s | %-6s | %-8d | %-20s | %-35s |\n" "$payload" "⭕" "$ELAPSED" "$CURRENT_TIME" "$SUMMARY" | tee -a "$OUTPUT_FILE"
            DETECTED_PAYLOADS+=("$payload")
        fi
    done < "$PAYLOAD_FILE"
done

echo "--------------------------------------------------------------------------------------" | tee -a "$OUTPUT_FILE"

if [[ ${#DETECTED_PAYLOADS[@]} -gt 0 ]]; then
    echo "[*] 변화 감지된 페이로드 목록:" | tee -a "$OUTPUT_FILE"
    for p in "${DETECTED_PAYLOADS[@]}"; do
        echo " - $p" | tee -a "$OUTPUT_FILE"
    done
else
    echo "[*] 변화 감지된 페이로드 없음" | tee -a "$OUTPUT_FILE"
fi

echo "[*] 검사 완료" | tee -a "$OUTPUT_FILE"
