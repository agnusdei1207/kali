#!/bin/bash

# 사용법 체크
if [ -z "$1" ]; then
    echo "[사용법] $0 <대상 IP>"
    exit 1
fi

TARGET="$1"
OUTPUT="scan_result_$(date +%Y%m%d_%H%M%S).txt"

echo "[*] 대상: $TARGET"
echo "[*] 은밀한 포트 스캔 시작 중..."

nmap -sS -T2 --scan-delay 1s -f --source-port 53 -Pn -vv -oN "$OUTPUT" "$TARGET"

echo "[*] 스캔 완료. 결과는 파일에 저장됨: $OUTPUT"
