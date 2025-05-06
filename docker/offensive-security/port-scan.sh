#!/bin/bash

# 사용법 체크
if [ -z "$1" ]; then
    echo "[사용법] $0 <대상 IP 또는 도메인>"
    exit 1
fi

TARGET="$1"
OUTPUT="tor_scan_$(date +%Y%m%d_%H%M%S).txt"

echo "[*] 대상: $TARGET"
echo "[*] Tor 네트워크를 통한 TCP/UDP 스캔 시작..."

# TCP Connect (-sT), UDP (-sU) 병합 스캔 (proxychains로 Tor 경유)
proxychains nmap -sT -sU -T2 --scan-delay 1s -Pn -n -vv -oN "$OUTPUT" "$TARGET"

echo "[*] 스캔 완료. 결과는 파일에 저장됨: $OUTPUT"
