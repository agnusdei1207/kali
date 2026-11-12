#!/bin/bash
# 포트 스캔 스크립트
# 사용법: ./scan_ports.sh <대상> <포트목록>

target=${1}
ports=${2:-top_ports.txt}

if [ -z "$target" ]; then
    echo "사용법: $0 <대상> [포트목록]"
    exit 1
fi

nmap -sS -p- --min-rate 1000 -T4 --open -iL "$ports" -oN "scan_$target.txt" "$target"
