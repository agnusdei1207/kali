#!/bin/bash
# generate_port.sh — 스캔용 포트 목록 txt 생성
# 사용법:
#   ./generate_port.sh            → 빈도 top 1000
#   ./generate_port.sh 100        → 빈도 top 100
#   ./generate_port.sh 1-65535    → 범위 전체

out=/tmp/ports_to_check.txt
arg="${1:-1000}"
# =~ -> 정규표현식 매칭 연산자
if [[ "$arg" =~ ^[0-9]+$ ]]; then
    awk -F'\t' '$2 ~ /\/tcp$/ && $3 != "" {p=$2; sub(/\/tcp$/,"",p); print $3, p}' /usr/share/nmap/services \
        | sort -rn | head -n "$arg" > "$out.tmp"
    awk '{print $2}' "$out.tmp" > "$out"; rm -f "$out.tmp"
elif [[ "$arg" =~ ^[0-9]+-[0-9]+$ ]]; then
    seq "${arg%-*}" "${arg#*-}" > "$out"
else
    echo "사용법: $0 [top N | 시작-끝]   예) $0 100 | $0 1000 | $0 1-65535" >&2
    exit 1
fi

[[ -s "$out" ]] || { echo "[!] 빈 결과 — $out" >&2; exit 1; }
cat "$out"
echo "[*] $(wc -l < "$out") ports -> $out" >&2
