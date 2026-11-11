#!/bin/bash
# 포트 목록 생성 스크립트
# 사용법: ./generate_ports.sh <시작> <끝> <출력파일>

start=${1:-1}
end=${2:-65535}
output=${3:-ports.txt}

seq $start $end > "$output"

echo "생성 완료: $output"
echo "포트 수: $((end - start + 1))"
