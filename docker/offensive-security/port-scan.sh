#!/bin/bash

# 스크립트 사용법
if [ $# -ne 2 ]; then
  echo "사용법: $0 <대상_IP> <결과_파일>"
  exit 1
fi

TARGET=$1            # 첫 번째 인수로 대상 IP를 받음
OUTPUT_FILE=$2       # 두 번째 인수로 결과 파일명을 받음

# 스캔할 포트 범위
PORT_RANGE="1-65535"

# Nmap 명령어 실행
echo "Nmap 스캔을 시작합니다: 대상 - $TARGET, 포트 범위 - $PORT_RANGE"
nmap -p $PORT_RANGE $TARGET -oN $OUTPUT_FILE

# 스캔 완료 후 결과 출력
echo "스캔이 완료되었습니다. 결과는 '$OUTPUT_FILE' 파일에 저장되었습니다."
