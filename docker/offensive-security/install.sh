#!/bin/bash

# 설치할 패키지 목록
packages=(
    openvpn             # VPN 클라이언트
    iputils-ping        # ping 명령어
    netcat-openbsd      # netcat 유틸리티
    nmap                # 포트 스캐너
    openssh-client      # SSH 클라이언트
    procps              # 시스템 프로세스 확인
    psmisc              # kill, fuser 등 유틸
    vim                 # 텍스트 편집기
    net-tools           # ifconfig 등 네트워크 도구
    tmux                # 터미널 멀티플렉서
)

# 성공한 패키지와 실패한 패키지를 저장할 배열
success_list=()
failure_list=()

echo "🧹 캐시 정리 중..."
if apt-get clean; then
    echo "✅ apt-get clean 완료"
else
    echo "❌ apt-get clean 실패"
fi

echo "🔄 패키지 목록 업데이트 중..."
if apt-get update; then
    echo "✅ apt-get update 완료"
else
    echo "❌ apt-get update 실패"
fi

# 각 패키지 설치 시도
for pkg in "${packages[@]}"; do
    echo "📦 ${pkg} 설치 중..."
    if apt-get install -y --fix-missing "$pkg"; then
        echo "✅ ${pkg} 설치 완료"
        success_list+=("$pkg")
    else
        echo "❌ ${pkg} 설치 실패"
        failure_list+=("$pkg")
    fi
done

# 최종 결과 출력
echo ""
echo "🔹 성공한 패키지 목록:"
if [ ${#success_list[@]} -gt 0 ]; then
    for item in "${success_list[@]}"; do
        echo "✅ $item"
    done
else
    echo "없음"
fi

echo ""
echo "🔸 실패한 패키지 목록:"
if [ ${#failure_list[@]} -gt 0 ]; then
    for item in "${failure_list[@]}"; do
        echo "❌ $item"
    done
else
    echo "없음"
fi
