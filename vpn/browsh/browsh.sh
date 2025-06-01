#!/bin/bash
# Browsh 설치 및 기본 사용법 스크립트 (OSCP 시험 참고용)

# 1. Browsh 다운로드 (공식 설치법 그대로)
echo "[*] Browsh 다운로드 시작..."
wget https://github.com/browsh-org/browsh/releases/download/v1.8.0/browsh_1.8.0_linux_amd64.deb

# 2. Browsh 설치 (공식 설치법 그대로)
echo "[*] Browsh 설치 중..."
sudo apt install ./browsh_1.8.0_linux_amd64.deb

# 3. 설치 파일 삭제
echo "[*] 설치 파일 삭제 중..."
rm ./browsh_1.8.0_linux_amd64.deb

# 4. 설치 완료 메시지
echo "[*] Browsh 설치 완료!"
echo "실행 방법: 터미널에서 'browsh' 입력 후 엔터"

F1: 도움말 문서 열기
화살표 키, Page Up, Page Down: 스크롤
Ctrl+q: Browsh 종료
Ctrl+l: URL 표시줄에 포커스
Backspace: 이전 페이지로 이동
Ctrl+r: 페이지 새로 고침
Ctrl+t: 새 탭 열기
Ctrl+w: 현재 탭 닫기
Ctrl+\: 다음 탭으로 전환
Alt+Shift+p: 스크린샷 찍기 (상태 표시줄에 저장 경로 표시)
Alt+m: 흑백 모드 전환 (오래된 터미널에서 렌더링 문제 해결에 유용)
Alt+u: 사용자 에이전트 전환 (데스크톱/모바일)
