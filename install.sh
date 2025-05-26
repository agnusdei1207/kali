#!/bin/bash

# ============================================
# OSCP 시험 준비용 도구 자동 설치 스크립트
# Tested on Kali Linux
# ============================================

echo "[*] 시스템 업데이트"
sudo apt update && sudo apt upgrade -y

# --------------------------------------------
# 1. 스캔 및 정보 수집 (Enumeration)
# --------------------------------------------
# 주요 목적: 포트 스캔, 서비스 탐지, SMB/DNS/LDAP 정보 수집

echo "[*] 스캔 및 정보 수집 도구 설치"
sudo apt install -y \
    nmap \                   # 포트/서비스 탐지 + NSE
    rustscan \               # 빠른 포트 스캐너
    netcat \                 # 포트 확인, 리버스 셸
    telnet \                 # 포트 접속 확인
    curl \                   # HTTP 요청 테스트
    dnsutils \               # dig, nslookup 포함
    dnsrecon \               # DNS zone 전이 등 분석
    whatweb \                # 웹 프레임워크 탐지
    gobuster \               # 웹 디렉토리 브루트포스
    ffuf \                   # 빠르고 유연한 Fuzzing
    nikto \                  # 웹 취약점 스캐너
    enum4linux-ng \          # SMB enumeration
    smbclient \              # SMB 공유 접근
    smbmap \                 # SMB 공유 권한 확인
    ldap-utils \             # LDAP 쿼리 도구
    crackmapexec \           # SMB/AD 인증 및 정보 수집
    samba-common-bin         # rpcclient 포함

# --------------------------------------------
# 2. 웹 취약점 분석 (Web Attacks)
# --------------------------------------------
# 주요 목적: 웹 디렉토리, 파라미터, API, 취약점 분석

echo "[*] 웹 취약점 분석 도구 설치"
sudo apt install -y \
    burpsuite \              # 웹 요청 분석 GUI
    wfuzz                    # 헤더/파라미터 Fuzzing

# dirsearch 수동 설치
echo "[*] dirsearch 다운로드"
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/maurosoria/dirsearch.git

# --------------------------------------------
# 3. 크리덴셜 공격 / 인증 우회
# --------------------------------------------
# 주요 목적: 해시 크랙, 로그인 브루트포스, 워드리스트 생성

echo "[*] 크리덴셜 공격 도구 설치"
sudo apt install -y \
    hydra \                 # 로그인 브루트포싱
    john \                  # 해시 크랙
    hashcat \               # GPU 기반 크랙
    cewl \                  # 웹 기반 워드리스트 생성
    crunch                  # 맞춤 워드리스트 생성기

# kerbrute 설치 (Go 필요)
echo "[*] kerbrute 설치"
cd ~/tools
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute && go build

# --------------------------------------------
# 4. 취약점 탐지 및 익스플로잇
# --------------------------------------------
# 주요 목적: Exploit 검색 및 컴파일

echo "[*] Exploit 및 컴파일 도구 설치"
sudo apt install -y \
    exploitdb \             # searchsploit 포함
    gcc \                   # C 컴파일러
    build-essential \       # make 등 포함
    python3 \               # 스크립트 실행
    perl                    # Perl 익스플로잇 실행용

# --------------------------------------------
# 5. 권한 상승 (Privilege Escalation)
# --------------------------------------------
# 주요 목적: 시스템 정보 수집, 자동 권한 상승 분석

echo "[*] linPEAS / winPEAS 다운로드"
mkdir -p ~/tools/peas
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O ~/tools/peas/linpeas.sh
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -O ~/tools/peas/winPEASx64.exe
chmod +x ~/tools/peas/linpeas.sh

echo "[*] 프로세스 감시 도구 설치"
sudo apt install -y lsof strace
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O ~/tools/pspy64
chmod +x ~/tools/pspy64

# --------------------------------------------
# 6. 리버스 셸 / 터널링 / 파일 전송
# --------------------------------------------
# 주요 목적: 셸 획득 및 전송, 포트 포워딩

echo "[*] 리버스 셸 및 파일 전송 도구 설치"
sudo apt install -y \
    socat \                 # TTY 지원 리버스 셸
    openssh-client \        # SCP 전송
    wget \                  # 파일 다운로드
    curl                    # 파일 다운로드

# --------------------------------------------
# 7. Windows / AD 특화 도구
# --------------------------------------------
# 주요 목적: AD 구조 분석, SMB 명령 실행, 해시 덤프

echo "[*] Impacket 설치"
cd ~/tools
git clone https://github.com/fortra/impacket.git
cd impacket && pip3 install .

echo "[*] BloodHound / Neo4j 설치"
sudo apt install -y bloodhound neo4j

echo "[*] 완료: 모든 OSCP 필수 도구 설치 완료!"