FROM kalilinux/kali-rolling

# 최신 서명키를 도커 빌드 컨텍스트에서 복사하여 설정
COPY archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

# 패키지 관리자에서 서명키 사용하도록 설정
RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list

# 패키지 목록 업데이트
RUN apt-get update

# 기본 유틸리티 설치
RUN apt-get install -y --no-install-recommends --fix-missing \
    curl \
    wget \
    unzip \
    git \
    vim \
    tmux \
    net-tools \
    procps \
    psmisc \
    iputils-ping \
    dnsutils \
    whois

# 보안 툴 설치
RUN apt-get install -y --no-install-recommends \
    openvpn \
    wireshark-common \
    exploitdb \
    gobuster \
    seclists \
    ffuf \
    amass \
    enum4linux \
    smbclient \
    responder \
    metasploit-framework

# Python 툴 설치
RUN apt-get install -y --no-install-recommends python3-pip && \
    pip3 install --no-cache-dir \
    crackmapexec \
    impacket \
    mitm6

# 불필요한 APT 캐시 및 임시 파일 정리
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# OpenVPN 포트 노출
EXPOSE 1194/udp

# 컨테이너를 계속 실행 상태로 유지 (테스트 용도)
CMD ["sleep", "infinity"]
