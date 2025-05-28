FROM kalilinux/kali-rolling

# 키링 복사 및 저장소 설정
COPY kali-archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

# 기본 시스템 패키지 설치
RUN apt update && \
    apt install -y --no-install-recommends \
    openvpn \
    net-tools iproute2 iputils-ping dnsutils \
    nmap netcat-traditional tmux vim \
    python3 python3-pip python3-venv \
    && apt clean

# 개발 도구 설치
RUN apt update && \
    apt install -y --no-install-recommends \
    gcc make build-essential \
    curl wget ftp tftp-hpa smbclient \
    git unzip p7zip-full jq sqlite3 \
    golang \
    && apt clean

# 보안 도구 설치
RUN apt update && \
    apt install -y --no-install-recommends \
    gdb gdbserver strace ltrace \
    responder \
    seclists wordlists \
    hashcat john \
    enum4linux-ng \
    ldap-utils \
    tcpdump \
    && apt clean && rm -rf /var/lib/apt/lists/*

# 워드리스트 설정 (복사 후 압축 해제)
RUN cp /usr/share/wordlists/rockyou.txt.gz /rockyou.txt.gz && \
    gzip -d /rockyou.txt.gz

# 자주 사용하는 포트 노출
EXPOSE 21 22 80 443 445 139 8080 1194/udp 1337/udp

# 기본 대기 (실습 환경 유지용)
CMD ["sleep", "infinity"]
