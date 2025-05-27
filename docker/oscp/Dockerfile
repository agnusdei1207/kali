FROM kalilinux/kali-rolling

# 키링 복사 및 소스 설정
COPY kali-archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

# 업데이트 및 OSCP 핵심 도구 설치
RUN apt update && apt list --upgradable && apt install -y \
    kali-linux-headless \
    nmap netcat-traditional tmux vim \
    python3 python3-pip python3-venv \
    gcc make build-essential \
    curl wget ftp tftp-hpa smbclient \
    git unzip p7zip-full jq sqlite3 \
    gdb gdbserver \
    responder \
    seclists wordlists \
    hashcat john \
    enum4linux-ng \
    ldap-utils \
    golang \
    && apt clean

# 워드리스트 링크 설정
RUN ln -s /usr/share/wordlists/rockyou.txt.gz /rockyou.txt.gz && \
    gzip -d /rockyou.txt.gz

# 포트 오픈
EXPOSE 1194/udp

# 무한 대기
CMD ["sleep", "infinity"]
