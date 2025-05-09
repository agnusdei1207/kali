FROM kalilinux/kali-rolling

# 최신 서명키를 복사 (사전에 도커 컨텍스트에 이 파일이 있어야 함)
COPY archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

# APT 소스 설정
RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
    apt-get update

# 기본 유틸리티 설치
RUN apt-get install -y --no-install-recommends --fix-missing \
    curl wget unzip git vim tmux net-tools procps psmisc \
    iputils-ping dnsutils whois && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# 보안 툴 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openvpn wireshark-common exploitdb gobuster seclists \
    ffuf amass enum4linux smbclient responder metasploit-framework && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Python 기반 도구 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-pip && \
    pip3 install --no-cache-dir \
        crackmapexec impacket mitm6 && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 1194/udp
CMD ["sleep", "infinity"]
