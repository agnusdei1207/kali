FROM kalilinux/kali-rolling

COPY archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list

# 기본 도구 설치 (1차)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget unzip git vim tmux net-tools

# 시스템 도구 설치 (2차)
RUN apt-get install -y --no-install-recommends \
    procps psmisc iputils-ping dnsutils whois

# 보안 도구 설치 (3차)
RUN apt-get install -y --no-install-recommends \
    openvpn wireshark-common exploitdb gobuster seclists

# 보안 도구 설치 (4차)
RUN apt-get install -y --no-install-recommends \
    ffuf amass enum4linux smbclient responder

# 큰 패키지 따로 설치 (5차)
RUN apt-get install -y --no-install-recommends \
    metasploit-framework

# Python 및 툴 설치
RUN apt-get install -y --no-install-recommends python3-pip && \
    pip3 install --no-cache-dir crackmapexec impacket mitm6

# 캐시 및 임시파일 정리
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 1194/udp
CMD ["sleep", "infinity"]
