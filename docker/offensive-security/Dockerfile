FROM kalilinux/kali-rolling

# 최신 서명키 다운로드 및 설정
COPY archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

# 패키지 관리자에서 서명키 사용하도록 설정
RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list

RUN apt update
RUN apt -y install kali-linux-headless
# 필요한 도구들 설치
# RUN apt-get update && apt-get install -y --fix-missing \
#     openvpn \
#     iputils-ping \
#     procps \
#     psmisc \
#     vim \
#     net-tools \
#     tmux \
#     wireshark-common \
#     exploitdb \
#     gobuster \
#     seclists \
#     ffuf \
#     amass \
#     enum4linux \
#     smbclient \
#     responder \
#     metasploit-framework \
#     curl \
#     wget \
#     unzip \
#     git \
#     dnsutils \
#     whois \
#     python3-pip && \
#     # Python 툴들 설치
#     pip3 install \
#     crackmapexec \
#     impacket \
#     mitm6 && \
#     # 불필요한 파일 정리
#     rm -rf /var/lib/apt/lists/*

# OpenVPN 포트 노출
EXPOSE 1194/udp

# 컨테이너를 계속 실행 상태로 유지 (테스트 용도)
CMD ["sleep", "infinity"]
