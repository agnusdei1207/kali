FROM kalilinux/kali-rolling

RUN apt-get update && \
    apt-get install -y --fix-missing \
    kali-linux-headless \
    openvpn \
    iputils-ping \
    procps \
    psmisc \
    vim \
    net-tools \
    tmux \
    wireshark-common \
    exploitdb \
    gobuster \
    seclists \
    ffuf \
    amass \
    enum4linux \
    smbclient \
    responder \
    metasploit-framework \
    curl \
    wget \
    unzip \
    git \
    dnsutils \
    whois \
    python3-pip && \
    pip3 install \
    crackmapexec \
    impacket \
    mitm6

EXPOSE 1194/udp

CMD ["sleep", "infinity"]
