FROM kalilinux/kali-rolling

COPY kali-archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

RUN apt update && apt install -y \
    kali-linux-headless \
    nmap netcat-traditional tmux vim \
    python3 python3-pip python3-venv \
    gcc make build-essential \
    curl wget ftp tftp smbclient \
    git unzip p7zip-full jq sqlite3 \
    gdb gdbserver \
    responder \
    seclists wordlists \
    hashcat john \
    enum4linux-ng \
    ldap-utils \
    golang \
    && apt clean

RUN ln -s /usr/share/wordlists/rockyou.txt.gz /rockyou.txt.gz && \
    gzip -d /rockyou.txt.gz

EXPOSE 1194/udp

CMD ["sleep", "infinity"]
