FROM kalilinux/kali-rolling

RUN apt-get clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        openvpn \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY docker/offensive-security/vpn.ovpn /

EXPOSE 6666

CMD ["sleep", "infinity"]
