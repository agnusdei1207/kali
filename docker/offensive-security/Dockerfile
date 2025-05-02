FROM kalilinux/kali-rolling

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates
RUN apt-get install -y --no-install-recommends openvpn
RUN rm -rf /var/lib/apt/lists/*

COPY docker/offensive-security/vpn.ovpn /

EXPOSE 6666

CMD ["sleep", "infinity"]
