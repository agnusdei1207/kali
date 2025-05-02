FROM kalilinux/kali-last-snapshot

COPY docker/offensive-security/vpn.ovpn /

RUN apt update && \
    apt install -y kali-linux-headless openvpn iproute2 iputils-ping net-tools
	
CMD ["sleep", "infinity"]