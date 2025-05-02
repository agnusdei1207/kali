FROM kalilinux/kali-rolling

COPY docker/offensive-security/vpn.ovpn /

RUN apt update && \
	apt install -y kali-linux-headless
	
EXPOSE 6666

CMD ["sleep", "infinity"]