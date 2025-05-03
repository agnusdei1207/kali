FROM kalilinux/kali-rolling

COPY 627776410739671080.ovpn /

RUN apt update && \
	apt install -y kali-linux-headless

EXPOSE 1194/udp
	
CMD ["sleep", "infinity"]