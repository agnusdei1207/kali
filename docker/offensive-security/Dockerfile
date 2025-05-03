FROM kalilinux/kali-rolling


RUN apt-get update && \
	apt-get install -y openvpn iputils-ping netcat-openbsd

EXPOSE 1194/udp
	
CMD ["sleep", "infinity"]