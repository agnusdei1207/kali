FROM kalilinux/kali-rolling

RUN apt-get update && \
    apt-get install -y \
    openvpn \
    iputils-ping \
    netcat-openbsd \
    nmap \
    openssh-client \
    procps \
    psmisc

EXPOSE 1194/udp
	
CMD ["sleep", "infinity"]