FROM kalilinux/kali-rolling:latest

RUN apt update && apt -y install kali-linux-headless
RUN apt-get update && \
	apt-get install -y \
	openvpn \
	iputils-ping \
	netcat-openbsd \
	nmap \
	openssh-client \
	procps \
	psmisc \
	vim \
	net-tools \
	tmux \
	wireshark-common \
	tcpdump \
	aircrack-ng \
	hashcat \
	john \
	hydra \
	sqlmap \
	nikto \
	gobuster \
	tor \
	proxychains4

EXPOSE 1194/udp

CMD ["sleep", "infinity"]