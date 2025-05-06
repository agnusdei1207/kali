FROM kalilinux/kali-rolling:latest

RUN apt-get update --fix-missing
RUN apt-get install -y openvpn --fix-missing
RUN apt-get install -y iputils-ping --fix-missing
RUN apt-get install -y netcat-openbsd --fix-missing
RUN apt-get install -y nmap --fix-missing
RUN apt-get install -y openssh-client --fix-missing
RUN apt-get install -y procps --fix-missing
RUN apt-get install -y psmisc --fix-missing
RUN apt-get install -y vim --fix-missing
RUN apt-get install -y net-tools --fix-missing
RUN apt-get install -y tmux --fix-missing
RUN apt-get install -y wireshark-common --fix-missing
RUN apt-get install -y tcpdump --fix-missing
RUN apt-get install -y aircrack-ng --fix-missing
RUN apt-get install -y hashcat --fix-missing
RUN apt-get install -y john --fix-missing
RUN apt-get install -y hydra --fix-missing
RUN apt-get install -y sqlmap --fix-missing
RUN apt-get install -y nikto --fix-missing
RUN apt-get install -y gobuster --fix-missing
RUN apt-get install -y tor --fix-missing
RUN apt-get install -y proxychains4 --fix-missing


EXPOSE 1194/udp

CMD ["sleep", "infinity"]