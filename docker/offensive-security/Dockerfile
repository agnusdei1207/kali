FROM kalilinux/kali-rolling

COPY archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list
RUN sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

RUN apt-get update --fix-missing
RUN apt install -y --fix-broken
RUN apt-get install -y --fix-missing vim
RUN apt-get install -y --fix-missing tmux
RUN apt install -y --fix-missing iputils-ping
RUN apt install -y --fix-missing net-tools


# not working list
# RUN apt-get install -y --fix-missing curl
# RUN apt-get install -y --fix-missing wget
# RUN apt-get install -y --fix-missing git
# RUN apt-get install -y --fix-missing python3
# RUN apt-get install -y --fix-missing python3-pip
# RUN apt-get install -y --fix-missing openvpn


EXPOSE 1194/udp

CMD ["sleep", "infinity"]
