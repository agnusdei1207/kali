FROM kalilinux/kali-rolling

COPY archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list
RUN sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

RUN apt-get update
RUN apt update
RUN apt list --upgradable

EXPOSE 1194/udp

CMD ["sleep", "infinity"]
