FROM kalilinux/kali-rolling

COPY kali-archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

RUN apt update && apt upgrade

EXPOSE 21 22 80 443 445 139 8080 1194/udp 1337/udp

CMD ["sleep", "infinity"]
