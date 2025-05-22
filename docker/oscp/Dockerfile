FROM kalilinux/kali-rolling

# 복사한 키링 등록 및 소스리스트 설정
COPY kali-archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

RUN apt update && apt -y install kali-linux-headless

EXPOSE 1194/udp

CMD ["sleep", "infinity"]
