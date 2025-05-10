FROM kalilinux/kali-rolling

# 최신 서명키 다운로드 및 설정
COPY archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

# 패키지 관리자에서 서명키 사용하도록 설정
RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list

RUN apt-get update --fix-missing
RUN apt install -y --fix-broken
RUN apt-get install -y --fix-missing vim
RUN apt-get install -y --fix-missing tmux
RUN apt install -y --fix-missing iputils-ping
RUN apt install -y --fix-missing net-tools
# RUN rm -rf /var/lib/apt/lists/*

EXPOSE 1194/udp

CMD ["sleep", "infinity"]
