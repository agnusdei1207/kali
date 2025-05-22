FROM kalilinux/kali-rolling

COPY kali-archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

COPY docker/oscp/install.sh /usr/local/bin/install.sh
RUN chmod +x /usr/local/bin/install.sh && /usr/local/bin/install.sh
RUN rm -rf /usr/local/bin/install.sh

COPY vpn.ovpn /etc/openvpn/vpn.ovpn

EXPOSE 1194/udp

CMD ["sleep", "infinity"]