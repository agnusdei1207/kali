FROM kalilinux/kali-rolling

COPY kali-archive-keyring.gpg /usr/share/keyrings/kali-archive-keyring.gpg
COPY docker/offensive-security/install.sh /usr/local/bin/install.sh

# Configure repository
RUN echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    sha1sum /usr/share/keyrings/kali-archive-keyring.gpg

# Make the install script executable and run it
RUN chmod +x /usr/local/bin/install.sh && /usr/local/bin/install.sh
RUN rm -rf /usr/local/bin/install.sh

EXPOSE 1194/udp

CMD ["sleep", "infinity"]