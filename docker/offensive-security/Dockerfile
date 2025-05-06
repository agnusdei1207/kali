FROM kalilinux/kali-rolling

COPY docker/offensive-security/install.sh /install.sh
COPY docker/offensive-security/port-scan.sh /port-scan.sh

RUN chmod +x /install.sh
RUN chmod +x /port-scan.sh

RUN ./install.sh

EXPOSE 1194/udp
	
CMD ["sleep", "infinity"]