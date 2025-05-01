FROM kalilinux/kali-rolling

# OpenVPN 설정 파일 복사
COPY docker/offensive-security/vpn.ovpn /

# 포트 6666을 외부에 노출
EXPOSE 6666

# CMD ["sleep", "infinity"]
CMD ["sudo", "openvpn", "/vpn.ovpn"]