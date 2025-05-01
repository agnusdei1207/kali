FROM kalilinux/kali-rolling

# OpenVPN 설정 파일 복사
COPY ./627776410739671080.ovpn /etc/openvpn/

# OpenVPN 패키지 설치
RUN apt-get update && apt-get install -y openvpn

# 포트 6666을 외부에 노출
EXPOSE 6666

# OpenVPN을 실행하여 연결 유지
# CMD ["openvpn", "--config", "/etc/openvpn/627776410739671080.ovpn"]

CMD ["sleep", "infinity"]