```bash
# apt
sudo apt update
sudo apt install gobuster -y
# git
sudo apt install golang -y
go install github.com/OJ/gobuster/v3@latest

# 기본: 대상 IP(Internet Protocol, 인터넷 프로토콜)에 대해 vhost 후보를 워드리스트로 빠르게 수집
gobuster vhost -u https://TARGET_IP -w /usr/share/wordlists/vhosts.txt --append-domain

# 스레드(동시요청) 늘려서 속도 향상 — 대상에 부하 주지 않도록 주의
gobuster vhost -u https://TARGET_IP -w vhosts.txt --append-domain -t 50

# HTTPS(하이퍼텍스트 전송 프로토콜 보안) 대상에서 인증서 검증 무시(테스트/자체서명용)
gobuster vhost -u https://TARGET_IP -w vhosts.txt --append-domain -k

# 특정 상태 코드(HTTP 상태 코드)만 표시 — 정상/리다이렉트 응답(200,301,302)만 관심있을 때
gobuster vhost -u http://TARGET_IP -w vhosts.txt --append-domain -s 200,301,302 -t 30

# 리디렉션(follow redirect) 따라가며 탐색 — 리다이렉트로 숨겨진 vhost 찾을 때 유용
gobuster vhost -u https://TARGET_IP -w vhosts.txt --append-domain --follow-redirect -t 40

# 트래픽을 로컬 프록시(예: Burp)로 전달 — 수동 검증/패킷 캡처용
gobuster vhost -u http://TARGET_IP -w vhosts.txt --append-domain --proxy http://127.0.0.1:8080

# 부하 낮추기: 요청 간 딜레이 및 타임아웃 설정(프로덕션 환경에서 권장)
gobuster vhost -u https://TARGET_IP -w vhosts.txt --append-domain --delay 200 --timeout 10s -t 20
```
