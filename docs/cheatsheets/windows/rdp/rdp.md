- 3389/tcp RDP에 freerdp(xfreerdp)로 GUI 원격 데스크톱 세션을 여는 설치·접속 명령과 nc -vz 포트 생존 확인
- 계정 크리덴셜을 확보하고 RDP가 활성화돼 있을 때 창 있는 GUI 세션이 필요한 작업(예: runas로 새 창 띄우기)에 쓴다
- 타깃 3389/tcp 접근 가능(nc -vz로 확인), Kali에 freerdp3-x11 설치와 $DISPLAY가 있는 X11 환경, 유효한 크리덴셜 필요, RDP 비활성화·방화벽 차단이면 접속 불가

```bash
# 3389 port
apt search freerdp
apt install freerdp3-x11 -y

echo $DISPLAY
```

```bash
xfreerdp /v:192.168.123.180 /u:mike /p:wazowski
```

```bash
# RDP health check
nc -vz -w 3 192.168.123.180 3389

# 이건 역방향 DNS (Domain Name System) 조회 실패일 뿐이야. RDP 연결 실패를 의미하지 않아.
inverse host lookup failed: Unknown host
```
