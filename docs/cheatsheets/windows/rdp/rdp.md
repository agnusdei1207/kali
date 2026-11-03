```bash
# 3389 port
apt search freerdp
apt install freerdp3-x11 -y

echo $DISPLAY
```

```bash
xfreerdp /v:192.168.243.180 /u:mike /p:wazowski
```

```bash
# RDP health check
nc -vz -w 3 192.168.243.180 3389

# 이건 역방향 DNS (Domain Name System) 조회 실패일 뿐이야. RDP 연결 실패를 의미하지 않아.
inverse host lookup failed: Unknown host
```
