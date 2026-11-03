```bash
# 5985 port
apt update
apt install evil-winrm -y

evil-winrm -i <타겟_IP> -u <사용자이름> -p <비밀번호>

evil-winrm -i 192.168.243.180 -u mike -p Mike14
```
