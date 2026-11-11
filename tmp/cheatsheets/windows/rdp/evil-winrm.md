- WinRM(5985/tcp)으로 Windows에 접속해 셸을 여는 evil-winrm의 설치와 접속 명령
- 유효한 계정 크리덴셜을 확보하고 5985 포트가 열려 있을 때 RDP보다 가볍게 셸을 따거나 패스워드 유효성을 검증할 때
- 타깃 5985/tcp(WinRM) 접근 가능, Kali에 evil-winrm 설치, 유효한 사용자 이름·패스워드 필요

```bash
# 5985 port
apt update
apt install evil-winrm -y

evil-winrm -i <타겟_IP> -u <사용자이름> -p <비밀번호>

evil-winrm -i 192.168.243.180 -u mike -p Mike14
```
