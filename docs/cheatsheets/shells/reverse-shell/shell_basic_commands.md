# shell basic commands

셸을 받자마자 돌리는 기본 확인 명령. OS별.

## Linux

```bash
whoami
hostname -I
ip a
ss -tulpn
ps aux
find / -name "*flag*" -type f 2>/dev/null
```

- `su`, `sudo`는 TTY가 없으면 멈춘다 → [../shell-upgrade/python_pty.md](../shell-upgrade/python_pty.md)

## Windows PowerShell

```powershell
whoami
hostname
ipconfig
netstat -ano
whoami /priv        # 프리비슩 분기점
Get-ChildItem -Path C:\Users -Recurse -Filter *flag* -ErrorAction SilentlyContinue
```

- 출력이 한 줄로 뭉개지면 파이프 끝에 `| Out-String`을 붙인다.

## Windows cmd.exe

```batch
whoami
systeminfo
netstat -ano
tasklist
dir /s C:\Users | findstr flag
```

## 다음 단계

- 프리비슩 → [../../linux/privesc/privilege_escalation_overview.md](../../linux/privesc/privilege_escalation_overview.md) · [../../windows/privileges/overview.md](../../windows/privileges/overview.md)
