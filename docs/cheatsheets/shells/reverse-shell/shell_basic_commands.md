# shell basic commands

> 무엇: 셸을 받자마자 돌리는 기본 확인 명령 모음(whoami·네트워크·프로세스·flag 검색, Linux/PowerShell/cmd별)
> 언제: 셸 확보 직후 초기 열거 단계에서 현재 사용자·호스트·내부망과 플래그 위치를 파악할 때, Windows면 whoami /priv로 권한 상승 분기점을 바로 확인한다
> 조건: 확보한 셸 OS에 맞는 명령 세트 선택, Linux에서 su·sudo는 TTY가 없으면 멈추므로 먼저 pty 안정화가 선행돼야 한다

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
