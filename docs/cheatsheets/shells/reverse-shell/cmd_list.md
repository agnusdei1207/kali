# cmd_list (자주 쓰는 명령)

## 개요

이 문서는 reverse shell 안에서 실제로 자주 쓰는 PowerShell/cmd 명령의 목록이다.
`reverse_shell.md`의 LHOST/LPORT에 값을 넣어 listener에 접속한 뒤, 여기서 그대로 실행한다.

## Windows PowerShell

```powershell
whoami
hostname
ipconfig
netstat -ano
Get-Process
Get-Service | Where-Object {$_.Status -eq 'Running'}

# 파일 탐색
Get-ChildItem -Recurse -Force C:\\Users | Select-Object FullName
Select-String -Path C:\\ -Recurse -Pattern \"flag\" -SimpleMatch

# 권한 확인
whoami /priv
```

## cmd.exe

```batch
whoami
systeminfo
netstat -ano
tasklist

dir /s C:\\Users
dir /s C:\\Users | findstr flag

typeflag.txt
```

## Linux (bash/sh)

```bash
whoami
hostname -I
ip a
ss -tulpn
ps aux
find / -name \"*.txt\" 2>/dev/null
find / -name \"flag\" -type f 2>/dev/null
```

## 힌트 출력 형식

- PowerShell 결과는 파이프로 감싸면 한 줄로 볼 수 있다:
  ```powershell
  (Get-Process).Id | Out-String
  ```
- 증적을 남길 때는 원본 명령을 그대로 기록한다. 결과의 줄번호와 함께.
- `certutil -dump`처럼 시스템 정보가 필요한 명령도 활용한다(Windows).

## 주의

- 증적에는 "어떻게 공격했는지"가 더 중요하다. 명령어 나열이 아니라, 각 단계의 판단 근거를 적는다.
