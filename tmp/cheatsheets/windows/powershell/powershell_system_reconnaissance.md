# PowerShell 시스템 정보 수집

OS, 환경변수, 프로세스, 로그인 세션, 패치, 토큰 확인.

> 관련 문서: [PowerShell 치트시트](./README.md) · [네트워크 열거](./powershell_network_enumeration.md) · [사용자 관리](./powershell_user_management.md)

## OS / 호스트 정보

```powershell
systeminfo
Get-ComputerInfo

Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain

systeminfo | findstr /i "OS Name"
systeminfo | findstr /i /c:"Domain" /c:"Hotfix"

# OS 버전/이름
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

# 컴퓨터 이름
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"

# 설치된 패치
Get-HotFix
```

## 환경변수

```powershell
$env:USERNAME
[System.Environment]::UserName
$pshome
```

## 프로세스

```powershell
# 실행 프로세스 + 세션 사용자
tasklist /v

# 특정 프로세스만
tasklist /fi "imagename eq lsass.exe"

# 프로세스 + 경로 정렬
Get-Process | Select-Object Name, Id, Path | Sort-Object Name

# system32 프로세스만
Get-Process | Where-Object Path -like "*system32*"

# SYSTEM 권한 프로세스
tasklist /v | findstr /i "system"
Get-Process lsass, winlogon -IncludeUserName
```

## 로그인 세션

```powershell
qwinsta     # RDP 세션 확인
quser       # 연결된 사용자
net accounts    # 패스워드 정책 / 로그온 제한
```

## 토큰 / 특권

```powershell
whoami /priv
whoami /groups
whoami /all     # 현재 토큰/그룹/특권 전체
```
