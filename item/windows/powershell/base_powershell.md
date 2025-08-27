### 명령 실행

Get-Process
Get-Service
Get-ChildItem # ls와 유사

### 파일/디렉터리 작업

cd 경로
ls 또는 dir
cat 파일명
cp 원본 대상
mv 원본 대상
rm 파일명

### 시스템 정보 확인

systeminfo
Get-ComputerInfo
Get-LocalUser

### 프로세스/서비스 관리

Start-Process notepad.exe
Stop-Process -Name notepad
Get-Service
Restart-Service 서비스명

### 네트워크

Test-Connection google.com # ping
Get-NetIPAddress
Get-NetTCPConnection

### 권한 상승

관리자 권한으로 실행 필요 시, 파워쉘 아이콘 우클릭 → "관리자 권한으로 실행"

### 스크립트 실행

Set-ExecutionPolicy RemoteSigned # 스크립트 실행 허용
.\script.ps1 # 스크립트 실행

### 도움말

Get-Help 명령어
예: Get-Help Get-Process

명령어는 윈도우 환경에 따라 다를 수 있으니, 필요에 따라 Get-Help로 확인.
Get-Content
Set-Location
