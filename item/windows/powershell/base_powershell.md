Get-Process
Get-Service
Get-ChildItem # ls와 유사

cd
ls 또는 dir
cat
cp
mv
rm

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

Test-Connection google.com # ping
Get-NetIPAddress
Get-NetTCPConnection

# 스크립트 실행

Set-ExecutionPolicy RemoteSigned # 스크립트 실행 허용
.\script.ps1 # 스크립트 실행

# 도움말

Get-Help 명령어
예: Get-Help Get-Process

명령어는 윈도우 환경에 따라 다를 수 있으니, 필요에 따라 Get-Help로 확인.
Get-Content
Set-Location
