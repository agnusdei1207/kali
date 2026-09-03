```powershell
Get-Process
Get-Service

# common

Get-ChildItem
ls
dir

Get-ChildItem -Path C:\Users


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


# script

Set-ExecutionPolicy RemoteSigned # 스크립트 실행 허용
.\script.ps1 # 스크립트 실행

# pipe

Get-ChildItem | Sort-Object Length
Get-ChildItem | Where-Object -Property "Extension" -eq ".txt"

# search

Select-String -Path ".\package-lock.json" -Pattern "hat"
Get-ChildItem | Where-Object -Property Length -gt 100

# help

Get-Help 명령어
Get-Help New-LocalUser -examples

명령어는 윈도우 환경에 따라 다를 수 있으니, 필요에 따라 Get-Help로 확인.
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

```
