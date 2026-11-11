# PowerShell 네트워크 열거

IP 설정, 포트·연결 확인, SMB 공유, 원격 명령.

> 관련 문서: [PowerShell 치트시트](./README.md) · [시스템 정보 수집](./powershell_system_reconnaissance.md)

## IP / 연결

```powershell
Test-Connection google.com     # ping

Get-NetIPConfiguration
Get-NetIPAddress
Get-NetTCPConnection
```

## 포트 / 연결 상태

```powershell
# 특정 포트 열림 확인
Test-NetConnection -ComputerName 192.168.192.65 -Port 445

# 확립된 연결
Get-NetTCPConnection -State Established

# 리스닝 포트 + PID
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess
netstat -ano | findstr LISTENING

# PID로 프로세스 확인
Get-Process -Id (Get-NetTCPConnection -State Listen | Select-Object -First 1 -Expand OwningProcess)

# SMB 통신 대상
Get-NetTCPConnection | Where-Object RemotePort -eq 445
```

## SMB 공유

```powershell
Get-SmbShare

net use \\localhost\IPC$ "" /user:Administrator ""
```

## 원격 명령

```powershell
Invoke-Command -ComputerName SERVER01 -ScriptBlock { Get-Process }
Invoke-Command -ComputerName SERVER01, SERVER02 -ScriptBlock { hostname }
Invoke-Command -ComputerName SERVER01 -Credential DOMAIN\User -ScriptBlock { Get-Service }
```
