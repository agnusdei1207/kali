---
title: "Windows Privilege Escalation"
date: 2026-06-20
weight: 80
draft: false
summary: "From low-privilege user to Administrator/SYSTEM: services, privileges, credentials, and kernel vulnerabilities."
---

Reference for going from low-privilege user to admin/SYSTEM on the current machine.

- Source: https://heretek.dev/oscp-cheatsheet/windows-privilege-escalation/ (Jean Romero) — Reconstructed
- Variables: $TARGET = target host, $KALI = attacker Kali IP

Scope: from low-privilege user to admin/SYSTEM on the current machine.

- Note: CMD vs PowerShell — evil-winrm uses PowerShell; psexec/wmiexec/nc.exe use CMD. Most commands below are CMD syntax. If PowerShell looks broken: cmd.exe to drop to CMD, or change && to ;, 2>nul to 2>$null, %VAR% to $env:VAR.

## Quick Reference — Windows Privilege Commands (Linux → Windows)

When you know Linux commands but not Windows equivalents:

- File owner? — CMD icacls file / PS Get-Acl file (Linux: ls -la file)
- Directory owner? — CMD icacls C:\dir / PS Get-Acl C:\dir (Linux: ls -la /dir)
- Writable here? — CMD echo test > C:\dir\test.txt / PS Set-Content C:\dir\test.txt "test" (Linux: echo test >> file)
- Show hidden files — CMD dir /a / PS Get-ChildItem -Force (Linux: ls -la)
- Find writable files — CMD icacls C:\path\* / PS Get-ChildItem -Recurse then check ACL (Linux: find / -writable)
- Who runs this process? — CMD tasklist /v / PS Get-WmiObject Win32_Process (Linux: ps aux)
- Running as SYSTEM? — CMD tasklist /v | findstr SYSTEM / PS same (Linux: ps aux | grep root)
- Check scheduled tasks — CMD schtasks /query /fo LIST /v / PS same (Linux: cat /etc/crontab)

### icacls Permission Codes (memorize)

- (F) — Full Control — exploitable. Read, write, delete, change permissions
- (M) — Modify — exploitable. Read, write, delete
- (W) — Write — exploitable. Overwrite files
- (R) — Read — not exploitable. Read only
- (RX) — Read + Execute — not exploitable. Read and execute only

If a service running as SYSTEM shows BUILTIN\Users:(F) or (M), replace it with your payload.

## PART 1 — Enumeration (run all of these first)

- Methodology: run all enumeration steps before attempting attacks. After collecting results, decide which attack path to take. Jumping to attacks too early narrows your view and causes you to miss privesc.

### Enum 1 — Who am I (always first)

```powershell
whoami /all
```

This single command gives username, groups, token privileges. Read everything.

- Integrity level -> Medium + local admin = UAC bypass candidate

### Enum 2 — System information

```powershell
hostname
systeminfo
ipconfig /all
```

Record OS version, architecture (x64/x86), domain membership, installed hotfixes.

### AppLocker

AppLocker bypass methods are plentiful. With default rules, placing an executable in the directory below bypasses it — default whitelist:

```text
C:\Windows\System32\spool\drivers\color
```

### Enum 3 — Running services, processes, ports

```powershell
tasklist /svc

# What services are running and from where?
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# Running processes with paths
Get-Process | Select ProcessName,Path | Sort-Object Path -Unique

# All listening ports
netstat -ano | findstr LISTENING

# Map ALL listening ports to process names (no admin needed)
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).Name}} | Sort-Object LocalPort
# If Get-NetTCPConnection unavailable — look up individual PIDs:
tasklist /FI "PID eq <PID>"
Get-Process -Id <PID> | Select-Object Name,Path
```

Check for:

- Services running from writable paths or non-default directories
- localhost-only services (127.0.0.1) — not visible externally, often run as SYSTEM
- 0.0.0.0 = listening on all interfaces (including localhost). 127.0.0.1 = localhost only
- Non-standard ports — custom applications worth investigating
- MySQL (3306), web server (80/443/8080), DB — check credentials

### Enum 4 — Non-default directories and installed software

```powershell
dir C:\\
```

Anything not Windows, Program Files, Users, PerfLogs is intentionally placed. Check it.

If you find an .exe in a non-default directory, run the full check routine:

```powershell
# Step 1 — Can you write to it?
icacls "C:\path\to\binary.exe"
# Look for (F)=Full, (M)=Modify, (W)=Write for your user, Everyone, Users, or Authenticated Users
# If NOT writable -> skip, can't exploit

# Step 2 — What runs it? (this is the step people miss)
# Is it a service?
Get-CimInstance -ClassName win32_service | Where-Object {$_.PathName -like '*binary*'} | Select Name,PathName,StartName,State
# Or search by directory:
Get-CimInstance -ClassName win32_service | Where-Object {$_.PathName -like '*DevelopmentExecutables*'} | Select Name,PathName,StartName,State

# Is it a scheduled task?
schtasks /query /fo LIST /v | findstr /i "binary|path|Run As|Task To Run"

# Is it an AutoRun entry?
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run | findstr /i "binary"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run | findstr /i "binary"

# Is a running process using it right now?
Get-Process | Where-Object {$_.Path -like '*binary*'} | Select Name,Id,Path

# Step 3 — WHO does it run as?
# For services:
sc.exe qc SERVICENAME
# Use the SERVICE NAME not the FILENAME: sc.exe qc auditTracker NOT sc.exe qc auditTracker.exe
# Look for SERVICE_START_NAME: LocalSystem = SYSTEM = exploit it

# For scheduled tasks:
schtasks /query /tn "TASKNAME" /fo LIST /v | findstr /i "Run As"
# Run As User: SYSTEM = exploit it

# Step 4 — If it runs as SYSTEM and you can write to it -> replace the binary
```