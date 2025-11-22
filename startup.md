# 10.64.159.86

nmap -Pn -sS -sV -sC --open -O -oN nmap.txt 10.64.159.86 -T4

──(root㉿docker-desktop)-[/vpn]
└─# nmap -Pn -sS -sV -sC --open -O -oN nmap.txt 10.64.159.86 -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-22 04:15 UTC
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 95.83% done; ETC: 04:15 (0:00:00 remaining)
Nmap scan report for 10.64.159.86
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (reset)
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 3.0.3
| ftp-syst:
| STAT:
| FTP server status:
| Connected to 192.168.128.109
| Logged in as ftp
| TYPE: ASCII
| No session bandwidth limit
| Session timeout in seconds is 300
| Control connection is plain text
| Data connections will be plain text
| At session startup, client count was 2
| vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx 2 65534 65534 4096 Nov 12 2020 ftp [NSE: writeable]
| -rw-r--r-- 1 0 0 251631 Nov 12 2020 important.jpg
|_-rw-r--r-- 1 0 0 208 Nov 12 2020 notice.txt
22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
| 256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|\_ 256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
|\_http-server-header: Apache/2.4.18 (Ubuntu)
|\_http-title: Maintenance
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 3 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.57 seconds

┌──(root㉿docker-desktop)-[/vpn]
└─# http 10.64.159.86:80
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 492
Content-Type: text/html
Date: Sat, 22 Nov 2025 04:16:43 GMT
ETag: "328-5b3e1b06be884-gzip"
Keep-Alive: timeout=5, max=100
Last-Modified: Thu, 12 Nov 2020 04:53:12 GMT
Server: Apache/2.4.18 (Ubuntu)
Vary: Accept-Encoding

<!doctype html>
<title>Maintenance</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
  a { color: #dc8100; text-decoration: none; }
  a:hover { color: #333; text-decoration: none; }
</style>

<article>
    <h1>No spice here!</h1>
    <div>
        <!--when are we gonna update this??-->
        <p>Please excuse us as we develop our site. We want to make it the most stylish and convienient way to buy peppers. Plus, we need a web developer. BTW if you're a web developer, <a href="mailto:#">contact us.</a> Otherwise, don't you worry. We'll be online shortly!</p>
        <p>&mdash; Dev Team</p>
    </div>
</article>

# directory path scan

──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.64.159.86/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.64.159.86/FUZZ
:: Wordlist : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

files [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 202ms]
server-status [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 199ms]
:: Progress: [29999/29999] :: Job [1/1] :: 195 req/sec :: Duration: [0:02:39] :: Errors: 1 ::

# common scan
