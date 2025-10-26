# 10.201.20.3

nmap -Pn -sV -sC -oN nmap.txt --open 10.201.20.3

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -sV -sC -oN nmap.txt --open 10.201.20.3
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-21 15:03 UTC
Nmap scan report for 10.201.20.3
Host is up (0.34s latency).
Not shown: 998 closed tcp ports (reset)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 7c:7e:2e:2c:f7:c0:c2:65:04:f4:3f:f4:f8:42:af:07 (RSA)
| 256 4b:6e:8e:ff:63:f4:bc:6b:8a:ec:65:97:0f:33:55:40 (ECDSA)
|\_ 256 a7:a3:b7:2f:64:4e:c9:38:10:44:69:58:e1:e8:85:aa (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-title: Publisher's Pulse: SPIP Insights & Tips
|\_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

ffuf -u http://10.201.20.3 -H "Host:FUZZ.10.201.20.3" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.201.20.3 -H "Host:FUZZ.10.201.20.3" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.20.3
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
:: Header : Host: FUZZ.10.201.20.3
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 178

---

22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
| 256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|\_ 256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-server-header: Apache/2.4.41 (Ubuntu)
|\_http-title: Publisher's Pulse: SPIP Insights & Tips
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

![](https://velog.velcdn.com/images/agnusdei1207/post/c9aee363-a145-4492-a058-9d1eabd973c6/image.png)

ffuf -u "http://10.201.20.3/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt -mc all -fs 0 -fc 404
┌──(root㉿docker-desktop)-[/]
└─# ffuf -u "http://10.201.20.3/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.20.3/FUZZ
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

images [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 334ms]
server-status [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 419ms]
spip [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 330ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

![](https://velog.velcdn.com/images/agnusdei1207/post/1857c055-20e8-41ff-a8fa-0947585311cb/image.png)

images, server-status, spip

![](https://velog.velcdn.com/images/agnusdei1207/post/4b46f70a-95d5-4c12-8b5a-47b174ffecf3/image.png)

![](https://velog.velcdn.com/images/agnusdei1207/post/af9a94e6-090f-4696-9601-444fa18824f8/image.png)
http://10.201.20.3/spip/spip.php?page=login&url=spip.php%3Fpage%3Dplan&lang=fr

![](https://velog.velcdn.com/images/agnusdei1207/post/c85edd3d-63d7-4a14-8bc1-cc659a4e2aea/image.png)

- 4.2.0 unauthenticated vulnerable

https://github.com/advisories/GHSA-7w4r-xxr6-xrcj
https://github.com/PaulSec/SPIPScan?source=post_page-----a256af21d7bd---------------------------------------
