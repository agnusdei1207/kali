#!/bin/bash

namp
nmap -sV -sC -oN scan.txt -Pn -O 10.10.11.159 -p-
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-29 01:41 BST
Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.01% done
Nmap scan report for 10.10.11.159
Host is up (0.00019s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
| http-title:             MagnusBilling        
|_Requested resource was http://10.10.11.159/mbilling/
3306/tcp open  mysql   MariaDB (unauthorized)
MAC Address: 02:C3:5A:87:D2:CD (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=5/29%OT=22%CT=1%CU=42274%PV=Y%DS=1%DC=D%G=Y%M=02C35A%T
OS:M=6837AD95%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10B%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11N
OS:W7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.87 seconds
gobuster
gobuster dir -u http://10.10.11.159/mbilling/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.159/mbilling/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.hta.html            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/akeeba.backend.log   (Status: 403) [Size: 277]
/archive              (Status: 301) [Size: 323] [--> http://10.10.11.159/mbilling/archive/]
/assets               (Status: 301) [Size: 322] [--> http://10.10.11.159/mbilling/assets/]
/cron.php             (Status: 200) [Size: 0]
/development.log      (Status: 403) [Size: 277]
/fpdf                 (Status: 301) [Size: 320] [--> http://10.10.11.159/mbilling/fpdf/]
/index.html           (Status: 200) [Size: 30760]
/index.html           (Status: 200) [Size: 30760]
/index.php            (Status: 200) [Size: 663]
/index.php            (Status: 200) [Size: 663]
/lib                  (Status: 301) [Size: 319] [--> http://10.10.11.159/mbilling/lib/]
/LICENSE              (Status: 200) [Size: 7652]
/production.log       (Status: 403) [Size: 277]
/protected            (Status: 403) [Size: 277]
/resources            (Status: 301) [Size: 325] [--> http://10.10.11.159/mbilling/resources/]
/spamlog.log          (Status: 403) [Size: 277]
/tmp                  (Status: 301) [Size: 319] [--> http://10.10.11.159/mbilling/tmp/]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================


http://10.10.11.159/mbilling/index.php
