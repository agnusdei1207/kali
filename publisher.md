# 10.201.74.120

nmap -Pn -sV -sC -oN nmap.txt --open 10.201.74.120

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -sV -sC -oN nmap.txt --open 10.201.74.120
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-21 15:03 UTC
Nmap scan report for 10.201.74.120
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

ffuf -u http://10.201.74.120 -H "Host:FUZZ.10.201.74.120" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302
