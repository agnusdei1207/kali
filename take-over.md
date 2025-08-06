10.201.29.44

# Nmap 7.95 scan initiated Wed Aug 6 14:23:39 2025 as: /usr/lib/nmap/nmap -Pn -sV -sC --open -oN nmap.txt 10.201.29.44

Nmap scan report for 10.201.29.44
Host is up (0.38s latency).
Not shown: 967 closed tcp ports (reset), 30 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 71:5a:59:e8:8b:66:d2:37:9c:a7:da:d9:7f:8e:56:e7 (RSA)
| 256 56:e1:b9:04:9b:3d:a5:46:a7:fc:65:b8:cd:9c:23:61 (ECDSA)
|_ 256 51:61:75:36:97:b2:96:12:61:b4:5e:9b:3f:e5:b2:f4 (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-server-header: Apache/2.4.41 (Ubuntu)
|\_http-title: Did not follow redirect to https://futurevera.thm/
443/tcp open ssl/http Apache httpd 2.4.41 ((Ubuntu))
|\_http-server-header: Apache/2.4.41 (Ubuntu)
| ssl-cert: Subject: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US
| Not valid before: 2022-03-13T10:05:19
|\_Not valid after: 2023-03-13T10:05:19
|\_ssl-date: TLS randomness does not represent time
|\_http-title: FutureVera
| tls-alpn:
|_ http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Aug 6 14:24:19 2025 -- 1 IP address (1 host up) scanned in 39.32 seconds

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u https://futurevera.thm/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -o ffuf_raft-large-directories.txt
