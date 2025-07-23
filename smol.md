# IP: 10.10.147.162

# nmap -> 22, 80

http://www.smol.thm

Nmap scan report for 10.10.147.162
Host is up (0.29s latency).
Not shown: 995 closed tcp ports (reset), 3 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 86:fb:3f:1f:18:c9:c9:32:cb:10:08:20:d0:f7:c3:58 (RSA)
| 256 ae:c8:74:d8:57:c1:26:67:92:b1:21:ef:9a:e0:c7:ea (ECDSA)
|\_ 256 59:77:71:a7:d8:b9:92:cc:00:e4:e3:b0:f9:16:03:f8 (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-title: Did not follow redirect to http://www.smol.thm
|\_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.78 seconds
