# 192.168.132.65

![](image.png)

> nmap -p- -sS -T4 -Pn -sC -sV --open -O -oN scan.txt 192.168.132.65

┌──(root㉿docker-desktop)-[/]
└─# nmap -p- -T4 -Pn -sC -sV --open -O -oN scan.txt 192.168.132.65
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-06 13:40 +0000
Nmap scan report for 192.168.132.65
Host is up (0.064s latency).
Not shown: 41159 filtered tcp ports (no-response), 24367 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
21/tcp open ftp Microsoft ftpd
| ftp-syst:
|_ SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20 10:31PM <DIR> ImapRetrieval
| 01-06-25 04:54AM <DIR> Logs
| 04-29-20 10:31PM <DIR> PopRetrieval
|_04-29-20 10:32PM <DIR> Spool
80/tcp open http Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_ Potentially risky methods: TRACE
|_http-title: IIS Windows
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds?
5040/tcp open unknown
49664/tcp open msrpc Microsoft Windows RPC
49666/tcp open msrpc Microsoft Windows RPC
49669/tcp open msrpc Microsoft Windows RPC
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode:
| 3.1.1:
|_ Message signing enabled but not required
| smb2-time:
| date: 2026-10-06T13:46:54
|_ start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 413.54 seconds
