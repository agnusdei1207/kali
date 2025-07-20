10.10.234.59

# nmap -Pn -sC -sV -T4 10.10.234.59 -oN nmap.txt --open -sS -> 22, 8000

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -sC -sV -T4 10.10.234.59 -oN nmap.txt --open -sS
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 13:56 UTC
Stats: 0:00:43 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 13:57 (0:00:39 remaining)
Nmap scan report for 10.10.234.59
Host is up (0.28s latency).
Not shown: 920 closed tcp ports (reset), 78 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 06:8f:ef:d3:a9:61:16:08:10:85:0b:ed:be:bc:53:6f (RSA)
| 256 ae:dc:5f:87:48:a1:5e:82:fd:72:26:6d:1f:14:ff:be (ECDSA)
|_ 256 63:b9:b8:e5:45:7c:27:20:7e:5e:fa:cd:d5:7a:c8:6c (ED25519)
8000/tcp open http-alt SimpleHTTP/0.6 Python/3.11.2
|\_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings:
| DNSStatusRequestTCP, DNSVersionBindReqTCP, JavaRMI, LANDesk-RC, NotesRPC, Socks4, X11Probe, afp, giop:
| source code string cannot contain null bytes
| FourOhFourRequest, LPDString, SIPOptions:
| invalid syntax (<string>, line 1)
| GetRequest:
| name 'GET' is not defined
| HTTPOptions, RTSPRequest:
| name 'OPTIONS' is not defined
| Help:
|_ name 'HELP' is not defined
|\_http-server-header: SimpleHTTP/0.6 Python/3.11.2
|\_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.95%I=7%D=7/20%Time=687CF5A3%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,1,"\n")%r(GetRequest,1A,"name\x20'GET'\x20is\x20not\x20defin
SF:ed\n")%r(X11Probe,2D,"source\x20code\x20string\x20cannot\x20contain\x20
SF:null\x20bytes\n")%r(FourOhFourRequest,22,"invalid\x20syntax\x20\(<strin
SF:g>,\x20line\x201\)\n")%r(Socks4,2D,"source\x20code\x20string\x20cannot\
SF:x20contain\x20null\x20bytes\n")%r(HTTPOptions,1E,"name\x20'OPTIONS'\x20
SF:is\x20not\x20defined\n")%r(RTSPRequest,1E,"name\x20'OPTIONS'\x20is\x20n
SF:ot\x20defined\n")%r(DNSVersionBindReqTCP,2D,"source\x20code\x20string\x
SF:20cannot\x20contain\x20null\x20bytes\n")%r(DNSStatusRequestTCP,2D,"sour
SF:ce\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(Help,1
SF:B,"name\x20'HELP'\x20is\x20not\x20defined\n")%r(LPDString,22,"invalid\x
SF:20syntax\x20\(<string>,\x20line\x201\)\n")%r(SIPOptions,22,"invalid\x20
SF:syntax\x20\(<string>,\x20line\x201\)\n")%r(LANDesk-RC,2D,"source\x20cod
SF:e\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(NotesRPC,2D,"so
SF:urce\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(Java
SF:RMI,2D,"source\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\
SF:n")%r(afp,2D,"source\x20code\x20string\x20cannot\x20contain\x20null\x20
SF:bytes\n")%r(giop,2D,"source\x20code\x20string\x20cannot\x20contain\x20n
SF:ull\x20bytes\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 193.67 seconds

# http 10.10.234.59/ -> 페이지 탐색 불가

┌──(root㉿docker-desktop)-[/]
└─# http 10.10.234.59/

http: error: ConnectionError: HTTPConnectionPool(host='10.10.234.59', port=80): Max retries exceeded with url: / (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7ffffd8d6f90>: Failed to establish a new connection: [Errno 111] Connection refused')) while doing a GET request to URL: http://10.10.234.59/

# nc 연결
