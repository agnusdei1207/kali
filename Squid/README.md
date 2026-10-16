docker cp universal.ovpn kali:/

apt install openvpn
openvpn --config /universal.ovpn --daemon

apt install procps
ps aux | grep openvpn

apt install iproute2
ip a | grep tun

# 192.168.165.189

nmap -Pn -O -oN nmap.txt -sV -sC -p- 192.168.165.189 --stats-every 1m

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -O -oN nmap.txt -sC -sV -p- 192.168.165.189
Starting Nmap 7.991 ( https://nmap.org ) at 2026-10-16 09:45 +0000
Nmap scan report for 192.168.165.189
Host is up (0.091s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT STATE SERVICE VERSION
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds?
3128/tcp open http-proxy Squid http proxy 4.14
|_http-server-header: squid/4.14
|_http-title: ERROR: The requested URL could not be retrieved
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Microsoft Windows Server 2019 (92%), Microsoft Windows 10 1903 - 22H2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
| 3.1.1:
|_ Message signing enabled but not required
| smb2-time:
| date: 2026-10-16T09:49:09
|_ start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 236.62 seconds
