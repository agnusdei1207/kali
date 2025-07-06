10.10.233.27

# nmap
nmap -sV -sC -Pn -T4 --open -oN namp.scan.txt 10.10.233.27

Nmap scan report for 10.10.233.27
Host is up (0.29s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-02 14:16:14Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-07-02T14:16:45+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2025-07-01T13:50:02
|_Not valid after:  2025-12-31T13:50:02
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-07-02T14:16:35+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-02T14:16:38
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .


| 포트           | 서비스 이름                  | 역할/기능                             | 종류                        |
| ------------ | ----------------------- | --------------------------------- | ------------------------- |
| **88/tcp**   | `kerberos-sec`          | 사용자 인증 (티켓 기반 로그인)                | **인증 프로토콜**               |
| **135/tcp**  | `msrpc`                 | 다양한 Windows 서비스용 원격 프로시저 호출 (RPC) | **프레임워크/통신**              |
| **139/tcp**  | `netbios-ssn`           | 오래된 SMB 통신 (파일 공유 등)              | **통신 프로토콜**               |
| **389/tcp**  | `ldap`                  | AD의 사용자/컴퓨터 정보 조회                 | **디렉터리 서비스 (DB 역할)**      |
| **445/tcp**  | `microsoft-ds`          | 최신 SMB 통신 (파일 공유, 인증 등)           | **파일/서비스 통신 프로토콜**        |
| **464/tcp**  | `kpasswd5`              | Kerberos 암호 변경 기능                 | **인증 서비스**                |
| **593/tcp**  | `ncacn_http`            | RPC over HTTP (원격 관리, Outlook 등)  | **통신 프레임워크**              |
| **636/tcp**  | `ldap over SSL`         | 보안된 LDAP 조회                       | **디렉터리 서비스 (암호화된 DB 조회)** |
| **3268/tcp** | `ldap (Global Catalog)` | AD 포리스트 전체에서 객체 검색                | **디렉터리 서비스 (중앙 DB 조회)**   |
| **3269/tcp** | `ldap GC over SSL`      | 보안된 글로벌 카탈로그 조회                   | **디렉터리 서비스 (암호화된 DB 조회)** |


# enum4linux
apt install enum4linux

──(root㉿docker-desktop)-[/]
└─# enum4linux -a 10.10.233.27
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Jul  6 05:49:20 2025

 =========================================( Target Information )=========================================

Target ........... 10.10.233.27
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.233.27 )============================

Can't exec "dig": No such file or directory at ./enum4linux.pl line 390.
Use of uninitialized value $global_workgroup in pattern match (m//) at ./enum4linux.pl line 391.

[E] Can't find workgroup/domain



 ================================( Nbtstat Information for 10.10.233.27 )================================

Looking up status of 10.10.233.27
No reply from 10.10.233.27

 ===================================( Session Check on 10.10.233.27 )===================================


[+] Server 10.10.233.27 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.233.27 )================================

Domain Name: THM-AD
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)


 ===================================( OS information on 10.10.233.27 )===================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.233.27 from srvinfo: 
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.10.233.27 )=======================================


[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED



[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED


 =================================( Share Enumeration on 10.10.233.27 )=================================

do_connect: Connection to 10.10.233.27 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.233.27


 ============================( Password Policy Information for 10.10.233.27 )============================


[E] Unexpected error from polenum:



[+] Attaching to 10.10.233.27 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.233.27)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient



 =======================================( Groups on 10.10.233.27 )=======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.233.27 via RID cycling (RIDS: 500-550,1000-1050) )==================


 ===============================( Getting printer info for 10.10.233.27 )===============================

Cannot connect to server.  Error was NT_STATUS_IO_TIMEOUT


enum4linux complete on Sun Jul  6 05:51:32 2025

