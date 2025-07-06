10.10.233.27

# nmap

nmap -sV -sC -Pn -T4 --open -oN namp.scan.txt 10.10.233.27

Nmap scan report for 10.10.233.27
Host is up (0.29s latency).
Not shown: 986 closed tcp ports (reset)
PORT STATE SERVICE VERSION
53/tcp open domain Simple DNS Plus
80/tcp open http Microsoft IIS httpd 10.0
| http-methods:
|_ Potentially risky methods: TRACE
|\_http-title: IIS Windows Server
88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2025-07-02 14:16:14Z)
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp open microsoft-ds?
464/tcp open kpasswd5?
593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0
636/tcp open tcpwrapped
3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open tcpwrapped
3389/tcp open ms-wbt-server Microsoft Terminal Services
|\_ssl-date: 2025-07-02T14:16:45+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2025-07-01T13:50:02
|\_Not valid after: 2025-12-31T13:50:02
| rdp-ntlm-info:
| Target_Name: THM-AD
| NetBIOS_Domain_Name: THM-AD
| NetBIOS_Computer_Name: ATTACKTIVEDIREC
| DNS_Domain_Name: spookysec.local
| DNS_Computer_Name: AttacktiveDirectory.spookysec.local
| Product_Version: 10.0.17763
|_ System_Time: 2025-07-02T14:16:35+00:00
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|\_http-server-header: Microsoft-HTTPAPI/2.0
|\_http-title: Not Found
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
| 3:1:1:
|_ Message signing enabled and required
| smb2-time:
| date: 2025-07-02T14:16:38
|_ start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap은 네트워크 스캐닝 도구로, 호스트와 네트워크 서비스에 대한 정보를 수집하는 데 사용됩니다. 제공된 Nmap 스캔 결과는 IP 주소 `10.10.233.27`에 대한 상세한 스캔 결과를 보여줍니다. 각 포트와 서비스에 대한 정보를 분석하면 다음과 같습니다:

1. **53/tcp**: DNS 서비스 (Simple DNS Plus)가 열려 있습니다. DNS는 도메인 이름을 IP 주소로 변환하는 데 사용됩니다.

2. **80/tcp**: HTTP 서비스 (Microsoft IIS httpd 10.0)가 열려 있습니다. 웹 서버로 사용되며, `TRACE` 메서드가 잠재적으로 위험할 수 있음을 나타냅니다.

3. **88/tcp**: Kerberos 보안 서비스 (Microsoft Windows Kerberos)가 열려 있습니다. Kerberos는 네트워크 인증 프로토콜로 사용됩니다.

4. **135/tcp**: Microsoft Windows RPC (Remote Procedure Call) 서비스가 열려 있습니다. RPC는 원격 시스템에서 프로시저를 실행하는 데 사용됩니다.

5. **139/tcp**: NetBIOS 서비스 (Microsoft Windows netbios-ssn)가 열려 있습니다. NetBIOS는 네트워크에서 통신을 관리하는 데 사용됩니다.

6. **389/tcp**: LDAP 서비스 (Microsoft Windows Active Directory LDAP)가 열려 있습니다. LDAP는 디렉토리 서비스를 제공하는 데 사용됩니다.

7. **445/tcp**: Microsoft-DS 서비스가 열려 있습니다. 이 포트는 SMB (Server Message Block) 프로토콜과 관련이 있습니다.

8. **464/tcp**: Kerberos 비밀번호 변경 서비스 (kpasswd5)가 열려 있습니다.

9. **593/tcp**: RPC over HTTP 서비스가 열려 있습니다. 이 서비스는 원격 프로시저 호출을 HTTP를 통해 수행합니다.

10. **636/tcp**: TCP 래핑된 서비스가 열려 있습니다. 일반적으로 LDAPS (LDAP over SSL)에 사용됩니다.

11. **3268/tcp**: LDAP 서비스 (Microsoft Windows Active Directory LDAP)가 열려 있습니다. 이 포트는 글로벌 카탈로그에 사용됩니다.

12. **3269/tcp**: TCP 래핑된 서비스가 열려 있습니다. 일반적으로 LDAPS에 사용됩니다.

13. **3389/tcp**: Microsoft Terminal Services (RDP)가 열려 있습니다. 원격 데스크톱 연결에 사용됩니다.

14. **5985/tcp**: HTTP 서비스 (Microsoft HTTPAPI httpd 2.0)가 열려 있습니다. SSDP/UPnP와 관련이 있습니다.

**호스트 정보**:

- 호스트 이름: `ATTACKTIVEDIREC`
- netbios 도메인 이름: `THM-AD`
- 운영 체제: Windows
- DNS 도메인 이름: `spookysec.local`

**추가 정보**:

- SMB2 보안 모드: 메시지 서명 활성화 및 필요
- 시스템 시간: 2025-07-02T14:16:38

이 스캔 결과는 대상 시스템이 Windows 기반이며, 다양한 네트워크 서비스를 실행 중임을 보여줍니다. 특히 Active Directory와 관련된 서비스들이 많이 열려 있어, 이 시스템이 도메인 컨트롤러로 사용될 가능성이 높습니다.

# /etc/hosts

10.10.233.27 spookysec.local

# enum4linux

apt install enum4linux

# dnsutils

sudo apt install dnsutils

# bloodhound + neo4j

sudo apt install bloodhound
sudo apt install neo4j

sudo neo4j console

# enum4linux

(kali㉿vbox)-[~]
└─$ sudo enum4linux -a 10.10.233.27
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Jul 6 03:45:13 2025

=========================================( Target Information )=========================================

Target ........... 10.10.233.27
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

============================( Enumerating Workgroup/Domain on 10.10.233.27 )============================

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

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

==================( Users on 10.10.233.27 via RID cycling (RIDS: 500-550,1000-1050) )==================

[I] Found new SID:  
S-1-5-21-3591857110-2884097990-301047963

[I] Found new SID:  
S-1-5-21-3591857110-2884097990-301047963

[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''

S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)  
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)

[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''

S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)  
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)

===============================( Getting printer info for 10.10.233.27 )===============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED

enum4linux complete on Sun Jul 6 04:04:05 2025

# 결과 분석

각 줄은 Windows 시스템에서 사용되는 보안 식별자(SID)와 해당 SID에 연결된 사용자 또는 그룹 계정을 나타냅니다. 각 요소는 다음과 같은 형식으로 구성되어 있습니다:

```
S-1-5-21-<도메인 식별자>-<RID> <도메인 이름>\<계정 이름> (<계정 유형>)
```

각 필드를 설명하면 다음과 같습니다:

1. **S-1-5-21-3591857110-2884097990-301047963**:

   - **설명**: 이 부분은 SID의 기본 구조를 나타냅니다. `S-1-5-21`은 Windows 시스템에서 도메인 사용자 및 그룹을 식별하는 데 사용되는 표준 접두사입니다. 그 뒤에 오는 숫자(`3591857110-2884097990-301047963`)는 해당 도메인을 고유하게 식별합니다.

2. **-<RID>**:

   - **설명**: Relative Identifier(RID)는 SID의 마지막 부분으로, 특정 사용자 또는 그룹을 고유하게 식별합니다. 예를 들어, `500`은 일반적으로 관리자 계정을 나타냅니다.

3. **<도메인 이름>**:

   - **설명**: 이 부분은 사용자 또는 그룹이 속한 도메인의 이름을 나타냅니다. 예제에서는 `THM-AD`가 도메인 이름으로 사용되었습니다.

4. **<계정 이름>**:

   - **설명**: 이 부분은 사용자 또는 그룹의 이름을 나타냅니다. 예를 들어, `Administrator`, `Guest`, `Domain Admins` 등이 있습니다.

5. **(<계정 유형>)**:
   - **설명**: 이 부분은 계정의 유형을 나타냅니다. `Local User`는 로컬 사용자 계정을, `Domain Group`은 도메인 그룹을 나타냅니다.

# Kerberos Enumeration

수집된 유저 정보를 가지고 브루트포스 실행하기

kerberute --usernames userlist --domain spookysec.local --kdc
