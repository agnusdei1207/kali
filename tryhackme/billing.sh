nmap -Pn -sC -sV -oN scan.txt -p- 10.10.210.108
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-31 02:33 BST
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 02:33 (0:00:02 remaining)
Nmap scan report for 10.10.210.108
Host is up (0.000087s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.62 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
| http-title:             MagnusBilling        
|_Requested resource was http://10.10.210.108/mbilling/
3306/tcp open  mysql    MariaDB (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
MAC Address: 02:DF:F8:A8:DC:A7 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

nc -nv 10.10.210.108 5038
Connection to 10.10.210.108 5038 port [tcp/*] succeeded!
Asterisk Call Manager/2.10.6
Response: Error
Message: Missing action in request
→ AMI(Asterisk Manager Interface)가 활성화되어 있지만, 인증 없이 명령을 보냈기 때문에 오류가 발생한 것입니다.


searchsploit Asterisk
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Asterisk 'asterisk-addons' 1.2.7/1.4.3 - CDR_ | linux/remote/30677.pl
Asterisk - 'ast_parse_digest()' Stack Buffer  | linux/dos/18855.txt
Asterisk 0.x/1.0/1.2 Voicemail - Unauthorized | cgi/webapps/26475.txt
Asterisk 1.0.12/1.2.12.1 - 'chan_skinny' Remo | multiple/dos/2597.pl
Asterisk 1.2.15/1.4.0 - Remote Denial of Serv | multiple/dos/3407.c
Asterisk 1.2.16/1.4.1 - SIP INVITE Remote Den | multiple/dos/3566.pl
Asterisk 1.2.x - SIP channel driver / in peda | multiple/dos/5749.pl
Asterisk 1.4 SIP T.38 SDP - Parsing Remote St | multiple/dos/29900.txt
Asterisk 1.4 SIP T.38 SDP - Parsing Remote St | multiple/dos/29901.txt
Asterisk 1.4.x - RTP Codec Payload Handling M | linux/dos/31440.txt
Asterisk 1.6 IAX - 'POKE' Requests Remote Den | linux/dos/32095.pl
Asterisk 1.8.4.1 - SIP 'REGISTER' Request Use | linux/remote/35801.txt
Asterisk 1.8.x - SIP INVITE Request User Enum | multiple/remote/35685.txt
Asterisk 1.x - BYE Message Remote Denial of S | multiple/dos/30974.txt
Asterisk 13.17.2 - 'chan_skinny' Remote Memor | multiple/dos/43992.py
Asterisk < 1.2.22/1.4.8 - IAX2 Channel Driver | multiple/dos/4249.rb
Asterisk < 1.2.22/1.4.8/2.2.1 - 'chan_skinny' | multiple/dos/4196.c
Asterisk chan_pjsip 15.2.0 - 'INVITE' Denial  | linux/dos/44181.py
Asterisk chan_pjsip 15.2.0 - 'SDP fmtp' Denia | linux/dos/44183.py
Asterisk chan_pjsip 15.2.0 - 'SDP' Denial of  | linux/dos/44182.py
Asterisk chan_pjsip 15.2.0 - 'SUBSCRIBE' Stac | linux/dos/44184.py
Asterisk IAX2 - Attacked IAX Fuzzer Resource  | multiple/dos/8940.pl
Asterisk PBX 0.7.x - Multiple Logging Format  | linux/remote/24221.pl
Asterisk Recording Interface 0.7.15 - 'Audio. | multiple/remote/27716.txt
Asterisk Recording Interface 0.7.15/0.10 - Mu | multiple/remote/34301.txt
Asteriskguru Queue Statistics - 'warning' Cro | php/webapps/38375.txt
Fonality trixbox - 'asterisk_info.php' Direct | php/webapps/39349.txt
---------------------------------------------- ---------------------------------
Shellcodes: No Results
root@ip-10-10-99-95:~# 


curl -s http://10.10.34.78/mbilling/ | grep -i version

--- 10.10.210.108 ping statistics ---
4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 3072ms

root@ip-10-10-99-95:~# curl http://10.10.210.108/mbilling/config/config.conf.php
curl: (7) Failed to connect to 10.10.210.108 port 80: Connection refused
root@ip-10-10-99-95:~# 


gobuster dir -u http://10.10.210.108/mbilling/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,log,js
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.34.78/mbilling/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,log,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

Error: error on running gobuster: unable to connect to http://10.10.34.78/mbilling/: Get "http://10.10.34.78/mbilling/": dial tcp 10.10.34.78:80: connect: no route to host
